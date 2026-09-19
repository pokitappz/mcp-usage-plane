//! Usage rollups and quota status.
//!
//! Grain note: there is no per-tool breakdown here, and that is not an
//! oversight. An `AggregatedUsage` carries only its identifier, billing
//! customer, meter name, unit count and timestamp; the meter aggregates on the
//! billing customer and meter name, and the library deliberately keeps tool
//! names, prompt names and resource URIs out of anything it persists or
//! exports. Reporting per tool would mean changing what the edge sends and
//! giving up that property. An operator who wants the breakdown can price tools
//! onto distinct meter names instead, which keeps the names on their side of
//! the wire.

use axum::extract::{Query, State};
use axum::{Json, Router, routing};
use chrono::{DateTime, Utc};
use mcp_usage_core::{Limits, Usage, assess_limits};
use serde::{Deserialize, Serialize};
use sqlx::Row as _;

use crate::AppState;
use crate::auth::AdminCaller;
use crate::error::{ApiError, ApiResult};

/// Query parameters for a rollup.
#[derive(Debug, Deserialize)]
pub struct RollupQuery {
    /// Inclusive lower bound.
    #[serde(default)]
    pub from: Option<DateTime<Utc>>,
    /// Exclusive upper bound.
    #[serde(default)]
    pub to: Option<DateTime<Utc>>,
    /// Restrict to one billing customer.
    #[serde(default)]
    pub customer_id: Option<String>,
    /// `hour`, `day` or `month`. Defaults to `day`.
    #[serde(default)]
    pub bucket: Option<String>,
}

/// One row of a rollup.
#[derive(Debug, Serialize)]
pub struct RollupRow {
    /// Start of the bucket.
    pub bucket: DateTime<Utc>,
    /// Billing customer.
    pub customer_id: String,
    /// Meter name.
    pub meter: String,
    /// Summed units.
    pub units: i64,
    /// Number of aggregates contributing.
    pub events: i64,
}

/// Quota status for one billing customer in the current window.
#[derive(Debug, Serialize)]
pub struct QuotaRow {
    /// Billing customer.
    pub customer_id: String,
    /// Units committed in the window.
    pub committed_units: u64,
    /// Spend committed in the window, in millionths.
    pub committed_spend_micros: u64,
    /// Unit quota, null for unbounded.
    pub max_units: Option<u64>,
    /// Spend cap in millionths, null for unbounded.
    pub max_spend_micros: Option<u64>,
    /// Whether another unit would currently be admitted.
    pub admitting: bool,
    /// Why not, when `admitting` is false.
    pub reason: Option<String>,
}

/// Admin reporting routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/usage", routing::get(rollup))
        .route("/v1/usage/quota", routing::get(quota))
}

/// Bucket sizes are an allowlist, never interpolated from caller input.
fn bucket_expression(bucket: Option<&str>) -> ApiResult<&'static str> {
    match bucket.unwrap_or("day") {
        "hour" => Ok("hour"),
        "day" => Ok("day"),
        "month" => Ok("month"),
        other => Err(ApiError::BadRequest(format!(
            "bucket {other:?} must be hour, day or month"
        ))),
    }
}

async fn rollup(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
    Query(params): Query<RollupQuery>,
) -> ApiResult<Json<Vec<RollupRow>>> {
    if let (Some(from), Some(to)) = (params.from, params.to)
        && from > to
    {
        return Err(ApiError::BadRequest("from must not be after to".to_owned()));
    }
    let bucket = bucket_expression(params.bucket.as_deref())?;

    let sql = format!(
        "SELECT date_trunc('{bucket}', event_at) AS bucket, customer_id, meter,
                SUM(units)::bigint AS units, COUNT(*)::bigint AS events
         FROM usage_events
         WHERE account_id = $1
           AND ($2::timestamptz IS NULL OR event_at >= $2)
           AND ($3::timestamptz IS NULL OR event_at < $3)
           AND ($4::text IS NULL OR customer_id = $4)
         GROUP BY 1, 2, 3
         ORDER BY 1 DESC, 2, 3"
    );

    let rows = sqlx::query(&sql)
        .bind(&caller.account_id)
        .bind(params.from)
        .bind(params.to)
        .bind(params.customer_id.as_deref())
        .fetch_all(&state.pool)
        .await?;

    rows.into_iter()
        .map(|row| {
            Ok(RollupRow {
                bucket: row.try_get("bucket")?,
                customer_id: row.try_get("customer_id")?,
                meter: row.try_get("meter")?,
                units: row.try_get("units")?,
                events: row.try_get("events")?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

async fn quota(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
) -> ApiResult<Json<Vec<QuotaRow>>> {
    let rows = sqlx::query(
        "SELECT t.billing_customer_id,
                MAX(t.max_units) AS max_units,
                MAX(t.max_spend_micros) AS max_spend_micros,
                COALESCE(MAX(c.units), 0) AS committed_units,
                COALESCE(MAX(c.spend_micros), 0) AS committed_spend_micros
         FROM tenants t
         LEFT JOIN usage_counters c
                ON c.account_id = t.account_id
               AND c.customer_id = t.billing_customer_id
               AND c.window_start = date_trunc('month', NOW())
         WHERE t.account_id = $1 AND t.revoked_at IS NULL
         GROUP BY t.billing_customer_id
         ORDER BY t.billing_customer_id",
    )
    .bind(&caller.account_id)
    .fetch_all(&state.pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let committed_units: i64 = row.try_get("committed_units")?;
        let committed_spend_micros: i64 = row.try_get("committed_spend_micros")?;
        let max_units: Option<i64> = row.try_get("max_units")?;
        let max_spend_micros: Option<i64> = row.try_get("max_spend_micros")?;

        let current = Usage {
            units: committed_units.unsigned_abs(),
            spend_micros: committed_spend_micros.unsigned_abs(),
        };
        let limits = Limits {
            max_units: max_units.map(i64::unsigned_abs),
            max_spend_micros: max_spend_micros.map(i64::unsigned_abs),
        };
        // The same pure decision the edge applies, so the plane and the sidecar
        // can never disagree about where a boundary sits.
        let decision = assess_limits(current, 0, 0, limits);
        out.push(QuotaRow {
            customer_id: row.try_get("billing_customer_id")?,
            committed_units: current.units,
            committed_spend_micros: current.spend_micros,
            max_units: limits.max_units,
            max_spend_micros: limits.max_spend_micros,
            admitting: decision.is_allowed(),
            reason: match decision {
                mcp_usage_core::LimitDecision::Allowed(_) => None,
                mcp_usage_core::LimitDecision::Rejected(reason) => Some(format!("{reason:?}")),
            },
        });
    }
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_sizes_are_an_allowlist() {
        assert_eq!(bucket_expression(None).unwrap(), "day");
        assert_eq!(bucket_expression(Some("hour")).unwrap(), "hour");
        assert_eq!(bucket_expression(Some("month")).unwrap(), "month");
        // The bucket is interpolated into SQL, so anything outside the
        // allowlist has to be refused rather than escaped.
        for attempt in ["day'); DROP TABLE usage_events; --", "week", ""] {
            assert!(bucket_expression(Some(attempt)).is_err(), "{attempt:?}");
        }
    }
}
