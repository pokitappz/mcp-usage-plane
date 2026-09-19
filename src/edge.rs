//! The two endpoints a sidecar talks to.
//!
//! Everything here is deliberately small. A sidecar sits in customer
//! infrastructure and stays up while this service is down, so the contract is
//! "pull a whole snapshot" and "post an idempotent batch", with no session, no
//! cursor and no ordering requirement between the two.

use axum::extract::State;
use axum::{Json, Router, routing};
use chrono::{DateTime, TimeZone, Utc};
use mcp_usage_core::PriceBook;
use serde::{Deserialize, Serialize};
use sqlx::Row as _;

use crate::AppState;
use crate::auth::EdgeCaller;
use crate::error::{ApiError, ApiResult};

/// One authenticating key, with everything the edge needs to price, admit and
/// attribute a call without asking again.
#[derive(Debug, Serialize)]
pub struct SnapshotEntry {
    /// SHA-256 of the tenant key, matching `mcp_usage_kit::hash_api_key`.
    pub api_key_sha256: String,
    /// `Tenant.id`.
    pub tenant_id: String,
    /// `Tenant.billing_customer_id`.
    pub billing_customer_id: String,
    /// `Tenant.prices`.
    pub prices: PriceBook,
    /// Unit quota, null for unbounded.
    pub max_units: Option<u64>,
    /// Spend cap in millionths, null for unbounded.
    pub max_spend_micros: Option<u64>,
    /// Monetary price of one unit, in millionths.
    pub unit_price_micros: u64,
    /// Units already committed in the current window.
    pub committed_units: u64,
    /// Spend already committed in the current window, in millionths.
    pub committed_spend_micros: u64,
}

/// A full replacement view of everything the edge may serve.
#[derive(Debug, Serialize)]
pub struct Snapshot {
    /// When the plane produced this. The edge ages its cache against it.
    pub issued_at: DateTime<Utc>,
    /// Start of the counter window the committed totals belong to.
    pub window_start: DateTime<Utc>,
    /// One entry per active key. A tenant with two keys appears twice.
    pub tenants: Vec<SnapshotEntry>,
}

/// One aggregate as the edge sends it. Mirrors `AggregatedUsage`.
#[derive(Debug, Deserialize)]
pub struct UsageIn {
    /// Stable provider-side idempotency identity.
    pub identifier: String,
    /// Billing-provider customer identifier.
    pub customer_id: String,
    /// Meter event name.
    pub meter: String,
    /// Summed integer quantity.
    pub units: u64,
    /// Unix seconds of the oldest event in the aggregate.
    pub timestamp: u64,
}

/// A batch post.
#[derive(Debug, Deserialize)]
pub struct UsageBatch {
    /// Aggregates in the exporter's original order.
    pub events: Vec<UsageIn>,
}

/// Per-event disposition. Maps one-to-one onto `MeterEventOutcome`.
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// Durably recorded, or already present.
    Accepted,
    /// Unresolved. The edge must resend with the same identifier.
    Retry,
    /// Permanently invalid. The edge must stop resending it.
    Rejected,
}

/// One outcome, echoed with its identifier so the edge cannot misalign them.
#[derive(Debug, Serialize)]
pub struct OutcomeOut {
    /// The identifier this outcome belongs to.
    pub identifier: String,
    /// What happened.
    pub outcome: Outcome,
}

/// The ingest response.
#[derive(Debug, Serialize)]
pub struct UsageAck {
    /// Exactly one entry per submitted event, in the submitted order.
    pub outcomes: Vec<OutcomeOut>,
}

/// Largest batch accepted in one request.
const MAX_BATCH: usize = 1_000;

/// Edge routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/edge/snapshot", routing::get(snapshot))
        .route("/v1/edge/usage", routing::post(ingest))
}

async fn snapshot(
    State(state): State<AppState>,
    EdgeCaller(caller): EdgeCaller,
) -> ApiResult<Json<Snapshot>> {
    // One row per live key. Revoked tenants and revoked keys are simply absent,
    // which is the whole revocation mechanism: the edge cannot authenticate a
    // key it was never given.
    let rows = sqlx::query(
        "SELECT k.key_sha256, t.tenant_key, t.billing_customer_id, t.prices,
                t.max_units, t.max_spend_micros, t.unit_price_micros,
                COALESCE(c.units, 0) AS committed_units,
                COALESCE(c.spend_micros, 0) AS committed_spend_micros
         FROM tenant_api_keys k
         JOIN tenants t ON t.id = k.tenant_id
         LEFT JOIN usage_counters c
                ON c.account_id = t.account_id
               AND c.customer_id = t.billing_customer_id
               AND c.window_start = date_trunc('month', NOW())
         WHERE t.account_id = $1
           AND t.revoked_at IS NULL
           AND k.revoked_at IS NULL",
    )
    .bind(&caller.account_id)
    .fetch_all(&state.pool)
    .await?;

    let window_start: DateTime<Utc> = sqlx::query_scalar("SELECT date_trunc('month', NOW())")
        .fetch_one(&state.pool)
        .await?;

    let mut tenants = Vec::with_capacity(rows.len());
    for row in rows {
        let prices: serde_json::Value = row.try_get("prices")?;
        let prices: PriceBook = serde_json::from_value(prices).map_err(|error| {
            tracing::error!(%error, "stored price book no longer deserializes");
            ApiError::Internal
        })?;
        tenants.push(SnapshotEntry {
            api_key_sha256: row.try_get("key_sha256")?,
            tenant_id: row.try_get("tenant_key")?,
            billing_customer_id: row.try_get("billing_customer_id")?,
            prices,
            max_units: to_u64_opt(row.try_get("max_units")?),
            max_spend_micros: to_u64_opt(row.try_get("max_spend_micros")?),
            unit_price_micros: to_u64(row.try_get("unit_price_micros")?),
            committed_units: to_u64(row.try_get("committed_units")?),
            committed_spend_micros: to_u64(row.try_get("committed_spend_micros")?),
        });
    }

    Ok(Json(Snapshot {
        issued_at: Utc::now(),
        window_start,
        tenants,
    }))
}

const fn to_u64(value: i64) -> u64 {
    // Every column feeding this has a `>= 0` check constraint.
    value.unsigned_abs()
}

const fn to_u64_opt(value: Option<i64>) -> Option<u64> {
    match value {
        Some(value) => Some(value.unsigned_abs()),
        None => None,
    }
}

/// Reject an event we can never store, rather than retrying it forever.
fn validate(event: &UsageIn) -> Result<(i64, DateTime<Utc>), &'static str> {
    if event.identifier.trim().is_empty() {
        return Err("empty identifier");
    }
    let units = i64::try_from(event.units).map_err(|_| "units out of range")?;
    let seconds = i64::try_from(event.timestamp).map_err(|_| "timestamp out of range")?;
    let Some(event_at) = Utc.timestamp_opt(seconds, 0).single() else {
        return Err("timestamp out of range");
    };
    Ok((units, event_at))
}

async fn ingest(
    State(state): State<AppState>,
    EdgeCaller(caller): EdgeCaller,
    Json(batch): Json<UsageBatch>,
) -> ApiResult<Json<UsageAck>> {
    if batch.events.len() > MAX_BATCH {
        return Err(ApiError::BadRequest(format!(
            "batch of {} exceeds the {MAX_BATCH} event limit",
            batch.events.len()
        )));
    }

    // Validate before opening a transaction, so a permanently invalid event
    // never costs a rollback and never blocks the valid ones beside it.
    let mut prepared = Vec::with_capacity(batch.events.len());
    for event in &batch.events {
        prepared.push(validate(event));
    }

    let mut tx = state.pool.begin().await?;
    let mut outcomes = Vec::with_capacity(batch.events.len());

    for (event, prepared) in batch.events.iter().zip(prepared) {
        let (units, event_at) = match prepared {
            Ok(values) => values,
            Err(reason) => {
                tracing::warn!(reason, "rejecting an unstorable usage event");
                outcomes.push(OutcomeOut {
                    identifier: event.identifier.clone(),
                    outcome: Outcome::Rejected,
                });
                continue;
            }
        };

        // The primary key is the whole deduplication story: the exporter
        // guarantees a stable identifier across retries, so a replayed batch
        // inserts nothing and moves no counter.
        let inserted: Option<String> = sqlx::query_scalar(
            "INSERT INTO usage_events
               (identifier, account_id, customer_id, meter, units, event_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (identifier) DO NOTHING
             RETURNING identifier",
        )
        .bind(&event.identifier)
        .bind(&caller.account_id)
        .bind(&event.customer_id)
        .bind(&event.meter)
        .bind(units)
        .bind(event_at)
        .fetch_optional(&mut *tx)
        .await?;

        if inserted.is_some() {
            // Tenants that share a billing customer share a quota pool. Where
            // they disagree on unit price the highest one applies, because
            // over-stating spend is the safe direction for a spend cap.
            let unit_price: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(unit_price_micros), 0) FROM tenants
                 WHERE account_id = $1 AND billing_customer_id = $2",
            )
            .bind(&caller.account_id)
            .bind(&event.customer_id)
            .fetch_one(&mut *tx)
            .await?;

            let spend = units.saturating_mul(unit_price);
            sqlx::query(
                "INSERT INTO usage_counters
                   (account_id, customer_id, window_start, units, spend_micros)
                 VALUES ($1, $2, date_trunc('month', $3::timestamptz), $4, $5)
                 ON CONFLICT (account_id, customer_id, window_start) DO UPDATE
                   SET units = usage_counters.units + EXCLUDED.units,
                       spend_micros = usage_counters.spend_micros + EXCLUDED.spend_micros",
            )
            .bind(&caller.account_id)
            .bind(&event.customer_id)
            .bind(event_at)
            .bind(units)
            .bind(spend)
            .execute(&mut *tx)
            .await?;
        }

        outcomes.push(OutcomeOut {
            identifier: event.identifier.clone(),
            outcome: Outcome::Accepted,
        });
    }

    // A failed commit means nothing landed, so every accepted verdict above is
    // withdrawn and the whole batch becomes retryable. Saying "accepted" for a
    // row that rolled back is the one outcome that loses money silently.
    if let Err(error) = tx.commit().await {
        tracing::error!(%error, "usage batch commit failed");
        return Ok(Json(UsageAck {
            outcomes: batch
                .events
                .iter()
                .map(|event| OutcomeOut {
                    identifier: event.identifier.clone(),
                    outcome: Outcome::Retry,
                })
                .collect(),
        }));
    }

    Ok(Json(UsageAck { outcomes }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(identifier: &str, units: u64, timestamp: u64) -> UsageIn {
        UsageIn {
            identifier: identifier.to_owned(),
            customer_id: "cus_acme".to_owned(),
            meter: "mcp_units".to_owned(),
            units,
            timestamp,
        }
    }

    #[test]
    fn a_normal_event_validates() {
        let (units, at) = validate(&event("id-1", 7, 1_789_757_188)).expect("valid");
        assert_eq!(units, 7);
        assert_eq!(at.timestamp(), 1_789_757_188);
    }

    #[test]
    fn an_empty_identifier_is_permanently_rejected() {
        assert_eq!(validate(&event("  ", 1, 0)), Err("empty identifier"));
    }

    #[test]
    fn units_beyond_i64_are_permanently_rejected() {
        assert_eq!(
            validate(&event("id-1", u64::MAX, 0)),
            Err("units out of range")
        );
    }

    #[test]
    fn an_absurd_timestamp_is_permanently_rejected() {
        assert_eq!(
            validate(&event("id-1", 1, u64::MAX)),
            Err("timestamp out of range")
        );
    }

    #[test]
    fn zero_units_still_validate() {
        // The meter does not emit zero-unit aggregates, but rejecting them here
        // would turn a harmless no-op into a permanent rejection.
        assert!(validate(&event("id-1", 0, 1_789_757_188)).is_ok());
    }
}
