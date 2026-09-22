//! Forwarding ingested usage to a billing provider, and reconciling what fails.
//!
//! ## Why this drives the provider directly
//!
//! `MeterEventExporter` exists so an in-process pipeline can keep partial retry
//! progress and a bounded dead letter queue in memory. The plane has a database:
//! the ledger already records every aggregate durably and idempotently, so the
//! in-memory machinery would only add a second, weaker copy of state that can
//! disagree with the first and dies with the process. This calls
//! `MeterEventProvider::submit` directly and writes each outcome to Postgres.
//!
//! ## Two directions
//!
//! Downstream is the product: an account's usage reaches *its own* billing
//! provider. Upstream is the revenue: the plane bills its customers for the
//! usage it processed. They ride the same providers and the same stable
//! identifiers, and are tracked in separate columns so either can be retried or
//! replayed without disturbing the other.

use axum::extract::{Path, State};
use axum::{Json, Router, routing};
use chrono::{DateTime, Utc};
use mcp_usage_export::{AggregatedUsage, MeterEventOutcome, MeterEventProvider};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row as _};

use crate::AppState;
use crate::auth::AdminCaller;
use crate::error::{ApiError, ApiResult};
use crate::providers::{StripeMeterProvider, WebhookProvider};
use crate::secret::SealingKey;

/// Largest number of aggregates sent to a provider in one cycle, per account.
const DRAIN_BATCH: i64 = 200;

/// Which direction a drain is running in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The account's usage to the account's own billing provider.
    Downstream,
    /// The usage the plane processed, to the plane's own billing provider.
    Upstream,
}

impl Direction {
    const fn column(self) -> &'static str {
        match self {
            Self::Downstream => "exported_at",
            Self::Upstream => "plane_billed_at",
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Downstream => "downstream",
            Self::Upstream => "upstream",
        }
    }

    /// The identifier presented to the provider.
    ///
    /// The two directions can reach the same provider account, so the upstream
    /// event is namespaced. Without it a customer forwarding to the same Stripe
    /// account the plane bills through would see one of the two silently
    /// deduplicated away.
    fn identifier_for(self, identifier: &str) -> String {
        match self {
            Self::Downstream => identifier.to_owned(),
            Self::Upstream => format!("plane:{identifier}"),
        }
    }
}

// ------------------------------------------------------------ destinations

/// A resolved export destination, with its credential already opened.
pub enum Destination {
    /// Keep the ledger only.
    None,
    /// Stripe Billing Meter Events.
    Stripe {
        /// The account's Stripe secret key.
        secret: String,
        /// Meter name override, or the edge's own meter name when absent.
        meter_name: Option<String>,
        /// Loopback override for tests.
        endpoint: Option<String>,
    },
    /// Signed JSON to a customer-supplied endpoint.
    Webhook {
        /// Where to post.
        endpoint: String,
        /// HMAC signing secret.
        secret: String,
        /// Meter name override.
        meter_name: Option<String>,
    },
}

impl Destination {
    /// The label recorded on a dead letter.
    const fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Stripe { .. } => "stripe",
            Self::Webhook { .. } => "webhook",
        }
    }

    /// Build the provider this destination describes.
    fn provider(
        &self,
        allow_loopback: bool,
    ) -> Option<Box<dyn MeterEventProvider + Send + Sync + '_>> {
        match self {
            Self::None => None,
            Self::Stripe {
                secret,
                meter_name,
                endpoint,
            } => {
                let provider = StripeMeterProvider::new(secret.clone(), meter_name.clone()).ok()?;
                let provider = match endpoint {
                    Some(endpoint) => provider.with_endpoint(endpoint.clone()).ok()?,
                    None => provider,
                };
                Some(Box::new(provider))
            }
            Self::Webhook {
                endpoint,
                secret,
                meter_name,
            } => WebhookProvider::new(
                endpoint.clone(),
                secret.clone(),
                meter_name.clone(),
                allow_loopback,
            )
            .ok()
            .map(|provider| Box::new(provider) as Box<dyn MeterEventProvider + Send + Sync>),
        }
    }
}

/// Load and open an account's destination.
///
/// # Errors
///
/// Returns [`ApiError::Internal`] when the stored credential cannot be opened,
/// which means the sealing key changed or the row was tampered with.
pub async fn load_destination(
    pool: &PgPool,
    sealing: Option<&SealingKey>,
    account_id: &str,
) -> ApiResult<Destination> {
    let Some(row) = sqlx::query(
        "SELECT kind, secret_sealed, meter_name, endpoint
         FROM export_destinations WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(Destination::None);
    };

    let kind: String = row.try_get("kind")?;
    if kind == "none" {
        return Ok(Destination::None);
    }

    let sealed: Option<String> = row.try_get("secret_sealed")?;
    let meter_name: Option<String> = row.try_get("meter_name")?;
    let endpoint: Option<String> = row.try_get("endpoint")?;

    let Some(sealing) = sealing else {
        tracing::error!(
            account_id,
            "a destination is configured but no sealing key is loaded"
        );
        return Err(ApiError::Internal);
    };
    let secret = sealing
        .open(sealed.as_deref().unwrap_or_default())
        .map_err(|error| {
            tracing::error!(account_id, %error, "stored billing credential could not be opened");
            ApiError::Internal
        })?;

    Ok(match kind.as_str() {
        "stripe" => Destination::Stripe {
            secret,
            meter_name,
            endpoint,
        },
        "webhook" => Destination::Webhook {
            endpoint: endpoint.unwrap_or_default(),
            secret,
            meter_name,
        },
        other => {
            tracing::error!(
                account_id,
                kind = other,
                "unknown destination kind in the database"
            );
            return Err(ApiError::Internal);
        }
    })
}

// --------------------------------------------------------------- the drain

/// Run one drain cycle for one account and direction.
///
/// Returns the number of aggregates the provider settled, accepted or rejected.
///
/// # Errors
///
/// Returns a database error. A provider failure is not an error here: it leaves
/// rows unmarked so the next cycle retries them.
/// One aggregate the provider refused for good, with its ledger key.
type Rejected = (AggregatedUsage, String, DateTime<Utc>, &'static str);

/// Record rejections durably and mark everything settled, in one transaction.
async fn settle(
    pool: &PgPool,
    account_id: &str,
    direction: Direction,
    destination: &Destination,
    rejected: &[Rejected],
    settled: &mut Vec<String>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    // A permanent rejection is settled, not retried, so it is recorded durably
    // before the row is marked. The library's in-process queue is bounded and
    // dies with the process; reconciliation data has to outlive both.
    for (usage, ledger_id, event_at, reason) in rejected {
        sqlx::query(
            "INSERT INTO export_dead_letters
               (identifier, account_id, customer_id, meter, units, event_at,
                direction, destination, reason)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (identifier, direction) DO NOTHING",
        )
        .bind(ledger_id)
        .bind(account_id)
        .bind(&usage.customer_id)
        .bind(&usage.meter)
        .bind(i64::try_from(usage.units).unwrap_or(i64::MAX))
        .bind(event_at)
        .bind(direction.as_str())
        .bind(destination.label())
        .bind(*reason)
        .execute(&mut *tx)
        .await?;

        tracing::error!(
            account_id,
            direction = direction.as_str(),
            destination = destination.label(),
            reason = *reason,
            "usage was permanently rejected and is now awaiting reconciliation"
        );
        settled.push(ledger_id.clone());
    }

    if !settled.is_empty() {
        sqlx::query(&format!(
            "UPDATE usage_events SET {column} = NOW()
             WHERE account_id = $1 AND identifier = ANY($2)",
            column = direction.column()
        ))
        .bind(account_id)
        .bind(&*settled)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await
}

/// The three parallel views of one drained page.
struct Prepared {
    /// What the provider is sent.
    batch: Vec<AggregatedUsage>,
    /// Event times, for a dead letter row.
    event_times: Vec<DateTime<Utc>>,
    /// Ledger keys, for the UPDATE and the dead letter row. Distinct from the
    /// provider-facing identifier, which the upstream direction namespaces.
    ledger_ids: Vec<String>,
}

fn prepare(
    rows: &[sqlx::PgRow],
    direction: Direction,
    customer_override: Option<&str>,
) -> Result<Prepared, sqlx::Error> {
    let mut batch = Vec::with_capacity(rows.len());
    let mut event_times = Vec::with_capacity(rows.len());
    let mut ledger_ids = Vec::with_capacity(rows.len());
    for row in rows {
        let units: i64 = row.try_get("units")?;
        let epoch: i64 = row.try_get("event_epoch")?;
        let identifier: String = row.try_get("identifier")?;
        let customer_id: String = row.try_get("customer_id")?;
        event_times.push(row.try_get("event_at")?);
        batch.push(AggregatedUsage {
            identifier: direction.identifier_for(&identifier),
            customer_id: customer_override.map_or(customer_id, str::to_owned),
            meter: row.try_get("meter")?,
            units: units.unsigned_abs(),
            timestamp: epoch.unsigned_abs(),
        });
        ledger_ids.push(identifier);
    }
    Ok(Prepared {
        batch,
        event_times,
        ledger_ids,
    })
}

/// `customer_override` re-attributes every aggregate to one billing customer.
/// Upstream needs it: the ledger records the account's *own* customer, but the
/// plane invoices the account, and sending the ledger value would bill a
/// stranger's identifier to the plane's Stripe account.
pub async fn drain_once(
    pool: &PgPool,
    allow_loopback: bool,
    account_id: &str,
    direction: Direction,
    destination: &Destination,
    customer_override: Option<&str>,
) -> Result<usize, sqlx::Error> {
    let Some(provider) = destination.provider(allow_loopback) else {
        return Ok(0);
    };

    let rows = sqlx::query(&format!(
        "SELECT identifier, customer_id, meter, units,
                EXTRACT(EPOCH FROM event_at)::bigint AS event_epoch, event_at
         FROM usage_events
         WHERE account_id = $1 AND {column} IS NULL
         ORDER BY event_at
         LIMIT $2",
        column = direction.column()
    ))
    .bind(account_id)
    .bind(DRAIN_BATCH)
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Ok(0);
    }

    let Prepared {
        batch,
        event_times,
        ledger_ids,
    } = prepare(&rows, direction, customer_override)?;

    let outcomes = match provider.submit(&batch).await {
        Ok(outcomes) if outcomes.len() == batch.len() => outcomes,
        Ok(outcomes) => {
            // The contract makes a wrong outcome count a batch-wide failure.
            // Applying them anyway would settle the wrong aggregates.
            tracing::error!(
                account_id,
                expected = batch.len(),
                received = outcomes.len(),
                "provider returned the wrong number of outcomes; nothing settled"
            );
            return Ok(0);
        }
        Err(error) => {
            tracing::warn!(
                account_id,
                direction = direction.as_str(),
                code = error.code(),
                "export failed; rows stay pending"
            );
            return Ok(0);
        }
    };

    let mut settled: Vec<String> = Vec::new();
    let mut rejected: Vec<Rejected> = Vec::new();
    for (((usage, event_at), ledger_id), outcome) in batch
        .iter()
        .zip(&event_times)
        .zip(&ledger_ids)
        .zip(&outcomes)
    {
        match outcome {
            MeterEventOutcome::Accepted => settled.push(ledger_id.clone()),
            MeterEventOutcome::PermanentRejection { code } => {
                rejected.push((usage.clone(), ledger_id.clone(), *event_at, *code));
            }
            // Left unmarked on purpose: the next cycle picks it up with the
            // same identifier, and the provider deduplicates.
            MeterEventOutcome::RetryableFailure { .. } => {}
        }
    }

    settle(
        pool,
        account_id,
        direction,
        destination,
        &rejected,
        &mut settled,
    )
    .await?;
    Ok(settled.len())
}

/// Drain every account with a configured destination, forever.
///
/// # Running more than one instance
///
/// Nothing here takes a lock, and that is deliberate rather than an oversight.
/// Two instances draining the same account select the same pending rows and
/// submit them both - which is safe, because every provider this plane talks to
/// deduplicates on the aggregate identifier: Stripe for at least 24 hours, and
/// a webhook receiver by the contract documented on `WebhookProvider`. The same
/// property is what lets a `RetryableFailure` be left unmarked and picked up by
/// the next cycle.
///
/// So concurrency here costs duplicate provider calls, not duplicate billing,
/// and a rolling deploy overlapping two instances is a rate-limit question
/// rather than a correctness one.
///
/// Do not "fix" this with a session-scoped `pg_advisory_lock`. These
/// connections come from a pool and are reused rather than closed, so a lock
/// left behind by a failed drain would block that account's exports until the
/// process restarts - trading a harmless duplicate for a silent, permanent
/// stall. If duplicate submissions ever need eliminating, it takes a claim
/// column with a lease, which is a migration.
pub async fn drain_forever(state: AppState, interval: std::time::Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if let Err(error) = drain_all(&state).await {
            tracing::error!(%error, "export drain cycle failed");
        }
    }
}

async fn drain_all(state: &AppState) -> Result<(), sqlx::Error> {
    let accounts: Vec<String> =
        sqlx::query_scalar("SELECT account_id FROM export_destinations WHERE kind <> 'none'")
            .fetch_all(&state.pool)
            .await?;

    for account_id in accounts {
        // Already logged inside. One unopenable row must not stop the others.
        let Ok(destination) =
            load_destination(&state.pool, state.sealing.as_ref(), &account_id).await
        else {
            continue;
        };
        match drain_once(
            &state.pool,
            state.allow_loopback_destinations,
            &account_id,
            Direction::Downstream,
            &destination,
            None,
        )
        .await
        {
            Ok(0) => {}
            Ok(settled) => tracing::info!(account_id, settled, "exported usage downstream"),
            Err(error) => tracing::error!(account_id, %error, "downstream drain failed"),
        }
    }
    Ok(())
}

// ------------------------------------------------------------- admin views

/// A destination as the admin API reports it. Never carries the credential.
#[derive(Debug, Serialize)]
pub struct DestinationView {
    /// `none`, `stripe` or `webhook`.
    pub kind: String,
    /// Whether a credential is stored. The credential itself is never returned.
    pub has_secret: bool,
    /// Meter name override.
    pub meter_name: Option<String>,
    /// Webhook endpoint.
    pub endpoint: Option<String>,
    /// Aggregates still waiting to be forwarded.
    pub pending: i64,
    /// Aggregates awaiting reconciliation.
    pub dead_lettered: i64,
}

/// Body for configuring a destination.
#[derive(Debug, Deserialize)]
pub struct SetDestination {
    /// `none`, `stripe` or `webhook`.
    pub kind: String,
    /// The credential. Required unless `kind` is `none`, and never readable after.
    #[serde(default)]
    pub secret: Option<String>,
    /// Meter name override.
    #[serde(default)]
    pub meter_name: Option<String>,
    /// Webhook endpoint, or a Stripe loopback override in tests.
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// One aggregate awaiting reconciliation.
#[derive(Debug, Serialize)]
pub struct DeadLetterView {
    /// The stable aggregate identifier.
    pub identifier: String,
    /// Billing customer.
    pub customer_id: String,
    /// Meter name.
    pub meter: String,
    /// Units that were never delivered.
    pub units: i64,
    /// When the usage happened.
    pub event_at: DateTime<Utc>,
    /// `downstream` or `upstream`.
    pub direction: String,
    /// Where delivery was attempted.
    pub destination: String,
    /// Static, low-cardinality rejection category.
    pub reason: String,
    /// When it was recorded.
    pub recorded_at: DateTime<Utc>,
}

/// Admin routes for export configuration and reconciliation.
pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/export/destination",
            routing::get(get_destination).put(set_destination),
        )
        .route("/v1/export/dead-letters", routing::get(list_dead_letters))
        .route(
            "/v1/export/dead-letters/{identifier}/resolve",
            routing::post(resolve_dead_letter),
        )
}

async fn set_destination(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
    Json(body): Json<SetDestination>,
) -> ApiResult<Json<DestinationView>> {
    let kind = body.kind.as_str();
    if !matches!(kind, "none" | "stripe" | "webhook") {
        return Err(ApiError::BadRequest(
            "kind must be none, stripe or webhook".to_owned(),
        ));
    }

    let sealed = if kind == "none" {
        None
    } else {
        let secret = body
            .secret
            .as_deref()
            .filter(|value| !value.trim().is_empty());
        let secret = secret.ok_or_else(|| {
            ApiError::BadRequest(format!("a {kind} destination requires a secret"))
        })?;
        let sealing = state.sealing.as_ref().ok_or_else(|| {
            ApiError::BadRequest(format!(
                "{} must be configured before storing a billing credential",
                crate::secret::KEY_VAR
            ))
        })?;
        Some(sealing.seal(secret).map_err(|error| {
            tracing::error!(%error, "could not seal a billing credential");
            ApiError::Internal
        })?)
    };

    if kind == "webhook" {
        let endpoint = body.endpoint.as_deref().unwrap_or_default();
        if !crate::providers::webhook_endpoint_is_allowed(
            endpoint,
            state.allow_loopback_destinations,
        ) {
            return Err(ApiError::BadRequest(
                "endpoint must be an https URL on a public host".to_owned(),
            ));
        }
    }
    if kind == "stripe"
        && let Some(endpoint) = body.endpoint.as_deref()
        && !crate::providers::stripe_endpoint_is_allowed(endpoint)
    {
        return Err(ApiError::BadRequest(
            "a Stripe endpoint override must be api.stripe.com or loopback".to_owned(),
        ));
    }

    sqlx::query(
        "INSERT INTO export_destinations
           (account_id, kind, secret_sealed, meter_name, endpoint)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (account_id) DO UPDATE
           SET kind = EXCLUDED.kind,
               secret_sealed = EXCLUDED.secret_sealed,
               meter_name = EXCLUDED.meter_name,
               endpoint = EXCLUDED.endpoint,
               updated_at = NOW()",
    )
    .bind(&caller.account_id)
    .bind(kind)
    .bind(sealed)
    .bind(body.meter_name.as_deref())
    .bind(body.endpoint.as_deref())
    .execute(&state.pool)
    .await?;

    destination_view(&state, &caller.account_id).await.map(Json)
}

async fn get_destination(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
) -> ApiResult<Json<DestinationView>> {
    destination_view(&state, &caller.account_id).await.map(Json)
}

async fn destination_view(state: &AppState, account_id: &str) -> ApiResult<DestinationView> {
    let row = sqlx::query(
        "SELECT kind, secret_sealed IS NOT NULL AS has_secret, meter_name, endpoint
         FROM export_destinations WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(&state.pool)
    .await?;

    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM usage_events WHERE account_id = $1 AND exported_at IS NULL",
    )
    .bind(account_id)
    .fetch_one(&state.pool)
    .await?;
    let dead_lettered: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM export_dead_letters
         WHERE account_id = $1 AND resolved_at IS NULL",
    )
    .bind(account_id)
    .fetch_one(&state.pool)
    .await?;

    Ok(match row {
        Some(row) => DestinationView {
            kind: row.try_get("kind")?,
            has_secret: row.try_get("has_secret")?,
            meter_name: row.try_get("meter_name")?,
            endpoint: row.try_get("endpoint")?,
            pending,
            dead_lettered,
        },
        None => DestinationView {
            kind: "none".to_owned(),
            has_secret: false,
            meter_name: None,
            endpoint: None,
            pending,
            dead_lettered,
        },
    })
}

async fn list_dead_letters(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
) -> ApiResult<Json<Vec<DeadLetterView>>> {
    let rows = sqlx::query(
        "SELECT identifier, customer_id, meter, units, event_at, direction,
                destination, reason, recorded_at
         FROM export_dead_letters
         WHERE account_id = $1 AND resolved_at IS NULL
         ORDER BY recorded_at DESC
         LIMIT 500",
    )
    .bind(&caller.account_id)
    .fetch_all(&state.pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(DeadLetterView {
                identifier: row.try_get("identifier")?,
                customer_id: row.try_get("customer_id")?,
                meter: row.try_get("meter")?,
                units: row.try_get("units")?,
                event_at: row.try_get("event_at")?,
                direction: row.try_get("direction")?,
                destination: row.try_get("destination")?,
                reason: row.try_get("reason")?,
                recorded_at: row.try_get("recorded_at")?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

async fn resolve_dead_letter(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
    Path(identifier): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let result = sqlx::query(
        "UPDATE export_dead_letters
         SET resolved_at = COALESCE(resolved_at, NOW()), resolved_by = $3
         WHERE account_id = $1 AND identifier = $2",
    )
    .bind(&caller.account_id)
    .bind(&identifier)
    .bind(&caller.account_id)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(serde_json::json!({ "resolved": identifier })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_upstream_identifier_is_namespaced_away_from_the_downstream_one() {
        // A customer forwarding to the same Stripe account the plane bills
        // through would otherwise see one of the two deduplicated away.
        assert_eq!(Direction::Downstream.identifier_for("agg-1"), "agg-1");
        assert_eq!(Direction::Upstream.identifier_for("agg-1"), "plane:agg-1");
        assert_ne!(
            Direction::Downstream.identifier_for("agg-1"),
            Direction::Upstream.identifier_for("agg-1")
        );
    }

    #[test]
    fn each_direction_owns_its_own_column() {
        // Sharing one column would make a downstream retry re-bill the plane,
        // or a plane-billing retry re-export to the customer.
        assert_eq!(Direction::Downstream.column(), "exported_at");
        assert_eq!(Direction::Upstream.column(), "plane_billed_at");
        assert_ne!(Direction::Downstream.column(), Direction::Upstream.column());
    }

    #[test]
    fn a_none_destination_builds_no_provider() {
        assert!(Destination::None.provider(false).is_none());
        assert_eq!(Destination::None.label(), "none");
    }

    #[test]
    fn a_webhook_destination_on_a_private_host_builds_no_provider() {
        let destination = Destination::Webhook {
            endpoint: "https://169.254.169.254/latest/meta-data".to_owned(),
            secret: "s".to_owned(),
            meter_name: None,
        };
        assert!(
            destination.provider(true).is_none(),
            "the allowlist must hold even with loopback enabled"
        );
    }
}
