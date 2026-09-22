//! The plane's own revenue: signup, subscription state, and billing accounts
//! for the usage they put through.
//!
//! This is the *upstream* direction and is deliberately kept apart from the
//! downstream export in [`crate::export`]. Downstream sends an account's usage
//! to the account's own provider; upstream sends the same usage, re-attributed
//! to the account's own Stripe customer, to the plane's provider. They are two
//! different Stripe accounts, two different credentials, and two different
//! columns on the ledger, so neither can settle or replay the other.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::{Json, Router, routing};
use chrono::{DateTime, TimeZone, Utc};
use hmac::digest::KeyInit as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::{PgPool, Row as _};

use crate::AppState;
use crate::auth::{AdminCaller, hash_token, mint_token};
use crate::error::{ApiError, ApiResult};
use crate::export::{Destination, Direction, drain_once};
use crate::providers::stripe_version_is_current;

type HmacSha256 = Hmac<Sha256>;

/// How far a webhook timestamp may be from now. Stripe's own recommendation.
const WEBHOOK_TOLERANCE_SECONDS: i64 = 300;

/// Subscription statuses the `account_billing` CHECK constraint accepts.
const KNOWN_SUBSCRIPTION_STATUSES: [&str; 4] = ["trialing", "active", "past_due", "canceled"];

/// The plane's own billing configuration, read once at startup.
#[derive(Clone, Default)]
pub struct PlaneBilling {
    /// The plane's Stripe secret key.
    pub stripe_secret: Option<String>,
    /// Meter the plane records its customers' processed units against.
    pub meter_name: Option<String>,
    /// Loopback override for tests.
    pub stripe_endpoint: Option<String>,
    /// Secret for verifying inbound Stripe webhooks.
    pub webhook_secret: Option<String>,
    /// Shared secret a signup request must present.
    pub signup_secret: Option<String>,
}

impl std::fmt::Debug for PlaneBilling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaneBilling")
            .field(
                "stripe_secret",
                &self.stripe_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("meter_name", &self.meter_name)
            .field(
                "webhook_secret",
                &self.webhook_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("signup_enabled", &self.signup_secret.is_some())
            .finish_non_exhaustive()
    }
}

impl PlaneBilling {
    /// Read the plane's billing configuration from the environment.
    #[must_use]
    pub fn from_env() -> Self {
        let read = |name: &str| {
            std::env::var(name)
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        Self {
            stripe_secret: read("PLANE_STRIPE_SECRET_KEY"),
            meter_name: read("PLANE_STRIPE_METER_NAME"),
            stripe_endpoint: read("PLANE_STRIPE_ENDPOINT"),
            webhook_secret: read("PLANE_STRIPE_WEBHOOK_SECRET"),
            signup_secret: read("PLANE_SIGNUP_SECRET"),
        }
    }

    /// The destination the plane bills its own customers through.
    #[must_use]
    pub fn destination(&self) -> Destination {
        match &self.stripe_secret {
            Some(secret) => Destination::Stripe {
                secret: secret.clone(),
                meter_name: self.meter_name.clone(),
                endpoint: self.stripe_endpoint.clone(),
            },
            None => Destination::None,
        }
    }
}

// ------------------------------------------------------------------ signup

/// Body for a self-serve signup.
#[derive(Debug, Deserialize)]
pub struct Signup {
    /// Display name for the new account.
    pub name: String,
    /// The shared secret that gates signup.
    pub signup_secret: String,
}

/// A new account and its credentials. Both tokens appear exactly once, here.
#[derive(Debug, Serialize)]
pub struct SignupResult {
    /// The new account identifier.
    pub account_id: String,
    /// Manages tenants, prices and export configuration.
    pub admin_token: String,
    /// Handed to a sidecar. Cannot reach pricing.
    pub edge_token: String,
}

/// Billing state as the admin API reports it.
#[derive(Debug, Serialize)]
pub struct BillingView {
    /// Stripe customer, once linked.
    pub stripe_customer_id: Option<String>,
    /// Stripe subscription, once one exists.
    pub stripe_subscription_id: Option<String>,
    /// `none`, `trialing`, `active`, `past_due` or `canceled`.
    pub status: String,
    /// End of the current paid period.
    pub current_period_end: Option<DateTime<Utc>>,
    /// When an invoice last failed to be paid.
    ///
    /// Surfaced because the subscription `status` only moves to `past_due`
    /// after Stripe exhausts its retries: the invoice event is the earlier
    /// signal, and the one an operator can act on.
    pub last_payment_failure_at: Option<DateTime<Utc>>,
    /// When an invoice was last paid.
    pub last_payment_success_at: Option<DateTime<Utc>>,
    /// Units the plane has not yet billed this account for.
    pub unbilled_units: i64,
}

/// Body for linking an account to a Stripe customer.
#[derive(Debug, Deserialize)]
pub struct LinkBilling {
    /// The Stripe customer the plane invoices.
    pub stripe_customer_id: String,
}

/// Billing routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/signup", routing::post(signup))
        .route(
            "/v1/billing",
            routing::get(billing_status).put(link_billing),
        )
        .route("/v1/stripe/webhook", routing::post(stripe_webhook))
}

async fn signup(
    State(state): State<AppState>,
    Json(body): Json<Signup>,
) -> ApiResult<Json<SignupResult>> {
    // Signup is off unless a secret is configured, so a fresh deployment is not
    // an open account factory.
    let Some(expected) = state.billing.signup_secret.as_deref() else {
        return Err(ApiError::NotFound);
    };
    if !constant_time_eq(expected.as_bytes(), body.signup_secret.as_bytes()) {
        return Err(ApiError::Unauthorized);
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 200 {
        return Err(ApiError::BadRequest(
            "name must be between 1 and 200 characters".to_owned(),
        ));
    }

    let account_id = mint_token("acct").replace('_', "");
    let admin_token = mint_token("mup_admin");
    let edge_token = mint_token("mup_edge");

    let mut tx = state.pool.begin().await?;
    sqlx::query("INSERT INTO accounts (id, name) VALUES ($1, $2)")
        .bind(&account_id)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    for (token, scope) in [(&admin_token, "admin"), (&edge_token, "edge")] {
        sqlx::query(
            "INSERT INTO account_tokens (token_sha256, account_id, scope, label)
             VALUES ($1, $2, $3, 'signup')",
        )
        .bind(hash_token(token))
        .bind(&account_id)
        .bind(scope)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("INSERT INTO account_billing (account_id) VALUES ($1)")
        .bind(&account_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    tracing::info!(account_id, "account created through self-serve signup");
    Ok(Json(SignupResult {
        account_id,
        admin_token,
        edge_token,
    }))
}

async fn billing_status(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
) -> ApiResult<Json<BillingView>> {
    view(&state.pool, &caller.account_id).await.map(Json)
}

async fn link_billing(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
    Json(body): Json<LinkBilling>,
) -> ApiResult<Json<BillingView>> {
    let customer = body.stripe_customer_id.trim();
    if !customer.starts_with("cus_") {
        return Err(ApiError::BadRequest(
            "stripe_customer_id must be a Stripe customer identifier".to_owned(),
        ));
    }
    let linked = sqlx::query(
        "INSERT INTO account_billing (account_id, stripe_customer_id)
         VALUES ($1, $2)
         ON CONFLICT (account_id) DO UPDATE
           SET stripe_customer_id = EXCLUDED.stripe_customer_id, updated_at = NOW()",
    )
    .bind(&caller.account_id)
    .bind(customer)
    .execute(&state.pool)
    .await;

    if let Err(error) = linked {
        // A partial unique index on `stripe_customer_id` is what actually
        // isolates accounts here. Worth being precise about why: every account
        // bills through the plane's single Stripe account, so retrieving the
        // customer would prove it exists, not that this caller owns it. First
        // claim wins is the guarantee, and a second claim has to be refused
        // rather than silently pointed at someone else's invoices.
        if is_unique_violation(&error) {
            return Err(ApiError::Conflict(
                "that Stripe customer is already linked to another account".to_owned(),
            ));
        }
        return Err(error.into());
    }

    warn_about_unbillable_backlog(&state.pool, &caller.account_id).await?;
    view(&state.pool, &caller.account_id).await.map(Json)
}

/// Whether a database error is a unique-constraint violation.
fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505")
    )
}

/// Report usage that can never reach Stripe, at the moment it becomes relevant.
///
/// Stripe rejects meter events stamped more than 35 days in the past, and
/// `bill_all` only bills linked accounts. So an account that accrues usage and
/// links its customer late has that backlog permanently rejected - one dead
/// letter at a time, discovered 200 rows per drain cycle, long after anything
/// could be done.
///
/// Linking is the moment the operator is looking. Saying it here is the
/// difference between a decision and an archaeology exercise.
async fn warn_about_unbillable_backlog(pool: &PgPool, account_id: &str) -> ApiResult<()> {
    let row = sqlx::query(
        "SELECT COUNT(*)::bigint AS events, COALESCE(SUM(units), 0)::bigint AS units
         FROM usage_events
         WHERE account_id = $1
           AND plane_billed_at IS NULL
           AND event_at < NOW() - INTERVAL '35 days'",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await?;

    let events: i64 = row.try_get("events")?;
    if events > 0 {
        let units: i64 = row.try_get("units")?;
        tracing::error!(
            account_id,
            events,
            units,
            "usage predates Stripe's 35 day meter-event window and cannot be \
             billed upstream; it will dead-letter on the next drain"
        );
    }
    Ok(())
}

async fn view(pool: &PgPool, account_id: &str) -> ApiResult<BillingView> {
    let row = sqlx::query(
        "SELECT stripe_customer_id, stripe_subscription_id, status, current_period_end,
                last_payment_failure_at, last_payment_success_at
         FROM account_billing WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;

    let unbilled_units: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(units), 0)::bigint FROM usage_events
         WHERE account_id = $1 AND plane_billed_at IS NULL",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await?;

    Ok(match row {
        Some(row) => BillingView {
            stripe_customer_id: row.try_get("stripe_customer_id")?,
            stripe_subscription_id: row.try_get("stripe_subscription_id")?,
            status: row.try_get("status")?,
            current_period_end: row.try_get("current_period_end")?,
            last_payment_failure_at: row.try_get("last_payment_failure_at")?,
            last_payment_success_at: row.try_get("last_payment_success_at")?,
            unbilled_units,
        },
        None => BillingView {
            stripe_customer_id: None,
            stripe_subscription_id: None,
            status: "none".to_owned(),
            current_period_end: None,
            last_payment_failure_at: None,
            last_payment_success_at: None,
            unbilled_units,
        },
    })
}

// ----------------------------------------------------------------- webhook

/// The `t` and `v1` values from a `Stripe-Signature` header.
struct SignatureHeader {
    timestamp: i64,
    signatures: Vec<String>,
}

fn parse_signature_header(value: &str) -> Option<SignatureHeader> {
    let mut timestamp = None;
    // Stripe may send several `v1` values during a secret rotation, and any one
    // matching is a valid signature.
    let mut signatures = Vec::new();
    for part in value.split(',') {
        match part.trim().split_once('=') {
            Some(("t", raw)) => timestamp = raw.parse::<i64>().ok(),
            Some(("v1", raw)) => signatures.push(raw.to_owned()),
            _ => {}
        }
    }
    Some(SignatureHeader {
        timestamp: timestamp?,
        signatures: (!signatures.is_empty()).then_some(signatures)?,
    })
}

fn expected_signature(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

/// Compare without leaking how much of the value matched.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |differences, (a, b)| differences | (a ^ b))
        == 0
}

/// Whether a presented `Stripe-Signature` authenticates this body.
#[must_use]
pub fn webhook_signature_is_valid(secret: &str, header: &str, body: &[u8], now: i64) -> bool {
    let Some(parsed) = parse_signature_header(header) else {
        return false;
    };
    // A replayed request with a valid old signature is still a replay.
    if (now - parsed.timestamp).abs() > WEBHOOK_TOLERANCE_SECONDS {
        return false;
    }
    let expected = expected_signature(secret, parsed.timestamp, body);
    parsed
        .signatures
        .iter()
        .any(|candidate| constant_time_eq(expected.as_bytes(), candidate.as_bytes()))
}

async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let Some(secret) = state.billing.webhook_secret.as_deref() else {
        return Err(ApiError::NotFound);
    };
    let signature = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    if !webhook_signature_is_valid(secret, signature, &body, Utc::now().timestamp()) {
        tracing::warn!("rejected a Stripe webhook with an invalid signature");
        return Err(ApiError::Unauthorized);
    }

    let event: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| ApiError::BadRequest("malformed event".into()))?;

    // The payload is rendered at the version pinned on the Stripe endpoint, not
    // at whatever this service sends on outbound calls, so the inbound contract
    // has to be checked against what actually arrived.
    let api_version = event.get("api_version").and_then(serde_json::Value::as_str);
    if !stripe_version_is_current(api_version) {
        tracing::error!(
            stripe_event_api_version = api_version.unwrap_or("unset"),
            "refusing a Stripe event rendered at an unexpected API release"
        );
        return Err(ApiError::BadRequest("unexpected api_version".into()));
    }

    let event_id = event
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.starts_with("evt_"))
        .ok_or_else(|| ApiError::BadRequest("missing event id".into()))?;
    let event_type = event
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();

    // Stripe redelivers, so the event id is the idempotency key. Claim and
    // apply in ONE transaction: claiming on the pool and applying separately
    // meant a transient database error left the event claimed but unapplied,
    // and Stripe's redelivery then answered `duplicate` without ever applying
    // it. That drops a subscription state change permanently.
    let mut tx = state.pool.begin().await?;
    let claimed = sqlx::query(
        "INSERT INTO stripe_webhook_events (event_id, event_type) VALUES ($1, $2)
         ON CONFLICT (event_id) DO NOTHING",
    )
    .bind(event_id)
    .bind(event_type)
    .execute(&mut *tx)
    .await?;
    if claimed.rows_affected() == 0 {
        return Ok(Json(serde_json::json!({ "status": "duplicate" })));
    }

    apply_event(&mut tx, event_type, &event).await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

async fn apply_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event_type: &str,
    event: &serde_json::Value,
) -> ApiResult<()> {
    let object = event
        .pointer("/data/object")
        .ok_or_else(|| ApiError::BadRequest("missing data.object".into()))?;

    match event_type {
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted" => {
            let customer = object.get("customer").and_then(serde_json::Value::as_str);
            let subscription = object.get("id").and_then(serde_json::Value::as_str);
            let Some(customer) = customer else {
                return Ok(());
            };
            // The column is CHECK-constrained, so an unrecognized Stripe
            // status cannot be written through. Falling back to `past_due`
            // rather than `active` means an unknown state never hands out
            // service the account may not be paying for.
            let reported = object
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let status = if event_type.ends_with("deleted") {
                "canceled"
            } else if KNOWN_SUBSCRIPTION_STATUSES.contains(&reported) {
                reported
            } else {
                "past_due"
            };
            let period_end = subscription_period_end(object);

            let updated = sqlx::query(
                "UPDATE account_billing
                 SET stripe_subscription_id = COALESCE($2, stripe_subscription_id),
                     status = $3,
                     current_period_end = COALESCE($4, current_period_end),
                     updated_at = NOW()
                 WHERE stripe_customer_id = $1",
            )
            .bind(customer)
            .bind(subscription)
            .bind(status)
            .bind(period_end)
            .execute(&mut **tx)
            .await?;

            if updated.rows_affected() == 0 {
                // Not an error: a Stripe account can hold customers this plane
                // has never heard of.
                tracing::info!(event_type, "subscription event for an unlinked customer");
            } else {
                tracing::info!(event_type, status, "applied a subscription event");
            }
        }
        // A failed payment used to reach a debug log and vanish. Stripe moves
        // the subscription to `past_due` eventually, but the invoice event is
        // the first signal and the only one that says which invoice.
        "invoice.payment_failed" | "invoice.payment_action_required" => {
            let Some(customer) = object.get("customer").and_then(serde_json::Value::as_str) else {
                return Ok(());
            };
            let updated = sqlx::query(
                "UPDATE account_billing
                 SET last_payment_failure_at = NOW(), updated_at = NOW()
                 WHERE stripe_customer_id = $1",
            )
            .bind(customer)
            .execute(&mut **tx)
            .await?;
            if updated.rows_affected() == 0 {
                tracing::info!(event_type, "payment event for an unlinked customer");
            } else {
                // Error, not warn: this is revenue not arriving, and it is the
                // signal an operator should be paged on.
                tracing::error!(event_type, "an account's payment did not succeed");
            }
        }
        "invoice.paid" | "invoice.payment_succeeded" => {
            let Some(customer) = object.get("customer").and_then(serde_json::Value::as_str) else {
                return Ok(());
            };
            sqlx::query(
                "UPDATE account_billing
                 SET last_payment_success_at = NOW(), updated_at = NOW()
                 WHERE stripe_customer_id = $1",
            )
            .bind(customer)
            .execute(&mut **tx)
            .await?;
            tracing::info!(event_type, "recorded a successful payment");
        }
        other => tracing::debug!(event_type = other, "ignoring an unhandled Stripe event"),
    }
    Ok(())
}

/// The end of the current billing period, read from the subscription's items.
///
/// Stripe moved `current_period_end` off the Subscription object and onto each
/// subscription item. Reading it from the top level, which is what this did,
/// resolves to `None` on every delivery - and the `COALESCE` in the UPDATE then
/// swallows that silently, so the column stayed NULL forever.
///
/// Verified against <https://docs.stripe.com/api/subscriptions/object>: the
/// attribute list has no top-level `current_period_end`, and the example
/// payload carries it at `items.data[].current_period_end`.
///
/// The maximum across items is the period end for the subscription as a whole:
/// items can be billed on different anchors, and the subscription is not done
/// with a period until its last item is.
fn subscription_period_end(object: &serde_json::Value) -> Option<DateTime<Utc>> {
    let seconds = object
        .pointer("/items/data")
        .and_then(serde_json::Value::as_array)?
        .iter()
        .filter_map(|item| {
            item.get("current_period_end")
                .and_then(serde_json::Value::as_i64)
        })
        .max()?;
    Utc.timestamp_opt(seconds, 0).single()
}

// ----------------------------------------------------------- upstream bill

/// Bill every linked account for the usage the plane processed, forever.
pub async fn bill_forever(state: AppState, interval: std::time::Duration) {
    let destination = state.billing.destination();
    if matches!(destination, Destination::None) {
        tracing::info!("no plane Stripe key configured; upstream billing is idle");
        return;
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if let Err(error) = bill_all(&state, &destination).await {
            tracing::error!(%error, "upstream billing cycle failed");
        }
    }
}

async fn bill_all(state: &AppState, destination: &Destination) -> Result<(), sqlx::Error> {
    // Only accounts the plane can actually invoice. An unlinked account keeps
    // accumulating unbilled rows, which is visible in its billing view.
    let rows = sqlx::query(
        "SELECT account_id, stripe_customer_id FROM account_billing
         WHERE stripe_customer_id IS NOT NULL",
    )
    .fetch_all(&state.pool)
    .await?;

    for row in rows {
        let account_id: String = row.try_get("account_id")?;
        let customer: String = row.try_get("stripe_customer_id")?;
        match drain_once(
            &state.pool,
            state.allow_loopback_destinations,
            &account_id,
            Direction::Upstream,
            destination,
            Some(&customer),
        )
        .await
        {
            Ok(0) => {}
            Ok(settled) => tracing::info!(account_id, settled, "billed the plane's own usage"),
            Err(error) => tracing::error!(account_id, %error, "upstream billing drain failed"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "whsec_test";

    fn header(timestamp: i64, body: &[u8], secret: &str) -> String {
        format!(
            "t={timestamp},v1={}",
            expected_signature(secret, timestamp, body)
        )
    }

    #[test]
    fn a_correctly_signed_recent_event_is_accepted() {
        let body = br#"{"id":"evt_1"}"#;
        let now = 1_800_000_000;
        assert!(webhook_signature_is_valid(
            SECRET,
            &header(now, body, SECRET),
            body,
            now
        ));
    }

    #[test]
    fn a_replayed_event_outside_the_tolerance_is_refused() {
        let body = br#"{"id":"evt_1"}"#;
        let now = 1_800_000_000;
        let stale = now - WEBHOOK_TOLERANCE_SECONDS - 1;
        // The signature is genuine; the age is what disqualifies it.
        assert!(!webhook_signature_is_valid(
            SECRET,
            &header(stale, body, SECRET),
            body,
            now
        ));
        assert!(webhook_signature_is_valid(
            SECRET,
            &header(now - WEBHOOK_TOLERANCE_SECONDS, body, SECRET),
            body,
            now
        ));
    }

    #[test]
    fn a_tampered_body_or_wrong_secret_is_refused() {
        let body = br#"{"id":"evt_1"}"#;
        let now = 1_800_000_000;
        let signature = header(now, body, SECRET);
        assert!(!webhook_signature_is_valid(SECRET, &signature, b"{}", now));
        assert!(!webhook_signature_is_valid(
            "whsec_other",
            &signature,
            body,
            now
        ));
    }

    #[test]
    fn a_malformed_header_is_refused_rather_than_panicking() {
        let body = b"{}";
        for header in ["", "t=abc,v1=xx", "v1=xx", "t=123", "garbage"] {
            assert!(
                !webhook_signature_is_valid(SECRET, header, body, 1_800_000_000),
                "{header:?}"
            );
        }
    }

    #[test]
    fn any_one_of_several_rotated_signatures_authenticates() {
        let body = br#"{"id":"evt_1"}"#;
        let now = 1_800_000_000;
        let valid = expected_signature(SECRET, now, body);
        let rotated = format!("t={now},v1=deadbeef,v1={valid}");
        assert!(webhook_signature_is_valid(SECRET, &rotated, body, now));
    }

    #[test]
    fn constant_time_comparison_still_compares() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
