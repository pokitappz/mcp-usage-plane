//! Operator provisioning: creating an account and its first credentials.
//!
//! # This is not a signup funnel
//!
//! It used to be called one, and it never was. There is no email here, no
//! identity, no verification, and no way for a stranger to reach it: the only
//! key is a shared secret held by whoever runs this service, and the route
//! answers 404 when that secret is unset, which is the default.
//!
//! Selling the product does not require a self-serve funnel. An account is
//! created here by hand, its Stripe customer is linked, its terms are set, and
//! the monthly close bills it like any other. Revenue and self-service are
//! separate questions, and conflating them is what made the old name
//! misleading.
//!
//! There are no people here either. The dashboard is opened by presenting one
//! of the account's own admin tokens, in [`crate::session`], so the credentials
//! minted here are also what signs in to look at the account.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::{Json, Router, routing};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::{hash_token, mint_token};
use crate::billing::constant_time_eq;
use crate::error::{ApiError, ApiResult};

/// Longest accepted account name.
const MAX_NAME: usize = 200;

/// Accounts one holder of the secret may create per window.
///
/// The old route took no budget at all. Nothing upstream takes one for a route
/// with no bearer extractor, so a leaked secret meant unlimited accounts at
/// line rate, which is a database filled by an attacker rather than a customer.
const PROVISION_BURST: u32 = 20;

/// The key provisioning attempts are counted against.
///
/// Fixed, so a caller guessing the secret cannot get a fresh allowance per
/// guess. See the comment in [`check_operator_secret`].
const PROVISION_SUBJECT: &str = "any";

/// Header carrying the operator secret.
///
/// An alternative to putting it in the body, for callers that would rather not,
/// and the only option for a request with no body. A query parameter would
/// write the secret into every access log between here and the server.
pub const SECRET_HEADER: &str = "x-provision-secret";

/// A request to create an account.
#[derive(Debug, Deserialize)]
pub struct ProvisionAccount {
    /// Display name for the new account.
    pub name: String,
    /// The operator secret.
    pub provision_secret: String,
}

/// A new account and its credentials. Both tokens appear exactly once, here.
///
/// The `admin` token is also how a human opens the dashboard for this account, so
/// this response is the whole path from an empty database to somebody able to
/// look at it. There is no separate person to create and no password to issue.
#[derive(Debug, Serialize)]
pub struct ProvisionedAccount {
    /// The new account identifier.
    pub account_id: String,
    /// Manages tenants, prices and export configuration.
    pub admin_token: String,
    /// Handed to a server that meters. Cannot reach pricing.
    pub edge_token: String,
}

/// Operator routes.
pub fn router() -> Router<AppState> {
    Router::new().route("/v1/accounts", routing::post(provision))
}

/// Authenticate an operator, from the header or from a body field.
///
/// Every operator route calls this, so the secret is checked one way in one
/// place. The order matters and is not cosmetic: the budget is spent **before**
/// the comparison, and counted against a fixed key rather than the presented
/// secret. Keying it on the secret would give every wrong guess its own fresh
/// allowance, which bounds nothing; that is a mistake this code made until a
/// test caught it. A fixed key is right here in a way it would not be for a
/// customer route, because there is one operator, so a shared bound cannot be
/// used to lock a legitimate user out.
///
/// # Errors
///
/// `not found` when no secret is configured, so a fresh deployment is not an
/// open account factory and does not advertise the route either. `too many
/// requests` when the budget is spent, and `unauthorized` when the secret is
/// wrong.
pub fn check_operator_secret(
    state: &AppState,
    from_body: Option<&str>,
    headers: &HeaderMap,
) -> ApiResult<()> {
    let Some(expected) = state.billing.provision_secret.as_deref() else {
        return Err(ApiError::NotFound);
    };

    // Taken explicitly because a route with no bearer extractor never reaches
    // the per-token budget.
    if !state
        .admission
        .take_named("provision", PROVISION_SUBJECT, PROVISION_BURST)
    {
        return Err(ApiError::TooManyRequests(
            state.admission.retry_after_seconds(PROVISION_SUBJECT),
        ));
    }

    let presented = headers
        .get(SECRET_HEADER)
        .and_then(|value| value.to_str().ok())
        .or(from_body)
        .unwrap_or_default();

    if constant_time_eq(expected.as_bytes(), presented.as_bytes()) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

/// Create an account row and the billing row that belongs with it.
///
/// Shared by provisioning and by granting an access request, so there is one
/// definition of what an account is made of. Two ways to create an account
/// means one of them eventually forgets a row, and the one that forgets is
/// discovered when a period closes and finds nothing to bill.
///
/// # Errors
///
/// Propagates the database error.
pub async fn create_account(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    name: &str,
) -> ApiResult<String> {
    let account_id = mint_token("acct").replace('_', "");
    sqlx::query("INSERT INTO accounts (id, name) VALUES ($1, $2)")
        .bind(&account_id)
        .bind(name)
        .execute(&mut **tx)
        .await?;
    sqlx::query("INSERT INTO account_billing (account_id) VALUES ($1)")
        .bind(&account_id)
        .execute(&mut **tx)
        .await?;
    Ok(account_id)
}

/// Validate a display name.
///
/// # Errors
///
/// Rejects an empty name and one longer than [`MAX_NAME`].
pub fn check_name(raw: &str) -> ApiResult<&str> {
    let name = raw.trim();
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(ApiError::BadRequest(format!(
            "name must be between 1 and {MAX_NAME} characters"
        )));
    }
    Ok(name)
}

async fn provision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ProvisionAccount>,
) -> ApiResult<Json<ProvisionedAccount>> {
    check_operator_secret(&state, Some(&body.provision_secret), &headers)?;

    let name = body.name.trim();
    let name = check_name(name)?;

    let admin_token = mint_token("mup_admin");
    let edge_token = mint_token("mup_edge");

    let mut tx = state.pool.begin().await?;
    let account_id = create_account(&mut tx, name).await?;
    for (token, scope) in [(&admin_token, "admin"), (&edge_token, "edge")] {
        sqlx::query(
            "INSERT INTO account_tokens (token_sha256, account_id, scope, label)
             VALUES ($1, $2, $3, 'provisioned')",
        )
        .bind(hash_token(token))
        .bind(&account_id)
        .bind(scope)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    // The origin is recorded because an account that appears without one is
    // worth noticing.
    tracing::info!(
        account_id,
        origin = headers
            .get(axum::http::header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("none"),
        "provisioned an account"
    );
    Ok(Json(ProvisionedAccount {
        account_id,
        admin_token,
        edge_token,
    }))
}
