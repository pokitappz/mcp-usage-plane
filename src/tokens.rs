//! Account credential lifecycle.
//!
//! Before this, the only two places that ever minted an account token were
//! provisioning and the startup bootstrap, and nothing revoked one. A lost or
//! leaked
//! admin token meant connecting to the database by hand, which is not a
//! procedure anyone wants to discover during an incident.
//!
//! These are *account* tokens - the credentials for this API. Tenant API keys,
//! which is what a metered caller presents to a sidecar, are a different thing
//! and live in [`crate::tenants`].

use axum::extract::{Path, State};
use axum::{Json, Router, routing};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row as _;

use crate::AppState;
use crate::auth::{AdminCaller, Scope, hash_token, mint_token};
use crate::error::{ApiError, ApiResult};

/// Longest accepted label.
const MAX_LABEL: usize = 200;

/// A request to mint a credential.
#[derive(Debug, Deserialize)]
pub struct MintToken {
    /// `admin` or `edge`.
    pub scope: String,
    /// Free-text note describing where this credential is used.
    #[serde(default)]
    pub label: Option<String>,
}

/// A freshly minted credential. The plaintext appears exactly once.
#[derive(Debug, Serialize)]
pub struct MintedToken {
    /// The credential. Not recoverable after this response.
    pub token: String,
    /// Lookup digest, and the handle used to revoke it.
    pub token_sha256: String,
    /// What it may do.
    pub scope: String,
    /// The label it was minted with.
    pub label: String,
}

/// A credential as listed. Never includes the credential itself.
#[derive(Debug, Serialize)]
pub struct TokenRow {
    /// Lookup digest, and the handle used to revoke it.
    pub token_sha256: String,
    /// What it may do.
    pub scope: String,
    /// Free-text note.
    pub label: String,
    /// When it was minted.
    pub created_at: DateTime<Utc>,
    /// When it was revoked, if it has been.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Account credential routes. All require an `admin` token.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/tokens", routing::get(list).post(mint))
        .route("/v1/tokens/{token_sha256}", routing::delete(revoke))
}

fn parse_scope(value: &str) -> ApiResult<Scope> {
    match value {
        "admin" => Ok(Scope::Admin),
        "edge" => Ok(Scope::Edge),
        other => Err(ApiError::BadRequest(format!(
            "scope {other:?} must be admin or edge"
        ))),
    }
}

async fn mint(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
    Json(body): Json<MintToken>,
) -> ApiResult<Json<MintedToken>> {
    mint_for(&state, &caller.account_id, &body.scope, body.label)
        .await
        .map(Json)
}

/// Mint a credential, without deciding who asked.
///
/// The plaintext is in the return value and nowhere else: it is never written
/// to a row, never logged, and never recoverable. A caller that loses it mints
/// another.
///
/// # Errors
///
/// Rejects an unknown scope and an empty or over-long label.
pub async fn mint_for(
    state: &AppState,
    account_id: &str,
    raw_scope: &str,
    raw_label: Option<String>,
) -> ApiResult<MintedToken> {
    let scope = parse_scope(raw_scope)?;
    // Absent means "default"; present but blank is a mistake worth reporting,
    // which is the distinction the JSON API has always drawn.
    let label = raw_label.unwrap_or_else(|| "default".to_owned());
    if label.trim().is_empty() || label.len() > MAX_LABEL {
        return Err(ApiError::BadRequest(format!(
            "label must be 1..={MAX_LABEL} characters"
        )));
    }

    // The prefix is cosmetic for the plane and load-bearing for the operator:
    // a leaked string is identifiable at a glance and secret scanners key on it.
    let token = mint_token(match scope {
        Scope::Admin => "mup_admin",
        Scope::Edge => "mup_edge",
    });
    let token_sha256 = hash_token(&token);

    sqlx::query(
        "INSERT INTO account_tokens (token_sha256, account_id, scope, label)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&token_sha256)
    .bind(account_id)
    .bind(raw_scope)
    .bind(&label)
    .execute(&state.pool)
    .await?;

    tracing::info!(account_id, scope = raw_scope, "minted an account token");

    Ok(MintedToken {
        token,
        token_sha256,
        scope: raw_scope.to_owned(),
        label,
    })
}

async fn list(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
) -> ApiResult<Json<Vec<TokenRow>>> {
    list_all(&state, &caller.account_id).await.map(Json)
}

/// Every token on an account, live and revoked, without deciding who asked.
pub async fn list_all(state: &AppState, account_id: &str) -> ApiResult<Vec<TokenRow>> {
    let rows = sqlx::query(
        "SELECT token_sha256, scope, label, created_at, revoked_at
         FROM account_tokens
         WHERE account_id = $1
         ORDER BY created_at DESC, token_sha256",
    )
    .bind(account_id)
    .fetch_all(&state.pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(TokenRow {
                token_sha256: row.try_get("token_sha256")?,
                scope: row.try_get("scope")?,
                label: row.try_get("label")?,
                created_at: row.try_get("created_at")?,
                revoked_at: row.try_get("revoked_at")?,
            })
        })
        .collect()
}

async fn revoke(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
    Path(token_sha256): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    revoke_for(&state, &caller.account_id, &token_sha256).await?;
    Ok(Json(serde_json::json!({ "revoked": true })))
}

/// Revoke a credential, without deciding who asked.
///
/// # Errors
///
/// Refuses to revoke the last live admin token, and answers `not found` for a
/// digest that is not this account's or is already revoked.
pub async fn revoke_for(state: &AppState, account_id: &str, token_sha256: &str) -> ApiResult<()> {
    // Revoking the last live admin credential locks the account out of its own
    // API, and the only way back is database access. Refuse, and say why.
    let live_admins: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM account_tokens
         WHERE account_id = $1 AND scope = 'admin' AND revoked_at IS NULL",
    )
    .bind(account_id)
    .fetch_one(&state.pool)
    .await?;

    let revoking_admin: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM account_tokens
                       WHERE account_id = $1 AND token_sha256 = $2
                         AND scope = 'admin' AND revoked_at IS NULL)",
    )
    .bind(account_id)
    .bind(token_sha256)
    .fetch_one(&state.pool)
    .await?;

    if revoking_admin && live_admins <= 1 {
        return Err(ApiError::Conflict(
            "refusing to revoke the last admin token; mint a replacement first".to_owned(),
        ));
    }

    let revoked = sqlx::query(
        "UPDATE account_tokens SET revoked_at = NOW()
         WHERE account_id = $1 AND token_sha256 = $2 AND revoked_at IS NULL",
    )
    .bind(account_id)
    .bind(token_sha256)
    .execute(&state.pool)
    .await?;

    if revoked.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    // The authentication cache is a revocation window. Dropping the entry makes
    // this immediate on the instance that served the request; any other
    // instance still waits out the TTL, which is why the TTL is short.
    state.admission.forget(token_sha256);

    tracing::info!(account_id, "revoked an account token");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_an_allowlist() {
        assert_eq!(parse_scope("admin").unwrap(), Scope::Admin);
        assert_eq!(parse_scope("edge").unwrap(), Scope::Edge);
        for attempt in ["root", "ADMIN", "", "admin'; --"] {
            assert!(parse_scope(attempt).is_err(), "{attempt:?}");
        }
    }
}
