//! Admin CRUD for tenants, prices, limits and keys.

use axum::extract::{Path, State};
use axum::{Json, Router, routing};
use chrono::{DateTime, Utc};
use mcp_usage_core::PriceBook;
use serde::{Deserialize, Serialize};
use sqlx::Row as _;

use crate::AppState;
use crate::auth::{AdminCaller, hash_token, mint_token};
use crate::error::{ApiError, ApiResult};

/// A tenant as the admin API reports it.
#[derive(Debug, Serialize)]
pub struct TenantView {
    /// Identifier the meter reports on usage events.
    pub tenant_key: String,
    /// Billing-provider customer identifier.
    pub billing_customer_id: String,
    /// Current price book.
    pub prices: PriceBook,
    /// Increments whenever the price book changes.
    pub price_version: i32,
    /// Unit quota, or null for unbounded.
    pub max_units: Option<i64>,
    /// Spend cap in millionths, or null for unbounded.
    pub max_spend_micros: Option<i64>,
    /// Monetary price of one metered unit, in millionths.
    pub unit_price_micros: i64,
    /// Set once the tenant is revoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Count of keys that still authenticate.
    pub active_keys: i64,
}

/// Body for creating a tenant.
#[derive(Debug, Deserialize)]
pub struct CreateTenant {
    /// Identifier the meter will report.
    pub tenant_key: String,
    /// Billing-provider customer identifier.
    pub billing_customer_id: String,
    /// Optional price book. Defaults to one unit for everything.
    #[serde(default)]
    pub prices: Option<PriceBook>,
    /// Optional unit quota.
    #[serde(default)]
    pub max_units: Option<i64>,
    /// Optional spend cap in millionths.
    #[serde(default)]
    pub max_spend_micros: Option<i64>,
    /// Monetary price of one unit, in millionths.
    #[serde(default)]
    pub unit_price_micros: Option<i64>,
}

/// Body for updating a tenant. Absent fields are left alone.
#[derive(Debug, Deserialize)]
#[expect(
    clippy::option_option,
    reason = "absent means leave the limit alone, explicit null means clear it; \
              one Option cannot express both and a limit must be clearable"
)]
pub struct UpdateTenant {
    /// Replacement price book. Bumps `price_version`.
    #[serde(default)]
    pub prices: Option<PriceBook>,
    /// Replacement unit quota. Use `Some(None)` to clear.
    #[serde(default, with = "double_option")]
    pub max_units: Option<Option<i64>>,
    /// Replacement spend cap. Use `Some(None)` to clear.
    #[serde(default, with = "double_option")]
    pub max_spend_micros: Option<Option<i64>>,
    /// Replacement unit price.
    #[serde(default)]
    pub unit_price_micros: Option<i64>,
}

/// Distinguishes "absent" from "explicitly null" so a limit can be cleared.
mod double_option {
    use serde::{Deserialize, Deserializer};

    #[expect(
        clippy::option_option,
        reason = "the outer Option is presence, the inner is the JSON null"
    )]
    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Some)
    }
}

/// A freshly minted key. The plaintext appears exactly once, here.
#[derive(Debug, Serialize)]
pub struct MintedKey {
    /// The secret. Not recoverable after this response.
    pub api_key: String,
    /// Lookup digest, used to revoke it later.
    pub key_sha256: String,
    /// Operator-supplied label.
    pub label: String,
}

/// Body for minting a key.
#[derive(Debug, Deserialize)]
pub struct MintKey {
    /// Operator-supplied label.
    #[serde(default = "default_label")]
    pub label: String,
}

fn default_label() -> String {
    "default".to_owned()
}

/// Admin routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/tenants", routing::get(list).post(create))
        .route(
            "/v1/tenants/{tenant_key}",
            routing::patch(update).delete(revoke),
        )
        .route("/v1/tenants/{tenant_key}/keys", routing::post(mint_key))
        .route(
            "/v1/tenants/{tenant_key}/keys/{key_sha256}",
            routing::delete(revoke_key),
        )
}

fn validate_limit(value: Option<i64>, field: &str) -> ApiResult<()> {
    if value.is_some_and(|value| value < 0) {
        return Err(ApiError::BadRequest(format!(
            "{field} must not be negative"
        )));
    }
    Ok(())
}

async fn create(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
    Json(body): Json<CreateTenant>,
) -> ApiResult<Json<TenantView>> {
    if body.tenant_key.trim().is_empty() || body.billing_customer_id.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "tenant_key and billing_customer_id are required".to_owned(),
        ));
    }
    validate_limit(body.max_units, "max_units")?;
    validate_limit(body.max_spend_micros, "max_spend_micros")?;
    validate_limit(body.unit_price_micros, "unit_price_micros")?;

    let prices = serde_json::to_value(body.prices.unwrap_or_default())
        .map_err(|_| ApiError::BadRequest("prices is not a valid price book".to_owned()))?;

    let result = sqlx::query(
        "INSERT INTO tenants
           (account_id, tenant_key, billing_customer_id, prices, max_units,
            max_spend_micros, unit_price_micros)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (account_id, tenant_key) DO NOTHING",
    )
    .bind(&caller.account_id)
    .bind(body.tenant_key.trim())
    .bind(body.billing_customer_id.trim())
    .bind(&prices)
    .bind(body.max_units)
    .bind(body.max_spend_micros)
    .bind(body.unit_price_micros.unwrap_or(0))
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::Conflict(format!(
            "tenant {} already exists",
            body.tenant_key.trim()
        )));
    }
    fetch_one(&state, &caller.account_id, body.tenant_key.trim())
        .await
        .map(Json)
}

async fn list(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
) -> ApiResult<Json<Vec<TenantView>>> {
    list_all(&state, &caller.account_id).await.map(Json)
}

/// Every live tenant on an account, without deciding who asked.
///
/// Split from the handler so the dashboard and the API answer from one query.
pub async fn list_all(state: &AppState, account_id: &str) -> ApiResult<Vec<TenantView>> {
    let rows = sqlx::query(&format!(
        "{TENANT_SELECT} WHERE t.account_id = $1 ORDER BY t.tenant_key"
    ))
    .bind(account_id)
    .fetch_all(&state.pool)
    .await?;
    rows.iter().map(row_to_view).collect()
}

async fn update(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
    Path(tenant_key): Path<String>,
    Json(body): Json<UpdateTenant>,
) -> ApiResult<Json<TenantView>> {
    validate_limit(body.max_units.flatten(), "max_units")?;
    validate_limit(body.max_spend_micros.flatten(), "max_spend_micros")?;
    validate_limit(body.unit_price_micros, "unit_price_micros")?;

    let prices = body
        .prices
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| ApiError::BadRequest("prices is not a valid price book".to_owned()))?;

    // COALESCE leaves an absent field alone. The limits use a sentinel-free
    // form instead: `$N::bigint` with a companion boolean says "this field was
    // present", so an explicit null clears the limit rather than being read as
    // "unchanged".
    let result = sqlx::query(
        "UPDATE tenants SET
            prices = COALESCE($3, prices),
            price_version = price_version + CASE WHEN $3 IS NULL THEN 0 ELSE 1 END,
            max_units = CASE WHEN $4 THEN $5 ELSE max_units END,
            max_spend_micros = CASE WHEN $6 THEN $7 ELSE max_spend_micros END,
            unit_price_micros = COALESCE($8, unit_price_micros),
            updated_at = NOW()
         WHERE account_id = $1 AND tenant_key = $2",
    )
    .bind(&caller.account_id)
    .bind(&tenant_key)
    .bind(prices)
    .bind(body.max_units.is_some())
    .bind(body.max_units.flatten())
    .bind(body.max_spend_micros.is_some())
    .bind(body.max_spend_micros.flatten())
    .bind(body.unit_price_micros)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    fetch_one(&state, &caller.account_id, &tenant_key)
        .await
        .map(Json)
}

async fn revoke(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
    Path(tenant_key): Path<String>,
) -> ApiResult<Json<TenantView>> {
    let result = sqlx::query(
        "UPDATE tenants SET revoked_at = COALESCE(revoked_at, NOW()), updated_at = NOW()
         WHERE account_id = $1 AND tenant_key = $2",
    )
    .bind(&caller.account_id)
    .bind(&tenant_key)
    .execute(&state.pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    fetch_one(&state, &caller.account_id, &tenant_key)
        .await
        .map(Json)
}

async fn mint_key(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
    Path(tenant_key): Path<String>,
    body: Option<Json<MintKey>>,
) -> ApiResult<Json<MintedKey>> {
    let label = body.map_or_else(default_label, |Json(body)| body.label);
    mint_key_for(&state, &caller.account_id, &tenant_key, label)
        .await
        .map(Json)
}

/// Mint a tenant API key, without deciding who asked.
///
/// The plaintext is in the return value and nowhere else. See
/// [`crate::tokens::mint_for`].
///
/// # Errors
///
/// Answers `not found` for a tenant that is not this account's.
pub async fn mint_key_for(
    state: &AppState,
    account_id: &str,
    tenant_key: &str,
    label: String,
) -> ApiResult<MintedKey> {
    let tenant_id: i64 =
        sqlx::query_scalar("SELECT id FROM tenants WHERE account_id = $1 AND tenant_key = $2")
            .bind(account_id)
            .bind(tenant_key)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;

    let api_key = mint_token("mut");
    let key_sha256 = hash_token(&api_key);
    sqlx::query("INSERT INTO tenant_api_keys (key_sha256, tenant_id, label) VALUES ($1, $2, $3)")
        .bind(&key_sha256)
        .bind(tenant_id)
        .bind(&label)
        .execute(&state.pool)
        .await?;

    Ok(MintedKey {
        api_key,
        key_sha256,
        label,
    })
}

async fn revoke_key(
    State(state): State<AppState>,
    AdminCaller(caller): AdminCaller,
    Path((tenant_key, key_sha256)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    let result = sqlx::query(
        "UPDATE tenant_api_keys k SET revoked_at = COALESCE(k.revoked_at, NOW())
         FROM tenants t
         WHERE k.tenant_id = t.id
           AND t.account_id = $1 AND t.tenant_key = $2 AND k.key_sha256 = $3",
    )
    .bind(&caller.account_id)
    .bind(&tenant_key)
    .bind(&key_sha256)
    .execute(&state.pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(serde_json::json!({ "revoked": key_sha256 })))
}

const TENANT_SELECT: &str = "SELECT t.tenant_key, t.billing_customer_id, t.prices,
            t.price_version, t.max_units, t.max_spend_micros, t.unit_price_micros,
            t.revoked_at,
            (SELECT COUNT(*) FROM tenant_api_keys k
              WHERE k.tenant_id = t.id AND k.revoked_at IS NULL) AS active_keys
     FROM tenants t";

async fn fetch_one(state: &AppState, account_id: &str, tenant_key: &str) -> ApiResult<TenantView> {
    let row = sqlx::query(&format!(
        "{TENANT_SELECT} WHERE t.account_id = $1 AND t.tenant_key = $2"
    ))
    .bind(account_id)
    .bind(tenant_key)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    row_to_view(&row)
}

fn row_to_view(row: &sqlx::postgres::PgRow) -> ApiResult<TenantView> {
    let prices: serde_json::Value = row.try_get("prices")?;
    Ok(TenantView {
        tenant_key: row.try_get("tenant_key")?,
        billing_customer_id: row.try_get("billing_customer_id")?,
        prices: serde_json::from_value(prices).map_err(|error| {
            tracing::error!(%error, "stored price book no longer deserializes");
            ApiError::Internal
        })?,
        price_version: row.try_get("price_version")?,
        max_units: row.try_get("max_units")?,
        max_spend_micros: row.try_get("max_spend_micros")?,
        unit_price_micros: row.try_get("unit_price_micros")?,
        revoked_at: row.try_get("revoked_at")?,
        active_keys: row.try_get("active_keys")?,
    })
}
