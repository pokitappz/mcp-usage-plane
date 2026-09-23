//! Deciding access requests: the other end of the landing page's form.
//!
//! # What was missing
//!
//! [`crate::pages`] writes a row when somebody asks for access, and until now
//! nothing read it. There was no route that could grant one, and no code path
//! anywhere that could create a `users` row or a `memberships` row, so the
//! documented flow of "a user row and a membership are created when an access
//! request is approved" was performed by hand against Postgres or not at all.
//!
//! # Granting is one transaction
//!
//! An account, a person, a membership and the decision itself all commit
//! together or none of them do. The failure this prevents is the interesting
//! one: an account created, the request left pending, and an operator who
//! grants it again and creates a second account nobody will ever look at.
//!
//! # No credentials are minted here
//!
//! Granting produces an account and somebody who can sign in, and no tokens.
//! The person mints what they need from the dashboard, which is the one place
//! a credential can be shown to the human who will hold it. Contrast
//! [`crate::accounts`], which does mint a pair, because it provisions accounts
//! that may have no human at all.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::{Json, Router, routing};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row as _;

use crate::AppState;
use crate::accounts::{check_name, check_operator_secret, create_account};
use crate::error::{ApiError, ApiResult};
use crate::people::attach_person;

/// Most requests returned in one listing.
///
/// The queue is read by a person deciding what to do next, and a person does
/// not read a thousand rows. Oldest first, so the listing is a queue rather
/// than a feed.
const MAX_LISTED: i64 = 200;

/// A queued request, as an operator sees it.
#[derive(Debug, Serialize)]
pub struct AccessRequestView {
    /// Row identifier, and the handle for deciding it.
    pub id: i64,
    /// Who asked.
    pub email: String,
    /// Who they said they work for.
    pub company: Option<String>,
    /// Their own forecast of monthly metered events.
    pub expected_events: Option<i64>,
    /// Anything they wanted to say.
    pub note: Option<String>,
    /// When they asked.
    pub created_at: DateTime<Utc>,
    /// When it was granted, if it was.
    pub granted_at: Option<DateTime<Utc>>,
    /// The account granting created.
    pub granted_account: Option<String>,
    /// When it was declined, if it was.
    pub declined_at: Option<DateTime<Utc>>,
    /// The account this address already belongs to, if any.
    ///
    /// Present on a pending request so an operator can see a duplicate before
    /// trying to grant it, rather than being refused and having to work out
    /// why.
    pub existing_account: Option<String>,
}

/// Which requests to list.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// `pending` by default; also `granted`, `declined` or `all`.
    #[serde(default)]
    pub state: Option<String>,
}

/// What an account created by granting should be called.
#[derive(Debug, Deserialize, Default)]
pub struct GrantRequest {
    /// Display name. Defaults to the company on the request, then the address.
    #[serde(default)]
    pub name: Option<String>,
    /// The operator secret, for callers that cannot set a header.
    #[serde(default)]
    pub provision_secret: Option<String>,
}

/// The outcome of granting.
#[derive(Debug, Serialize)]
pub struct GrantedAccess {
    /// The request that was decided.
    pub id: i64,
    /// The new account.
    pub account_id: String,
    /// Its display name.
    pub name: String,
    /// The person who may now sign in.
    pub email: String,
    /// Their stable identifier.
    pub user_id: String,
    /// Whether the notification actually went out.
    ///
    /// Reported rather than hidden: the grant is committed either way, and an
    /// operator who knows the mail failed can tell the person by hand instead
    /// of waiting for a sign-in that is never attempted.
    pub notified: bool,
}

/// Operator routes for the access queue.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/access-requests", routing::get(list))
        .route("/v1/access-requests/{id}/grant", routing::post(grant))
        .route("/v1/access-requests/{id}/decline", routing::post(decline))
}

/// The SQL filter for a listing state. An allowlist, never interpolated input.
fn state_filter(state: Option<&str>) -> ApiResult<&'static str> {
    match state.unwrap_or("pending") {
        "pending" => Ok("granted_at IS NULL AND declined_at IS NULL"),
        "granted" => Ok("granted_at IS NOT NULL"),
        "declined" => Ok("declined_at IS NOT NULL"),
        "all" => Ok("TRUE"),
        other => Err(ApiError::BadRequest(format!(
            "state {other:?} must be pending, granted, declined or all"
        ))),
    }
}

/// The account this address already belongs to, if any.
///
/// Granting a second account to somebody who already has one would produce an
/// account they cannot reach: resolving a session picks the oldest membership
/// and the dashboard has no account switcher, so the new one would be
/// invisible. Refusing and saying which account they are on is the honest
/// answer until there is a switcher.
///
/// # Errors
///
/// Propagates the database error.
pub async fn membership_for(executor: &sqlx::PgPool, email: &str) -> ApiResult<Option<String>> {
    // `$1::citext` for the same reason as the lookups in `people`: a bound
    // parameter is `text`, and `citext = text` compares case sensitively.
    Ok(sqlx::query_scalar(
        "SELECT m.account_id
         FROM users u
         JOIN memberships m ON m.user_id = u.id
         WHERE u.email = $1::citext
         ORDER BY m.created_at
         LIMIT 1",
    )
    .bind(email)
    .fetch_optional(executor)
    .await?)
}

async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Vec<AccessRequestView>>> {
    check_operator_secret(&state, None, &headers)?;
    let filter = state_filter(query.state.as_deref())?;

    // The join reports whether each address already has an account, so a
    // duplicate is visible in the queue rather than only when granting it
    // fails.
    let sql = format!(
        "SELECT r.id, r.email::text AS email, r.company, r.expected_events, r.note,
                r.created_at, r.granted_at, r.granted_account, r.declined_at,
                (SELECT m.account_id
                   FROM users u
                   JOIN memberships m ON m.user_id = u.id
                  WHERE u.email = r.email
                  ORDER BY m.created_at
                  LIMIT 1) AS existing_account
         FROM access_requests r
         WHERE {filter}
         ORDER BY r.created_at
         LIMIT $1"
    );

    let rows = sqlx::query(&sql)
        .bind(MAX_LISTED)
        .fetch_all(&state.pool)
        .await?;

    rows.into_iter()
        .map(|row| {
            Ok(AccessRequestView {
                id: row.try_get("id")?,
                email: row.try_get("email")?,
                company: row.try_get("company")?,
                expected_events: row.try_get("expected_events")?,
                note: row.try_get("note")?,
                created_at: row.try_get("created_at")?,
                granted_at: row.try_get("granted_at")?,
                granted_account: row.try_get("granted_account")?,
                declined_at: row.try_get("declined_at")?,
                existing_account: row.try_get("existing_account")?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

async fn grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    body: Option<Json<GrantRequest>>,
) -> ApiResult<Json<GrantedAccess>> {
    let body = body.map(|Json(body)| body).unwrap_or_default();
    check_operator_secret(&state, body.provision_secret.as_deref(), &headers)?;

    let mut tx = state.pool.begin().await?;

    // Locked for the length of the decision. Two operators clicking grant at
    // the same moment would otherwise both read a pending row and both create
    // an account, and the second account would belong to nobody.
    let row = sqlx::query(
        "SELECT email::text AS email, company, granted_at, declined_at
         FROM access_requests WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;

    let email: String = row.try_get("email")?;
    let company: Option<String> = row.try_get("company")?;
    let granted_at: Option<DateTime<Utc>> = row.try_get("granted_at")?;
    let declined_at: Option<DateTime<Utc>> = row.try_get("declined_at")?;

    if granted_at.is_some() {
        return Err(ApiError::Conflict(format!(
            "request {id} was already granted"
        )));
    }
    if declined_at.is_some() {
        return Err(ApiError::Conflict(format!(
            "request {id} was declined; it cannot then be granted"
        )));
    }

    if let Some(existing) = membership_for(&state.pool, &email).await? {
        return Err(ApiError::Conflict(format!(
            "{email} already belongs to account {existing}; \
             granting again would create an account they cannot reach"
        )));
    }

    // The company if they gave one, otherwise the address. Never blank: an
    // account list of empty strings is a list nobody can read.
    let name = body
        .name
        .as_deref()
        .or(company.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&email)
        .to_owned();
    let name = check_name(&name)?.to_owned();

    let account_id = create_account(&mut tx, &name).await?;
    let user_id = attach_person(&mut tx, &email, &account_id).await?;

    sqlx::query(
        "UPDATE access_requests
         SET granted_at = NOW(), granted_account = $2
         WHERE id = $1",
    )
    .bind(id)
    .bind(&account_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(id, account_id, user_id, "granted an access request");

    // After the commit, and deliberately not inside it. Holding a transaction
    // open across an HTTP call to a mail service would keep a row locked for
    // as long as that service takes to answer, and a mail failure must not
    // undo an account that already exists.
    let notified = notify(&state, &email).await;

    Ok(Json(GrantedAccess {
        id,
        account_id,
        name,
        email,
        user_id,
        notified,
    }))
}

async fn decline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    body: Option<Json<GrantRequest>>,
) -> ApiResult<Json<serde_json::Value>> {
    let body = body.map(|Json(body)| body).unwrap_or_default();
    check_operator_secret(&state, body.provision_secret.as_deref(), &headers)?;

    // One statement, so the decision is the same race-free thing granting is.
    // The WHERE clause is the check: a row that already has an outcome does
    // not match, and matching nothing is how this reports a conflict.
    let decided = sqlx::query(
        "UPDATE access_requests
         SET declined_at = NOW()
         WHERE id = $1 AND granted_at IS NULL AND declined_at IS NULL",
    )
    .bind(id)
    .execute(&state.pool)
    .await?;

    if decided.rows_affected() == 0 {
        // Distinguish "no such request" from "already decided", because they
        // need different things from the operator.
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM access_requests WHERE id = $1)")
                .bind(id)
                .fetch_one(&state.pool)
                .await?;
        return Err(if exists {
            ApiError::Conflict(format!("request {id} was already decided"))
        } else {
            ApiError::NotFound
        });
    }

    // The address is not logged. This is a request that was refused, and a
    // refused stranger's address does not need to be in log storage.
    tracing::info!(id, "declined an access request");
    Ok(Json(serde_json::json!({ "declined": id })))
}

/// Tell somebody their account is ready. Never fatal.
async fn notify(state: &AppState, email: &str) -> bool {
    let Some(client) = state.email.as_ref() else {
        tracing::warn!("email is not configured; the grant was not announced");
        return false;
    };
    let sign_in_url = format!("{}/signin", state.public_url.as_deref().unwrap_or_default());
    match client.send_access_granted(email, &sign_in_url).await {
        Ok(()) => true,
        Err(error) => {
            tracing::error!(%error, "granted access but could not announce it");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_states_are_an_allowlist() {
        assert_eq!(
            state_filter(None).unwrap(),
            "granted_at IS NULL AND declined_at IS NULL",
            "the default listing is the queue, not everything"
        );
        for state in ["pending", "granted", "declined", "all"] {
            assert!(state_filter(Some(state)).is_ok(), "{state}");
        }
        // The filter is interpolated into SQL, so anything outside the
        // allowlist has to be refused rather than escaped.
        for attempt in [
            "TRUE; DROP TABLE access_requests; --",
            "granted_at IS NULL OR TRUE",
            "",
        ] {
            assert!(state_filter(Some(attempt)).is_err(), "{attempt:?}");
        }
    }
}
