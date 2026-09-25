//! People: sign-in codes, browser sessions, and the account a person acts on.
//!
//! # Why this is not the bearer-token path
//!
//! [`crate::auth`] authenticates machines. Its credential is a long-lived token
//! that is also a full admin credential for an account, which is not something
//! to put in a browser: any script on the page can read it, it does not expire,
//! and it cannot be attributed to a person. This module authenticates humans,
//! with a cookie the page's JavaScript cannot read and a server-side row that
//! can be revoked.
//!
//! # The shape
//!
//! Passwordless. A six digit code is emailed, redeemed once, and exchanged for
//! an opaque session whose SHA-256 is what the database stores. There is no
//! password to leak, reuse, or reset.
//!
//! # Rate limiting is not inherited here
//!
//! The process-local budget in [`crate::throttle`] is spent inside
//! `auth::resolve`, so a route with no bearer extractor never touches it. That
//! is why `POST /v1/accounts` has to take one explicitly too. Every route
//! below takes a
//! budget explicitly.

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row as _;

use crate::AppState;
use crate::auth::hash_token;
use crate::error::{ApiError, ApiResult};

/// Cookie carrying the session.
const SESSION_COOKIE: &str = "usagekit_session";
/// How long a session lives without being renewed.
const SESSION_LIFETIME_DAYS: i64 = 7;
/// How long a sign-in code stays redeemable.
const CODE_LIFETIME_MINUTES: i64 = 10;
/// Wrong guesses allowed before a code is spent.
///
/// A six digit code has a million values, so five guesses is a 1 in 200,000
/// chance. The bound matters more than the number: without it the code is
/// brute-forceable in an afternoon.
const MAX_CODE_ATTEMPTS: i32 = 5;
/// Shortest gap between two codes for one address, so the endpoint cannot be
/// used to send someone a stream of mail.
const RESEND_COOLDOWN_SECONDS: i64 = 60;

/// Sign-in requests allowed per window, per email and per client.
const SIGN_IN_BURST: u32 = 5;
/// Code submissions allowed per window.
const VERIFY_BURST: u32 = 20;

/// A request for a sign-in code.
#[derive(Debug, Deserialize)]
pub struct RequestCode {
    /// Where to send it.
    pub email: String,
}

/// A code being redeemed.
#[derive(Debug, Deserialize)]
pub struct RedeemCode {
    /// The address the code was sent to.
    pub email: String,
    /// The six digits.
    pub code: String,
}

/// What a signed-in caller is told about themselves.
#[derive(Debug, Serialize)]
pub struct SessionView {
    /// Stable identifier for the person.
    ///
    /// Not a credential, and the handle anything that attributes an action to
    /// a person will use. Attribution is the reason this table exists: nothing
    /// in the schema currently records who changed a price or revoked a token.
    pub user_id: String,
    /// The person.
    pub email: String,
    /// The account they are acting on.
    pub account_id: String,
    /// Display name of that account.
    pub account_name: String,
    /// `owner` or `member`.
    pub role: String,
}

/// A resolved human caller.
///
/// Extracting this is the authorization check. A handler that takes it cannot
/// be reached without a live session, which is the difference between gating a
/// page and merely redirecting from it in JavaScript.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    /// Stable user identifier.
    pub user_id: String,
    /// The person's address.
    pub email: String,
    /// Account this session acts on.
    pub account_id: String,
    /// Role within that account.
    pub role: String,
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = session_cookie(&parts.headers).ok_or(ApiError::Unauthorized)?;
        resolve_session(state, &token)
            .await?
            .ok_or(ApiError::Unauthorized)
    }
}

impl axum::extract::OptionalFromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    /// Resolve a session if there is one, without refusing when there is not.
    ///
    /// The pages need this: an anonymous visitor to the dashboard should be
    /// sent to sign in, not handed a JSON 401 in a browser window. It is still
    /// a server-side gate, because a handler that gets `None` renders a
    /// redirect and never the dashboard.
    ///
    /// A cookie that is present but unusable resolves to `None` rather than an
    /// error, so a stale session from a previous deployment sends someone to
    /// sign in instead of stranding them on an error page with no way out.
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Option<Self>, Self::Rejection> {
        let Some(token) = session_cookie(&parts.headers) else {
            return Ok(None);
        };
        resolve_session(state, &token).await
    }
}

/// Human authentication routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/code", routing::post(request_code))
        .route("/v1/auth/session", routing::get(session).delete(sign_out))
        .route("/v1/auth/verify", routing::post(verify))
}

// ------------------------------------------------------------------ cookies

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|pair| {
            pair.trim()
                .strip_prefix(SESSION_COOKIE)
                .and_then(|rest| rest.strip_prefix('='))
                .map(str::to_owned)
        })
        .filter(|value| !value.is_empty())
}

/// Build the `Set-Cookie` value for a new session.
///
/// `HttpOnly` so a script cannot read it, `SameSite=Lax` so it does not ride
/// along on a cross-site POST, and `Secure` whenever the service is actually
/// reachable over https.
fn set_cookie(token: &str, secure: bool) -> HeaderValue {
    let max_age = SESSION_LIFETIME_DAYS * 24 * 60 * 60;
    let suffix = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Max-Age={max_age}; Path=/{suffix}"
    ))
    .unwrap_or_else(|_| clear_cookie())
}

fn clear_cookie() -> HeaderValue {
    HeaderValue::from_static("usagekit_session=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/")
}

/// Whether a state-changing request came from this service's own pages.
///
/// The session cookie is `SameSite=Lax`, which already keeps it off cross-site
/// POSTs. This is the second lock: an absent `Origin` is refused rather than
/// assumed friendly, so the check fails closed.
pub fn origin_is_trusted(headers: &HeaderMap, public_url: Option<&str>) -> bool {
    let (Some(origin), Some(public_url)) = (
        headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok()),
        public_url,
    ) else {
        return false;
    };
    let (Ok(origin), Ok(public_url)) = (url::Url::parse(origin), url::Url::parse(public_url))
    else {
        return false;
    };
    origin.origin() == public_url.origin()
}

// ------------------------------------------------------------- code helpers

/// A six digit code, from the OS random source.
fn generate_code() -> String {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).expect("the OS must provide randomness");
    format!("{:06}", u32::from_be_bytes(bytes) % 1_000_000)
}

/// An opaque session token.
fn generate_session_token() -> String {
    use std::fmt::Write as _;

    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the OS must provide randomness");
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Normalize an address for storage and comparison.
///
/// The column is `CITEXT`, so case is already handled; this trims and bounds
/// the length so an unbounded string never reaches the database.
///
/// Shared with the access form in [`crate::pages`] rather than reimplemented
/// there. Two validators for one column drift, and the one that drifts is
/// always the one guarding the unauthenticated route.
pub fn normalize_email(raw: &str) -> ApiResult<String> {
    let email = raw.trim();
    let valid = (3..=254).contains(&email.len())
        && email.split('@').count() == 2
        && email.split('@').all(|part| !part.is_empty())
        && !email.contains(char::is_whitespace);
    if valid {
        Ok(email.to_owned())
    } else {
        Err(ApiError::BadRequest("a valid email is required".to_owned()))
    }
}

// --------------------------------------------------------------- handlers

async fn request_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RequestCode>,
) -> ApiResult<Json<serde_json::Value>> {
    let development_code = issue_code(&state, &headers, &body.email).await?;
    Ok(Json(match development_code {
        Some(code) => serde_json::json!({ "status": "sent", "development_code": code }),
        None => serde_json::json!({ "status": "sent" }),
    }))
}

/// Issue a sign-in code, without deciding how the answer is presented.
///
/// Split from the handler so the JSON route and the browser form share one
/// implementation. Two copies of a sign-in path is one copy too many: the one
/// that drifts is the one that forgets the oracle-avoidance below.
///
/// # Errors
///
/// Refuses an untrusted origin, an unusable address, and a spent budget.
/// Everything else answers the same way whether or not the address exists.
pub async fn issue_code(
    state: &AppState,
    headers: &HeaderMap,
    raw_email: &str,
) -> ApiResult<Option<String>> {
    if !origin_is_trusted(headers, state.public_url.as_deref()) {
        return Err(ApiError::Forbidden);
    }
    let email = normalize_email(raw_email)?;

    // Budget is taken here, explicitly, because nothing upstream takes one for
    // a route with no bearer extractor.
    if !state
        .admission
        .take_named("signin", &hash_token(&email), SIGN_IN_BURST)
    {
        return Err(ApiError::TooManyRequests(
            state.admission.retry_after_seconds(&hash_token(&email)),
        ));
    }

    // Only a known user is sent a code. Access is granted by hand, so an
    // address nobody invited has nothing to sign in to.
    // `$1::citext` is load bearing. sqlx binds every parameter as `text`, and
    // Postgres resolves `citext = text` by casting the *column* down to text,
    // which is case sensitive. Without the cast the column type is silently
    // defeated: somebody invited as `Person@Example.com` who types
    // `person@example.com` is simply not found, and because this endpoint
    // deliberately answers the same way for an unknown address, they are told a
    // code was sent and it never arrives.
    let user: Option<(String, Option<DateTime<Utc>>)> =
        sqlx::query("SELECT id, disabled_at FROM users WHERE email = $1::citext")
            .bind(&email)
            .fetch_optional(&state.pool)
            .await?
            .map(|row| -> ApiResult<_> { Ok((row.try_get("id")?, row.try_get("disabled_at")?)) })
            .transpose()?;

    // The same answer either way. Telling an anonymous caller whether an
    // address is registered turns this into an account-existence oracle.
    let Some((user_id, disabled_at)) = user else {
        return Ok(None);
    };
    if disabled_at.is_some() {
        return Ok(None);
    }

    let code = generate_code();
    let expires_at = Utc::now() + Duration::minutes(CODE_LIFETIME_MINUTES);

    // The cooldown lives in the WHERE clause so two concurrent requests cannot
    // both decide they are first.
    let issued = sqlx::query(
        "INSERT INTO user_login_codes (user_id, code_sha256, expires_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id) DO UPDATE
           SET code_sha256 = EXCLUDED.code_sha256,
               expires_at = EXCLUDED.expires_at,
               attempts = 0,
               issued_at = NOW()
         WHERE user_login_codes.issued_at < NOW() - ($4 || ' seconds')::interval",
    )
    .bind(&user_id)
    .bind(hash_token(&code))
    .bind(expires_at)
    .bind(RESEND_COOLDOWN_SECONDS.to_string())
    .execute(&state.pool)
    .await?;

    if issued.rows_affected() == 0 {
        // Inside the cooldown. Still the same answer: whether a code was just
        // sent is also information about the address.
        return Ok(None);
    }

    deliver_code(state, &email, &code).await
}

/// Send a sign-in code, or explain why it cannot be sent.
///
/// Without a mail service the code can never arrive, so failing is the honest
/// answer rather than a cheerful "sent". A debug build against no mail service
/// returns the code instead, which keeps the flow testable; that arm is
/// compiled out of a release build.
async fn deliver_code(state: &AppState, email: &str, code: &str) -> ApiResult<Option<String>> {
    let Some(client) = state.email.as_ref() else {
        #[cfg(debug_assertions)]
        {
            tracing::warn!("email is not configured; returning the code for development");
            return Ok(Some(code.to_owned()));
        }
        #[cfg(not(debug_assertions))]
        {
            tracing::error!("email is not configured; no sign-in code can be delivered");
            return Err(ApiError::Internal);
        }
    };

    if let Err(error) = client.send_sign_in_code(email, code).await {
        tracing::error!(%error, "could not send a sign-in code");
        return Err(ApiError::Internal);
    }
    Ok(None)
}

async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RedeemCode>,
) -> ApiResult<Response> {
    let token = redeem_code(&state, &headers, &body.email, &body.code).await?;
    let mut response = Json(serde_json::json!({ "status": "signed_in" })).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie_for(&state, &token));
    Ok(response)
}

/// Redeem a code and open a session, returning the new session token.
///
/// Split from the handler for the same reason as [`issue_code`]. The caller
/// decides what to do with the token; every caller must set it with
/// [`session_cookie_for`] rather than handing it to a page.
///
/// # Errors
///
/// Refuses an untrusted origin, a spent budget, and anything about the code
/// being wrong, expired or already spent, all as the same `unauthorized`.
pub async fn redeem_code(
    state: &AppState,
    headers: &HeaderMap,
    raw_email: &str,
    raw_code: &str,
) -> ApiResult<String> {
    if !origin_is_trusted(headers, state.public_url.as_deref()) {
        return Err(ApiError::Forbidden);
    }
    let email = normalize_email(raw_email)?;
    let code = raw_code.trim().to_owned();

    if !state
        .admission
        .take_named("verify", &hash_token(&email), VERIFY_BURST)
    {
        return Err(ApiError::TooManyRequests(
            state.admission.retry_after_seconds(&hash_token(&email)),
        ));
    }

    let mut tx = state.pool.begin().await?;

    // Locked, so two concurrent submissions cannot both consume an attempt
    // without the other seeing it, and cannot both redeem one code.
    let row = sqlx::query(
        "SELECT c.user_id, c.code_sha256, c.attempts, c.expires_at
         FROM user_login_codes c
         JOIN users u ON u.id = c.user_id
         WHERE u.email = $1::citext AND u.disabled_at IS NULL
         FOR UPDATE OF c",
    )
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        return Err(ApiError::Unauthorized);
    };
    let user_id: String = row.try_get("user_id")?;
    let stored: String = row.try_get("code_sha256")?;
    let attempts: i32 = row.try_get("attempts")?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at")?;

    if expires_at <= Utc::now() || attempts >= MAX_CODE_ATTEMPTS {
        return Err(ApiError::Unauthorized);
    }

    if hash_token(&code) != stored {
        // Spend an attempt, and commit that spend even though the request
        // failed. Rolling back here would make the attempt counter free.
        sqlx::query("UPDATE user_login_codes SET attempts = attempts + 1 WHERE user_id = $1")
            .bind(&user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Err(ApiError::Unauthorized);
    }

    // Correct. The code is spent whether or not anything below succeeds.
    sqlx::query("DELETE FROM user_login_codes WHERE user_id = $1")
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE users SET verified_at = COALESCE(verified_at, NOW()) WHERE id = $1")
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;

    let token = generate_session_token();
    let expires_at = Utc::now() + Duration::days(SESSION_LIFETIME_DAYS);
    sqlx::query(
        "INSERT INTO user_sessions (session_sha256, user_id, expires_at)
         VALUES ($1, $2, $3)",
    )
    .bind(hash_token(&token))
    .bind(&user_id)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(token)
}

/// The `Set-Cookie` value for a new session on this deployment.
///
/// `Secure` is decided from the configured public origin rather than from the
/// request, because a request header is attacker-controlled and this decides
/// whether the cookie may travel in plaintext.
#[must_use]
pub fn session_cookie_for(state: &AppState, token: &str) -> HeaderValue {
    let secure = state
        .public_url
        .as_deref()
        .is_some_and(|url| url.starts_with("https://"));
    set_cookie(token, secure)
}

/// The `Set-Cookie` value that ends a session.
#[must_use]
pub fn session_clear_cookie() -> HeaderValue {
    clear_cookie()
}

/// Drop whatever session the request carries. Never fails for lack of one.
///
/// # Errors
///
/// Only when the delete cannot reach the database.
pub async fn end_session(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if let Some(token) = session_cookie(headers) {
        sqlx::query("DELETE FROM user_sessions WHERE session_sha256 = $1")
            .bind(hash_token(&token))
            .execute(&state.pool)
            .await?;
    }
    Ok(())
}

async fn session(user: CurrentUser, State(state): State<AppState>) -> ApiResult<Json<SessionView>> {
    let row = sqlx::query("SELECT name FROM accounts WHERE id = $1")
        .bind(&user.account_id)
        .fetch_optional(&state.pool)
        .await?;
    Ok(Json(SessionView {
        user_id: user.user_id,
        email: user.email,
        account_id: user.account_id,
        account_name: row
            .map(|row| row.try_get("name"))
            .transpose()?
            .unwrap_or_default(),
        role: user.role,
    }))
}

async fn sign_out(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    // Deliberately not behind `CurrentUser`: signing out with an already
    // invalid session should clear the cookie, not answer 401.
    end_session(&state, &headers).await?;
    let mut response = Json(serde_json::json!({ "status": "signed_out" })).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, clear_cookie());
    Ok(response)
}

/// Create a person, or reuse the one that address already names, and give
/// them ownership of an account.
///
/// Nothing in this service could do this before: `users` and `memberships`
/// were written only by test fixtures, so granting somebody access meant
/// connecting to Postgres and writing two rows by hand.
///
/// `verified_at` stays null. A row here means invited, not proven: the person
/// becomes verified by redeeming their first emailed code, which is the step
/// that shows they actually read that mailbox. [`resolve_session`] refuses an
/// unverified user, so an invite on its own opens nothing.
///
/// # Errors
///
/// Propagates the database error. The caller is expected to have already
/// decided that this address should get an account. Creating a person who
/// already belongs to another account is allowed and does nothing surprising:
/// the membership insert is a no-op on conflict.
pub async fn attach_person(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    email: &str,
    account_id: &str,
) -> ApiResult<String> {
    // `ON CONFLICT ... DO UPDATE` rather than `DO NOTHING` because `DO NOTHING`
    // returns no row, and this needs the id whether it inserted or not. The
    // update is a no-op write of the address the row already has.
    let user_id: String = sqlx::query_scalar(
        "INSERT INTO users (id, email) VALUES ($1, $2)
         ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
         RETURNING id",
    )
    .bind(mint_user_id())
    .bind(email)
    .fetch_one(&mut **tx)
    .await?;

    sqlx::query(
        "INSERT INTO memberships (user_id, account_id, role)
         VALUES ($1, $2, 'owner')
         ON CONFLICT (user_id, account_id) DO NOTHING",
    )
    .bind(&user_id)
    .bind(account_id)
    .execute(&mut **tx)
    .await?;

    Ok(user_id)
}

/// An opaque user identifier, shaped like the account identifier beside it.
fn mint_user_id() -> String {
    crate::auth::mint_token("usr").replace('_', "")
}

/// Resolve a session cookie to the person and account it belongs to.
async fn resolve_session(state: &AppState, token: &str) -> ApiResult<Option<CurrentUser>> {
    let row = sqlx::query(
        "SELECT u.id AS user_id, u.email, m.account_id, m.role
         FROM user_sessions s
         JOIN users u ON u.id = s.user_id
         JOIN memberships m ON m.user_id = u.id
         WHERE s.session_sha256 = $1
           AND s.expires_at > NOW()
           AND u.disabled_at IS NULL
           AND u.verified_at IS NOT NULL
         ORDER BY m.created_at
         LIMIT 1",
    )
    .bind(hash_token(token))
    .fetch_optional(&state.pool)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    // Best effort: a failed touch must not fail the request.
    let _ = sqlx::query("UPDATE user_sessions SET last_seen_at = NOW() WHERE session_sha256 = $1")
        .bind(hash_token(token))
        .execute(&state.pool)
        .await;

    Ok(Some(CurrentUser {
        user_id: row.try_get("user_id")?,
        email: row.try_get("email")?,
        account_id: row.try_get("account_id")?,
        role: row.try_get("role")?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(name: header::HeaderName, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_str(value).expect("a header"));
        headers
    }

    #[test]
    fn a_session_cookie_is_read_from_among_others() {
        let headers = headers_with(
            header::COOKIE,
            "other=1; usagekit_session=abc123; trailing=2",
        );
        assert_eq!(session_cookie(&headers).as_deref(), Some("abc123"));

        // A cookie whose name merely ends in ours must not match.
        let headers = headers_with(header::COOKIE, "not_usagekit_session=abc123");
        assert_eq!(session_cookie(&headers), None);
        assert_eq!(session_cookie(&HeaderMap::new()), None);
    }

    #[test]
    fn the_cookie_is_http_only_and_secure_only_over_https() {
        let secure = set_cookie("token", true);
        let rendered = secure.to_str().expect("ascii");
        assert!(rendered.contains("HttpOnly"));
        assert!(rendered.contains("SameSite=Lax"));
        assert!(rendered.contains("; Secure"));

        let insecure = set_cookie("token", false);
        assert!(!insecure.to_str().expect("ascii").contains("Secure"));
    }

    #[test]
    fn a_missing_origin_is_refused_rather_than_assumed_friendly() {
        let public = Some("https://usagekit.example");
        assert!(!origin_is_trusted(&HeaderMap::new(), public));
        assert!(origin_is_trusted(
            &headers_with(header::ORIGIN, "https://usagekit.example"),
            public
        ));
        for attempt in [
            "https://usagekit.example.evil.test",
            "http://usagekit.example",
            "https://evil.test",
            "null",
        ] {
            assert!(
                !origin_is_trusted(&headers_with(header::ORIGIN, attempt), public),
                "{attempt} was trusted"
            );
        }
        // No configured origin means nothing can be trusted against it.
        assert!(!origin_is_trusted(
            &headers_with(header::ORIGIN, "https://usagekit.example"),
            None
        ));
    }

    #[test]
    fn emails_are_bounded_and_shaped_before_they_reach_the_database() {
        assert_eq!(
            normalize_email("  Person@Example.com ").unwrap(),
            "Person@Example.com"
        );
        for attempt in [
            "",
            "no-at-sign",
            "two@at@signs",
            "@nolocal",
            "nodomain@",
            "has space@example.com",
        ] {
            assert!(
                normalize_email(attempt).is_err(),
                "{attempt:?} was accepted"
            );
        }
        let too_long = format!("{}@example.com", "a".repeat(300));
        assert!(normalize_email(&too_long).is_err());
    }

    #[test]
    fn a_generated_code_is_six_digits_and_not_constant() {
        let first = generate_code();
        assert_eq!(first.len(), 6);
        assert!(first.chars().all(|character| character.is_ascii_digit()));
        let differs = (0..20).any(|_| generate_code() != first);
        assert!(differs, "every generated code was identical");
    }

    #[test]
    fn a_session_token_is_long_and_unique() {
        let first = generate_session_token();
        assert_eq!(first.len(), 64, "32 bytes as hex");
        assert_ne!(first, generate_session_token());
    }
}
