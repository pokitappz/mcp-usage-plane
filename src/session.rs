//! Browser sessions for the dashboard, and the account one acts on.
//!
//! # Why there is a session at all
//!
//! The dashboard is not a read-only view. `POST /app/tokens` mints a full admin
//! credential for the account, so an ungated `/app` would mean whoever finds the
//! URL mints themselves one. That is the whole reason this module exists, and the
//! reason the service binds loopback by default: the cheapest gate is not being
//! reachable.
//!
//! # Why a token and not a credential of its own
//!
//! Every action the dashboard offers has a `/v1/*` equivalent that an `admin`
//! token already performs. A password, or an emailed code, would be a second and
//! weaker credential invented to reach a subset of what its holder could already
//! do, and it would need a store, a reset path, and a defence against guessing
//! something a person chose. So the token is the credential. Signing in presents
//! it once and receives a session; nothing is escalated, because the session does
//! strictly less than the thing presented to get it.
//!
//! The exchange is still worth making rather than sending the token on every
//! request. What the browser then holds is `HttpOnly`, expires, and can be
//! revoked server side by deleting one row; the token is none of those things.
//! Only the SHA-256 of the session reaches the database, so a database disclosure
//! hands over no live session, which is the property `account_tokens` already has.
//!
//! # There is no person here
//!
//! Every holder of an account's admin token is indistinguishable, so there is
//! nobody for a session to name and nothing to attribute an action to. That is a
//! real limitation rather than an oversight: per-person attribution needs a
//! per-person credential, which is the thing this design deliberately does
//! without. A deployment that needs to know who revoked a price wants something
//! else.
//!
//! # Rate limiting is not inherited here
//!
//! The process-local budget in [`crate::throttle`] is spent inside
//! `auth::resolve`, so a route with no bearer extractor never touches it. That
//! is why `POST /v1/accounts` has to take one explicitly too. Every route below
//! takes a budget explicitly.

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::hash_token;
use crate::error::{ApiError, ApiResult};

/// Cookie carrying the session.
const SESSION_COOKIE: &str = "usagekit_session";
/// How long a session lives without being renewed.
const SESSION_LIFETIME_DAYS: i64 = 7;
/// How long a sign-in code stays redeemable.
const SIGN_IN_BURST: u32 = 5;

/// A sign-in attempt.
#[derive(Debug, Deserialize)]
pub struct SignIn {
    /// An `admin` token for the account to open a dashboard on.
    pub token: String,
}

/// Who the session belongs to.
#[derive(Debug, Serialize)]
pub struct SessionView {
    /// The account this session acts on.
    pub account_id: String,
    /// Display name of that account.
    pub account_name: String,
}

/// A resolved dashboard session.
///
/// Extracting this is the authorization check. A handler that takes it cannot be
/// reached without a live session, which is the difference between gating a page
/// and merely redirecting from it in JavaScript.
///
/// There is no person here, deliberately. The session is opened by presenting an
/// `admin` token, and every holder of that token is indistinguishable, so there
/// is nobody for this to name. Attributing an action to a person would need a
/// per-person credential, which is the thing this design does without.
#[derive(Debug, Clone)]
pub struct DashboardSession {
    /// Account this session acts on.
    pub account_id: String,
}

impl FromRequestParts<AppState> for DashboardSession {
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

impl axum::extract::OptionalFromRequestParts<AppState> for DashboardSession {
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
    Router::new().route(
        "/v1/auth/session",
        routing::get(session).post(sign_in_json).delete(sign_out),
    )
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

// ---------------------------------------------------------- session helpers

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

// --------------------------------------------------------------- handlers

async fn sign_in_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SignIn>,
) -> ApiResult<Response> {
    let session = sign_in(&state, &headers, &body.token).await?;
    let mut response = Json(serde_json::json!({ "status": "signed in" })).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie_for(&state, &session));
    Ok(response)
}

/// Exchange an `admin` token for a browser session.
///
/// Shared by the JSON route and the browser form, so there is one definition of
/// what signing in means.
///
/// # Why a token and not a password
///
/// Every action the dashboard offers has a `/v1/*` equivalent that an `admin`
/// token already performs, so a password would be a second, weaker, human-chosen
/// credential invented to reach a subset of what the holder could already do. The
/// token is 32 bytes from the OS random source, is already stored only as a
/// SHA-256, and cannot be guessed. Nothing is escalated by this route: the
/// session it opens does strictly less than the credential presented to get it.
///
/// It also removes a problem rather than solving one. There is no password to
/// forget, so there is no reset path to build, which matters because this service
/// sends no mail and a self-hosted deployment has nobody else to ask.
///
/// The exchange is worth making rather than sending the token on every request:
/// the browser then holds a `HttpOnly` cookie that expires and can be revoked
/// server side, instead of a long-lived full-admin credential that cannot.
///
/// # Errors
///
/// Refuses an untrusted origin, and a token that is unknown, revoked or not
/// `admin` scoped. Those are one answer, because telling them apart tells
/// somebody holding a guess which part of it was close.
pub async fn sign_in(state: &AppState, headers: &HeaderMap, presented: &str) -> ApiResult<String> {
    if !origin_is_trusted(headers, state.public_url.as_deref()) {
        return Err(ApiError::Forbidden);
    }
    let presented = presented.trim();
    if presented.is_empty() {
        return Err(ApiError::Unauthorized);
    }

    // The hash, never the token. It is what the database stores, so nothing here
    // holds a live credential, and the comparison is a primary key lookup rather
    // than anything whose duration depends on how much of the token was right.
    let digest = hash_token(presented);

    // Budget taken on the digest, before the lookup, because this route has no
    // bearer extractor and so never reaches the budget `auth::resolve` spends.
    // Counted on the digest rather than a fixed key so one operator retrying a
    // typo cannot spend everybody's allowance.
    if !state.admission.take_named("signin", &digest, SIGN_IN_BURST) {
        return Err(ApiError::TooManyRequests(
            state.admission.retry_after_seconds(&digest),
        ));
    }

    // `admin` only. An `edge` token belongs to a proxy in front of a customer's
    // server, which is the most exposed component in the whole system; letting it
    // open a dashboard would hand that component the one thing its scope exists
    // to keep away from it.
    let account_id: Option<String> = sqlx::query_scalar(
        "SELECT account_id FROM account_tokens
         WHERE token_sha256 = $1 AND revoked_at IS NULL AND scope = 'admin'",
    )
    .bind(&digest)
    .fetch_optional(&state.pool)
    .await?;

    let Some(account_id) = account_id else {
        return Err(ApiError::Unauthorized);
    };

    let session = generate_session_token();
    let expires_at = Utc::now() + Duration::days(SESSION_LIFETIME_DAYS);
    sqlx::query(
        "INSERT INTO dashboard_sessions (session_sha256, account_id, expires_at)
         VALUES ($1, $2, $3)",
    )
    .bind(hash_token(&session))
    .bind(&account_id)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;

    tracing::info!(account = %account_id, "opened a dashboard session");
    Ok(session)
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
        sqlx::query("DELETE FROM dashboard_sessions WHERE session_sha256 = $1")
            .bind(hash_token(&token))
            .execute(&state.pool)
            .await?;
    }
    Ok(())
}

async fn session(
    session: DashboardSession,
    State(state): State<AppState>,
) -> ApiResult<Json<SessionView>> {
    let account_name: String = sqlx::query_scalar("SELECT name FROM accounts WHERE id = $1")
        .bind(&session.account_id)
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(SessionView {
        account_id: session.account_id,
        account_name,
    }))
}

async fn sign_out(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    // Deliberately not behind `DashboardSession`: signing out with an already
    // invalid session should clear the cookie, not answer 401.
    end_session(&state, &headers).await?;
    let mut response = Json(serde_json::json!({ "status": "signed_out" })).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, clear_cookie());
    Ok(response)
}

/// Resolve a session cookie to the person and account it belongs to.
async fn resolve_session(state: &AppState, token: &str) -> ApiResult<Option<DashboardSession>> {
    let account_id: Option<String> = sqlx::query_scalar(
        "SELECT account_id FROM dashboard_sessions
         WHERE session_sha256 = $1 AND expires_at > NOW()",
    )
    .bind(hash_token(token))
    .fetch_optional(&state.pool)
    .await?;

    let Some(account_id) = account_id else {
        return Ok(None);
    };

    // Best effort: a failed touch must not fail the request.
    let _ =
        sqlx::query("UPDATE dashboard_sessions SET last_seen_at = NOW() WHERE session_sha256 = $1")
            .bind(hash_token(token))
            .execute(&state.pool)
            .await;

    Ok(Some(DashboardSession { account_id }))
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
    fn a_session_token_is_long_and_unique() {
        let first = generate_session_token();
        assert_eq!(first.len(), 64, "32 bytes as hex");
        assert_ne!(first, generate_session_token());
    }
}
