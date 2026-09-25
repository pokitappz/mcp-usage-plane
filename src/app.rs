//! The dashboard: what a customer sees about their own account.
//!
//! Server rendered and gated server-side. A handler here either resolved a
//! session or it renders a redirect, so there is no state in which the shell
//! reaches an anonymous browser and JavaScript is trusted to send them away.
//! That distinction matters more than it looks: a dashboard gated in the
//! client is a dashboard whose markup, structure and panel names are public.
//!
//! # No JavaScript, deliberately
//!
//! Every action is a form post that redirects. The session cookie is
//! `SameSite=Lax` and every mutating handler checks `Origin` against the
//! configured public URL, which together is the whole CSRF story; there is no
//! token to mint, store or forget to check. The cost is a page load per action,
//! which for a dashboard somebody opens a few times a month is not a cost.
//!
//! # The figures come from the API's own queries
//!
//! Each panel calls the function the matching JSON handler calls, rather than a
//! second copy of its SQL. Two copies of a billing query drift, and the one
//! that drifts silently is the one a customer is reading.

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use sqlx::Row as _;

use crate::AppState;
use crate::error::{ApiError, ApiResult};
use crate::pages::{Shell, render};
use crate::people::{self, CurrentUser};
use crate::pricing::micros_to_cents;

/// How much usage history the dashboard shows.
const WINDOW_DAYS: i64 = 30;
/// Most usage rows rendered. Beyond this the page stops being readable long
/// before it stops being correct, and the API is the right tool for bulk.
const MAX_USAGE_ROWS: u32 = 400;

// --------------------------------------------------------------- formatting

/// Group digits so a seven figure count is readable at a glance.
fn thousands(value: i64) -> String {
    let negative = value < 0;
    let digits = value.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if negative {
        out.push('-');
    }
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// Millionths of a unit of currency, as money.
///
/// Rounded through the same half-up function the invoice uses, so the figure
/// on the page is the figure that was charged rather than a second rounding of
/// the same number.
fn money(micros: i64) -> String {
    let cents = micros_to_cents(micros);
    let units = i64::try_from(cents / 100).unwrap_or(i64::MAX);
    format!("${}.{:02}", thousands(units), cents % 100)
}

/// A cap, or a word rather than a blank when there is not one.
fn cap(value: Option<i64>, format: fn(i64) -> String) -> String {
    value.map_or_else(|| "Unbounded".to_owned(), format)
}

fn day(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%d").to_string()
}

fn minute(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%d %H:%M").to_string()
}

fn month(at: DateTime<Utc>) -> String {
    at.format("%B %Y").to_string()
}

// ------------------------------------------------------------- view model

struct Summary {
    units_30d: String,
    tenants: usize,
    pending: i64,
    dead_lettered: i64,
}

struct Terms {
    summary: String,
}

struct UsageLine {
    day: String,
    customer: String,
    meter: String,
    units: String,
    events: String,
}

impl From<crate::usage::RollupRow> for UsageLine {
    fn from(row: crate::usage::RollupRow) -> Self {
        Self {
            day: day(row.bucket),
            customer: row.customer_id,
            meter: row.meter,
            units: thousands(row.units),
            events: thousands(row.events),
        }
    }
}

struct QuotaLine {
    customer: String,
    units: String,
    spend: String,
    admitting: bool,
    reason: String,
}

/// `committed` against `limit`, or just `committed` when there is no limit.
///
/// Rendering "1,234 of 0" for an unbounded customer would read as a customer
/// who has blown through their cap, which is the opposite of the truth.
fn against_limit(committed: u64, limit: Option<u64>, format: fn(i64) -> String) -> String {
    let committed = format(i64::try_from(committed).unwrap_or(i64::MAX));
    match limit {
        Some(limit) => format!(
            "{committed} of {}",
            format(i64::try_from(limit).unwrap_or(i64::MAX))
        ),
        None => committed,
    }
}

/// Say why a customer is blocked, in words rather than in a variant name.
///
/// The JSON API reports the reason as the library names it, which is right for
/// a machine and wrong for the person reading a dashboard: `QuotaExceeded` was
/// appearing on the page as-is. The API contract is unchanged; only what is
/// shown to a human is translated, and an unrecognised value falls through as
/// itself rather than being swallowed.
fn plain_reason(reason: Option<&str>) -> String {
    match reason {
        None => String::new(),
        Some("QuotaExceeded") => "Over their usage limit".to_owned(),
        Some("SpendCapExceeded") => "Over their spending limit".to_owned(),
        Some(other) => other.to_owned(),
    }
}

impl From<crate::usage::QuotaRow> for QuotaLine {
    fn from(row: crate::usage::QuotaRow) -> Self {
        Self {
            customer: row.customer_id,
            units: against_limit(row.committed_units, row.max_units, thousands),
            spend: against_limit(row.committed_spend_micros, row.max_spend_micros, money),
            admitting: row.admitting,
            reason: plain_reason(row.reason.as_deref()),
        }
    }
}

struct InvoiceLine {
    period: String,
    units: String,
    revenue: String,
    charge: String,
    settled: bool,
}

impl From<crate::pricing::Invoice> for InvoiceLine {
    fn from(row: crate::pricing::Invoice) -> Self {
        Self {
            period: month(row.period_start),
            units: thousands(row.units),
            revenue: money(row.revenue_micros),
            charge: money(row.charge_micros),
            settled: row.settled,
        }
    }
}

struct TenantLine {
    key: String,
    customer: String,
    unit_price: String,
    max_units: String,
    max_spend: String,
    active_keys: i64,
    revoked: bool,
}

impl From<crate::tenants::TenantView> for TenantLine {
    fn from(row: crate::tenants::TenantView) -> Self {
        Self {
            key: row.tenant_key,
            customer: row.billing_customer_id,
            unit_price: money(row.unit_price_micros),
            max_units: cap(row.max_units, thousands),
            max_spend: cap(row.max_spend_micros, money),
            active_keys: row.active_keys,
            revoked: row.revoked_at.is_some(),
        }
    }
}

struct DeadLetterLine {
    identifier: String,
    customer: String,
    meter: String,
    units: String,
    when: String,
    direction: String,
    reason: String,
}

/// Say where a charge was headed, rather than which side of the system it was.
///
/// `downstream` and `upstream` are the names the export code uses for itself.
/// They were reaching the page unchanged, where they tell a customer nothing.
fn plain_direction(direction: &str) -> String {
    match direction {
        "downstream" => "To your payment provider".to_owned(),
        "upstream" => "To UsageKit Cloud".to_owned(),
        other => other.to_owned(),
    }
}

impl From<crate::export::DeadLetterView> for DeadLetterLine {
    fn from(row: crate::export::DeadLetterView) -> Self {
        Self {
            identifier: row.identifier,
            customer: row.customer_id,
            meter: row.meter,
            units: thousands(row.units),
            when: minute(row.recorded_at),
            direction: plain_direction(&row.direction),
            reason: row.reason,
        }
    }
}

struct TokenLine {
    digest: String,
    digest_short: String,
    scope: String,
    label: String,
    created: String,
    revoked: bool,
}

impl From<crate::tokens::TokenRow> for TokenLine {
    fn from(row: crate::tokens::TokenRow) -> Self {
        Self {
            // The digest is the revocation handle and is safe to show: it is
            // what the database stores, and the credential cannot be recovered
            // from it.
            digest_short: row.token_sha256.chars().take(12).collect(),
            digest: row.token_sha256,
            scope: row.scope,
            label: row.label,
            created: day(row.created_at),
            revoked: row.revoked_at.is_some(),
        }
    }
}

#[derive(Template)]
#[template(path = "app.html")]
struct AppTemplate {
    shell: Shell,
    account_name: String,
    user_email: String,
    notice: Option<&'static str>,
    notice_kind: &'static str,
    summary: Summary,
    terms: Terms,
    destination_kind: String,
    destination_secret: &'static str,
    usage: Vec<UsageLine>,
    quota: Vec<QuotaLine>,
    invoices: Vec<InvoiceLine>,
    tenants: Vec<TenantLine>,
    dead_letters: Vec<DeadLetterLine>,
    tokens: Vec<TokenLine>,
}

#[derive(Template)]
#[template(path = "signin.html")]
struct SignInTemplate {
    shell: Shell,
    notice: Option<&'static str>,
    notice_kind: &'static str,
}

#[derive(Template)]
#[template(path = "signin_code.html")]
struct SignInCodeTemplate {
    shell: Shell,
    email: String,
    development_code: Option<String>,
    notice: Option<&'static str>,
    notice_kind: &'static str,
}

#[derive(Template)]
#[template(path = "secret.html")]
struct SecretTemplate {
    shell: Shell,
    account_name: String,
    user_email: String,
    eyebrow: &'static str,
    label: String,
    secret: String,
    explanation: &'static str,
}

/// Dashboard and sign-in routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/app", routing::get(dashboard))
        .route("/signin", routing::get(sign_in_page).post(sign_in_start))
        .route("/signin/verify", routing::post(sign_in_finish))
        .route("/signout", routing::post(sign_out))
        .route("/app/tokens", routing::post(mint_token))
        .route("/app/tokens/{digest}/revoke", routing::post(revoke_token))
        .route("/app/tenants/{tenant_key}/keys", routing::post(mint_key))
        .route(
            "/app/dead-letters/{identifier}/resolve",
            routing::post(resolve_dead_letter),
        )
}

// ------------------------------------------------------------- redirects

fn redirect(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

/// Send the caller back to the dashboard with an outcome code.
fn back(outcome: &str) -> Response {
    redirect(&format!("/app?done={outcome}"))
}

/// What the dashboard is saying about the last action.
#[derive(Debug, Deserialize)]
pub struct AppQuery {
    /// An outcome code, never a message. See [`notice_for`].
    done: Option<String>,
}

/// Map an outcome code to fixed copy.
///
/// Same reasoning as the landing page: a query parameter rendered into the
/// page lets anyone put words in our mouth on our own domain, and the fact
/// that they would be escaped does not make them less convincing.
fn notice_for(query: &AppQuery) -> (Option<&'static str>, &'static str) {
    let message = match query.done.as_deref() {
        Some("revoked") => {
            "That key no longer works. Anything still using it will start failing within ten seconds."
        }
        Some("resolved") => {
            "Marked as handled and cleared from the list. Nothing was resent: this only records that somebody dealt with it."
        }
        Some("last-admin") => {
            "That is your last working admin key. Create a replacement before revoking it, or you will lock yourself out of your own API."
        }
        Some("missing") => "That is no longer there. It may already have been revoked or handled.",
        Some("failed") => "That did not work, and nothing was changed.",
        _ => return (None, ""),
    };
    let kind = if matches!(query.done.as_deref(), Some("revoked" | "resolved")) {
        "notice-ok"
    } else {
        "notice-bad"
    };
    (Some(message), kind)
}

/// Turn a failed mutation into an outcome the dashboard can explain.
fn outcome_of(error: &ApiError) -> &'static str {
    match error {
        ApiError::NotFound => "missing",
        ApiError::Conflict(_) => "last-admin",
        _ => "failed",
    }
}

// -------------------------------------------------------------- dashboard

async fn dashboard(
    user: Option<CurrentUser>,
    State(state): State<AppState>,
    Query(query): Query<AppQuery>,
) -> ApiResult<Response> {
    // The gate. A handler that reaches past this point has a live session, and
    // one that does not renders a redirect rather than the page.
    let Some(user) = user else {
        return Ok(redirect("/signin"));
    };

    let account_name = account_name(&state, &user.account_id).await?;
    let (notice, notice_kind) = notice_for(&query);

    let since = Utc::now() - Duration::days(WINDOW_DAYS);
    let rollup_query = crate::usage::RollupQuery {
        from: Some(since),
        to: None,
        customer_id: None,
        bucket: Some("day".to_owned()),
        limit: Some(MAX_USAGE_ROWS),
    };

    // Each of these is the function the matching JSON route calls.
    let rollup = crate::usage::rollup_rows(&state, &user.account_id, &rollup_query).await?;
    let quota = crate::usage::quota_rows(&state, &user.account_id).await?;
    let invoices = crate::pricing::invoice_rows(&state, &user.account_id).await?;
    let pricing = crate::pricing::read_terms(&state, &user.account_id).await?;
    let tenants = crate::tenants::list_all(&state, &user.account_id).await?;
    let destination = crate::export::destination_view(&state, &user.account_id).await?;
    let dead_letters = crate::export::dead_letter_rows(&state, &user.account_id).await?;
    let tokens = crate::tokens::list_all(&state, &user.account_id).await?;

    let units_30d: i64 = rollup.iter().map(|row| row.units).sum();

    let page = AppTemplate {
        shell: Shell::private(
            &state,
            "/app",
            "Dashboard",
            "Usage, limits, bills and API keys for your UsageKit Cloud account.",
        ),
        account_name: account_name.clone(),
        user_email: user.email.clone(),
        notice,
        notice_kind,
        summary: Summary {
            units_30d: thousands(units_30d),
            tenants: tenants.len(),
            pending: destination.pending,
            dead_lettered: destination.dead_lettered,
        },
        terms: Terms {
            summary: describe_terms(&pricing),
        },
        destination_kind: destination.kind.clone(),
        destination_secret: if destination.has_secret {
            "A credential is stored, sealed at rest. It cannot be read back."
        } else {
            "No credential stored, so nothing is being forwarded."
        },
        usage: rollup.into_iter().map(UsageLine::from).collect(),
        quota: quota.into_iter().map(QuotaLine::from).collect(),
        invoices: invoices.into_iter().map(InvoiceLine::from).collect(),
        tenants: tenants.into_iter().map(TenantLine::from).collect(),
        dead_letters: dead_letters.into_iter().map(DeadLetterLine::from).collect(),
        tokens: tokens.into_iter().map(TokenLine::from).collect(),
    };

    Ok(render(&page, StatusCode::OK))
}

async fn account_name(state: &AppState, account_id: &str) -> ApiResult<String> {
    let row = sqlx::query("SELECT name FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_optional(&state.pool)
        .await?;
    Ok(row
        .map(|row| row.try_get::<String, _>("name"))
        .transpose()?
        .unwrap_or_else(|| account_id.to_owned()))
}

/// Say what an account is charged, in the words the pricing page uses.
fn describe_terms(pricing: &crate::pricing::Pricing) -> String {
    if pricing.per_event_micros == 0 && pricing.rate_bps == 0 && pricing.floor_micros == 0 {
        return "No prices are set on this account, so nothing is being charged. That is not \
                the same as being on a free plan: an account with no prices is skipped by the \
                monthly billing run entirely."
            .to_owned();
    }

    let mut parts = Vec::new();
    if pricing.per_event_micros > 0 {
        // Quoted per ten thousand because that is how it is published, and a
        // price a customer cannot match to the pricing page invites a ticket.
        parts.push(format!(
            "{} per 10,000 billable events",
            money(pricing.per_event_micros.saturating_mul(10_000))
        ));
    }
    if pricing.included_units > 0 {
        parts.push(format!(
            "with the first {} each month included",
            thousands(pricing.included_units)
        ));
    }
    if pricing.rate_bps > 0 {
        parts.push(format!(
            "plus {}% of what you bill your own customers",
            f64::from(pricing.rate_bps) / 100.0
        ));
    }
    if pricing.floor_micros > 0 {
        parts.push(format!(
            "with a monthly minimum of {}",
            money(pricing.floor_micros)
        ));
    }
    format!("You are charged {}.", parts.join(", "))
}

// ---------------------------------------------------------------- sign in

/// A sign-in form submission.
#[derive(Debug, Deserialize)]
pub struct SignInForm {
    /// The address to send a code to.
    pub email: String,
}

/// A code submission.
#[derive(Debug, Deserialize)]
pub struct VerifyForm {
    /// The address the code was sent to.
    pub email: String,
    /// The six digits.
    pub code: String,
}

fn sign_in_shell(state: &AppState) -> Shell {
    Shell::private(
        state,
        "/signin",
        "Sign in",
        "Sign in to your UsageKit Cloud account with a code we email you.",
    )
}

async fn sign_in_page(user: Option<CurrentUser>, State(state): State<AppState>) -> Response {
    // Already signed in: send them where they were going rather than asking
    // for a code they do not need.
    if user.is_some() {
        return redirect("/app");
    }
    render(
        &SignInTemplate {
            shell: sign_in_shell(&state),
            notice: None,
            notice_kind: "",
        },
        StatusCode::OK,
    )
}

async fn sign_in_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<SignInForm>,
) -> ApiResult<Response> {
    let email = body.email.trim().to_owned();

    match people::issue_code(&state, &headers, &email).await {
        Ok(development_code) => Ok(render(
            &SignInCodeTemplate {
                shell: sign_in_shell(&state),
                email,
                development_code,
                notice: None,
                notice_kind: "",
            },
            StatusCode::OK,
        )),
        // The address being unusable is the visitor's to fix and is safe to
        // say. Everything else is answered without distinguishing whether the
        // address exists, which is the property `issue_code` is built around.
        Err(ApiError::BadRequest(_)) => Ok(render(
            &SignInTemplate {
                shell: sign_in_shell(&state),
                notice: Some("That email address does not look valid. Please check it."),
                notice_kind: "notice-bad",
            },
            StatusCode::BAD_REQUEST,
        )),
        Err(ApiError::TooManyRequests(_)) => Ok(render(
            &SignInTemplate {
                shell: sign_in_shell(&state),
                notice: Some(
                    "That is more sign-in attempts than we accept in one go. \
                     Please wait a minute and try again.",
                ),
                notice_kind: "notice-bad",
            },
            StatusCode::TOO_MANY_REQUESTS,
        )),
        Err(error) => Err(error),
    }
}

async fn sign_in_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<VerifyForm>,
) -> ApiResult<Response> {
    let email = body.email.trim().to_owned();

    match people::redeem_code(&state, &headers, &email, &body.code).await {
        Ok(token) => {
            let mut response = redirect("/app");
            response.headers_mut().insert(
                header::SET_COOKIE,
                people::session_cookie_for(&state, &token),
            );
            Ok(response)
        }
        // Wrong, expired and already spent are one answer, because telling
        // them apart is telling an attacker which guess to keep.
        Err(ApiError::Unauthorized | ApiError::BadRequest(_)) => Ok(render(
            &SignInCodeTemplate {
                shell: sign_in_shell(&state),
                email,
                development_code: None,
                notice: Some(
                    "That code is not right, or it has expired. \
                     Ask for another and try again.",
                ),
                notice_kind: "notice-bad",
            },
            StatusCode::UNAUTHORIZED,
        )),
        Err(error) => Err(error),
    }
}

async fn sign_out(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    // Not behind `CurrentUser`: signing out with an already invalid session
    // should clear the cookie rather than answer 401. The origin check still
    // applies, so this cannot be triggered from somewhere else as a nuisance.
    if !people::origin_is_trusted(&headers, state.public_url.as_deref()) {
        return Err(ApiError::Forbidden);
    }
    people::end_session(&state, &headers).await?;
    let mut response = redirect("/");
    response
        .headers_mut()
        .insert(header::SET_COOKIE, people::session_clear_cookie());
    Ok(response)
}

// --------------------------------------------------------------- actions

/// Check that a mutation came from our own page.
///
/// Every handler below calls this first. The cookie is `SameSite=Lax`, so it
/// does not ride along on a cross-site POST in a current browser; this is the
/// second lock, and it fails closed on a missing header.
fn guard(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if people::origin_is_trusted(headers, state.public_url.as_deref()) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// A token being minted from the dashboard.
#[derive(Debug, Deserialize)]
pub struct MintTokenForm {
    /// `admin` or `edge`.
    pub scope: String,
    /// Where this credential will be used.
    pub label: Option<String>,
}

fn secret_page(
    state: &AppState,
    user: &CurrentUser,
    account_name: String,
    eyebrow: &'static str,
    explanation: &'static str,
    label: String,
    secret: String,
) -> Response {
    render(
        &SecretTemplate {
            shell: Shell::private(state, "/app", "New API key", "A newly created API key."),
            account_name,
            user_email: user.email.clone(),
            eyebrow,
            label,
            secret,
            explanation,
        },
        StatusCode::OK,
    )
}

async fn mint_token(
    user: CurrentUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<MintTokenForm>,
) -> ApiResult<Response> {
    guard(&state, &headers)?;
    let label = body.label.filter(|value| !value.trim().is_empty());

    match crate::tokens::mint_for(&state, &user.account_id, &body.scope, label).await {
        // Rendered rather than redirected, deliberately. A redirect would have
        // to carry the credential in a query string, which puts it in browser
        // history, in any proxy log, and in the referrer of the next request.
        Ok(minted) => {
            let name = account_name(&state, &user.account_id).await?;
            Ok(secret_page(
                &state,
                &user,
                name,
                "Your new API key",
                "This key works now. Put it in the settings of whatever is going to use it.",
                format!("{} key, labelled {}", minted.scope, minted.label),
                minted.token,
            ))
        }
        Err(error) => Ok(back(outcome_of(&error))),
    }
}

async fn revoke_token(
    user: CurrentUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(digest): Path<String>,
) -> ApiResult<Response> {
    guard(&state, &headers)?;
    Ok(
        match crate::tokens::revoke_for(&state, &user.account_id, &digest).await {
            Ok(()) => back("revoked"),
            Err(error) => back(outcome_of(&error)),
        },
    )
}

async fn mint_key(
    user: CurrentUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tenant_key): Path<String>,
) -> ApiResult<Response> {
    guard(&state, &headers)?;

    match crate::tenants::mint_key_for(
        &state,
        &user.account_id,
        &tenant_key,
        "dashboard".to_owned(),
    )
    .await
    {
        Ok(minted) => {
            let name = account_name(&state, &user.account_id).await?;
            Ok(secret_page(
                &state,
                &user,
                name,
                "New customer API key",
                "Give this to the server handling that customer's traffic. It identifies their \
                 calls and does nothing else.",
                format!("API key for {tenant_key}"),
                minted.api_key,
            ))
        }
        Err(error) => Ok(back(outcome_of(&error))),
    }
}

async fn resolve_dead_letter(
    user: CurrentUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(identifier): Path<String>,
) -> ApiResult<Response> {
    guard(&state, &headers)?;
    Ok(
        match crate::export::resolve_for(&state, &user.account_id, &identifier).await {
            Ok(()) => back("resolved"),
            Err(error) => back(outcome_of(&error)),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_are_grouped_and_money_is_never_a_float() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(thousands(-1_234), "-1,234");

        assert_eq!(money(0), "$0.00");
        assert_eq!(money(500_000), "$0.50");
        assert_eq!(money(10_000_000), "$10.00");
        assert_eq!(money(47_500_000), "$47.50");
        assert_eq!(money(1_234_560_000), "$1,234.56");
        // A fraction of a cent rounds the way the invoice rounds it, not the
        // way a display-only rule would.
        assert_eq!(money(5_000), "$0.01");
        assert_eq!(money(4_999), "$0.00");
    }

    #[test]
    fn the_published_price_reads_back_as_the_published_price() {
        // 50 micros an event is $0.50 per 10,000. If this ever stops matching
        // the pricing page, one of the two is lying to a customer.
        let pricing = crate::pricing::Pricing {
            rate_bps: 0,
            floor_micros: 0,
            per_event_micros: 50,
            included_units: 50_000,
            starts_at: Utc::now(),
            ends_at: None,
        };
        let described = describe_terms(&pricing);
        assert!(
            described.contains("$0.50 per 10,000 billable events"),
            "{described}"
        );
        assert!(described.contains("first 50,000"), "{described}");
    }

    #[test]
    fn an_account_with_no_terms_is_told_so_rather_than_shown_zero() {
        let pricing = crate::pricing::Pricing {
            rate_bps: 0,
            floor_micros: 0,
            per_event_micros: 0,
            included_units: 0,
            starts_at: Utc::now(),
            ends_at: None,
        };
        assert!(describe_terms(&pricing).contains("No prices are set"));
    }

    #[test]
    fn only_known_outcome_codes_produce_a_message() {
        let query = |done: Option<&str>| AppQuery {
            done: done.map(str::to_owned),
        };
        assert_eq!(notice_for(&query(Some("revoked"))).1, "notice-ok");
        assert_eq!(notice_for(&query(Some("last-admin"))).1, "notice-bad");
        // Anything a visitor puts there themselves shows nothing at all.
        for attempt in [
            "unknown",
            "<script>alert(1)</script>",
            "Call 1-800-555-0123",
        ] {
            assert!(notice_for(&query(Some(attempt))).0.is_none(), "{attempt}");
        }
        assert!(notice_for(&query(None)).0.is_none());
    }

    #[test]
    fn library_variant_names_do_not_reach_the_page() {
        // `QuotaExceeded` was rendering on the dashboard exactly like that.
        assert_eq!(
            plain_reason(Some("QuotaExceeded")),
            "Over their usage limit"
        );
        assert_eq!(
            plain_reason(Some("SpendCapExceeded")),
            "Over their spending limit"
        );
        assert_eq!(plain_direction("downstream"), "To your payment provider");
        assert_eq!(plain_direction("upstream"), "To UsageKit Cloud");

        // A value this does not recognise is shown as it is rather than
        // swallowed: a blank cell where a reason should be is worse than an
        // ugly one, because it looks like there was no reason.
        assert_eq!(plain_reason(None), "");
        assert_eq!(plain_reason(Some("SomethingNew")), "SomethingNew");
        assert_eq!(plain_direction("sideways"), "sideways");
    }

    #[test]
    fn an_absent_cap_reads_as_unbounded_rather_than_as_nothing() {
        assert_eq!(cap(None, thousands), "Unbounded");
        assert_eq!(cap(Some(10_000), thousands), "10,000");
        assert_eq!(cap(Some(5_000_000), money), "$5.00");
    }

    #[test]
    fn an_unbounded_customer_is_not_shown_as_over_a_cap_of_zero() {
        // "1,234 of 0" reads as a customer who has blown through their limit,
        // which is the opposite of what no limit means.
        assert_eq!(against_limit(1_234, None, thousands), "1,234");
        assert_eq!(
            against_limit(1_234, Some(10_000), thousands),
            "1,234 of 10,000"
        );
    }
}
