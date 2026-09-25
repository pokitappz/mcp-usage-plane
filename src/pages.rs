//! The public site: what a visitor reads before they have an account.
//!
//! Server rendered with compile-time templates, so a typo in a page is a build
//! failure rather than a 500 in front of the person deciding whether to trust
//! this service. There is no client side framework, no build step, and no
//! JavaScript: every page here works with scripting disabled, which is also why
//! the access form is a real `POST` rather than a `fetch`.
//!
//! # These pages do not vary by caller
//!
//! Deliberately. They are served `public, must-revalidate` with an `ETag`, and a
//! page whose masthead changed for a signed-in visitor would be a page a shared
//! cache could hand to the next anonymous one. The navigation therefore links
//! to the dashboard unconditionally and lets [`crate::people`] decide who may
//! see it, which is the only place that decision belongs anyway.

use askama::Template;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::AppState;
use crate::auth::hash_token;
use crate::error::{ApiError, ApiResult};
use crate::people::{normalize_email, origin_is_trusted};

/// Where the site lives when `APP_PUBLIC_URL` is unset.
///
/// Only reachable in development: `public_url_from_env` refuses to start with a
/// value that is neither https nor loopback.
const DEV_BASE_URL: &str = "http://localhost:8081";

/// Access requests accepted per window, across the process.
///
/// Fixed key, like the provisioning route: keying this on the submitted address
/// would give every made-up address its own fresh allowance, which bounds a
/// person retrying and does nothing at all about a script working through a
/// list. Every accepted request sends mail, so the budget is what stops the
/// form being used as a mail cannon.
const ACCESS_BURST: u32 = 30;
/// The key access requests are counted against. See [`ACCESS_BURST`].
const ACCESS_SUBJECT: &str = "any";

/// Longest company name and note accepted, matching the column widths.
const MAX_COMPANY: usize = 200;
const MAX_NOTE: usize = 2000;
/// Ceiling on the forecast, so a typo cannot store an absurd number.
const MAX_EXPECTED_EVENTS: i64 = 1_000_000_000_000;

/// Everything the shared page shell needs.
///
/// Nested on each page struct rather than flattened into it, so adding a head
/// element changes one struct instead of every one.
pub struct Shell {
    /// Contents of `<title>`.
    pub title: String,
    /// Meta description.
    pub description: &'static str,
    /// Absolute canonical URL.
    pub canonical: String,
    /// Robots directive.
    pub robots: &'static str,
    /// Path of the current page, for `aria-current` in the navigation.
    pub nav: &'static str,
    /// What this deployment calls itself, for the wordmark.
    pub product: crate::Branding,
}

impl Shell {
    /// A public, indexable page.
    pub fn new(
        state: &AppState,
        path: &'static str,
        title: &str,
        description: &'static str,
    ) -> Self {
        let base = state.public_url.as_deref().unwrap_or(DEV_BASE_URL);
        Self {
            title: format!("{title} | {}", state.product.full()),
            description,
            canonical: format!("{base}{path}"),
            robots: "index,follow",
            nav: path,
            product: state.product.clone(),
        }
    }

    /// A page behind a session.
    ///
    /// `noindex, nofollow` in the markup as well as the header, because the two
    /// are read by different things and a dashboard should be absent from a
    /// search index whichever one is consulted. The middleware also serves
    /// these `no-store`.
    pub fn private(
        state: &AppState,
        path: &'static str,
        title: &str,
        description: &'static str,
    ) -> Self {
        Self {
            robots: "noindex,nofollow",
            ..Self::new(state, path, title, description)
        }
    }
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate {
    shell: Shell,
    notice: Option<&'static str>,
    notice_kind: &'static str,
}

#[derive(Template)]
#[template(path = "pricing.html")]
struct PricingTemplate {
    shell: Shell,
}

#[derive(Template)]
#[template(path = "security.html")]
struct SecurityTemplate {
    shell: Shell,
}

#[derive(Template)]
#[template(path = "docs.html")]
struct DocsTemplate {
    shell: Shell,
}

#[derive(Template)]
#[template(path = "message.html")]
struct MessageTemplate {
    shell: Shell,
    eyebrow: &'static str,
    heading: &'static str,
    message: &'static str,
}

/// Public routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", routing::get(home))
        .route("/pricing", routing::get(pricing))
        .route("/security", routing::get(security))
        .route("/docs", routing::get(docs))
        .route("/request-access", routing::post(request_access))
}

/// Render a template, or say so plainly if it cannot be rendered.
///
/// The `ETag` is the digest of the body, so it is correct by construction: a
/// page that renders the same bytes keeps its tag whatever else changed, and a
/// page whose content moved gets a new one without anyone remembering to bump
/// a version.
pub fn render<T: Template>(template: &T, status: StatusCode) -> Response {
    match template.render() {
        Ok(body) => {
            let etag = format!("\"{}\"", hex_digest(&body));
            let mut response = (
                status,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                body,
            )
                .into_response();
            let headers = response.headers_mut();
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=0, must-revalidate"),
            );
            if let Ok(value) = HeaderValue::from_str(&etag) {
                headers.insert(header::ETAG, value);
            }
            response
        }
        Err(error) => {
            // A compile-time template that fails at runtime means a value it
            // formats misbehaved, which is a bug here rather than a bad
            // request. Saying so in plain text beats a blank page.
            tracing::error!(%error, "page render failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "This page could not be rendered.",
            )
                .into_response()
        }
    }
}

fn hex_digest(body: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(body.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

// ----------------------------------------------------------------- pages

/// Why the home page is showing a message.
///
/// The outcome of a submission arrives as a code in the query string and is
/// mapped to a fixed message here. Nothing the visitor typed is reflected back
/// into the page: a query parameter rendered into HTML is the oldest way to
/// turn a marketing page into a phishing host, and the escaping that would
/// make it safe is not a thing to rely on when a lookup table costs nothing.
#[derive(Debug, Deserialize)]
pub struct HomeQuery {
    /// Set when a request was accepted.
    requested: Option<String>,
    /// Set when it was not, carrying a code rather than a message.
    error: Option<String>,
}

fn notice_for(query: &HomeQuery) -> (Option<&'static str>, &'static str) {
    if query.requested.is_some() {
        return (
            Some(
                "Thank you. Your request is recorded and a person will read it. \
                 Expect a reply to the address you gave.",
            ),
            "notice-ok",
        );
    }
    let message = match query.error.as_deref() {
        Some("email") => "That email address does not look valid. Please check it and try again.",
        Some("throttled") => {
            "That is more requests than we accept in one go. Please wait a minute and try again."
        }
        Some("internal") => {
            "Something on our side failed to save that. Please try again, or email \
             support@pokitapps.com directly."
        }
        _ => return (None, ""),
    };
    (Some(message), "notice-bad")
}

async fn home(State(state): State<AppState>, Query(query): Query<HomeQuery>) -> Response {
    let (notice, notice_kind) = notice_for(&query);
    render(
        &HomeTemplate {
            shell: Shell::new(
                &state,
                "/",
                "Usage billing for MCP servers",
                "Bill your MCP customers for what they actually received, not for every HTTP \
                 request. Usage records, automatic charging and a monthly billing run, on your \
                 own infrastructure.",
            ),
            notice,
            notice_kind,
        },
        StatusCode::OK,
    )
}

async fn pricing(State(state): State<AppState>) -> Response {
    render(
        &PricingTemplate {
            shell: Shell::new(
                &state,
                "/pricing",
                "Pricing",
                "$299 a month per production deployment, flat. Free to read, build and run \
                 outside production. Every version becomes Apache-2.0 four years after it ships.",
            ),
        },
        StatusCode::OK,
    )
}

async fn security(State(state): State<AppState>) -> Response {
    render(
        &SecurityTemplate {
            shell: Shell::new(
                &state,
                "/security",
                "Security",
                "What this software stores about your customers, how your payment keys are \
                 encrypted, the limits on every request, and what it does not do yet. It runs on \
                 your infrastructure, so none of it reaches us.",
            ),
        },
        StatusCode::OK,
    )
}

async fn docs(State(state): State<AppState>) -> Response {
    render(
        &DocsTemplate {
            shell: Shell::new(
                &state,
                "/docs",
                "Docs",
                "How to measure usage in an MCP server with the open source UsageKit crates, \
                 and how to connect it to a control plane you run yourself.",
            ),
        },
        StatusCode::OK,
    )
}

/// Anything with no route.
///
/// A bare framework 404 on a public domain reads as a broken deployment, which
/// is the wrong thing to tell someone evaluating whether to trust the service.
pub async fn not_found(State(state): State<AppState>) -> Response {
    let mut shell = Shell::new(
        &state,
        "/",
        "Page not found",
        "That page does not exist on UsageKit Cloud.",
    );
    shell.robots = "noindex,follow";
    render(
        &MessageTemplate {
            shell,
            eyebrow: "404",
            heading: "There is nothing at that address.",
            message: "The link may be out of date, or the page may have moved. \
                      Everything that does exist is linked below.",
        },
        StatusCode::NOT_FOUND,
    )
}

// -------------------------------------------------------- request access

/// The access form.
///
/// Every field but the address is optional, because a form that demands a
/// company name before it will talk to you filters for patience rather than
/// for fit.
#[derive(Debug, Deserialize)]
pub struct AccessRequest {
    /// Where to reply.
    pub email: String,
    /// Who they work for.
    pub company: Option<String>,
    /// Rough monthly metered events, as typed.
    pub expected_events: Option<String>,
    /// Anything they wanted to say.
    pub note: Option<String>,
}

/// Trim, bound, and drop to `None` when nothing is left.
fn optional_text(raw: Option<String>, max: usize) -> Option<String> {
    raw.map(|value| value.trim().chars().take(max).collect::<String>())
        .filter(|value| !value.is_empty())
}

/// Parse the forecast, treating nonsense as absent rather than as an error.
///
/// It is an optional hint on an optional field. Refusing the whole submission
/// because someone typed "about 50k" would lose a lead to a validation rule
/// that protects nothing.
fn optional_count(raw: Option<String>) -> Option<i64> {
    raw?.trim()
        .replace([',', '_', ' '], "")
        .parse::<i64>()
        .ok()
        .filter(|value| (0..=MAX_EXPECTED_EVENTS).contains(value))
}

fn redirect_home(outcome: &str) -> Response {
    let location = format!("/?{outcome}#buy");
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

async fn request_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<AccessRequest>,
) -> ApiResult<Response> {
    // Fails closed on a missing Origin, like every other state-changing human
    // route here. A browser posting this form from our own page always sends
    // one, so refusing is not a real-visitor path.
    if !origin_is_trusted(&headers, state.public_url.as_deref()) {
        return Err(ApiError::Forbidden);
    }

    // Taken before anything else is done with the body, and explicitly:
    // nothing upstream takes a budget for a route with no bearer extractor.
    if !state
        .admission
        .take_named("access", ACCESS_SUBJECT, ACCESS_BURST)
    {
        return Ok(redirect_home("error=throttled"));
    }

    let Ok(email) = normalize_email(&body.email) else {
        return Ok(redirect_home("error=email"));
    };
    let company = optional_text(body.company, MAX_COMPANY);
    let note = optional_text(body.note, MAX_NOTE);
    let expected_events = optional_count(body.expected_events);

    // The row is written first and mail is best effort on top. A mail service
    // that is down must not lose the lead: the request is still in the queue an
    // operator reads, which is the thing that actually grants access.
    let inserted = sqlx::query(
        "INSERT INTO access_requests (email, company, expected_events, note)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&email)
    .bind(&company)
    .bind(expected_events)
    .bind(&note)
    .execute(&state.pool)
    .await;

    if let Err(error) = inserted {
        tracing::error!(%error, "could not record an access request");
        return Ok(redirect_home("error=internal"));
    }

    tracing::info!(
        // The address is hashed rather than logged: this is an unauthenticated
        // form, so anything typed into it ends up in log storage and in
        // whatever reads it. The digest is enough to tell repeat submissions
        // apart without keeping the address twice.
        email = hash_token(&email),
        has_company = company.is_some(),
        expected_events,
        "access requested"
    );

    if let Some(client) = state.email.as_ref()
        && let Err(error) = client
            .send_access_request(&email, company.as_deref(), expected_events, note.as_deref())
            .await
    {
        tracing::error!(%error, "access request recorded but the notification failed");
    }

    Ok(redirect_home("requested=1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_outcome_codes_produce_a_message() {
        let query = |requested: Option<&str>, error: Option<&str>| HomeQuery {
            requested: requested.map(str::to_owned),
            error: error.map(str::to_owned),
        };

        let (notice, kind) = notice_for(&query(Some("1"), None));
        assert!(notice.is_some());
        assert_eq!(kind, "notice-ok");

        let (notice, kind) = notice_for(&query(None, Some("email")));
        assert!(notice.is_some());
        assert_eq!(kind, "notice-bad");

        // An unknown code, and anything a visitor puts there themselves, shows
        // nothing at all rather than being rendered into the page.
        for attempt in [
            "unknown",
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
        ] {
            let (notice, _) = notice_for(&query(None, Some(attempt)));
            assert!(notice.is_none(), "{attempt} produced a message");
        }
        assert!(notice_for(&query(None, None)).0.is_none());
    }

    #[test]
    fn optional_fields_are_trimmed_bounded_and_emptied() {
        assert_eq!(
            optional_text(Some("  Acme  ".to_owned()), MAX_COMPANY).as_deref(),
            Some("Acme")
        );
        assert_eq!(optional_text(Some("   ".to_owned()), MAX_COMPANY), None);
        assert_eq!(optional_text(None, MAX_COMPANY), None);

        // Bounded by characters rather than bytes, so a multi-byte name cannot
        // be cut mid-character into something that is not valid UTF-8.
        let long = optional_text(Some("é".repeat(500)), MAX_COMPANY).expect("a value");
        assert_eq!(long.chars().count(), MAX_COMPANY);
    }

    #[test]
    fn a_forecast_that_is_not_a_number_is_absent_rather_than_an_error() {
        assert_eq!(optional_count(Some("50000".to_owned())), Some(50_000));
        assert_eq!(
            optional_count(Some(" 1,250,000 ".to_owned())),
            Some(1_250_000)
        );
        for attempt in ["about 50k", "", "-1", "99999999999999999999"] {
            assert_eq!(
                optional_count(Some(attempt.to_owned())),
                None,
                "{attempt} parsed"
            );
        }
        assert_eq!(optional_count(None), None);
    }

    #[test]
    fn the_etag_follows_the_body() {
        assert_eq!(hex_digest("same"), hex_digest("same"));
        assert_ne!(hex_digest("one"), hex_digest("two"));
        assert_eq!(hex_digest("").len(), 64);
    }
}
