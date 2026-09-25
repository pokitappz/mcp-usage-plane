//! The dashboard, signed in, against a real database and the real binary.
//!
//! The property worth defending here is that the page is gated by the server
//! rather than by the browser. A dashboard that ships its markup to anyone and
//! redirects in JavaScript has leaked its structure, its panel names and its
//! routes to anyone who reads the response, and it is one broken script away
//! from leaking the rest. Several of these tests exist only to make that
//! failure loud.
//!
//! The second property is that the figures on the page are the figures the API
//! returns. They come from the same functions, and the test below proves it by
//! reading both and comparing, so a future refactor that quietly forks the two
//! fails here rather than in a customer's monthly reconciliation.

mod common;

use common::Plane;

/// Strings that appear on the dashboard and nowhere a stranger can reach.
///
/// The gating test asserts these are **absent** for an anonymous caller, which
/// is only worth something while they are present for a real one. Renaming a
/// panel without updating this list would otherwise turn that test into an
/// assertion about nothing, silently, and it would stay green forever. So the
/// test checks both directions against this one list.
const DASHBOARD_MARKERS: [&str; 3] = [
    "Billable events",
    "API credentials",
    "Usage and spending limits",
];
use serde_json::json;

struct Page {
    status: reqwest::StatusCode,
    headers: reqwest::header::HeaderMap,
    body: String,
}

fn header<'a>(page: &'a Page, name: &str) -> &'a str {
    page.headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

/// A client that does not follow redirects, because the redirect is the result.
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build a client")
}

/// The text inside the first element carrying `class="<class>"`.
///
/// Reading the element beats scanning for a character class: credentials are
/// URL-safe base64 and contain `-` about three times in four, so a scan for
/// alphanumerics truncated the token into something that looked plausible,
/// did not work, and failed only sometimes.
fn text_of(body: &str, class: &str) -> String {
    let marker = format!("class=\"{class}\">");
    let start = body
        .find(&marker)
        .map(|at| at + marker.len())
        .unwrap_or_else(|| panic!("no element with class {class} on the page"));
    let rest = &body[start..];
    let end = rest.find('<').unwrap_or(rest.len());
    rest[..end].trim().to_owned()
}

async fn into_page(response: reqwest::Response) -> Page {
    Page {
        status: response.status(),
        headers: response.headers().clone(),
        body: response.text().await.unwrap_or_default(),
    }
}

async fn get(plane: &Plane, path: &str, cookie: Option<&str>) -> Page {
    let mut request = client().get(plane.url(path));
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    into_page(request.send().await.expect("request reaches the plane")).await
}

async fn post(
    plane: &Plane,
    path: &str,
    cookie: Option<&str>,
    origin: Option<&str>,
    form: &[(&str, &str)],
) -> Page {
    let mut request = client().post(plane.url(path)).form(form);
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    if let Some(origin) = origin {
        request = request.header(reqwest::header::ORIGIN, origin);
    }
    into_page(request.send().await.expect("request reaches the plane")).await
}

/// Create a person on the bootstrap account, the way an operator does by hand.
async fn invite(plane: &Plane, email: &str) {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&plane.db_url)
        .await
        .expect("connect to the scratch database");
    let user_id = format!("usr_{}", email.replace(['@', '.'], "_"));
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
        .bind(&user_id)
        .bind(email)
        .execute(&pool)
        .await
        .expect("insert the user");
    sqlx::query("INSERT INTO memberships (user_id, account_id) VALUES ($1, $2)")
        .bind(&user_id)
        .bind(common::ACCOUNT)
        .execute(&pool)
        .await
        .expect("insert the membership");
    pool.close().await;
}

/// Sign in through the browser forms, not the JSON API.
///
/// Deliberately the same path a person takes, so a broken form is a failing
/// test rather than something only discovered by opening a browser.
async fn sign_in(plane: &Plane, email: &str) -> String {
    invite(plane, email).await;

    let started = post(
        plane,
        "/signin",
        None,
        Some(&plane.base),
        &[("email", email)],
    )
    .await;
    assert_eq!(started.status, 200, "the sign-in form did not accept it");

    // A debug build with no mail service renders the code on the page, which
    // is what makes this flow testable without a mail service at all.
    let marker = "<strong>";
    let start = started
        .body
        .find(marker)
        .map(|at| at + marker.len())
        .expect("the development code is shown in a debug build");
    let code: String = started.body[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    assert_eq!(code.len(), 6, "expected six digits, got {code:?}");

    let verified = post(
        plane,
        "/signin/verify",
        None,
        Some(&plane.base),
        &[("email", email), ("code", &code)],
    )
    .await;
    assert_eq!(verified.status, 303, "the code was not accepted");

    header(&verified, "set-cookie")
        .split(';')
        .next()
        .expect("a name=value pair")
        .to_owned()
}

// ------------------------------------------------------------------ gating

#[tokio::test]
async fn the_dashboard_is_gated_by_the_server_and_not_by_the_browser() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    // Anonymous: a redirect, and critically no markup. Asserting the body is
    // empty is the point of the test. A client-side gate would return the
    // whole page here and redirect afterwards.
    let anonymous = get(&plane, "/app", None).await;
    assert_eq!(anonymous.status, 303);
    assert_eq!(header(&anonymous, "location"), "/signin");
    for marker in DASHBOARD_MARKERS {
        assert!(
            !anonymous.body.contains(marker),
            "the dashboard markup reached an anonymous caller: found {marker:?}"
        );
    }

    // A bearer token authenticates a machine, not a person. It must not open a
    // browser session, whatever it is allowed to do on the JSON API.
    let with_token = client()
        .get(plane.url("/app"))
        .bearer_auth(common::ADMIN_TOKEN)
        .send()
        .await
        .expect("request reaches the plane");
    let with_token = into_page(with_token).await;
    assert_eq!(
        with_token.status, 303,
        "an admin token opened the dashboard; it is not a person"
    );

    // A cookie that is not a session must not either.
    let forged = get(&plane, "/app", Some("usagekit_session=not-a-real-session")).await;
    assert_eq!(forged.status, 303);
    for marker in DASHBOARD_MARKERS {
        assert!(
            !forged.body.contains(marker),
            "{marker:?} reached a forged cookie"
        );
    }

    // And the other direction, in this same test: the markers have to actually
    // be on the real dashboard. Without this, renaming a panel would turn every
    // assertion above into a statement about a string that no longer exists,
    // and the test would keep passing while testing nothing.
    let cookie = sign_in(&plane, "owner@example.com").await;
    let real = get(&plane, "/app", Some(&cookie)).await;
    assert_eq!(real.status, 200);
    for marker in DASHBOARD_MARKERS {
        assert!(
            real.body.contains(marker),
            "{marker:?} is no longer on the dashboard, so the checks above prove nothing"
        );
    }
}

#[tokio::test]
async fn a_signed_in_person_sees_their_account() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let cookie = sign_in(&plane, "owner@example.com").await;

    let page = get(&plane, "/app", Some(&cookie)).await;
    assert_eq!(page.status, 200);
    assert!(header(&page, "content-type").starts_with("text/html"));

    for panel in [
        "Usage",
        "Usage and spending limits",
        "What you have been charged",
        "Your customers",
        "Where the money goes",
        "API credentials",
    ] {
        assert!(page.body.contains(panel), "the {panel} panel is missing");
    }
    assert!(
        page.body.contains("owner@example.com"),
        "no signed-in identity"
    );

    // Caller-specific, so it must be out of every cache and every index.
    assert_eq!(header(&page, "cache-control"), "no-store");
    assert_eq!(header(&page, "x-robots-tag"), "noindex, nofollow");
    assert!(
        page.body.contains("content=\"noindex,nofollow\""),
        "the markup should say so too, not only the header"
    );
}

// ------------------------------------------------------------- the figures

#[tokio::test]
async fn the_page_shows_the_same_figures_the_api_returns() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_acme").await;

    // Real usage through the real ingest path, so the numbers are produced the
    // way a customer's numbers are produced.
    let (status, _) = plane
        .send(
            reqwest::Method::POST,
            "/v1/edge/usage",
            Some(json!({"events": [
                // Two different days, so the rollup produces two rows rather
                // than one summed one. A same-day pair would still total
                // correctly and would not prove the per-day grain renders.
                {"identifier": "agg-1", "customer_id": "cus_acme", "meter": "calls",
                 "units": 1234, "timestamp": (chrono::Utc::now() - chrono::Duration::days(3)).timestamp()},
                {"identifier": "agg-2", "customer_id": "cus_acme", "meter": "calls",
                 "units": 4321, "timestamp": (chrono::Utc::now() - chrono::Duration::days(1)).timestamp()}
            ]})),
            Some(common::EDGE_TOKEN),
        )
        .await;
    assert_eq!(status, 200, "seeding usage failed");

    let (status, api) = plane
        .admin(reqwest::Method::GET, "/v1/usage?bucket=day", None)
        .await;
    assert_eq!(status, 200);
    let total: i64 = api
        .as_array()
        .expect("an array")
        .iter()
        .map(|row| row["units"].as_i64().unwrap_or_default())
        .sum();
    assert_eq!(total, 5_555, "the API did not report the seeded usage");

    let cookie = sign_in(&plane, "owner@example.com").await;
    let page = get(&plane, "/app", Some(&cookie)).await;

    // The page groups digits, so the figure a person reads is the figure the
    // API reports. If these two ever drift, one of them is wrong in a way that
    // reaches an invoice.
    assert!(
        page.body.contains("5,555"),
        "the dashboard does not show the total the API reports"
    );
    assert!(page.body.contains("1,234") && page.body.contains("4,321"));
    assert!(page.body.contains("cus_acme"), "the customer is missing");
    assert!(page.body.contains("calls"), "the meter is missing");
}

#[tokio::test]
async fn an_empty_account_says_so_rather_than_rendering_blank_tables() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let cookie = sign_in(&plane, "owner@example.com").await;

    let page = get(&plane, "/app", Some(&cookie)).await;
    assert!(page.body.contains("No usage recorded"));
    assert!(page.body.contains("No month has been billed yet"));
    // An account with no terms is told so. Showing "$0.00" would read as free
    // terms, which is a different thing from no terms.
    assert!(
        page.body.contains("No prices are set"),
        "an account with no prices should be told, not shown zero"
    );
}

// ----------------------------------------------------------------- actions

#[tokio::test]
async fn a_minted_token_is_shown_once_and_never_put_in_a_url() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let cookie = sign_in(&plane, "owner@example.com").await;

    let minted = post(
        &plane,
        "/app/tokens",
        Some(&cookie),
        Some(&plane.base),
        &[("scope", "edge"), ("label", "staging sidecar")],
    )
    .await;

    // Rendered, not redirected. A redirect would have to carry the credential
    // in a query string, which puts it in browser history and in every proxy
    // log between here and the customer.
    assert_eq!(
        minted.status, 200,
        "minting should render the secret, not redirect with it"
    );
    assert_eq!(
        header(&minted, "location"),
        "",
        "the credential must never travel in a Location header"
    );

    let token = text_of(&minted.body, "secret-value");
    assert!(token.starts_with("mup_edge_"), "unexpected token: {token}");
    assert!(token.len() > 20, "the token looks truncated: {token}");

    // It authenticates, and it is scoped: an edge credential on an admin route
    // is refused for lacking scope, not for being unrecognised. A 401 here
    // would mean the page showed something that is not the real token.
    let (status, _) = plane
        .send(reqwest::Method::GET, "/v1/tenants", None, Some(&token))
        .await;
    assert_eq!(
        status, 403,
        "the token on the page should authenticate and then be refused for scope"
    );

    // And it is not shown again.
    let page = get(&plane, "/app", Some(&cookie)).await;
    assert!(
        !page.body.contains(&token),
        "the credential is still on the dashboard after being shown once"
    );
    assert!(
        page.body.contains("staging sidecar"),
        "the label should be listed even though the secret is not"
    );
}

#[tokio::test]
async fn the_last_admin_token_cannot_be_revoked_from_the_dashboard_either() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let cookie = sign_in(&plane, "owner@example.com").await;

    let (status, tokens) = plane.admin(reqwest::Method::GET, "/v1/tokens", None).await;
    assert_eq!(status, 200);
    let admin_digest = tokens
        .as_array()
        .expect("an array")
        .iter()
        .find(|row| row["scope"] == "admin")
        .and_then(|row| row["token_sha256"].as_str())
        .expect("an admin token")
        .to_owned();

    let refused = post(
        &plane,
        &format!("/app/tokens/{admin_digest}/revoke"),
        Some(&cookie),
        Some(&plane.base),
        &[],
    )
    .await;
    assert_eq!(refused.status, 303);
    assert_eq!(header(&refused, "location"), "/app?done=last-admin");

    // Still usable, which is the thing the refusal is protecting.
    let (status, _) = plane.admin(reqwest::Method::GET, "/v1/tokens", None).await;
    assert_eq!(status, 200, "the last admin token was revoked anyway");

    let page = get(&plane, "/app?done=last-admin", Some(&cookie)).await;
    assert!(page.body.contains("last working admin key"));
}

#[tokio::test]
async fn a_dead_letter_can_be_resolved_and_leaves_the_queue() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let cookie = sign_in(&plane, "owner@example.com").await;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&plane.db_url)
        .await
        .expect("connect to the scratch database");
    sqlx::query(
        "INSERT INTO export_dead_letters
             (account_id, identifier, customer_id, meter, units, event_at,
              direction, destination, reason)
         VALUES ($1, 'agg-dead', 'cus_acme', 'calls', 42, NOW(),
                 'downstream', 'stripe', 'rejected')",
    )
    .bind(common::ACCOUNT)
    .execute(&pool)
    .await
    .expect("insert a dead letter");
    pool.close().await;

    // A nonzero count is money nobody is being charged for, so it gets its own
    // banner rather than being a number in a corner.
    let page = get(&plane, "/app", Some(&cookie)).await;
    assert!(
        page.body.contains("could not be billed"),
        "no banner for usage that failed to bill"
    );
    assert!(page.body.contains("agg-dead") || page.body.contains("cus_acme"));

    let resolved = post(
        &plane,
        "/app/dead-letters/agg-dead/resolve",
        Some(&cookie),
        Some(&plane.base),
        &[],
    )
    .await;
    assert_eq!(resolved.status, 303);
    assert_eq!(header(&resolved, "location"), "/app?done=resolved");

    let page = get(&plane, "/app", Some(&cookie)).await;
    assert!(
        !page.body.contains("could not be billed"),
        "the banner is still showing after the list was cleared"
    );
    // And the page is honest about what resolving did.
    let after = get(&plane, "/app?done=resolved", Some(&cookie)).await;
    assert!(after.body.contains("Nothing was resent"));
}

// -------------------------------------------------------------------- CSRF

#[tokio::test]
async fn every_action_refuses_a_request_from_somewhere_else() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let cookie = sign_in(&plane, "owner@example.com").await;

    // A live session plus a missing or foreign Origin. The cookie is
    // SameSite=Lax, so this is the second lock rather than the only one, and it
    // fails closed on an absent header.
    for path in [
        "/app/tokens",
        "/app/dead-letters/agg-dead/resolve",
        "/app/tenants/acme/keys",
        "/signout",
    ] {
        let no_origin = post(&plane, path, Some(&cookie), None, &[("scope", "edge")]).await;
        assert_eq!(no_origin.status, 403, "{path} accepted a missing Origin");

        let foreign = post(
            &plane,
            path,
            Some(&cookie),
            Some("https://evil.example"),
            &[("scope", "edge")],
        )
        .await;
        assert_eq!(foreign.status, 403, "{path} accepted a foreign Origin");
    }

    // The session survived all of that.
    assert_eq!(get(&plane, "/app", Some(&cookie)).await.status, 200);
}

#[tokio::test]
async fn an_action_without_a_session_is_refused_whatever_its_origin() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let minted = post(
        &plane,
        "/app/tokens",
        None,
        Some(&plane.base),
        &[("scope", "admin"), ("label", "stolen")],
    )
    .await;
    assert_eq!(
        minted.status, 401,
        "a token was minted with no session at all"
    );

    let (status, tokens) = plane.admin(reqwest::Method::GET, "/v1/tokens", None).await;
    assert_eq!(status, 200);
    assert!(
        !tokens
            .as_array()
            .expect("an array")
            .iter()
            .any(|row| row["label"] == "stolen"),
        "an unauthenticated mint reached the database"
    );
}

// ------------------------------------------------------------- sign in/out

#[tokio::test]
async fn signing_out_ends_the_session_for_the_page_too() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let cookie = sign_in(&plane, "owner@example.com").await;
    assert_eq!(get(&plane, "/app", Some(&cookie)).await.status, 200);

    let out = post(&plane, "/signout", Some(&cookie), Some(&plane.base), &[]).await;
    assert_eq!(out.status, 303);
    assert_eq!(header(&out, "location"), "/");
    assert!(header(&out, "set-cookie").contains("Max-Age=0"));

    // The row is gone, so holding on to the cookie string achieves nothing.
    let after = get(&plane, "/app", Some(&cookie)).await;
    assert_eq!(after.status, 303, "the session outlived the sign out");
}

#[tokio::test]
async fn a_wrong_code_says_one_thing_however_it_was_wrong() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    invite(&plane, "owner@example.com").await;

    let attempt = post(
        &plane,
        "/signin/verify",
        None,
        Some(&plane.base),
        &[("email", "owner@example.com"), ("code", "000000")],
    )
    .await;
    assert_eq!(attempt.status, 401);
    assert!(attempt.body.contains("not right, or it has expired"));

    // An address with no account is answered identically, so the form cannot
    // be used to find out who has one.
    let unknown = post(
        &plane,
        "/signin/verify",
        None,
        Some(&plane.base),
        &[("email", "nobody@example.com"), ("code", "000000")],
    )
    .await;
    assert_eq!(unknown.status, 401);
    assert!(unknown.body.contains("not right, or it has expired"));
}

#[tokio::test]
async fn a_signed_in_person_is_not_asked_to_sign_in_again() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let cookie = sign_in(&plane, "owner@example.com").await;

    let page = get(&plane, "/signin", Some(&cookie)).await;
    assert_eq!(page.status, 303);
    assert_eq!(header(&page, "location"), "/app");
}

// ------------------------------------------------------------- discipline

#[tokio::test]
async fn the_dashboard_uses_the_same_words_the_public_pages_do() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let cookie = sign_in(&plane, "owner@example.com").await;
    let key = plane.seed_tenant("acme", "cus_acme").await;

    // Seed the states that only render when something is wrong, because those
    // are exactly the labels written in a hurry and the ones a customer reads
    // when they are already annoyed.
    //
    // A customer over their limit is one of them. Without pushing one over,
    // the "why is this blocked" cell never renders and the check below would
    // pass without ever looking at it.
    let (status, _) = plane
        .admin(
            reqwest::Method::PATCH,
            "/v1/tenants/acme",
            Some(json!({"max_units": 10})),
        )
        .await;
    assert_eq!(status, 200, "could not set a usage limit");
    let (status, _) = plane
        .send(
            reqwest::Method::POST,
            "/v1/edge/usage",
            Some(json!({"events": [{
                "identifier": "agg-over", "customer_id": "cus_acme", "meter": "calls",
                "units": 50, "timestamp": chrono::Utc::now().timestamp()
            }]})),
            Some(common::EDGE_TOKEN),
        )
        .await;
    assert_eq!(status, 200, "could not push the customer over their limit");
    let _ = &key;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&plane.db_url)
        .await
        .expect("connect to the scratch database");
    sqlx::query(
        "INSERT INTO export_dead_letters
             (account_id, identifier, customer_id, meter, units, event_at,
              direction, destination, reason)
         VALUES ($1, 'agg-dead', 'cus_acme', 'calls', 42, NOW(),
                 'downstream', 'stripe', 'rejected')",
    )
    .bind(common::ACCOUNT)
    .execute(&pool)
    .await
    .expect("insert a dead letter");
    pool.close().await;

    // Same list as the public site keeps, for the same reason: the vocabulary
    // drifts back one sentence at a time and each reintroduction looks
    // harmless on its own.
    let retired = [
        "the plane",
        "sidecar",
        "dead letter",
        "terminal delivery",
        "metered event",
        "hot path",
        "price book",
        "reconcil",
        "admitting",
        // Library variant names and internal direction labels were reaching
        // the page verbatim: a customer was shown "QuotaExceeded".
        "quotaexceeded",
        "spendcapexceeded",
        "downstream",
        "upstream",
    ];

    for (label, path) in [("dashboard", "/app"), ("notice", "/app?done=resolved")] {
        let body = get(&plane, path, Some(&cookie)).await.body.to_lowercase();
        for term in retired {
            assert!(!body.contains(term), "the {label} still says {term:?}");
        }
    }
}

#[tokio::test]
async fn the_dashboard_holds_to_the_same_markup_rules_as_the_public_pages() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let cookie = sign_in(&plane, "owner@example.com").await;
    plane.seed_tenant("acme", "cus_acme").await;

    // Including the minted-secret page, which is the one most likely to be
    // written in a hurry.
    let minted = post(
        &plane,
        "/app/tokens",
        Some(&cookie),
        Some(&plane.base),
        &[("scope", "edge"), ("label", "test")],
    )
    .await;

    let signin = get(&plane, "/signin", None).await;
    let dashboard = get(&plane, "/app", Some(&cookie)).await;

    for (name, page) in [
        ("/app", &dashboard),
        ("/signin", &signin),
        ("the minted secret page", &minted),
    ] {
        let body = &page.body;
        assert!(!body.contains("<script"), "{name} carries a script tag");
        assert!(!body.contains("style=\""), "{name} carries an inline style");
        assert!(!body.contains("<style"), "{name} carries a style element");
        for handler in [
            " onclick=",
            " onload=",
            " onsubmit=",
            " onerror=",
            " onchange=",
        ] {
            assert!(
                !body.contains(handler),
                "{name} carries an{handler}attribute"
            );
        }
        for (character, label) in [('\u{2014}', "em-dash"), ('\u{2013}', "en-dash")] {
            assert!(!body.contains(character), "{name} contains an {label}");
        }
        assert!(
            body.contains("content=\"noindex,nofollow\""),
            "{name} is not marked noindex"
        );
    }
}
