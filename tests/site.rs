//! The public site, exercised over HTTP against the real binary.
//!
//! These assert on what is actually served rather than on what a template
//! renders in isolation, which is the only version that catches a middleware
//! that stopped being applied or a stylesheet the container cannot find.
//!
//! # The discipline tests earn their keep
//!
//! Three of these assert properties of the markup rather than behaviour: no
//! inline script, style or handler; a canonical and a description on every
//! page; no em-dashes. Each one guards something that is easy to break by
//! writing ordinary-looking HTML, and where the breakage is invisible until it
//! matters. An inline `style=` attribute does not look wrong in a diff, and the
//! content security policy this service advertises on its own security page
//! would silently stop applying to it.

mod common;

use common::Plane;

/// Every page a visitor can reach without an account.
const PUBLIC_PAGES: [&str; 4] = ["/", "/pricing", "/security", "/docs"];

struct Page {
    status: reqwest::StatusCode,
    headers: reqwest::header::HeaderMap,
    body: String,
}

async fn get(plane: &Plane, path: &str) -> Page {
    let response = plane
        .http
        .get(plane.url(path))
        .send()
        .await
        .expect("request reaches the plane");
    Page {
        status: response.status(),
        headers: response.headers().clone(),
        body: response.text().await.expect("a body"),
    }
}

fn header<'a>(page: &'a Page, name: &str) -> &'a str {
    page.headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

#[tokio::test]
async fn every_public_page_renders_and_declares_itself() {
    let url = require_db!();
    let plane = Plane::start(&url).await;

    for path in PUBLIC_PAGES {
        let page = get(&plane, path).await;
        assert_eq!(page.status, 200, "{path} did not render");
        assert!(
            header(&page, "content-type").starts_with("text/html"),
            "{path} is not served as HTML"
        );

        for required in [
            "<html lang=\"en\">",
            "<meta name=\"description\"",
            "<link rel=\"canonical\"",
            "<title>",
            "UsageKit",
        ] {
            assert!(page.body.contains(required), "{path} is missing {required}");
        }

        // The canonical has to be absolute and point at this page, not merely
        // be present. A canonical that points everywhere at the home page is
        // the usual way this goes wrong and it is worse than having none.
        let canonical = format!("<link rel=\"canonical\" href=\"{}{path}\">", plane.base);
        assert!(
            page.body.contains(&canonical),
            "{path} does not name itself as canonical; looked for {canonical}"
        );

        // Content-addressed, so a page that renders identical bytes keeps its
        // tag and a page whose copy changed does not.
        assert!(header(&page, "etag").starts_with('"'), "{path} has no ETag");
    }
}

#[tokio::test]
async fn no_page_carries_inline_script_style_or_handlers() {
    let url = require_db!();
    let plane = Plane::start(&url).await;

    // The policy served with every page has no `unsafe-inline`, so anything
    // inline is dead markup that looks like working markup. Checked against
    // rendered output rather than the template source, because a value
    // interpolated from the database could introduce one just as easily.
    for path in PUBLIC_PAGES.iter().chain(["/nothing-is-here"].iter()) {
        let page = get(&plane, path).await;
        let body = &page.body;

        assert!(
            !body.contains("<script"),
            "{path} carries a script tag; the policy forbids inline script and \
             an external one belongs under /assets"
        );
        assert!(
            !body.contains("style=\""),
            "{path} carries an inline style attribute; the policy forbids it"
        );
        assert!(
            !body.contains("<style"),
            "{path} carries a style element; the policy forbids it"
        );
        assert!(
            !body.contains("javascript:"),
            "{path} carries a javascript: URL"
        );

        // Event handler attributes, which are inline script wearing a
        // different syntax and are blocked by the same directive.
        for handler in [
            " onclick=",
            " onload=",
            " onerror=",
            " onsubmit=",
            " onchange=",
            " onfocus=",
            " onmouseover=",
            " oninput=",
        ] {
            assert!(
                !body.contains(handler),
                "{path} carries an{handler}attribute"
            );
        }
    }
}

#[tokio::test]
async fn nothing_served_carries_an_em_dash_or_en_dash() {
    let url = require_db!();
    let plane = Plane::start(&url).await;

    // House style, and the kind of thing that arrives by way of a word
    // processor rather than by decision. Cheaper to assert than to notice.
    for path in PUBLIC_PAGES
        .iter()
        .chain(["/nothing-is-here", "/assets/usagekit.css"].iter())
    {
        let page = get(&plane, path).await;
        for (character, name) in [('\u{2014}', "em-dash"), ('\u{2013}', "en-dash")] {
            assert!(
                !page.body.contains(character),
                "{path} contains an {name}; use a plain hyphen"
            );
        }
    }
}

/// Words that were removed from customer-facing copy, and why.
///
/// Every one of these is either internal vocabulary ("the plane"), a second
/// name for something that already has one, or a term of art a buyer has no
/// reason to know. They were replaced rather than explained, because the site
/// previously used four different words for one concept and that is most of
/// what made it unreadable.
const RETIRED_TERMS: [(&str, &str); 8] = [
    (
        "the plane",
        "internal shorthand for the control plane; say UsageKit Cloud",
    ),
    ("sidecar", "say a proxy in front of your server"),
    ("dead letter", "say usage that could not be billed"),
    (
        "terminal delivery",
        "say a result your customer actually received",
    ),
    ("metered event", "say billable event"),
    ("hot path", "say your live traffic"),
    ("price book", "say what each customer pays"),
    ("reconcil", "say handled, or could not be billed"),
];

#[tokio::test]
async fn the_pages_use_one_word_per_concept() {
    let url = require_db!();
    let plane = Plane::start(&url).await;

    // A vocabulary this size drifts back one sentence at a time, and each
    // individual reintroduction looks harmless in a diff. Checking the rendered
    // pages is the only place it stays visible.
    //
    // The dashboard is checked in the dashboard suite, which can sign in.
    for path in PUBLIC_PAGES
        .iter()
        .chain(["/nothing-is-here", "/signin"].iter())
    {
        let page = get(&plane, path).await;
        let body = page.body.to_lowercase();
        for (term, instead) in RETIRED_TERMS {
            assert!(
                !body.contains(term),
                "{path} still says {term:?}; {instead}"
            );
        }
    }
}

#[tokio::test]
async fn the_home_page_answers_a_buyer_before_it_answers_an_engineer() {
    let url = require_db!();
    let plane = Plane::start(&url).await;
    let home = get(&plane, "/").await;
    let body = &home.body;

    // The three things a non-technical reader needs and the page did not used
    // to give them: what it costs, what the problem costs, and what MCP is.
    assert!(
        body.contains("$0.50 per 10,000 billable events"),
        "the price is not on the home page, so a buyer has to go looking for it"
    );
    assert!(
        body.contains("Model Context Protocol"),
        "MCP is never expanded, so a reader who does not know it cannot start"
    );
    assert!(
        body.contains("$3.04 of real usage billed as $9.06"),
        "the measurement is never turned into money"
    );

    // And the proof a technical reader needs is still on the same page rather
    // than having been softened away.
    assert!(
        body.contains("cargo run -p mcp-overbilling"),
        "the reproduce-it-yourself command was lost in the rewrite"
    );
    for figure in ["45", "152", "453"] {
        assert!(
            body.contains(figure),
            "the measurement lost the figure {figure}"
        );
    }
}

#[tokio::test]
async fn every_response_carries_the_security_headers() {
    let url = require_db!();
    let plane = Plane::start(&url).await;

    // Including the JSON API and the 404, because the middleware sits outside
    // every route precisely so none of them can be the exception.
    for path in ["/", "/pricing", "/v1/usage", "/nothing-is-here"] {
        let page = get(&plane, path).await;
        let policy = header(&page, "content-security-policy");

        assert!(
            policy.contains("default-src 'self'"),
            "{path} has no usable content security policy"
        );
        assert!(
            !policy.contains("unsafe-inline") && !policy.contains("unsafe-eval"),
            "{path} has a policy with an escape hatch: {policy}"
        );
        assert!(
            policy.contains("frame-ancestors 'none'"),
            "{path} can be framed"
        );
        assert!(
            policy.contains("form-action 'self'"),
            "{path} allows a form to post anywhere"
        );

        assert_eq!(header(&page, "x-frame-options"), "DENY", "{path}");
        assert_eq!(header(&page, "x-content-type-options"), "nosniff", "{path}");
        assert_eq!(
            header(&page, "referrer-policy"),
            "strict-origin-when-cross-origin",
            "{path}"
        );
        assert!(
            header(&page, "strict-transport-security").contains("max-age="),
            "{path} has no HSTS"
        );
    }
}

#[tokio::test]
async fn caller_specific_paths_are_kept_out_of_caches_and_indexes() {
    let url = require_db!();
    let plane = Plane::start(&url).await;

    // A dashboard page held by a shared cache is one account's revenue served
    // to whoever asks next through the same proxy.
    let private = get(&plane, "/v1/usage").await;
    assert_eq!(header(&private, "cache-control"), "no-store");
    assert_eq!(header(&private, "x-robots-tag"), "noindex, nofollow");

    // Marketing pages are the opposite: cacheable, revalidated, and indexable.
    let public = get(&plane, "/pricing").await;
    assert!(header(&public, "cache-control").contains("must-revalidate"));
    assert!(!header(&public, "cache-control").contains("no-store"));
    assert_eq!(header(&public, "x-robots-tag"), "");
}

#[tokio::test]
async fn the_stylesheet_is_served_from_disk() {
    let url = require_db!();
    let plane = Plane::start(&url).await;

    // `ServeDir` resolves against the working directory rather than the crate
    // root, so this fails the moment the assets stop being where the process
    // can find them. That is a container-only failure otherwise, and it looks
    // like a design regression rather than a missing file.
    let sheet = get(&plane, "/assets/usagekit.css").await;
    assert_eq!(sheet.status, 200, "the stylesheet is not being served");
    assert!(header(&sheet, "content-type").contains("text/css"));
    assert!(sheet.body.contains("--accent"), "the stylesheet is empty");

    // Not fingerprinted, so it must be revalidated rather than held for a year.
    assert!(header(&sheet, "cache-control").contains("must-revalidate"));

    // Components set `display`, so the attribute has to win or a panel hidden
    // from script stays on the page looking deliberate.
    assert!(
        sheet
            .body
            .contains("[hidden] { display: none !important; }"),
        "the hidden attribute is not forced"
    );

    // Every page references it, so a 404 here is an unstyled site.
    let home = get(&plane, "/").await;
    assert!(home.body.contains("/assets/usagekit.css"));
}

#[tokio::test]
async fn an_unknown_path_renders_a_page_rather_than_a_bare_404() {
    let url = require_db!();
    let plane = Plane::start(&url).await;

    let page = get(&plane, "/nothing-is-here").await;
    assert_eq!(page.status, 404);
    assert!(header(&page, "content-type").starts_with("text/html"));
    assert!(page.body.contains("UsageKit"), "the 404 has no shell");
    assert_eq!(
        header(&page, "x-robots-tag"),
        "noindex, follow",
        "a 404 that gets indexed competes with a page somebody wrote"
    );
}

// ----------------------------------------------------------- access requests

async fn request_access(plane: &Plane, origin: Option<&str>, form: &[(&str, &str)]) -> Page {
    // Redirects are not followed: the redirect *is* the result being asserted,
    // and following it would assert the home page instead.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build a client");
    let mut request = client.post(plane.url("/request-access")).form(form);
    if let Some(origin) = origin {
        request = request.header(reqwest::header::ORIGIN, origin);
    }
    let response = request.send().await.expect("request reaches the plane");
    Page {
        status: response.status(),
        headers: response.headers().clone(),
        body: response.text().await.unwrap_or_default(),
    }
}

async fn recorded_requests(plane: &Plane) -> Vec<(String, Option<String>, Option<i64>)> {
    let pool = sqlx::PgPool::connect(&plane.db_url)
        .await
        .expect("connect to the scratch database");
    let rows: Vec<(String, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT email::text, company, expected_events FROM access_requests ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("read access_requests");
    pool.close().await;
    rows
}

#[tokio::test]
async fn an_access_request_is_recorded_and_the_visitor_is_told_so() {
    let url = require_db!();
    let plane = Plane::start(&url).await;
    let origin = plane.base.clone();

    let response = request_access(
        &plane,
        Some(&origin),
        &[
            ("email", "  Person@Example.com "),
            ("company", "  Acme  "),
            ("expected_events", "250,000"),
            ("note", "Metering a tools server."),
        ],
    )
    .await;

    assert_eq!(
        response.status, 303,
        "the form should redirect after a post"
    );
    assert_eq!(
        header(&response, "location"),
        "/?requested=1#request-access",
        "the visitor should land back at the form with an acknowledgement"
    );

    let rows = recorded_requests(&plane).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "Person@Example.com", "the address is trimmed");
    assert_eq!(rows[0].1.as_deref(), Some("Acme"), "the company is trimmed");
    assert_eq!(
        rows[0].2,
        Some(250_000),
        "a thousands-separated forecast should parse"
    );

    // Following the redirect shows the acknowledgement, and it is the fixed
    // copy rather than anything echoed from the request.
    let home = get(&plane, "/?requested=1").await;
    assert!(home.body.contains("Thank you"), "no acknowledgement shown");
}

#[tokio::test]
async fn an_access_request_from_nowhere_is_refused_and_records_nothing() {
    let url = require_db!();
    let plane = Plane::start(&url).await;
    let origin = plane.base.clone();

    // An absent Origin is refused rather than assumed friendly: the check fails
    // closed, which is the whole point of having it alongside SameSite=Lax.
    let no_origin = request_access(&plane, None, &[("email", "person@example.com")]).await;
    assert_eq!(no_origin.status, 403, "a missing Origin was accepted");

    let foreign = request_access(
        &plane,
        Some("https://evil.example"),
        &[("email", "person@example.com")],
    )
    .await;
    assert_eq!(foreign.status, 403, "a foreign Origin was accepted");

    // A near-miss on the configured origin must not pass either.
    let lookalike = request_access(
        &plane,
        Some(&format!("{origin}.evil.example")),
        &[("email", "person@example.com")],
    )
    .await;
    assert_eq!(lookalike.status, 403, "a lookalike Origin was accepted");

    assert!(
        recorded_requests(&plane).await.is_empty(),
        "a refused request still wrote a row"
    );
}

#[tokio::test]
async fn an_unusable_address_is_rejected_without_writing_a_row() {
    let url = require_db!();
    let plane = Plane::start(&url).await;
    let origin = plane.base.clone();

    for attempt in ["", "no-at-sign", "two@at@signs", "has space@example.com"] {
        let response = request_access(&plane, Some(&origin), &[("email", attempt)]).await;
        assert_eq!(response.status, 303, "{attempt}");
        assert_eq!(
            header(&response, "location"),
            "/?error=email#request-access",
            "{attempt} did not send the visitor back to fix it"
        );
    }

    assert!(
        recorded_requests(&plane).await.is_empty(),
        "an invalid address was stored"
    );

    // The message shown is the fixed copy for that code.
    let shown = get(&plane, "/?error=email").await;
    assert!(shown.body.contains("does not look valid"));
    assert!(
        shown.body.contains("class=\"notice"),
        "a known code rendered no notice element, so the check below proves nothing"
    );

    // An unknown code renders no notice at all. Asserting the absence of the
    // element rather than the absence of a script is deliberate: askama escapes
    // the value either way, and escaped text phishes perfectly well. The thing
    // worth preventing is arbitrary text appearing in our voice on our page,
    // not just the subset of it that happens to be executable.
    for attempt in [
        "unknown",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "Your%20account%20is%20suspended.%20Call%201-800-555-0123.",
    ] {
        let injected = get(&plane, &format!("/?error={attempt}")).await;
        assert!(
            !injected.body.contains("class=\"notice"),
            "{attempt} put a message on the page"
        );
        assert!(
            !injected.body.contains("alert(1)") && !injected.body.contains("555-0123"),
            "{attempt} was reflected into the page"
        );
    }
}

#[tokio::test]
async fn access_requests_are_bounded_however_many_addresses_are_used() {
    let url = require_db!();
    let plane = Plane::start(&url).await;
    let origin = plane.base.clone();

    // A different address every time, which is exactly the case a budget keyed
    // on the address would fail to bound: each new value would get its own
    // fresh allowance. The budget is deliberately keyed on a fixed subject.
    let mut refused = 0;
    for attempt in 0..40 {
        let response = request_access(
            &plane,
            Some(&origin),
            &[("email", &format!("person{attempt}@example.com"))],
        )
        .await;
        if header(&response, "location") == "/?error=throttled#request-access" {
            refused += 1;
        }
    }

    assert!(
        refused > 0,
        "40 requests from 40 distinct addresses were all accepted; the budget \
         is not bounding anything"
    );

    let stored = recorded_requests(&plane).await.len();
    assert!(
        stored < 40,
        "every request was stored despite the budget: {stored} rows"
    );
}
