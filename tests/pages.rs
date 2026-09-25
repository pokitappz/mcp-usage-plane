//! What the service serves in a browser: sign-in, the 404, and the assets.
//!
//! This file used to cover a marketing site as well. Those pages are a separate
//! repository now, so what is left is the discipline that applies to anything
//! rendered here, and it is worth keeping even though there are fewer pages to
//! apply it to: an inline style or a stray em-dash does not look wrong in a
//! diff, and the content security policy this service sets would quietly stop
//! protecting the pages that break it.

mod common;

use common::Plane;

/// Pages a browser can reach without signing in.
const OPEN_PAGES: [&str; 2] = ["/signin", "/nothing-is-here"];

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

async fn get(plane: &Plane, path: &str) -> Page {
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build a client")
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

#[tokio::test]
async fn the_front_door_leads_to_signing_in() {
    let url = require_db!();
    let plane = Plane::start(&url).await;

    // There is no marketing page here any more, so `/` has one useful thing to
    // do. A bare 404 on the root of a deployment reads as broken.
    let root = get(&plane, "/").await;
    assert_eq!(root.status, 303);
    assert_eq!(header(&root, "location"), "/signin");

    let signin = get(&plane, "/signin").await;
    assert_eq!(signin.status, 200);
    assert!(header(&signin, "content-type").starts_with("text/html"));
    for required in [
        "<html lang=\"en\">",
        "<meta name=\"description\"",
        "<title>",
    ] {
        assert!(
            signin.body.contains(required),
            "sign-in is missing {required}"
        );
    }
}

#[tokio::test]
async fn no_page_carries_inline_script_style_or_handlers() {
    let url = require_db!();
    let plane = Plane::start(&url).await;

    // The policy served with every page has no `unsafe-inline`, so anything
    // inline is dead markup that looks like working markup.
    for path in OPEN_PAGES {
        let body = get(&plane, path).await.body;
        assert!(!body.contains("<script"), "{path} carries a script tag");
        assert!(!body.contains("style=\""), "{path} carries an inline style");
        assert!(!body.contains("<style"), "{path} carries a style element");
        assert!(
            !body.contains("javascript:"),
            "{path} carries a javascript: URL"
        );
        for handler in [
            " onclick=",
            " onload=",
            " onerror=",
            " onsubmit=",
            " onchange=",
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

    for path in OPEN_PAGES.iter().chain(["/assets/usagekit.css"].iter()) {
        let body = get(&plane, path).await.body;
        for (character, name) in [('\u{2014}', "em-dash"), ('\u{2013}', "en-dash")] {
            assert!(!body.contains(character), "{path} contains an {name}");
        }
    }
}

#[tokio::test]
async fn the_pages_use_one_word_per_concept() {
    let url = require_db!();
    let plane = Plane::start(&url).await;

    // The vocabulary drifts back one sentence at a time, and each
    // reintroduction looks harmless on its own.
    let retired = [
        (
            "the plane",
            "internal shorthand; name the product or say the control plane",
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
    ];
    for path in OPEN_PAGES {
        let body = get(&plane, path).await.body.to_lowercase();
        for (term, instead) in retired {
            assert!(
                !body.contains(term),
                "{path} still says {term:?}; {instead}"
            );
        }
    }
}

#[tokio::test]
async fn every_response_carries_the_security_headers() {
    let url = require_db!();
    let plane = Plane::start(&url).await;

    // Including the JSON API and the 404, because the middleware sits outside
    // every route precisely so none of them can be the exception.
    for path in [
        "/signin",
        "/v1/usage",
        "/nothing-is-here",
        "/assets/usagekit.css",
    ] {
        let page = get(&plane, path).await;
        let policy = header(&page, "content-security-policy");

        assert!(
            policy.contains("default-src 'self'"),
            "{path} has no policy"
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
            "{path} allows a stray form target"
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

    // A dashboard page held by a shared cache is one account's figures served
    // to whoever asks next through the same proxy. Sign-in is on the list too,
    // because the code step carries an address in a form field.
    for path in ["/v1/usage", "/app", "/signin"] {
        let page = get(&plane, path).await;
        assert_eq!(header(&page, "cache-control"), "no-store", "{path}");
        assert_eq!(header(&page, "x-robots-tag"), "noindex, nofollow", "{path}");
    }

    // The stylesheet is the same for everybody and may be cached.
    let sheet = get(&plane, "/assets/usagekit.css").await;
    assert!(header(&sheet, "cache-control").contains("must-revalidate"));
    assert!(!header(&sheet, "cache-control").contains("no-store"));
}

#[tokio::test]
async fn the_assets_are_compiled_into_the_binary() {
    let url = require_db!();
    let plane = Plane::start(&url).await;

    // Read from disk until this became something people install from a
    // registry. There is no directory beside an installed binary, so a
    // stylesheet that 404s here is a dashboard that renders unstyled for
    // everyone who did not build from source.
    let sheet = get(&plane, "/assets/usagekit.css").await;
    assert_eq!(sheet.status, 200, "the stylesheet is not being served");
    assert!(header(&sheet, "content-type").contains("text/css"));
    assert!(sheet.body.contains("--accent"), "the stylesheet is empty");
    assert!(
        sheet
            .body
            .contains("[hidden] { display: none !important; }"),
        "the hidden attribute is not forced"
    );

    let mark = get(&plane, "/assets/mark.svg").await;
    assert_eq!(mark.status, 200);
    assert!(header(&mark, "content-type").contains("image/svg+xml"));

    // And nothing else is reachable through that route.
    for attempt in ["/assets/nothing.css", "/assets/Cargo.toml"] {
        assert_eq!(
            get(&plane, attempt).await.status,
            404,
            "{attempt} was served"
        );
    }
}

#[tokio::test]
async fn an_unknown_path_renders_a_page_rather_than_a_bare_404() {
    let url = require_db!();
    let plane = Plane::start(&url).await;

    let page = get(&plane, "/nothing-is-here").await;
    assert_eq!(page.status, 404);
    assert!(header(&page, "content-type").starts_with("text/html"));
    assert_eq!(
        header(&page, "x-robots-tag"),
        "noindex, follow",
        "a 404 that gets indexed competes with a page somebody wrote"
    );
}
