//! What somebody else gets when they run this.
//!
//! This service is distributed under a licence that lets other people deploy
//! it, which makes a class of bug possible that did not exist while we were the
//! only operator: our branding, our addresses and our marketing reaching their
//! customers. None of it looks wrong in a diff, and all of it is embarrassing
//! in production on somebody else's domain.
//!
//! So these boot the binary the way a stranger would, with nothing configured,
//! and check what comes out.

mod common;

use common::Plane;

/// Boot the way a stranger would, having configured nothing.
///
/// `PLANE_PUBLIC_SITE` is *unset* rather than set to `0`, deliberately. Setting
/// it to `0` would prove the flag is read and prove nothing about which way it
/// defaults, and the default is the property that matters: somebody who never
/// reads the documentation must not end up serving our shop front.
async fn self_hosted(db: &str) -> Plane {
    // Every variable that makes this deployment *ours* is unset, not set to
    // something else. The harness sets them because the rest of the suite
    // asserts on our own copy, and leaving them in place here is how this test
    // first passed while the sign-in page still carried our wordmark.
    Plane::start_with_env(
        db,
        &[
            ("PLANE_PUBLIC_SITE", ""),
            ("PLANE_PRODUCT_NAME", ""),
            ("PLANE_PRODUCT_SUFFIX", ""),
        ],
    )
    .await
}

async fn get(plane: &Plane, path: &str) -> (reqwest::StatusCode, String) {
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build a client")
        .get(plane.url(path))
        .send()
        .await
        .expect("request reaches the plane");
    let status = response.status();
    (status, response.text().await.unwrap_or_default())
}

#[tokio::test]
async fn a_self_hosted_deployment_serves_none_of_our_marketing() {
    let db = require_db!();
    let plane = self_hosted(&db).await;

    // The pages advertise our pricing and make claims about how we operate,
    // almost all of which are untrue of somebody else's deployment.
    for path in ["/pricing", "/security", "/docs", "/request-access"] {
        let (status, body) = get(&plane, path).await;
        assert_eq!(status, 404, "{path} is still being served");
        assert!(
            !body.contains("UsageKit"),
            "{path} returned our branding in its 404"
        );
    }

    // The front door leads somewhere useful rather than to a marketing page.
    let (status, _) = get(&plane, "/").await;
    assert_eq!(
        status, 303,
        "/ should lead to sign-in when there is no site"
    );

    // And the 404 for anything else does not render our shell either.
    let (status, body) = get(&plane, "/nothing-here").await;
    assert_eq!(status, 404);
    for ours in ["UsageKit", "pokitapps", "Request access"] {
        assert!(!body.contains(ours), "the 404 page mentions {ours}");
    }
}

#[tokio::test]
async fn the_pages_a_self_hoster_does_serve_carry_none_of_our_branding() {
    let db = require_db!();
    let plane = self_hosted(&db).await;

    // The marketing pages being gone is the easy half. These are the pages a
    // self-hosted deployment *does* serve, to its own customers, and the
    // wordmark and page titles were baked into the shared templates. Booting
    // the binary with nothing configured is what found that; the test above
    // only looked at the routes that had been removed.
    for path in ["/signin", "/app"] {
        let (_, body) = get(&plane, path).await;
        for ours in ["UsageKit", "pokitapps.com", "usagekit.cloud"] {
            assert!(
                !body.contains(ours),
                "{path} shows {ours} to a self-hoster's customers"
            );
        }
    }

    // Something generic is rendered rather than nothing, because an empty
    // wordmark would look like a broken page rather than an unconfigured one.
    let (_, body) = get(&plane, "/signin").await;
    assert!(
        body.contains("Usage control plane"),
        "the default branding is missing, so the header renders empty"
    );
}

#[tokio::test]
async fn the_parts_a_self_hoster_actually_needs_still_work() {
    let db = require_db!();
    let plane = self_hosted(&db).await;

    // Turning the site off must not turn off the product.
    let (status, _) = get(&plane, "/healthz").await;
    assert_eq!(status, 200, "health checks stopped working");

    let (status, _) = get(&plane, "/signin").await;
    assert_eq!(status, 200, "nobody can sign in");

    // The dashboard still gates rather than 404s, which is the difference
    // between "not configured" and "not authorised".
    let (status, _) = get(&plane, "/app").await;
    assert_eq!(status, 303, "the dashboard is gone rather than gated");

    // The API is untouched.
    let (status, _) = plane.admin(reqwest::Method::GET, "/v1/tenants", None).await;
    assert_eq!(status, 200, "the admin API stopped working");

    // And so is the thing the whole service exists for.
    let key = plane.seed_tenant("acme", "cus_acme").await;
    assert!(!key.is_empty());
    let (status, _) = plane
        .send(
            reqwest::Method::POST,
            "/v1/edge/usage",
            Some(serde_json::json!({"events": [{
                "identifier": "agg-1", "customer_id": "cus_acme", "meter": "calls",
                "units": 7, "timestamp": chrono::Utc::now().timestamp()
            }]})),
            Some(common::EDGE_TOKEN),
        )
        .await;
    assert_eq!(status, 200, "usage ingest stopped working");
}

#[tokio::test]
async fn the_static_assets_are_still_reachable_for_the_dashboard() {
    let db = require_db!();
    let plane = self_hosted(&db).await;

    // The dashboard and the sign-in pages use the same stylesheet the
    // marketing site does, so turning the site off must not take it with it.
    let (status, body) = get(&plane, "/assets/usagekit.css").await;
    assert_eq!(status, 200, "the dashboard would render unstyled");
    assert!(body.contains("--accent"));
}
