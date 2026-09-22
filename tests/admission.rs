//! The request-path bounds, exercised against a running plane.
//!
//! These are integration tests rather than unit tests on purpose. The unit
//! tests in `throttle` prove the bucket arithmetic; what matters here is that
//! the arithmetic is actually reached by a real request, returns the status and
//! header a client can act on, and does not accidentally apply to the health
//! endpoint the platform polls.

mod common;

use common::{ADMIN_TOKEN, EDGE_TOKEN, Plane};
use reqwest::Method;

#[tokio::test]
async fn a_token_over_its_budget_gets_429_with_a_usable_retry_after() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    // Spend the budget. The limit is per token, so this is bounded work.
    let mut refused = None;
    for _ in 0..1_000 {
        let (status, headers) = plane
            .send_raw(Method::GET, "/v1/tenants", Some(ADMIN_TOKEN))
            .await;
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            refused = Some(headers);
            break;
        }
        assert_eq!(
            status,
            reqwest::StatusCode::OK,
            "unexpected status {status}"
        );
    }

    let headers = refused.expect("the budget must actually be a bound");
    let retry_after = headers
        .get(reqwest::header::RETRY_AFTER)
        .expect("a 429 without Retry-After tells a client to retry immediately")
        .to_str()
        .expect("Retry-After is ascii")
        .parse::<u64>()
        .expect("Retry-After is a number of seconds");
    assert!(
        (1..=60).contains(&retry_after),
        "Retry-After was {retry_after}"
    );
}

#[tokio::test]
async fn one_tokens_spending_does_not_refuse_another() {
    // A shared bucket would let any one customer's sidecar deny service to
    // every other customer, which is worse than the problem the limit solves.
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let mut exhausted = false;
    for _ in 0..1_000 {
        let (status, _) = plane
            .send_raw(Method::GET, "/v1/tenants", Some(ADMIN_TOKEN))
            .await;
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            exhausted = true;
            break;
        }
    }
    assert!(exhausted, "the admin budget must be spendable");

    // The edge token has its own budget and has spent none of it.
    let (status, _) = plane
        .send_raw(Method::GET, "/v1/edge/snapshot", Some(EDGE_TOKEN))
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "a second token must be unaffected"
    );
}

#[tokio::test]
async fn the_health_endpoint_is_not_rate_limited() {
    // The platform polls this every few seconds from an unauthenticated
    // position. Applying the per-token budget to it would have the health
    // check take the instance out of rotation by itself.
    let db = require_db!();
    let plane = Plane::start(&db).await;

    for attempt in 0..300 {
        let (status, _) = plane.send_raw(Method::GET, "/healthz", None).await;
        assert_eq!(
            status,
            reqwest::StatusCode::OK,
            "health poll {attempt} returned {status}"
        );
    }
}

#[tokio::test]
async fn an_unknown_token_is_refused_and_then_throttled() {
    // A failed authentication always reaches the database, so it gets its own
    // tighter budget. Without one, an unauthenticated client can spend pool
    // connections indefinitely.
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let mut saw_unauthorized = false;
    let mut throttled = false;
    for _ in 0..200 {
        let (status, _) = plane
            .send_raw(
                Method::GET,
                "/v1/tenants",
                Some("mup_admin_not_a_real_token"),
            )
            .await;
        match status {
            reqwest::StatusCode::UNAUTHORIZED => saw_unauthorized = true,
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                throttled = true;
                break;
            }
            other => panic!("unexpected status {other}"),
        }
    }
    assert!(
        saw_unauthorized,
        "a bad token must first be refused as such"
    );
    assert!(
        throttled,
        "repeated failures must be throttled, not answered forever"
    );
}

#[tokio::test]
async fn an_oversized_body_is_refused_rather_than_buffered() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    // Comfortably past the admin ceiling, far below the edge usage ceiling.
    let padding = "x".repeat(256 * 1024);
    let (status, _) = plane
        .admin(
            Method::POST,
            "/v1/tenants",
            Some(serde_json::json!({
                "tenant_key": padding,
                "billing_customer_id": "cus_acme"
            })),
        )
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
        "an unbounded admin body is a way to spend memory for free"
    );
}

#[tokio::test]
async fn the_edge_usage_route_still_accepts_a_full_batch() {
    // The tight default must not break the one route that legitimately carries
    // a large body, or the limit has traded an abuse bound for an outage.
    let db = require_db!();
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_acme").await;

    let events: Vec<_> = (0..1_000)
        .map(|n| {
            serde_json::json!({
                "identifier": format!("agg-bulk-{n}"),
                "customer_id": "cus_acme",
                "meter": "mcp_units",
                "units": 1,
                "timestamp": 1_789_757_188u64
            })
        })
        .collect();

    let (status, body) = plane
        .edge(
            Method::POST,
            "/v1/edge/usage",
            Some(serde_json::json!({ "events": events })),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(body["outcomes"].as_array().expect("outcomes").len(), 1_000);
}

#[tokio::test]
async fn concurrent_authenticated_requests_do_not_exhaust_the_pool() {
    // A regression guard, and deliberately not advertised as more than that.
    //
    // Fly admits 128 concurrent requests against a pool of 10 with a five
    // second acquire timeout, and before the auth cache every one of those
    // requests took a connection to authenticate. That is a real narrowing,
    // but this test passes with the cache removed too: against a local
    // Postgres, ten connections cycle 120 requests well inside the timeout.
    // The starvation argument is about a *remote* database, where the same
    // round trip is a network hop rather than a microsecond.
    //
    // What is worth guarding is the invariant: concurrency at this level must
    // not produce 5xx. 120 is under the per-token budget and far over the pool.
    let db = require_db!();
    let plane = std::sync::Arc::new(Plane::start(&db).await);

    let mut inflight = Vec::with_capacity(120);
    for _ in 0..120 {
        let plane = std::sync::Arc::clone(&plane);
        inflight.push(tokio::spawn(async move {
            plane
                .send_raw(Method::GET, "/v1/tenants", Some(ADMIN_TOKEN))
                .await
                .0
        }));
    }

    let mut server_errors = 0;
    let mut ok = 0;
    for task in inflight {
        let status = task.await.expect("the request task completes");
        if status.is_server_error() {
            server_errors += 1;
        } else if status == reqwest::StatusCode::OK {
            ok += 1;
        }
    }

    assert_eq!(
        server_errors, 0,
        "{server_errors} of 120 concurrent requests failed; the pool is the ceiling"
    );
    assert!(ok > 0, "no request succeeded at all");
}

/// Not an assertion, a measurement. Run with --nocapture.
#[tokio::test]
#[ignore = "measurement, not a gate"]
async fn measure_authenticated_request_latency() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    // Warm: first request pays the database, the rest should not.
    plane
        .send_raw(Method::GET, "/v1/tenants", Some(ADMIN_TOKEN))
        .await;

    let started = std::time::Instant::now();
    let n = 200;
    for _ in 0..n {
        plane
            .send_raw(Method::GET, "/v1/tenants", Some(ADMIN_TOKEN))
            .await;
    }
    let per = started.elapsed().as_micros() as f64 / f64::from(n);
    println!("MEASURED {per:.0} us/request over {n} requests");
}

#[tokio::test]
async fn a_minted_token_works_and_revoking_it_takes_effect_at_once() {
    // The revocation path is the reason the auth cache is allowed to exist. If
    // revoking only took effect when the TTL expired, the cache would be a ten
    // second window in which a leaked credential still works after an operator
    // has explicitly killed it.
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let (status, minted) = plane
        .admin(
            Method::POST,
            "/v1/tokens",
            Some(serde_json::json!({"scope": "edge", "label": "a sidecar"})),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{minted}");
    let token = minted["token"].as_str().expect("a token").to_owned();
    let digest = minted["token_sha256"]
        .as_str()
        .expect("a digest")
        .to_owned();
    assert!(token.starts_with("mup_edge_"));

    // It authenticates, and the result is now cached.
    let (status, _) = plane
        .send_raw(Method::GET, "/v1/edge/snapshot", Some(&token))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);

    let (status, _) = plane
        .admin(Method::DELETE, &format!("/v1/tokens/{digest}"), None)
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);

    // Immediately, not after the TTL.
    let (status, _) = plane
        .send_raw(Method::GET, "/v1/edge/snapshot", Some(&token))
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNAUTHORIZED,
        "a revoked token must stop working without waiting out the cache"
    );
}

#[tokio::test]
async fn the_last_admin_token_cannot_be_revoked() {
    // Otherwise the only way back into the account is database access, which
    // is a thing to discover before an incident rather than during one.
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let (_, tokens) = plane.admin(Method::GET, "/v1/tokens", None).await;
    let admin_digest = tokens
        .as_array()
        .expect("a list")
        .iter()
        .find(|row| row["scope"] == "admin")
        .expect("the bootstrap admin token is listed")["token_sha256"]
        .as_str()
        .expect("a digest")
        .to_owned();

    let (status, body) = plane
        .admin(Method::DELETE, &format!("/v1/tokens/{admin_digest}"), None)
        .await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{body}");

    // With a replacement in place it is allowed, because the account is not
    // locking itself out any more.
    let (_, replacement) = plane
        .admin(
            Method::POST,
            "/v1/tokens",
            Some(serde_json::json!({"scope": "admin", "label": "replacement"})),
        )
        .await;
    assert!(replacement["token"].is_string());

    let (status, _) = plane
        .admin(Method::DELETE, &format!("/v1/tokens/{admin_digest}"), None)
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn tokens_are_listed_without_ever_returning_the_credential() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let (_, listed) = plane.admin(Method::GET, "/v1/tokens", None).await;
    let rows = listed.as_array().expect("a list");
    assert!(!rows.is_empty());
    for row in rows {
        assert!(
            row.get("token").is_none(),
            "a listing must never carry the credential: {row}"
        );
        assert!(row["token_sha256"].is_string());
    }
}

#[tokio::test]
async fn an_edge_token_cannot_manage_account_credentials() {
    // Sidecars run in customer infrastructure and are the most exposed
    // component. A sidecar that could mint an admin token would make a sidecar
    // compromise an account compromise.
    let db = require_db!();
    let plane = Plane::start(&db).await;

    for (method, path) in [
        (Method::GET, "/v1/tokens"),
        (Method::POST, "/v1/tokens"),
        (Method::DELETE, "/v1/tokens/deadbeef"),
    ] {
        let (status, _) = plane.send_raw(method.clone(), path, Some(EDGE_TOKEN)).await;
        assert_eq!(
            status,
            reqwest::StatusCode::FORBIDDEN,
            "{method} {path} was not refused"
        );
    }
}
