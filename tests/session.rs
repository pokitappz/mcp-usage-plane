//! Dashboard sign-in, against a real database and the real binary.
//!
//! The dashboard is authenticated by the account's own `admin` token. There is no
//! person, no password and no mail, so what matters here is narrow: that the
//! right token opens a session, that nothing else does, that the session is
//! stored only as a digest and actually gates something, and that a refusal says
//! nothing about which part of the presented token was wrong.

mod common;

use common::Plane;
use serde_json::json;

/// Present a token to the JSON sign-in route.
async fn sign_in(plane: &Plane, token: &str) -> (reqwest::StatusCode, reqwest::header::HeaderMap) {
    let response = plane
        .http
        .post(plane.url("/v1/auth/session"))
        .header("origin", &plane.base)
        .json(&json!({ "token": token }))
        .send()
        .await
        .expect("request reaches the plane");
    (response.status(), response.headers().clone())
}

fn session_cookie(headers: &reqwest::header::HeaderMap) -> String {
    headers
        .get(reqwest::header::SET_COOKIE)
        .expect("a session cookie")
        .to_str()
        .expect("ascii")
        .split(';')
        .next()
        .expect("a name=value pair")
        .to_owned()
}

async fn stored_sessions(plane: &Plane) -> Vec<String> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&plane.db_url)
        .await
        .expect("connect to the scratch database");
    let rows: Vec<String> = sqlx::query_scalar("SELECT session_sha256 FROM dashboard_sessions")
        .fetch_all(&pool)
        .await
        .expect("read sessions");
    pool.close().await;
    rows
}

#[tokio::test]
async fn an_admin_token_opens_a_session_that_gates_the_account() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    // Anonymous first, so the gate is proven shut before it is opened.
    let anonymous = plane
        .http
        .get(plane.url("/v1/auth/session"))
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(anonymous.status(), 401);

    let (status, headers) = sign_in(&plane, common::ADMIN_TOKEN).await;
    assert_eq!(status, 200, "an admin token could not open a session");
    let cookie = session_cookie(&headers);

    let response = plane
        .http
        .get(plane.url("/v1/auth/session"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(response.status(), 200);
    let body = response
        .json::<serde_json::Value>()
        .await
        .expect("a session view");
    assert_eq!(body["account_id"], common::ACCOUNT);
    // No person, deliberately: every holder of the token is indistinguishable.
    assert!(
        body.get("email").is_none() && body.get("user_id").is_none(),
        "the session names a person it cannot possibly know: {body}"
    );
}

#[tokio::test]
async fn an_edge_token_cannot_open_a_session() {
    // The scope split is the point. An edge token belongs to a proxy in front of
    // a customer's server, which is the most exposed component in the system.
    // Letting it open a dashboard would hand that component the ability to mint
    // admin credentials, which is exactly what its scope exists to prevent.
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let (status, headers) = sign_in(&plane, common::EDGE_TOKEN).await;
    assert_eq!(status, 401, "an edge token opened a dashboard session");
    assert!(headers.get(reqwest::header::SET_COOKIE).is_none());
    assert!(
        stored_sessions(&plane).await.is_empty(),
        "a session row was written for a token that was refused"
    );
}

#[tokio::test]
async fn a_token_that_is_not_a_token_is_refused_the_same_way() {
    // One answer for every kind of wrong, because telling them apart tells
    // somebody holding a near miss which part of it was close.
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let mut seen = Vec::new();
    for attempt in [
        "",
        "   ",
        "not-a-token",
        "mup_admin_almost_but_not_quite_the_real_one",
        common::EDGE_TOKEN,
        // The digest of the real token, in case anything ever compares the wrong
        // side of the hash.
        "5f4dcc3b5aa765d61d8327deb882cf99",
    ] {
        let (status, headers) = sign_in(&plane, attempt).await;
        assert_eq!(status, 401, "{attempt:?} was accepted");
        assert!(headers.get(reqwest::header::SET_COOKIE).is_none());
        seen.push(status);
    }
    assert!(
        seen.windows(2).all(|pair| pair[0] == pair[1]),
        "different kinds of wrong token answer differently: {seen:?}"
    );
}

#[tokio::test]
async fn a_revoked_token_stops_opening_sessions() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    // Mint a second admin token, so revoking it does not remove the last one.
    let (status, minted) = plane
        .admin(
            reqwest::Method::POST,
            "/v1/tokens",
            Some(json!({ "scope": "admin", "label": "for revoking" })),
        )
        .await;
    assert_eq!(status, 200, "could not mint a token: {minted}");
    let token = minted["token"].as_str().expect("a token").to_owned();
    let digest = minted["token_sha256"]
        .as_str()
        .expect("a digest")
        .to_owned();

    let (status, _) = sign_in(&plane, &token).await;
    assert_eq!(status, 200, "a freshly minted admin token was refused");

    let (status, _) = plane
        .admin(
            reqwest::Method::DELETE,
            &format!("/v1/tokens/{digest}"),
            None,
        )
        .await;
    assert_eq!(status, 200, "could not revoke the token");

    let (status, _) = sign_in(&plane, &token).await;
    assert_eq!(
        status, 401,
        "a revoked token still opens a dashboard, so revocation does not reach \
         the one credential path a browser uses"
    );
}

#[tokio::test]
async fn the_session_is_stored_only_as_a_digest() {
    // A database disclosure must not hand over live sessions, which is the same
    // property `account_tokens` already has.
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let (_, headers) = sign_in(&plane, common::ADMIN_TOKEN).await;
    let cookie = session_cookie(&headers);
    let token = cookie.split_once('=').expect("name=value").1.to_owned();

    let stored = stored_sessions(&plane).await;
    assert_eq!(stored.len(), 1);
    assert!(!token.is_empty());
    assert!(
        !stored.iter().any(|value| value == &token),
        "the raw session token is in the database"
    );
}

#[tokio::test]
async fn the_admin_token_is_not_stored_by_the_session() {
    // The exchange exists so the browser holds something weaker and revocable.
    // If the token itself ended up in the session row, the exchange would have
    // bought nothing.
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let (_, _) = sign_in(&plane, common::ADMIN_TOKEN).await;
    let stored = stored_sessions(&plane).await;
    assert!(
        !stored
            .iter()
            .any(|value| value.contains(common::ADMIN_TOKEN)),
        "the admin token is in a session row"
    );
}

#[tokio::test]
async fn a_state_changing_route_refuses_without_a_trusted_origin() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    for origin in [None, Some("https://evil.example"), Some("null")] {
        let mut request = plane
            .http
            .post(plane.url("/v1/auth/session"))
            .json(&json!({ "token": common::ADMIN_TOKEN }));
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        let response = request.send().await.expect("request reaches the plane");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::FORBIDDEN,
            "origin {origin:?} was accepted"
        );
    }
}

#[tokio::test]
async fn guessing_a_token_is_rate_limited() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    // Counted on the digest of what was presented, so repeating one wrong guess
    // is bounded. Nothing here needs a lockout: a token is 32 random bytes, not
    // something a person chose.
    let mut throttled = false;
    for _ in 0..12 {
        let (status, _) = sign_in(&plane, "mup_admin_the_same_wrong_guess_every_time").await;
        if status == 429 {
            throttled = true;
            break;
        }
        assert_eq!(status, 401);
    }
    assert!(
        throttled,
        "twelve identical wrong tokens in a row were all answered without throttling"
    );
}

#[tokio::test]
async fn signing_out_ends_the_session_immediately() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let (_, headers) = sign_in(&plane, common::ADMIN_TOKEN).await;
    let cookie = session_cookie(&headers);

    let out = plane
        .http
        .delete(plane.url("/v1/auth/session"))
        .header("origin", &plane.base)
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(out.status(), 200);

    // Server side, not just a cleared cookie: the same cookie must now fail.
    let after = plane
        .http
        .get(plane.url("/v1/auth/session"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(
        after.status(),
        401,
        "the session outlived the sign-out, so clearing the cookie was the whole \
         of it and a copied cookie still works"
    );

    // And the admin token still works, because signing out of a browser must not
    // touch the credential that opened it.
    let (status, _) = sign_in(&plane, common::ADMIN_TOKEN).await;
    assert_eq!(
        status, 200,
        "signing out invalidated the admin token itself"
    );
}

#[tokio::test]
async fn a_bearer_token_is_not_a_session_on_its_own() {
    // The two paths stay separate. Presenting the token as a bearer header must
    // not act as a session cookie: the exchange is deliberate, and a page that
    // accepted either would be a page that accepts a long-lived credential from
    // anything that can set a header.
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let response = plane
        .http
        .get(plane.url("/v1/auth/session"))
        .bearer_auth(common::ADMIN_TOKEN)
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(response.status(), 401, "a bearer token acted as a session");

    // A client that does not follow redirects, because the gate answers with one
    // and `plane.http` would chase it to the sign-in page's legitimate 200.
    let page = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build a client")
        .get(plane.url("/app"))
        .bearer_auth(common::ADMIN_TOKEN)
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(page.status(), 303, "a bearer token reached the dashboard");
    assert_eq!(
        page.headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/signin"),
        "the gate did not send them to sign in"
    );
}

#[tokio::test]
async fn a_session_only_reaches_its_own_account() {
    let db = require_db!();
    let plane =
        Plane::start_with_env(&db, &[("PLANE_PROVISION_SECRET", common::PROVISION_SECRET)]).await;

    let (status, other) = plane
        .send(
            reqwest::Method::POST,
            "/v1/accounts",
            Some(json!({
                "name": "Someone Else",
                "provision_secret": common::PROVISION_SECRET
            })),
            None,
        )
        .await;
    assert_eq!(status, 200, "could not provision a second account: {other}");
    let their_token = other["admin_token"].as_str().expect("a token").to_owned();
    let their_account = other["account_id"].as_str().expect("an id").to_owned();

    let (status, headers) = sign_in(&plane, &their_token).await;
    assert_eq!(status, 200);
    let cookie = session_cookie(&headers);

    let body = plane
        .http
        .get(plane.url("/v1/auth/session"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .expect("request reaches the plane")
        .json::<serde_json::Value>()
        .await
        .expect("a session view");
    assert_eq!(
        body["account_id"], their_account,
        "the session landed on the wrong account"
    );
    assert_ne!(body["account_id"], common::ACCOUNT);
}
