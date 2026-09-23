//! Human sign-in, against a real database and the real binary.
//!
//! The unit tests in `people` cover cookie parsing, origin comparison and email
//! shaping. What matters here is the whole exchange: that a code only reaches a
//! known address, that redeeming it yields a session a browser can hold safely,
//! that the session actually gates anything, and that the endpoint does not
//! answer questions about who has an account.

mod common;

use common::Plane;
use serde_json::json;

/// Create a user and attach them to the bootstrap account.
///
/// Access is granted by hand, so this is what an operator does after approving
/// an access request. There is deliberately no endpoint for it yet.
async fn invite(plane: &Plane, email: &str) -> String {
    let user_id = format!("usr_{}", email.replace(['@', '.'], "_"));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&plane.db_url)
        .await
        .expect("connect to the scratch database");
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
    user_id
}

/// Ask for a code and read it out of the development response.
async fn request_code(plane: &Plane, email: &str) -> (reqwest::StatusCode, serde_json::Value) {
    let response = plane
        .http
        .post(plane.url("/v1/auth/code"))
        .header("origin", &plane.base)
        .json(&json!({ "email": email }))
        .send()
        .await
        .expect("request reaches the plane");
    let status = response.status();
    let body = response
        .json::<serde_json::Value>()
        .await
        .unwrap_or(serde_json::Value::Null);
    (status, body)
}

async fn redeem(
    plane: &Plane,
    email: &str,
    code: &str,
) -> (reqwest::StatusCode, reqwest::header::HeaderMap) {
    let response = plane
        .http
        .post(plane.url("/v1/auth/verify"))
        .header("origin", &plane.base)
        .json(&json!({ "email": email, "code": code }))
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

#[tokio::test]
async fn an_address_signs_in_however_it_is_capitalised() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    // Invited in one capitalisation, as a person types it into a form.
    invite(&plane, "Person@Example.com").await;

    // Typed back in another, as the same person types it a week later. The
    // column is CITEXT for exactly this, but a bound parameter is `text` and
    // Postgres resolves `citext = text` by casting the column down to text,
    // which is case sensitive. Without an explicit `::citext` on the parameter
    // this fails in the cruellest way available: the endpoint answers unknown
    // addresses identically to known ones, so the person is told a code was
    // sent and waits for mail that was never generated.
    let (status, body) = request_code(&plane, "person@example.com").await;
    assert_eq!(status, 200);
    let code = body["development_code"]
        .as_str()
        .expect("a differently cased address must still get a code")
        .to_owned();

    let (status, headers) = redeem(&plane, "PERSON@EXAMPLE.COM", &code).await;
    assert_eq!(
        status, 200,
        "a code must redeem whatever capitalisation it is presented with"
    );

    // And the session it produced is a real one.
    let cookie = session_cookie(&headers);
    let response = plane
        .http
        .get(plane.url("/v1/auth/session"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(response.status(), 200);
    let session = response
        .json::<serde_json::Value>()
        .await
        .expect("a session body");
    assert_eq!(
        session["email"], "Person@Example.com",
        "the address is stored as it was invited, not as it was typed"
    );
}

#[tokio::test]
async fn a_code_becomes_a_session_that_gates_the_account() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    invite(&plane, "person@example.com").await;

    let (status, body) = request_code(&plane, "person@example.com").await;
    assert_eq!(status, 200, "{body}");
    let code = body["development_code"]
        .as_str()
        .expect("a debug build returns the code when email is unconfigured")
        .to_owned();

    let (status, headers) = redeem(&plane, "person@example.com", &code).await;
    assert_eq!(status, 200);

    let cookie = headers
        .get(reqwest::header::SET_COOKIE)
        .expect("a session cookie")
        .to_str()
        .expect("ascii");
    // The properties that make this safe to hold in a browser.
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Lax"), "{cookie}");
    assert!(
        !cookie.contains("Secure"),
        "the test plane is http, so Secure would make the cookie unusable"
    );

    let response = plane
        .http
        .get(plane.url("/v1/auth/session"))
        .header("cookie", session_cookie(&headers))
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(response.status(), 200);
    let view: serde_json::Value = response.json().await.expect("json");
    assert_eq!(view["email"], "person@example.com");
    assert_eq!(view["account_id"], common::ACCOUNT);
    assert_eq!(view["role"], "owner");
}

#[tokio::test]
async fn the_session_is_stored_only_as_a_digest() {
    // A database disclosure must not hand over live sessions, which is the
    // same property `account_tokens` already has.
    let db = require_db!();
    let plane = Plane::start(&db).await;
    invite(&plane, "person@example.com").await;

    let (_, body) = request_code(&plane, "person@example.com").await;
    let code = body["development_code"]
        .as_str()
        .expect("a code")
        .to_owned();
    let (_, headers) = redeem(&plane, "person@example.com", &code).await;
    let cookie = session_cookie(&headers);
    let token = cookie.split_once('=').expect("name=value").1.to_owned();

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&plane.db_url)
        .await
        .expect("connect");
    let stored: Vec<String> = sqlx::query_scalar("SELECT session_sha256 FROM user_sessions")
        .fetch_all(&pool)
        .await
        .expect("read sessions");
    pool.close().await;

    assert_eq!(stored.len(), 1);
    assert!(!token.is_empty());
    assert!(
        !stored.iter().any(|value| value == &token),
        "the raw session token is in the database"
    );
}

#[tokio::test]
async fn an_unknown_address_is_answered_exactly_like_a_known_one() {
    // Otherwise the endpoint is an account-existence oracle, which is a thing
    // an anonymous caller can mine.
    let db = require_db!();
    let plane = Plane::start(&db).await;
    invite(&plane, "known@example.com").await;

    let (known_status, known_body) = request_code(&plane, "known@example.com").await;
    let (unknown_status, unknown_body) = request_code(&plane, "stranger@example.com").await;

    assert_eq!(known_status, unknown_status);
    assert_eq!(known_body["status"], "sent");
    assert_eq!(unknown_body["status"], "sent");
    assert!(
        unknown_body["development_code"].is_null(),
        "no code exists for an address nobody invited"
    );
}

#[tokio::test]
async fn a_state_changing_route_refuses_without_a_trusted_origin() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    invite(&plane, "person@example.com").await;

    for origin in [None, Some("https://evil.example"), Some("null")] {
        let mut request = plane
            .http
            .post(plane.url("/v1/auth/code"))
            .json(&json!({ "email": "person@example.com" }));
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
async fn a_wrong_code_is_bounded_and_then_spent() {
    // Six digits is a million values. Without an attempt bound it is
    // brute-forceable in an afternoon.
    let db = require_db!();
    let plane = Plane::start(&db).await;
    invite(&plane, "person@example.com").await;

    let (_, body) = request_code(&plane, "person@example.com").await;
    let code = body["development_code"]
        .as_str()
        .expect("a code")
        .to_owned();

    // Five wrong guesses.
    for attempt in 0..5 {
        let wrong = format!("{:06}", (attempt * 7 + 1) % 1_000_000);
        assert_ne!(wrong, code, "the test must actually guess wrong");
        let (status, _) = redeem(&plane, "person@example.com", &wrong).await;
        assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    }

    // The real code no longer works: the attempts are spent, not reset.
    let (status, _) = redeem(&plane, "person@example.com", &code).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNAUTHORIZED,
        "a code must be spent by exhausted attempts, not survive them"
    );
}

#[tokio::test]
async fn a_code_cannot_be_redeemed_twice() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    invite(&plane, "person@example.com").await;

    let (_, body) = request_code(&plane, "person@example.com").await;
    let code = body["development_code"]
        .as_str()
        .expect("a code")
        .to_owned();

    let (first, _) = redeem(&plane, "person@example.com", &code).await;
    assert_eq!(first, 200);

    let (second, _) = redeem(&plane, "person@example.com", &code).await;
    assert_eq!(
        second,
        reqwest::StatusCode::UNAUTHORIZED,
        "a redeemed code must not work again"
    );
}

#[tokio::test]
async fn asking_again_immediately_does_not_send_a_second_code() {
    // The cooldown is enforced in SQL rather than a handler, so it holds even
    // when two requests race. Without it this endpoint mails someone endlessly.
    let db = require_db!();
    let plane = Plane::start(&db).await;
    invite(&plane, "person@example.com").await;

    let (_, first) = request_code(&plane, "person@example.com").await;
    assert!(first["development_code"].is_string());

    let (status, second) = request_code(&plane, "person@example.com").await;
    assert_eq!(status, 200, "the answer must not reveal the cooldown");
    assert!(
        second["development_code"].is_null(),
        "a second code was issued inside the cooldown"
    );
}

#[tokio::test]
async fn signing_out_ends_the_session_immediately() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    invite(&plane, "person@example.com").await;

    let (_, body) = request_code(&plane, "person@example.com").await;
    let code = body["development_code"]
        .as_str()
        .expect("a code")
        .to_owned();
    let (_, headers) = redeem(&plane, "person@example.com", &code).await;
    let cookie = session_cookie(&headers);

    let response = plane
        .http
        .delete(plane.url("/v1/auth/session"))
        .header("cookie", &cookie)
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(response.status(), 200);

    let response = plane
        .http
        .get(plane.url("/v1/auth/session"))
        .header("cookie", &cookie)
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "the session must be gone from the server, not just from the browser"
    );
}

#[tokio::test]
async fn a_session_is_required_and_a_bearer_token_is_not_one() {
    // The two credential systems are separate on purpose. An admin token is a
    // machine credential with no person behind it, so it must not open a
    // human route.
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let anonymous = plane
        .http
        .get(plane.url("/v1/auth/session"))
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(anonymous.status(), reqwest::StatusCode::UNAUTHORIZED);

    let with_bearer = plane
        .http
        .get(plane.url("/v1/auth/session"))
        .bearer_auth(common::ADMIN_TOKEN)
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(
        with_bearer.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "an admin token is not a person"
    );

    let forged = plane
        .http
        .get(plane.url("/v1/auth/session"))
        .header("cookie", "usagekit_session=not_a_real_session")
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(forged.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_disabled_person_cannot_sign_in_or_keep_a_session() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let user_id = invite(&plane, "person@example.com").await;

    let (_, body) = request_code(&plane, "person@example.com").await;
    let code = body["development_code"]
        .as_str()
        .expect("a code")
        .to_owned();
    let (_, headers) = redeem(&plane, "person@example.com", &code).await;
    let cookie = session_cookie(&headers);

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&plane.db_url)
        .await
        .expect("connect");
    sqlx::query("UPDATE users SET disabled_at = NOW() WHERE id = $1")
        .bind(&user_id)
        .execute(&pool)
        .await
        .expect("disable the user");
    pool.close().await;

    // An existing session stops resolving, without needing to be deleted.
    let response = plane
        .http
        .get(plane.url("/v1/auth/session"))
        .header("cookie", &cookie)
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    // And no new code is issued.
    let (_, body) = request_code(&plane, "person@example.com").await;
    assert!(body["development_code"].is_null());
}
