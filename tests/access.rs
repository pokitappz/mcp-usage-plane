//! Deciding access requests, against a real database and the real binary.
//!
//! The test that matters here is the round trip: somebody submits the form on
//! the landing page, an operator grants it, and that person signs in and
//! reaches their dashboard. Every other test in this file guards one way that
//! loop can be left half-open, which was its previous state: the form wrote a
//! row, and nothing in the service could act on it.

mod common;

use common::Plane;

/// The environment that opens the operator routes at all.
const WITH_SECRET: [(&str, &str); 1] = [("PLANE_PROVISION_SECRET", common::PROVISION_SECRET)];

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build a client")
}

/// Submit the landing page form, the way a visitor does.
async fn request_access(plane: &Plane, email: &str, company: Option<&str>) {
    let mut form = vec![("email", email)];
    if let Some(company) = company {
        form.push(("company", company));
    }
    let response = client()
        .post(plane.url("/request-access"))
        .header(reqwest::header::ORIGIN, &plane.base)
        .form(&form)
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(response.status(), 303, "the access form rejected {email}");
}

/// Call an operator route with the secret in the header.
async fn operator(
    plane: &Plane,
    method: reqwest::Method,
    path: &str,
    secret: Option<&str>,
) -> (reqwest::StatusCode, serde_json::Value) {
    let mut request = client().request(method, plane.url(path));
    if let Some(secret) = secret {
        request = request.header("x-provision-secret", secret);
    }
    let response = request.send().await.expect("request reaches the plane");
    let status = response.status();
    let body = response
        .json::<serde_json::Value>()
        .await
        .unwrap_or(serde_json::Value::Null);
    (status, body)
}

async fn pending(plane: &Plane) -> Vec<serde_json::Value> {
    let (status, body) = operator(
        plane,
        reqwest::Method::GET,
        "/v1/access-requests",
        Some(common::PROVISION_SECRET),
    )
    .await;
    assert_eq!(status, 200, "listing the queue failed");
    body.as_array().expect("an array").clone()
}

async fn count(plane: &Plane, sql: &str) -> i64 {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&plane.db_url)
        .await
        .expect("connect to the scratch database");
    let count: i64 = sqlx::query_scalar(sql)
        .fetch_one(&pool)
        .await
        .expect("count rows");
    pool.close().await;
    count
}

// ------------------------------------------------------------- the round trip

#[tokio::test]
async fn a_request_becomes_an_account_its_owner_can_sign_in_to() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;

    // 1. A visitor asks, through the real form on the real landing page.
    request_access(&plane, "founder@northwind.example", Some("Northwind Tools")).await;

    // 2. It is in the operator's queue, and nothing has been granted.
    let queue = pending(&plane).await;
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0]["email"], "founder@northwind.example");
    assert_eq!(queue[0]["company"], "Northwind Tools");
    assert!(queue[0]["granted_at"].is_null());
    assert!(
        queue[0]["existing_account"].is_null(),
        "a first-time address should not be reported as already having an account"
    );
    let id = queue[0]["id"].as_i64().expect("an id");

    // 3. The operator grants it.
    let (status, granted) = operator(
        &plane,
        reqwest::Method::POST,
        &format!("/v1/access-requests/{id}/grant"),
        Some(common::PROVISION_SECRET),
    )
    .await;
    assert_eq!(status, 200, "granting failed: {granted}");
    assert_eq!(
        granted["name"], "Northwind Tools",
        "the account should be named after the company they gave"
    );
    let account_id = granted["account_id"]
        .as_str()
        .expect("an account")
        .to_owned();

    // 4. The queue is empty and the row records what happened.
    assert!(pending(&plane).await.is_empty(), "the queue did not drain");
    let (_, all) = operator(
        &plane,
        reqwest::Method::GET,
        "/v1/access-requests?state=granted",
        Some(common::PROVISION_SECRET),
    )
    .await;
    let all = all.as_array().expect("an array");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["granted_account"], account_id.as_str());

    // 5. And the part that was impossible before: that person signs in and
    //    reaches their own dashboard. This is the whole point of the feature,
    //    so it is exercised end to end rather than asserted from the rows.
    let started = client()
        .post(plane.url("/signin"))
        .header(reqwest::header::ORIGIN, &plane.base)
        .form(&[("email", "founder@northwind.example")])
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(started.status(), 200);
    let body = started.text().await.expect("a body");
    let marker = "<strong>";
    let at = body.find(marker).map(|at| at + marker.len()).expect(
        "a granted address must be able to get a code; \
         without one the account exists and nobody can reach it",
    );
    let code: String = body[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    assert_eq!(code.len(), 6);

    let verified = client()
        .post(plane.url("/signin/verify"))
        .header(reqwest::header::ORIGIN, &plane.base)
        .form(&[("email", "founder@northwind.example"), ("code", &code)])
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(
        verified.status(),
        303,
        "the granted owner could not sign in"
    );
    let cookie = verified
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("a session cookie")
        .to_str()
        .expect("ascii")
        .split(';')
        .next()
        .expect("a name=value pair")
        .to_owned();

    let dashboard = client()
        .get(plane.url("/app"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(dashboard.status(), 200, "the owner could not reach /app");
    let page = dashboard.text().await.expect("a body");
    assert!(
        page.contains("Northwind Tools"),
        "the dashboard is not showing the account that was just created"
    );
    assert!(page.contains("founder@northwind.example"));

    // They own it, so they can mint their own credentials. Granting minted
    // none, deliberately: the dashboard is the one place a credential can be
    // shown to the person who will hold it.
    assert_eq!(
        count(
            &plane,
            &format!("SELECT COUNT(*) FROM account_tokens WHERE account_id = '{account_id}'")
        )
        .await,
        0,
        "granting should not mint credentials nobody asked for"
    );
}

// ----------------------------------------------------------------- deciding

#[tokio::test]
async fn granting_twice_refuses_and_creates_exactly_one_account() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;
    request_access(&plane, "founder@northwind.example", None).await;
    let id = pending(&plane).await[0]["id"].as_i64().expect("an id");

    let path = format!("/v1/access-requests/{id}/grant");
    let (first, _) = operator(
        &plane,
        reqwest::Method::POST,
        &path,
        Some(common::PROVISION_SECRET),
    )
    .await;
    assert_eq!(first, 200);

    // The second attempt is the dangerous one: an operator refreshing a page,
    // or two operators working the queue, must not produce a second account
    // that belongs to nobody.
    let (second, body) = operator(
        &plane,
        reqwest::Method::POST,
        &path,
        Some(common::PROVISION_SECRET),
    )
    .await;
    assert_eq!(second, 409, "a second grant was accepted: {body}");

    assert_eq!(
        count(&plane, "SELECT COUNT(*) FROM accounts").await,
        2,
        "expected the bootstrap account and exactly one granted account"
    );
    assert_eq!(count(&plane, "SELECT COUNT(*) FROM users").await, 1);
    assert_eq!(count(&plane, "SELECT COUNT(*) FROM memberships").await, 1);
}

#[tokio::test]
async fn a_granted_request_stays_granted_even_after_its_person_is_removed() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;
    request_access(&plane, "founder@northwind.example", Some("Northwind")).await;
    let id = pending(&plane).await[0]["id"].as_i64().expect("an id");

    let path = format!("/v1/access-requests/{id}/grant");
    let (status, granted) = operator(
        &plane,
        reqwest::Method::POST,
        &path,
        Some(common::PROVISION_SECRET),
    )
    .await;
    assert_eq!(status, 200);
    let first_account = granted["account_id"]
        .as_str()
        .expect("an account")
        .to_owned();

    // Offboard the person. Their membership cascades away with them, so the
    // duplicate-address check stops firing and the decision on the request is
    // the only thing still saying this was handled. Without that check an
    // operator working an old queue creates a second account and overwrites
    // `granted_account`, orphaning the first one with nobody able to sign in.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&plane.db_url)
        .await
        .expect("connect to the scratch database");
    sqlx::query("DELETE FROM users WHERE email = 'founder@northwind.example'::citext")
        .execute(&pool)
        .await
        .expect("delete the user");
    pool.close().await;
    assert_eq!(count(&plane, "SELECT COUNT(*) FROM memberships").await, 0);

    let (status, body) = operator(
        &plane,
        reqwest::Method::POST,
        &path,
        Some(common::PROVISION_SECRET),
    )
    .await;
    assert_eq!(
        status, 409,
        "an already granted request was granted again: {body}"
    );

    assert_eq!(
        count(&plane, "SELECT COUNT(*) FROM accounts").await,
        2,
        "expected the bootstrap account and the one already granted"
    );
    let (_, granted_now) = operator(
        &plane,
        reqwest::Method::GET,
        "/v1/access-requests?state=granted",
        Some(common::PROVISION_SECRET),
    )
    .await;
    assert_eq!(
        granted_now.as_array().expect("an array")[0]["granted_account"],
        first_account.as_str(),
        "the request should still point at the account it originally created"
    );
}

#[tokio::test]
async fn a_declined_request_leaves_the_queue_and_cannot_then_be_granted() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;
    request_access(&plane, "nope@example.com", None).await;
    let id = pending(&plane).await[0]["id"].as_i64().expect("an id");

    let (status, _) = operator(
        &plane,
        reqwest::Method::POST,
        &format!("/v1/access-requests/{id}/decline"),
        Some(common::PROVISION_SECRET),
    )
    .await;
    assert_eq!(status, 200);

    // A queue you can only add to is a queue that grows forever. Declining has
    // to actually remove it from the operator's view.
    assert!(
        pending(&plane).await.is_empty(),
        "a declined request is still in the queue"
    );

    let (status, body) = operator(
        &plane,
        reqwest::Method::POST,
        &format!("/v1/access-requests/{id}/grant"),
        Some(common::PROVISION_SECRET),
    )
    .await;
    assert_eq!(status, 409, "a declined request was granted anyway: {body}");
    assert_eq!(
        count(&plane, "SELECT COUNT(*) FROM users").await,
        0,
        "declining then granting created a person"
    );

    // Declining twice is a conflict, not a silent success.
    let (status, _) = operator(
        &plane,
        reqwest::Method::POST,
        &format!("/v1/access-requests/{id}/decline"),
        Some(common::PROVISION_SECRET),
    )
    .await;
    assert_eq!(status, 409);
}

#[tokio::test]
async fn an_address_that_already_has_an_account_is_refused_with_the_reason() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;

    request_access(&plane, "founder@northwind.example", Some("Northwind")).await;
    let first = pending(&plane).await[0]["id"].as_i64().expect("an id");
    let (status, granted) = operator(
        &plane,
        reqwest::Method::POST,
        &format!("/v1/access-requests/{first}/grant"),
        Some(common::PROVISION_SECRET),
    )
    .await;
    assert_eq!(status, 200);
    let account_id = granted["account_id"]
        .as_str()
        .expect("an account")
        .to_owned();

    // The same person asks again, perhaps for a second company. The dashboard
    // has no account switcher and a session resolves to the oldest membership,
    // so a second account would be one they could never see.
    request_access(&plane, "Founder@Northwind.Example", Some("Second Co")).await;
    let queue = pending(&plane).await;
    assert_eq!(queue.len(), 1);
    assert_eq!(
        queue[0]["existing_account"],
        account_id.as_str(),
        "the queue should show the duplicate before an operator tries to grant it"
    );

    let second = queue[0]["id"].as_i64().expect("an id");
    let (status, body) = operator(
        &plane,
        reqwest::Method::POST,
        &format!("/v1/access-requests/{second}/grant"),
        Some(common::PROVISION_SECRET),
    )
    .await;
    assert_eq!(status, 409, "a second account was created for one person");
    let message = body["error"].as_str().unwrap_or_default();
    assert!(
        message.contains(&account_id),
        "the refusal should name the account they are already on: {message}"
    );

    assert_eq!(
        count(&plane, "SELECT COUNT(*) FROM accounts").await,
        2,
        "expected the bootstrap account and one granted account"
    );
}

#[tokio::test]
async fn an_account_is_never_left_nameless() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;

    // No company given, and a blank one, which is what an optional text field
    // produces when somebody tabs through it.
    request_access(&plane, "solo@example.com", None).await;
    request_access(&plane, "blank@example.com", Some("   ")).await;

    for entry in pending(&plane).await {
        let id = entry["id"].as_i64().expect("an id");
        let (status, granted) = operator(
            &plane,
            reqwest::Method::POST,
            &format!("/v1/access-requests/{id}/grant"),
            Some(common::PROVISION_SECRET),
        )
        .await;
        assert_eq!(status, 200);
        let name = granted["name"].as_str().expect("a name");
        assert!(!name.trim().is_empty(), "account {id} was named nothing");
        assert_eq!(
            name,
            granted["email"].as_str().expect("an email"),
            "with no company the address is the readable fallback"
        );
    }
}

// ------------------------------------------------------------------- access

#[tokio::test]
async fn the_queue_is_closed_without_the_operator_secret() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;
    request_access(&plane, "founder@northwind.example", None).await;

    for (label, secret) in [("none", None), ("wrong", Some("not-the-secret"))] {
        let (status, _) =
            operator(&plane, reqwest::Method::GET, "/v1/access-requests", secret).await;
        assert_eq!(status, 401, "the queue was readable with a {label} secret");

        let (status, _) = operator(
            &plane,
            reqwest::Method::POST,
            "/v1/access-requests/1/grant",
            secret,
        )
        .await;
        assert_eq!(status, 401, "granting worked with a {label} secret");
    }

    assert_eq!(
        count(&plane, "SELECT COUNT(*) FROM users").await,
        0,
        "an unauthenticated grant created a person"
    );
}

#[tokio::test]
async fn the_queue_does_not_exist_unless_a_secret_is_configured() {
    let db = require_db!();
    // No PLANE_PROVISION_SECRET, which is the default for a fresh deployment.
    let plane = Plane::start(&db).await;

    // 404 rather than 401: an unconfigured deployment should not advertise
    // that these routes are there to be guessed at.
    for (method, path) in [
        (reqwest::Method::GET, "/v1/access-requests"),
        (reqwest::Method::POST, "/v1/access-requests/1/grant"),
        (reqwest::Method::POST, "/v1/access-requests/1/decline"),
    ] {
        let (status, _) = operator(&plane, method, path, Some("anything")).await;
        assert_eq!(
            status, 404,
            "{path} answered on a deployment with no secret"
        );
    }
}

#[tokio::test]
async fn guessing_the_secret_against_the_queue_is_bounded() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;

    // A different guess every time, which is the case a budget keyed on the
    // presented secret would fail to bound: each new value would get its own
    // fresh allowance. These routes share the provisioning budget, on a fixed
    // key, precisely so a guesser cannot outrun it by varying the guess.
    let mut refused = false;
    for attempt in 0..60 {
        let (status, _) = operator(
            &plane,
            reqwest::Method::GET,
            "/v1/access-requests",
            Some(&format!("guess-{attempt}")),
        )
        .await;
        if status == 429 {
            refused = true;
            break;
        }
    }
    assert!(
        refused,
        "60 distinct guesses were all answered; the budget is not bounding anything"
    );
}

#[tokio::test]
async fn an_unknown_request_is_not_confused_with_a_decided_one() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;

    for action in ["grant", "decline"] {
        let (status, _) = operator(
            &plane,
            reqwest::Method::POST,
            &format!("/v1/access-requests/999999/{action}"),
            Some(common::PROVISION_SECRET),
        )
        .await;
        assert_eq!(status, 404, "{action} on a row that does not exist");
    }
}

#[tokio::test]
async fn listing_states_are_refused_rather_than_interpolated() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;
    request_access(&plane, "founder@northwind.example", None).await;

    // The state picks a SQL fragment, so anything outside the allowlist has to
    // be refused rather than escaped.
    for attempt in ["weekly", "TRUE%3B%20DROP%20TABLE%20access_requests%3B%20--"] {
        let (status, _) = operator(
            &plane,
            reqwest::Method::GET,
            &format!("/v1/access-requests?state={attempt}"),
            Some(common::PROVISION_SECRET),
        )
        .await;
        assert_eq!(status, 400, "state {attempt:?} was accepted");
    }

    // And the table is still there.
    assert_eq!(
        count(&plane, "SELECT COUNT(*) FROM access_requests").await,
        1
    );
}
