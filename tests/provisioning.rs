//! Creating an account and the person who signs in to it.
//!
//! This is the only path from an empty database to somebody able to open the
//! dashboard. It used to be the access queue, fed by a form on the marketing
//! site; that site is a separate repository now and the queue went with it, so
//! provisioning grew an `owner_email` and does the whole job in one request.
//!
//! The round trip below is the test that matters. Everything else about
//! provisioning, including the operator secret and its rate limit, is covered
//! in the billing suite where those routes were first written.

mod common;

use common::Plane;
use serde_json::json;

const WITH_SECRET: [(&str, &str); 1] = [("PLANE_PROVISION_SECRET", common::PROVISION_SECRET)];

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build a client")
}

async fn provision(
    plane: &Plane,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    plane
        .send(reqwest::Method::POST, "/v1/accounts", Some(body), None)
        .await
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
        .expect("count");
    pool.close().await;
    count
}

#[tokio::test]
async fn a_provisioned_owner_can_sign_in_to_the_account() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;

    let (status, created) = provision(
        &plane,
        json!({
            "name": "Northwind Tools",
            "provision_secret": common::PROVISION_SECRET,
            "owner_email": "  Founder@Northwind.Example  "
        }),
    )
    .await;
    assert_eq!(status, 200, "provisioning failed: {created}");
    assert_eq!(
        created["owner_email"], "Founder@Northwind.Example",
        "the address should be trimmed and reported back"
    );
    let account_id = created["account_id"]
        .as_str()
        .expect("an account")
        .to_owned();

    // The half that used to be impossible without writing rows by hand: that
    // person signs in and reaches their own dashboard. Deliberately using a
    // different capitalisation, because the lookup is case insensitive only
    // when the parameter is cast, and that is easy to lose.
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
        "a provisioned owner must be able to get a code; without one the \
         account exists and nobody can reach it",
    );
    let code: String = body[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    assert_eq!(code.len(), 6);

    let verified = client()
        .post(plane.url("/signin/verify"))
        .header(reqwest::header::ORIGIN, &plane.base)
        .form(&[("email", "FOUNDER@NORTHWIND.EXAMPLE"), ("code", &code)])
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(
        verified.status(),
        303,
        "the provisioned owner could not sign in"
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

    // The tokens still work and are scoped to the new account.
    let (status, _) = plane
        .send(
            reqwest::Method::GET,
            "/v1/tenants",
            None,
            created["admin_token"].as_str(),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(count(&plane, "SELECT COUNT(*) FROM memberships").await, 1);
    let _ = account_id;
}

#[tokio::test]
async fn an_account_with_no_owner_creates_no_person() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;

    // An account that only serves machines needs nobody able to sign in, and
    // inventing a person for it would be worse than leaving it without one.
    let (status, created) = provision(
        &plane,
        json!({"name": "Machines Only", "provision_secret": common::PROVISION_SECRET}),
    )
    .await;
    assert_eq!(status, 200);
    assert!(created["owner_email"].is_null());
    assert_eq!(count(&plane, "SELECT COUNT(*) FROM users").await, 0);
    assert_eq!(count(&plane, "SELECT COUNT(*) FROM memberships").await, 0);

    // The tokens are still usable, which is the point of that shape.
    let (status, _) = plane
        .send(
            reqwest::Method::GET,
            "/v1/tenants",
            None,
            created["admin_token"].as_str(),
        )
        .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn an_unusable_owner_address_creates_nothing_at_all() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;

    for attempt in [
        "no-at-sign",
        "two@at@signs",
        "has space@example.com",
        "@nolocal",
    ] {
        let (status, _) = provision(
            &plane,
            json!({
                "name": "Northwind",
                "provision_secret": common::PROVISION_SECRET,
                "owner_email": attempt
            }),
        )
        .await;
        assert_eq!(status, 400, "{attempt} was accepted");
    }

    // Refused before the transaction opens, so there is no account left behind
    // with nobody able to reach it.
    assert_eq!(
        count(&plane, "SELECT COUNT(*) FROM accounts").await,
        1,
        "expected only the bootstrap account"
    );
    assert_eq!(count(&plane, "SELECT COUNT(*) FROM users").await, 0);

    // A blank address is absence rather than an error, since the field is
    // optional and an empty form field is how absence usually arrives.
    let (status, created) = provision(
        &plane,
        json!({
            "name": "Northwind",
            "provision_secret": common::PROVISION_SECRET,
            "owner_email": "   "
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert!(created["owner_email"].is_null());
}

#[tokio::test]
async fn one_person_can_own_more_than_one_account() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;

    for name in ["First Co", "Second Co"] {
        let (status, _) = provision(
            &plane,
            json!({
                "name": name,
                "provision_secret": common::PROVISION_SECRET,
                "owner_email": "founder@example.com"
            }),
        )
        .await;
        assert_eq!(status, 200, "provisioning {name} failed");
    }

    // One person, two memberships. The second provision reuses the user rather
    // than failing on the unique address, which is what makes an operator able
    // to set up a second account for somebody without a special case.
    assert_eq!(count(&plane, "SELECT COUNT(*) FROM users").await, 1);
    assert_eq!(count(&plane, "SELECT COUNT(*) FROM memberships").await, 2);
}
