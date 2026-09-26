//! Creating an account, and reaching its dashboard afterwards.
//!
//! This is the only path from an empty database to somebody able to open the
//! dashboard, and it is now one request: provisioning returns the account's
//! `admin` token, and that token is what signs in. There is no person to create,
//! no password to issue and no mail to send, so there is nothing else to arrange.

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
async fn a_provisioned_account_can_be_opened_in_a_browser() {
    // The whole path, in one request and one form post. Before the dashboard was
    // authenticated by its own token this took a person, a password, and in the
    // version before that a mail service.
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;

    let (status, created) = provision(
        &plane,
        json!({"name": "Northwind Tools", "provision_secret": common::PROVISION_SECRET}),
    )
    .await;
    assert_eq!(status, 200, "provisioning failed: {created}");
    let admin = created["admin_token"].as_str().expect("a token").to_owned();
    let account_id = created["account_id"].as_str().expect("an id").to_owned();

    // Nothing about a person comes back, because there is no longer any such
    // thing to create.
    for gone in ["owner_email", "owner_password", "owner_sign_in_code"] {
        assert!(
            created.get(gone).is_none(),
            "{gone} is still in the provisioning response: {created}"
        );
    }

    let signed_in = client()
        .post(plane.url("/signin"))
        .header(reqwest::header::ORIGIN, &plane.base)
        .form(&[("token", admin.as_str())])
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(
        signed_in.status(),
        303,
        "the provisioned admin token could not open the dashboard"
    );
    let cookie = signed_in
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
    assert_eq!(dashboard.status(), 200, "could not reach /app");
    let page = dashboard.text().await.expect("a body");
    assert!(
        page.contains("Northwind Tools"),
        "the dashboard is not showing the account that was just created"
    );
    assert!(
        page.contains(&account_id),
        "the dashboard does not show the account id, which is what an operator \
         needs to run anything against /v1/*"
    );

    // The token still works as a bearer credential too. Exchanging it for a
    // session must not consume it.
    let (status, _) = plane
        .send(reqwest::Method::GET, "/v1/tenants", None, Some(&admin))
        .await;
    assert_eq!(status, 200, "signing in spent the admin token");
}

#[tokio::test]
async fn provisioning_creates_no_identity_tables_to_populate() {
    // The tables went with the credential they served. This asserts they are
    // actually gone rather than dormant, because a table nothing can write to is
    // a trap for whoever reads the schema next.
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;

    let (status, _) = provision(
        &plane,
        json!({"name": "Northwind Tools", "provision_secret": common::PROVISION_SECRET}),
    )
    .await;
    assert_eq!(status, 200);

    for gone in ["users", "memberships", "user_login_codes", "user_sessions"] {
        let present = count(
            &plane,
            &format!(
                "SELECT COUNT(*) FROM information_schema.tables \
                 WHERE table_schema = 'public' AND table_name = '{gone}'"
            ),
        )
        .await;
        assert_eq!(present, 0, "{gone} still exists");
    }
}

#[tokio::test]
async fn an_unusable_name_creates_nothing_at_all() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;

    for attempt in ["", "   "] {
        let (status, _) = provision(
            &plane,
            json!({"name": attempt, "provision_secret": common::PROVISION_SECRET}),
        )
        .await;
        assert_eq!(status, 400, "{attempt:?} was accepted");
    }

    // Refused before the transaction opens, so there is no account left behind
    // with nothing usable in it. One account exists: the bootstrap one.
    assert_eq!(count(&plane, "SELECT COUNT(*) FROM accounts").await, 1);
}

#[tokio::test]
async fn provisioning_is_closed_unless_a_secret_is_set() {
    let db = require_db!();
    // Deliberately started without `PLANE_PROVISION_SECRET`.
    let plane = Plane::start(&db).await;

    let (status, _) = provision(
        &plane,
        json!({"name": "Northwind Tools", "provision_secret": common::PROVISION_SECRET}),
    )
    .await;
    assert_eq!(
        status, 404,
        "a deployment with no provisioning secret is an open account factory"
    );
    assert_eq!(count(&plane, "SELECT COUNT(*) FROM accounts").await, 1);
}

#[tokio::test]
async fn each_account_gets_its_own_tokens() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &WITH_SECRET).await;

    let mut tokens = Vec::new();
    for name in ["First", "Second"] {
        let (status, created) = provision(
            &plane,
            json!({"name": name, "provision_secret": common::PROVISION_SECRET}),
        )
        .await;
        assert_eq!(status, 200);
        tokens.push((
            created["account_id"].as_str().expect("an id").to_owned(),
            created["admin_token"].as_str().expect("a token").to_owned(),
            created["edge_token"].as_str().expect("a token").to_owned(),
        ));
    }

    assert_ne!(
        tokens[0].1, tokens[1].1,
        "two accounts share an admin token"
    );
    assert_ne!(tokens[0].2, tokens[1].2, "two accounts share an edge token");
    assert_ne!(tokens[0].0, tokens[1].0);
}
