//! Export, reconciliation and the plane's own billing.

mod common;

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::Plane;
use hmac::digest::KeyInit as _;
use hmac::{Hmac, Mac};
use reqwest::Method;
use serde_json::json;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A Stripe meter-events endpoint the test can steer.
#[derive(Clone)]
struct FakeStripe {
    /// Status returned to every request.
    status: Arc<AtomicU16>,
    /// Form bodies received, in order.
    received: Arc<Mutex<Vec<String>>>,
}

impl FakeStripe {
    fn new() -> Self {
        Self {
            status: Arc::new(AtomicU16::new(200)),
            received: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn set_status(&self, status: u16) {
        self.status.store(status, Ordering::SeqCst);
    }

    fn identifiers(&self) -> Vec<String> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter_map(|body| {
                body.split('&')
                    .find_map(|pair| pair.strip_prefix("identifier="))
                    .map(str::to_owned)
            })
            .collect()
    }

    fn customers(&self) -> Vec<String> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter_map(|body| {
                body.split('&')
                    .find_map(|pair| pair.strip_prefix("payload%5Bstripe_customer_id%5D="))
                    .map(str::to_owned)
            })
            .collect()
    }
}

/// Serve the fake on loopback and return its base URL.
async fn spawn_stripe(fake: FakeStripe) -> String {
    use axum::extract::State;
    use axum::{Router, routing};

    let app = Router::new()
        .route(
            "/v1/billing/meter_events",
            routing::post(|State(fake): State<FakeStripe>, body: String| async move {
                fake.received.lock().unwrap().push(body);
                let status = fake.status.load(Ordering::SeqCst);
                (
                    axum::http::StatusCode::from_u16(status).unwrap(),
                    r#"{"error":{"type":"invalid_request_error"}}"#,
                )
            }),
        )
        .with_state(fake);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}/v1/billing/meter_events")
}

/// Poll until `check` passes, or fail loudly rather than sleeping and hoping.
async fn eventually<F, Fut>(label: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..120 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for: {label}");
}

fn usage_event(identifier: &str, units: u64) -> serde_json::Value {
    json!({
        "identifier": identifier,
        "customer_id": "cus_enduser",
        "meter": "mcp_units",
        "units": units,
        "timestamp": chrono::Utc::now().timestamp()
    })
}

// ----------------------------------------------------------- destinations

#[tokio::test]
async fn a_stored_credential_is_never_readable_afterwards() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let (status, view) = plane
        .admin(
            Method::PUT,
            "/v1/export/destination",
            Some(json!({"kind": "stripe", "secret": "sk_test_supersecret"})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(view["kind"], "stripe");
    assert_eq!(view["has_secret"], true);

    let (_, view) = plane
        .admin(Method::GET, "/v1/export/destination", None)
        .await;
    let rendered = view.to_string();
    assert!(
        !rendered.contains("sk_test_supersecret"),
        "a stored credential must never come back out: {rendered}"
    );

    // Nor is it in the database in the clear.
    let pool = sqlx::PgPool::connect(&plane.db_url).await.unwrap();
    let sealed: String =
        sqlx::query_scalar("SELECT secret_sealed FROM export_destinations LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    pool.close().await;
    assert!(
        sealed.starts_with("enc:"),
        "credential must be sealed at rest"
    );
    assert!(!sealed.contains("sk_test_supersecret"));
}

#[tokio::test]
async fn a_webhook_destination_on_a_private_host_is_refused() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    // The endpoint is customer-supplied, so this is the difference between a
    // product feature and an SSRF proxy into the plane's own network.
    for endpoint in [
        "https://169.254.169.254/latest/meta-data",
        "https://10.0.0.5/hook",
        "https://[fd00::1]/hook",
        "http://billing.example.com/hook",
    ] {
        let (status, _) = plane
            .admin(
                Method::PUT,
                "/v1/export/destination",
                Some(json!({"kind": "webhook", "secret": "s", "endpoint": endpoint})),
            )
            .await;
        assert_eq!(status, 400, "endpoint {endpoint}");
    }
}

#[tokio::test]
async fn a_destination_without_a_secret_is_refused() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let (status, _) = plane
        .admin(
            Method::PUT,
            "/v1/export/destination",
            Some(json!({"kind": "stripe"})),
        )
        .await;
    assert_eq!(status, 400);
}

// ------------------------------------------------------------- the drain

#[tokio::test]
async fn usage_is_forwarded_downstream_and_marked_exported() {
    let db = require_db!();
    let fake = FakeStripe::new();
    let endpoint = spawn_stripe(fake.clone()).await;
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_enduser").await;

    plane
        .admin(
            Method::PUT,
            "/v1/export/destination",
            Some(json!({"kind": "stripe", "secret": "sk_test_x", "endpoint": endpoint})),
        )
        .await;
    plane
        .edge(
            Method::POST,
            "/v1/edge/usage",
            Some(json!({"events": [usage_event("agg-1", 7)]})),
        )
        .await;

    eventually("the aggregate to reach Stripe", || async {
        !fake.identifiers().is_empty()
    })
    .await;
    assert_eq!(fake.identifiers(), vec!["agg-1"]);

    let (_, view) = plane
        .admin(Method::GET, "/v1/export/destination", None)
        .await;
    assert_eq!(
        view["pending"], 0,
        "a delivered aggregate must not stay pending"
    );
    assert_eq!(view["dead_lettered"], 0);
}

#[tokio::test]
async fn a_retryable_failure_leaves_the_row_pending_and_is_retried() {
    let db = require_db!();
    let fake = FakeStripe::new();
    // 429 describes the account, not the event, so it must never settle a row.
    fake.set_status(429);
    let endpoint = spawn_stripe(fake.clone()).await;
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_enduser").await;

    plane
        .admin(
            Method::PUT,
            "/v1/export/destination",
            Some(json!({"kind": "stripe", "secret": "sk_test_x", "endpoint": endpoint})),
        )
        .await;
    plane
        .edge(
            Method::POST,
            "/v1/edge/usage",
            Some(json!({"events": [usage_event("agg-1", 7)]})),
        )
        .await;

    eventually("at least two delivery attempts", || async {
        fake.identifiers().len() >= 2
    })
    .await;

    let (_, view) = plane
        .admin(Method::GET, "/v1/export/destination", None)
        .await;
    assert_eq!(view["pending"], 1, "a rate-limited aggregate stays pending");
    assert_eq!(view["dead_lettered"], 0, "and is never quarantined");

    // Once the provider recovers, the same identifier settles.
    fake.set_status(200);
    eventually("the retry to settle", || {
        let plane = &plane;
        async move {
            let (_, view) = plane
                .admin(Method::GET, "/v1/export/destination", None)
                .await;
            view["pending"] == 0
        }
    })
    .await;
}

#[tokio::test]
async fn a_permanent_rejection_is_quarantined_and_reconcilable() {
    let db = require_db!();
    let fake = FakeStripe::new();
    // 400 describes this event and always will.
    fake.set_status(400);
    let endpoint = spawn_stripe(fake.clone()).await;
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_enduser").await;

    plane
        .admin(
            Method::PUT,
            "/v1/export/destination",
            Some(json!({"kind": "stripe", "secret": "sk_test_x", "endpoint": endpoint})),
        )
        .await;
    plane
        .edge(
            Method::POST,
            "/v1/edge/usage",
            Some(json!({"events": [usage_event("agg-1", 7)]})),
        )
        .await;

    eventually("the rejection to be recorded", || {
        let plane = &plane;
        async move {
            let (_, letters) = plane
                .admin(Method::GET, "/v1/export/dead-letters", None)
                .await;
            !letters.as_array().unwrap().is_empty()
        }
    })
    .await;

    let (_, letters) = plane
        .admin(Method::GET, "/v1/export/dead-letters", None)
        .await;
    let letter = &letters[0];
    assert_eq!(letter["identifier"], "agg-1");
    assert_eq!(letter["direction"], "downstream");
    assert_eq!(letter["destination"], "stripe");
    assert_eq!(letter["units"], 7);
    // A static, low-cardinality category, never a provider message.
    assert_eq!(letter["reason"], "invalid_request");

    // A settled rejection stops being retried, so it must not stay pending.
    let (_, view) = plane
        .admin(Method::GET, "/v1/export/destination", None)
        .await;
    assert_eq!(view["pending"], 0);
    assert_eq!(view["dead_lettered"], 1);

    let (status, _) = plane
        .admin(Method::POST, "/v1/export/dead-letters/agg-1/resolve", None)
        .await;
    assert_eq!(status, 200);

    let (_, letters) = plane
        .admin(Method::GET, "/v1/export/dead-letters", None)
        .await;
    assert!(
        letters.as_array().unwrap().is_empty(),
        "resolved letters drop out"
    );
}

// --------------------------------------------------------------- upstream

#[tokio::test]
async fn upstream_billing_reattributes_usage_to_the_accounts_own_customer() {
    let db = require_db!();
    let fake = FakeStripe::new();
    let endpoint = spawn_stripe(fake.clone()).await;
    let plane = Plane::start_with_env(
        &db,
        &[
            ("PLANE_STRIPE_SECRET_KEY", "sk_test_plane"),
            ("PLANE_STRIPE_METER_NAME", "mcp_units_processed"),
            ("PLANE_STRIPE_ENDPOINT", &endpoint),
        ],
    )
    .await;
    plane.seed_tenant("acme", "cus_enduser").await;

    plane
        .admin(
            Method::PUT,
            "/v1/billing",
            Some(json!({"stripe_customer_id": "cus_theaccount"})),
        )
        .await;
    plane
        .edge(
            Method::POST,
            "/v1/edge/usage",
            Some(json!({"events": [usage_event("agg-1", 7)]})),
        )
        .await;

    eventually("the plane to bill its own customer", || async {
        !fake.customers().is_empty()
    })
    .await;

    assert_eq!(
        fake.customers(),
        vec!["cus_theaccount"],
        "the plane invoices the account, not the account's end customer"
    );
    assert_eq!(
        fake.identifiers(),
        vec!["plane%3Aagg-1"],
        "the upstream identifier is namespaced so it cannot collide downstream"
    );

    let (_, view) = plane.admin(Method::GET, "/v1/billing", None).await;
    assert_eq!(view["unbilled_units"], 0);
}

// ----------------------------------------------------------------- signup

#[tokio::test]
async fn signup_is_closed_unless_a_secret_is_configured() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let (status, _) = plane
        .send(
            Method::POST,
            "/v1/signup",
            Some(json!({"name": "Acme", "signup_secret": "anything"})),
            None,
        )
        .await;
    assert_eq!(
        status, 404,
        "a fresh deployment is not an open account factory"
    );
}

#[tokio::test]
async fn signup_issues_working_tokens_scoped_to_a_new_account() {
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &[("PLANE_SIGNUP_SECRET", common::SIGNUP_SECRET)]).await;

    let (status, _) = plane
        .send(
            Method::POST,
            "/v1/signup",
            Some(json!({"name": "Acme", "signup_secret": "wrong"})),
            None,
        )
        .await;
    assert_eq!(status, 401);

    let (status, created) = plane
        .send(
            Method::POST,
            "/v1/signup",
            Some(json!({"name": "Acme", "signup_secret": common::SIGNUP_SECRET})),
            None,
        )
        .await;
    assert_eq!(status, 200);
    let admin = created["admin_token"].as_str().unwrap();
    let edge = created["edge_token"].as_str().unwrap();

    // The new admin token works and sees an empty, isolated account.
    let (status, tenants) = plane
        .send(Method::GET, "/v1/tenants", None, Some(admin))
        .await;
    assert_eq!(status, 200);
    assert!(tenants.as_array().unwrap().is_empty());

    // The edge token is the weaker one, exactly as for a bootstrapped account.
    let (status, _) = plane
        .send(Method::GET, "/v1/tenants", None, Some(edge))
        .await;
    assert_eq!(status, 403);
    let (status, _) = plane
        .send(Method::GET, "/v1/edge/snapshot", None, Some(edge))
        .await;
    assert_eq!(status, 200);
}

// ---------------------------------------------------------------- webhook

fn stripe_signature(secret: &str, timestamp: i64, body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    let hex: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("t={timestamp},v1={hex}")
}

async fn post_webhook(
    plane: &Plane,
    body: &str,
    signature: &str,
) -> (reqwest::StatusCode, serde_json::Value) {
    let response = plane
        .http
        .post(plane.url("/v1/stripe/webhook"))
        .header("stripe-signature", signature)
        .header("content-type", "application/json")
        .body(body.to_owned())
        .send()
        .await
        .expect("request reaches the plane");
    let status = response.status();
    let value = response
        .json::<serde_json::Value>()
        .await
        .unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[tokio::test]
async fn a_signed_subscription_event_updates_billing_and_replays_are_ignored() {
    let db = require_db!();
    let plane = Plane::start_with_env(
        &db,
        &[("PLANE_STRIPE_WEBHOOK_SECRET", common::WEBHOOK_SECRET)],
    )
    .await;
    plane
        .admin(
            Method::PUT,
            "/v1/billing",
            Some(json!({"stripe_customer_id": "cus_theaccount"})),
        )
        .await;

    // The period end lives on the subscription's ITEMS, not on the
    // subscription. This payload previously put it at the top level and never
    // asserted it landed, which is exactly why reading it from the wrong place
    // went unnoticed. The older `.dahlia` date is deliberate: only the release
    // suffix is checked, so a monthly version stays acceptable.
    let body = json!({
        "id": "evt_1",
        "type": "customer.subscription.updated",
        "api_version": "2026-07-29.dahlia",
        "data": {"object": {
            "id": "sub_1", "customer": "cus_theaccount",
            "status": "active",
            "items": {"object": "list", "data": [
                {"id": "si_1", "current_period_end": 1_900_000_000u64},
                {"id": "si_2", "current_period_end": 1_800_000_000u64}
            ]}
        }}
    })
    .to_string();
    let signature = stripe_signature(
        common::WEBHOOK_SECRET,
        chrono::Utc::now().timestamp(),
        &body,
    );

    let (status, ack) = post_webhook(&plane, &body, &signature).await;
    assert_eq!(status, 200);
    assert_eq!(ack["status"], "ok");

    let (_, view) = plane.admin(Method::GET, "/v1/billing", None).await;
    assert_eq!(view["status"], "active");
    assert_eq!(view["stripe_subscription_id"], "sub_1");
    // The latest item's period end wins: items can bill on different anchors,
    // and the subscription is not done with a period until its last item is.
    assert!(
        view["current_period_end"]
            .as_str()
            .expect("current_period_end must be populated, not silently NULL")
            .starts_with("2030-"),
        "got {}",
        view["current_period_end"]
    );

    // Stripe redelivers, so the event id is the idempotency key.
    let (status, ack) = post_webhook(&plane, &body, &signature).await;
    assert_eq!(status, 200);
    assert_eq!(ack["status"], "duplicate");
}

#[tokio::test]
async fn an_unsigned_or_tampered_webhook_is_refused() {
    let db = require_db!();
    let plane = Plane::start_with_env(
        &db,
        &[("PLANE_STRIPE_WEBHOOK_SECRET", common::WEBHOOK_SECRET)],
    )
    .await;

    let body =
        json!({"id": "evt_1", "type": "ping", "api_version": "2026-07-29.dahlia"}).to_string();
    let now = chrono::Utc::now().timestamp();

    for signature in [
        String::new(),
        "t=1,v1=deadbeef".to_owned(),
        stripe_signature("whsec_wrong", now, &body),
        // A genuine signature over different content.
        stripe_signature(common::WEBHOOK_SECRET, now, "{}"),
        // A genuine signature, far outside the replay tolerance.
        stripe_signature(common::WEBHOOK_SECRET, now - 3600, &body),
    ] {
        let (status, _) = post_webhook(&plane, &body, &signature).await;
        assert_eq!(status, 401, "signature {signature:?}");
    }
}

#[tokio::test]
async fn an_event_from_an_unexpected_api_release_is_refused() {
    let db = require_db!();
    let plane = Plane::start_with_env(
        &db,
        &[("PLANE_STRIPE_WEBHOOK_SECRET", common::WEBHOOK_SECRET)],
    )
    .await;

    // The payload is rendered at the version pinned on the Stripe endpoint, not
    // at whatever this service sends outbound, so an unexpected release means
    // the parsers here may silently misread it.
    let body = json!({
        "id": "evt_1", "type": "customer.subscription.updated",
        "api_version": "2024-06-20.acacia",
        "data": {"object": {"id": "sub_1", "customer": "cus_x", "status": "active"}}
    })
    .to_string();
    let signature = stripe_signature(
        common::WEBHOOK_SECRET,
        chrono::Utc::now().timestamp(),
        &body,
    );

    let (status, _) = post_webhook(&plane, &body, &signature).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn one_stripe_customer_cannot_be_claimed_by_two_accounts() {
    // The subscription webhook updates by customer id:
    //
    //     UPDATE account_billing ... WHERE stripe_customer_id = $1
    //
    // With two accounts naming the same customer that touches both rows, and
    // upstream billing invoices one party for the other's usage.
    let db = require_db!();
    let plane = Plane::start_with_env(&db, &[("PLANE_SIGNUP_SECRET", "signup-secret")]).await;

    let (status, _) = plane
        .admin(
            Method::PUT,
            "/v1/billing",
            Some(json!({"stripe_customer_id": "cus_contested"})),
        )
        .await;
    assert_eq!(status, 200, "the first claim is allowed");

    // A second account, created through signup so it has its own admin token.
    let (status, created) = plane
        .send(
            Method::POST,
            "/v1/signup",
            Some(json!({"name": "second", "signup_secret": "signup-secret"})),
            None,
        )
        .await;
    assert_eq!(status, 200, "{created}");
    let other_admin = created["admin_token"].as_str().expect("an admin token");

    let response = plane
        .http
        .put(plane.url("/v1/billing"))
        .bearer_auth(other_admin)
        .json(&json!({"stripe_customer_id": "cus_contested"}))
        .send()
        .await
        .expect("request reaches the plane");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::CONFLICT,
        "a second account must not be able to claim a linked customer"
    );
}

#[tokio::test]
async fn a_failed_payment_is_recorded_rather_than_ignored() {
    // It used to reach a debug log and vanish. The invoice event is the first
    // signal that revenue is not arriving, and the only one naming the invoice.
    let db = require_db!();
    let plane = Plane::start_with_env(
        &db,
        &[("PLANE_STRIPE_WEBHOOK_SECRET", common::WEBHOOK_SECRET)],
    )
    .await;
    plane
        .admin(
            Method::PUT,
            "/v1/billing",
            Some(json!({"stripe_customer_id": "cus_payer"})),
        )
        .await;

    let body = json!({
        "id": "evt_failed_1",
        "type": "invoice.payment_failed",
        "api_version": "2026-08-26.dahlia",
        "data": {"object": {"id": "in_1", "customer": "cus_payer"}}
    })
    .to_string();
    let signature = stripe_signature(
        common::WEBHOOK_SECRET,
        chrono::Utc::now().timestamp(),
        &body,
    );
    let (status, ack) = post_webhook(&plane, &body, &signature).await;
    assert_eq!(status, 200);
    assert_eq!(
        ack["status"], "ok",
        "the event must be handled, not ignored"
    );

    let (_, view) = plane.admin(Method::GET, "/v1/billing", None).await;
    assert!(
        view["last_payment_failure_at"].is_string(),
        "a failed payment must leave a trace: {view}"
    );
    assert!(view["last_payment_success_at"].is_null());

    // And a later success is recorded separately, so the two are not confused.
    let body = json!({
        "id": "evt_paid_1",
        "type": "invoice.paid",
        "api_version": "2026-08-26.dahlia",
        "data": {"object": {"id": "in_2", "customer": "cus_payer"}}
    })
    .to_string();
    let signature = stripe_signature(
        common::WEBHOOK_SECRET,
        chrono::Utc::now().timestamp(),
        &body,
    );
    post_webhook(&plane, &body, &signature).await;

    let (_, view) = plane.admin(Method::GET, "/v1/billing", None).await;
    assert!(view["last_payment_success_at"].is_string(), "{view}");
    assert!(
        view["last_payment_failure_at"].is_string(),
        "the earlier failure must not be erased by a later success"
    );
}

#[tokio::test]
async fn a_webhook_that_cannot_be_applied_is_not_left_claimed() {
    // Claiming the event id on the pool and applying separately meant a
    // transient database error left the event claimed but unapplied, and
    // Stripe's redelivery answered `duplicate` without ever applying it - a
    // subscription state change dropped permanently.
    //
    // `data.object` missing makes `apply_event` error, which is the cheapest
    // reachable stand-in for that failure.
    let db = require_db!();
    let plane = Plane::start_with_env(
        &db,
        &[("PLANE_STRIPE_WEBHOOK_SECRET", common::WEBHOOK_SECRET)],
    )
    .await;

    let broken = json!({
        "id": "evt_broken_1",
        "type": "customer.subscription.updated",
        "api_version": "2026-08-26.dahlia",
        "data": {}
    })
    .to_string();
    let signature = stripe_signature(
        common::WEBHOOK_SECRET,
        chrono::Utc::now().timestamp(),
        &broken,
    );
    let (status, _) = post_webhook(&plane, &broken, &signature).await;
    assert_eq!(status, 400, "an unapplicable event must not be accepted");

    // Stripe redelivers. The same id must get a real attempt, not `duplicate`.
    plane
        .admin(
            Method::PUT,
            "/v1/billing",
            Some(json!({"stripe_customer_id": "cus_retry"})),
        )
        .await;
    let good = json!({
        "id": "evt_broken_1",
        "type": "customer.subscription.updated",
        "api_version": "2026-08-26.dahlia",
        "data": {"object": {
            "id": "sub_retry", "customer": "cus_retry", "status": "active",
            "items": {"data": [{"current_period_end": 1_900_000_000u64}]}
        }}
    })
    .to_string();
    let signature = stripe_signature(
        common::WEBHOOK_SECRET,
        chrono::Utc::now().timestamp(),
        &good,
    );
    let (status, ack) = post_webhook(&plane, &good, &signature).await;
    assert_eq!(status, 200);
    assert_eq!(
        ack["status"], "ok",
        "a redelivery after a failed apply must be applied, not dismissed"
    );

    let (_, view) = plane.admin(Method::GET, "/v1/billing", None).await;
    assert_eq!(view["status"], "active");
}
