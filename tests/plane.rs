//! Database-backed integration tests for the control plane.

mod common;

use common::Plane;
use reqwest::Method;
use serde_json::json;

fn usage_event(identifier: &str, customer: &str, units: u64) -> serde_json::Value {
    json!({
        "identifier": identifier,
        "customer_id": customer,
        "meter": "mcp_units",
        "units": units,
        "timestamp": 1_789_757_188u64
    })
}

#[tokio::test]
async fn a_minted_key_appears_in_the_edge_snapshot_with_its_prices() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let key = plane.seed_tenant("acme", "cus_acme").await;

    let (status, snapshot) = plane.edge(Method::GET, "/v1/edge/snapshot", None).await;
    assert_eq!(status, 200);

    let tenants = snapshot["tenants"].as_array().expect("tenants array");
    assert_eq!(tenants.len(), 1);
    let entry = &tenants[0];
    assert_eq!(entry["tenant_id"], "acme");
    assert_eq!(entry["billing_customer_id"], "cus_acme");
    assert_eq!(entry["prices"]["names"]["sum"], 7);
    assert_eq!(entry["committed_units"], 0);

    // The digest must be the one the edge will compute from the plaintext key.
    let expected = sha256_hex(&key);
    assert_eq!(entry["api_key_sha256"], expected);
}

fn sha256_hex(value: &str) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    Sha256::digest(value.as_bytes())
        .iter()
        .fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[tokio::test]
async fn revoking_a_key_removes_it_from_the_snapshot() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    let key = plane.seed_tenant("acme", "cus_acme").await;
    let digest = sha256_hex(&key);

    let (status, _) = plane
        .admin(
            Method::DELETE,
            &format!("/v1/tenants/acme/keys/{digest}"),
            None,
        )
        .await;
    assert_eq!(status, 200);

    let (_, snapshot) = plane.edge(Method::GET, "/v1/edge/snapshot", None).await;
    assert!(
        snapshot["tenants"].as_array().expect("array").is_empty(),
        "a revoked key must not be served: absence from the snapshot IS the revocation"
    );
}

#[tokio::test]
async fn revoking_a_tenant_removes_all_of_its_keys() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_acme").await;
    plane
        .admin(
            Method::POST,
            "/v1/tenants/acme/keys",
            Some(json!({"label": "second"})),
        )
        .await;

    let (_, snapshot) = plane.edge(Method::GET, "/v1/edge/snapshot", None).await;
    assert_eq!(snapshot["tenants"].as_array().expect("array").len(), 2);

    let (status, _) = plane.admin(Method::DELETE, "/v1/tenants/acme", None).await;
    assert_eq!(status, 200);

    let (_, snapshot) = plane.edge(Method::GET, "/v1/edge/snapshot", None).await;
    assert!(snapshot["tenants"].as_array().expect("array").is_empty());
}

#[tokio::test]
async fn replaying_a_usage_batch_does_not_double_count() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_acme").await;

    let batch = json!({"events": [usage_event("agg-1", "cus_acme", 7)]});

    for attempt in 0..3 {
        let (status, ack) = plane
            .edge(Method::POST, "/v1/edge/usage", Some(batch.clone()))
            .await;
        assert_eq!(status, 200, "attempt {attempt}");
        assert_eq!(ack["outcomes"][0]["outcome"], "accepted");
        assert_eq!(ack["outcomes"][0]["identifier"], "agg-1");
    }

    let (_, snapshot) = plane.edge(Method::GET, "/v1/edge/snapshot", None).await;
    assert_eq!(
        snapshot["tenants"][0]["committed_units"], 7,
        "three submissions of one stable identifier must commit once"
    );
    assert_eq!(
        snapshot["tenants"][0]["committed_spend_micros"], 7000,
        "spend follows units at the configured unit price"
    );
}

#[tokio::test]
async fn the_ledger_survives_a_restart_and_still_refuses_a_replay() {
    let db = require_db!();
    let mut plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_acme").await;
    let batch = json!({"events": [usage_event("agg-1", "cus_acme", 5)]});
    plane
        .edge(Method::POST, "/v1/edge/usage", Some(batch.clone()))
        .await;

    // A sidecar that was mid-retry when the plane went down will resend the
    // same identifier once it comes back. That must stay a no-op.
    plane.restart().await;
    let (status, ack) = plane
        .edge(Method::POST, "/v1/edge/usage", Some(batch))
        .await;
    assert_eq!(status, 200);
    assert_eq!(ack["outcomes"][0]["outcome"], "accepted");

    let (_, snapshot) = plane.edge(Method::GET, "/v1/edge/snapshot", None).await;
    assert_eq!(snapshot["tenants"][0]["committed_units"], 5);
}

#[tokio::test]
async fn an_invalid_event_is_rejected_without_taking_its_batch_down() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_acme").await;

    let (status, ack) = plane
        .edge(
            Method::POST,
            "/v1/edge/usage",
            Some(json!({"events": [
                usage_event("good-1", "cus_acme", 3),
                {"identifier": "", "customer_id": "cus_acme", "meter": "m", "units": 1, "timestamp": 0},
                usage_event("good-2", "cus_acme", 4)
            ]})),
        )
        .await;

    assert_eq!(status, 200);
    let outcomes = ack["outcomes"].as_array().expect("array");
    assert_eq!(outcomes.len(), 3, "one outcome per event, in order");
    assert_eq!(outcomes[0]["outcome"], "accepted");
    assert_eq!(outcomes[1]["outcome"], "rejected");
    assert_eq!(outcomes[2]["outcome"], "accepted");

    let (_, snapshot) = plane.edge(Method::GET, "/v1/edge/snapshot", None).await;
    assert_eq!(snapshot["tenants"][0]["committed_units"], 7);
}

#[tokio::test]
async fn usage_for_an_unknown_customer_is_still_recorded() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_acme").await;

    // Losing usage because a tenant was renamed or deleted would be worse than
    // holding an unattributed row, so ingest never refuses on attribution.
    let (status, ack) = plane
        .edge(
            Method::POST,
            "/v1/edge/usage",
            Some(json!({"events": [usage_event("agg-x", "cus_nobody", 9)]})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(ack["outcomes"][0]["outcome"], "accepted");

    let (_, rollup) = plane
        .admin(Method::GET, "/v1/usage?customer_id=cus_nobody", None)
        .await;
    assert_eq!(rollup[0]["units"], 9);
}

#[tokio::test]
async fn an_edge_token_cannot_manage_tenants_and_an_admin_token_cannot_act_as_an_edge() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    let (status, _) = plane
        .send(Method::GET, "/v1/tenants", None, Some(common::EDGE_TOKEN))
        .await;
    assert_eq!(status, 403, "a sidecar credential must not reach pricing");

    let (status, _) = plane
        .send(
            Method::GET,
            "/v1/edge/snapshot",
            None,
            Some(common::ADMIN_TOKEN),
        )
        .await;
    assert_eq!(
        status, 403,
        "admin tokens are not edge tokens; a sidecar should hold the weaker one"
    );
}

#[tokio::test]
async fn an_unknown_or_missing_token_is_refused() {
    let db = require_db!();
    let plane = Plane::start(&db).await;

    for token in [None, Some("not-a-real-token")] {
        let (status, _) = plane.send(Method::GET, "/v1/tenants", None, token).await;
        assert_eq!(status, 401, "token {token:?}");
    }
}

#[tokio::test]
async fn one_accounts_data_is_invisible_to_another() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_acme").await;

    // A second account with its own admin token, inserted directly because the
    // plane has no self-serve signup yet.
    let pool = sqlx::PgPool::connect(&plane.db_url).await.expect("connect");
    sqlx::query("INSERT INTO accounts (id, name) VALUES ('acct_other', 'other')")
        .execute(&pool)
        .await
        .expect("insert account");
    sqlx::query(
        "INSERT INTO account_tokens (token_sha256, account_id, scope, label)
         VALUES ($1, 'acct_other', 'admin', 'test')",
    )
    .bind(sha256_hex("other-admin-token"))
    .execute(&pool)
    .await
    .expect("insert token");
    pool.close().await;

    let (status, tenants) = plane
        .send(Method::GET, "/v1/tenants", None, Some("other-admin-token"))
        .await;
    assert_eq!(status, 200);
    assert!(
        tenants.as_array().expect("array").is_empty(),
        "tenancy is scoped in SQL, not in the handler"
    );
}

#[tokio::test]
async fn updating_prices_bumps_the_version_and_reaches_the_edge() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_acme").await;

    let (status, updated) = plane
        .admin(
            Method::PATCH,
            "/v1/tenants/acme",
            Some(json!({"prices": {"default_units": 2, "names": {"sum": 11}}})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(updated["price_version"], 2);
    assert_eq!(updated["prices"]["names"]["sum"], 11);

    let (_, snapshot) = plane.edge(Method::GET, "/v1/edge/snapshot", None).await;
    assert_eq!(snapshot["tenants"][0]["prices"]["names"]["sum"], 11);
    assert_eq!(snapshot["tenants"][0]["prices"]["default_units"], 2);
}

#[tokio::test]
async fn a_limit_can_be_set_and_then_explicitly_cleared() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_acme").await;

    let (_, updated) = plane
        .admin(
            Method::PATCH,
            "/v1/tenants/acme",
            Some(json!({"max_units": 100})),
        )
        .await;
    assert_eq!(updated["max_units"], 100);

    // An absent field leaves the limit alone.
    let (_, updated) = plane
        .admin(
            Method::PATCH,
            "/v1/tenants/acme",
            Some(json!({"unit_price_micros": 5})),
        )
        .await;
    assert_eq!(
        updated["max_units"], 100,
        "an absent field must not clear a limit"
    );

    // An explicit null clears it.
    let (_, updated) = plane
        .admin(
            Method::PATCH,
            "/v1/tenants/acme",
            Some(json!({"max_units": null})),
        )
        .await;
    assert!(
        updated["max_units"].is_null(),
        "an explicit null must clear the limit"
    );
}

#[tokio::test]
async fn the_quota_endpoint_reports_the_same_verdict_the_edge_would_reach() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_acme").await;
    plane
        .admin(
            Method::PATCH,
            "/v1/tenants/acme",
            Some(json!({"max_units": 10})),
        )
        .await;

    plane
        .edge(
            Method::POST,
            "/v1/edge/usage",
            Some(json!({"events": [usage_event("agg-1", "cus_acme", 10)]})),
        )
        .await;

    // Exactly at the limit is still admitting: `assess_limits` rejects only when
    // the new total would be greater.
    let (status, quota) = plane.admin(Method::GET, "/v1/usage/quota", None).await;
    assert_eq!(status, 200);
    assert_eq!(quota[0]["committed_units"], 10);
    assert_eq!(quota[0]["admitting"], true);

    plane
        .edge(
            Method::POST,
            "/v1/edge/usage",
            Some(json!({"events": [usage_event("agg-2", "cus_acme", 1)]})),
        )
        .await;

    let (_, quota) = plane.admin(Method::GET, "/v1/usage/quota", None).await;
    assert_eq!(quota[0]["committed_units"], 11);
    assert_eq!(quota[0]["admitting"], false);
    assert_eq!(quota[0]["reason"], "QuotaExceeded");
}

#[tokio::test]
async fn a_duplicate_tenant_key_is_a_conflict_not_a_silent_overwrite() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_acme").await;

    let (status, _) = plane
        .admin(
            Method::POST,
            "/v1/tenants",
            Some(json!({"tenant_key": "acme", "billing_customer_id": "cus_other"})),
        )
        .await;
    assert_eq!(status, 409);
}

#[tokio::test]
async fn a_rollup_buckets_by_the_requested_size_and_refuses_anything_else() {
    let db = require_db!();
    let plane = Plane::start(&db).await;
    plane.seed_tenant("acme", "cus_acme").await;
    plane
        .edge(
            Method::POST,
            "/v1/edge/usage",
            Some(json!({"events": [
                usage_event("agg-1", "cus_acme", 3),
                usage_event("agg-2", "cus_acme", 4)
            ]})),
        )
        .await;

    for bucket in ["hour", "day", "month"] {
        let (status, rollup) = plane
            .admin(Method::GET, &format!("/v1/usage?bucket={bucket}"), None)
            .await;
        assert_eq!(status, 200, "bucket {bucket}");
        assert_eq!(rollup[0]["units"], 7, "bucket {bucket}");
        assert_eq!(rollup[0]["events"], 2, "bucket {bucket}");
    }

    let (status, _) = plane
        .admin(Method::GET, "/v1/usage?bucket=week", None)
        .await;
    assert_eq!(status, 400);
}
