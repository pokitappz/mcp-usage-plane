//! Harness for the database-backed integration tests.
//!
//! These boot the compiled binary against a scratch database and talk to it
//! over HTTP, following the same reasoning as the Backstock suite: the things
//! worth protecting here are stack properties, not handler properties. Scope
//! enforcement is an extractor, idempotency is a primary key, and counter
//! arithmetic is SQL. A test calling handlers directly would skip all three.
//!
//! `TEST_DATABASE_URL` must point at a Postgres this suite may **freely
//! destroy**. Each test gets its own scratch database, created fresh from
//! nothing, which makes "the migrations apply cleanly to an empty database" an
//! assertion of every test rather than a thing nobody checks until a deploy.
//! Per-test databases rather than a shared wiped schema because the suite runs
//! in parallel, and a shared schema means tests racing each other's DROP.
//! Tests skip themselves with a printed note when the variable is unset.
//!
//! ```sh
//! createdb mcp_plane_test
//! TEST_DATABASE_URL='postgres://localhost/mcp_plane_test' cargo test
//! ```

#![allow(dead_code)] // Each test binary uses a different subset.

use std::process::{Child, Command};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

pub const ACCOUNT: &str = "acct_test";
/// 32 bytes of nothing, base64. Fine for a scratch database.
pub const SEALING_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
pub const PROVISION_SECRET: &str = "provision-secret-not-a-real-secret";
pub const WEBHOOK_SECRET: &str = "whsec_not_a_real_secret";
pub const ADMIN_TOKEN: &str = "mup_admin_test_token_not_a_real_secret_0001";
pub const EDGE_TOKEN: &str = "mup_edge_test_token_not_a_real_secret_0001";

static NEXT_PORT: AtomicU16 = AtomicU16::new(19180);

pub struct Plane {
    /// `None` once the process has been stopped, so a restart does not need a
    /// placeholder process to swap in.
    child: Option<Child>,
    pub base: String,
    pub http: reqwest::Client,
    /// The scratch database this instance was booted against, so a restart can
    /// reuse it and prove the ledger outlived the process.
    pub db_url: String,
}

impl Drop for Plane {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Create an empty scratch database for one test and return its URL.
///
/// Named from the test's port so the set stays bounded and self-cleaning across
/// runs. `WITH (FORCE)` evicts a connection leaked by an earlier run rather than
/// failing the whole suite on it.
async fn create_scratch_database(base_url: &str, port: u16) -> String {
    let (prefix, base_name) = base_url
        .rsplit_once('/')
        .expect("TEST_DATABASE_URL must end in /<database>");
    let scratch = format!("{base_name}_s{port}");

    let admin = sqlx::PgPool::connect(base_url)
        .await
        .expect("connect to TEST_DATABASE_URL");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {scratch} WITH (FORCE)"))
        .execute(&admin)
        .await
        .expect("drop any leftover scratch database");
    sqlx::query(&format!("CREATE DATABASE {scratch}"))
        .execute(&admin)
        .await
        .expect("create the scratch database");
    admin.close().await;

    format!("{prefix}/{scratch}")
}

/// The scratch database URL, or `None` when the suite should skip.
///
/// # Panics
///
/// Panics when `PLANE_REQUIRE_DATABASE` is set and no database URL is
/// available. Without that, a CI service container that failed to start looks
/// exactly like a passing run: every database-backed test skips itself, the
/// job goes green, and nothing was actually exercised. Anywhere the database
/// is meant to be present, set the variable and let a missing one fail loudly.
#[must_use]
pub fn database_url() -> Option<String> {
    let url = std::env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty());
    assert!(
        !(url.is_none() && std::env::var("PLANE_REQUIRE_DATABASE").is_ok()),
        "PLANE_REQUIRE_DATABASE is set but TEST_DATABASE_URL is missing or empty; \
         the database-backed tests would have silently skipped"
    );
    url
}

#[macro_export]
macro_rules! require_db {
    () => {
        match $crate::common::database_url() {
            Some(url) => url,
            None => {
                eprintln!("skipping: set TEST_DATABASE_URL to run the database-backed tests");
                return;
            }
        }
    };
}

impl Plane {
    /// Boot the binary against a scratch database of its own.
    pub async fn start(base_url: &str) -> Self {
        Self::start_with_env(base_url, &[]).await
    }

    /// Boot with extra environment, for the billing and export suites.
    ///
    /// `extra` is applied last so a suite can override any default below.
    pub async fn start_with_env(base_url: &str, extra: &[(&str, &str)]) -> Self {
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let db_url = create_scratch_database(base_url, port).await;
        Self::boot_with_env(&db_url, port, extra).await
    }

    /// Boot again against the same scratch database, without wiping it.
    ///
    /// Used to prove a restarted plane still refuses a replayed batch, which is
    /// only meaningful if the ledger survives the process.
    pub async fn restart(&mut self) {
        self.kill();
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let mut replacement = Self::boot(&self.db_url, port).await;
        self.child = replacement.child.take();
        self.base = replacement.base.clone();
    }

    async fn boot(db_url: &str, port: u16) -> Self {
        Self::boot_with_env(db_url, port, &[]).await
    }

    async fn boot_with_env(db_url: &str, port: u16, extra: &[(&str, &str)]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-usage-plane"));
        command
            .env("DATABASE_URL", db_url)
            .env("PORT", port.to_string())
            .env(
                "MIGRATIONS_DIR",
                concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"),
            )
            .env("PLANE_BOOTSTRAP_ACCOUNT_ID", ACCOUNT)
            .env("PLANE_BOOTSTRAP_ADMIN_TOKEN", ADMIN_TOKEN)
            .env("PLANE_BOOTSTRAP_EDGE_TOKEN", EDGE_TOKEN)
            .env("RUST_LOG", "mcp_usage_plane=warn")
            // A fixed key, so a sealed credential written by one boot can still
            // be opened after a restart.
            .env("SECRET_SEALING_KEY", SEALING_KEY)
            // Export destinations in these suites point at loopback test
            // servers, which production must never allow.
            .env("ALLOW_LOOPBACK_DESTINATIONS", "1")
            .env("EXPORT_DRAIN_INTERVAL_SECONDS", "1")
            // The CSRF check compares Origin against this, and the session
            // cookie is only `Secure` when it is https. Without it every
            // state-changing human route refuses, which is the right default
            // but makes the sign-in suite untestable.
            .env("APP_PUBLIC_URL", format!("http://127.0.0.1:{port}"));
        for (name, value) in extra {
            command.env(name, value);
        }

        let mut child = command.spawn().expect("spawn the control plane binary");
        let base = format!("http://127.0.0.1:{port}");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build a client");

        for attempt in 0..100 {
            if let Ok(response) = http.get(format!("{base}/healthz")).send().await
                && response.status().is_success()
            {
                return Self {
                    child: Some(child),
                    base,
                    http,
                    db_url: db_url.to_owned(),
                };
            }
            tokio::time::sleep(Duration::from_millis(50 * (1 + attempt / 20))).await;
        }
        // Reap the process before failing, or the suite leaves an orphan
        // holding the scratch database open.
        let _ = child.kill();
        let _ = child.wait();
        panic!("control plane did not become healthy on {base}");
    }

    /// Stop the process, leaving the database intact. Idempotent.
    pub fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub async fn admin(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (reqwest::StatusCode, serde_json::Value) {
        self.send(method, path, body, Some(ADMIN_TOKEN)).await
    }

    pub async fn edge(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (reqwest::StatusCode, serde_json::Value) {
        self.send(method, path, body, Some(EDGE_TOKEN)).await
    }

    /// Like [`Self::send`], but surfaces the response headers.
    ///
    /// The rate limiter's contract is a 429 *with* `Retry-After`; a test that
    /// only sees the status cannot tell a useful refusal from a bare one.
    pub async fn send_raw(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
    ) -> (reqwest::StatusCode, reqwest::header::HeaderMap) {
        let mut request = self.http.request(method, self.url(path));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.expect("request reaches the plane");
        (response.status(), response.headers().clone())
    }

    pub async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
        token: Option<&str>,
    ) -> (reqwest::StatusCode, serde_json::Value) {
        let mut request = self.http.request(method, self.url(path));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("request reaches the plane");
        let status = response.status();
        let value = response
            .json::<serde_json::Value>()
            .await
            .unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    /// Create a tenant and mint one key, returning the plaintext key.
    pub async fn seed_tenant(&self, tenant_key: &str, customer: &str) -> String {
        let (status, _) = self
            .admin(
                reqwest::Method::POST,
                "/v1/tenants",
                Some(serde_json::json!({
                    "tenant_key": tenant_key,
                    "billing_customer_id": customer,
                    "prices": {"default_units": 1, "names": {"sum": 7}},
                    "unit_price_micros": 1000
                })),
            )
            .await;
        assert_eq!(status, 200, "create tenant {tenant_key}");

        let (status, minted) = self
            .admin(
                reqwest::Method::POST,
                &format!("/v1/tenants/{tenant_key}/keys"),
                Some(serde_json::json!({"label": "test"})),
            )
            .await;
        assert_eq!(status, 200, "mint key for {tenant_key}");
        minted["api_key"].as_str().expect("a key").to_owned()
    }
}
