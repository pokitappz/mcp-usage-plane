//! Hosted usage and entitlement control plane for MCP servers.
//!
//! Sidecars pull a snapshot of who may call and at what price, then post
//! idempotent usage aggregates back. This service owns the authoritative
//! counters; the sidecar owns the hot path and must keep serving when this
//! service is unavailable, so every contract here is pull-based, idempotent,
//! and free of session state.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

mod auth;
mod billing;
mod edge;
mod error;
mod export;
mod pricing;
mod providers;
mod secret;
mod tenants;
mod throttle;
mod tokens;
mod usage;

use std::net::SocketAddr;
use std::time::Duration;

use axum::{Json, Router, routing};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    /// Connection pool.
    pub pool: PgPool,
    /// Key that seals customer billing credentials at rest, when configured.
    pub sealing: Option<secret::SealingKey>,
    /// Whether a loopback export destination may be dialled. Off in production;
    /// the integration suite turns it on to point a destination at a test server.
    pub allow_loopback_destinations: bool,
    /// The plane's own billing configuration.
    pub billing: billing::PlaneBilling,
    /// Most recent database probe, so an unauthenticated health poll does not
    /// cost a query every time.
    pub health: std::sync::Arc<throttle::HealthProbe>,
    /// Per-token authentication cache and rate limiter.
    ///
    /// `Arc` because `AppState` is cloned per request and the budget has to be
    /// shared; cloning the maps would give every request its own allowance.
    pub admission: std::sync::Arc<throttle::Admission>,
}

/// Ceiling on every request body except the edge's usage post.
///
/// Bodies large enough to matter arrive on exactly one route: an edge may post
/// `MAX_BATCH` usage events, and `edge::router` raises the ceiling for that
/// route alone. Everything else here is small.
const ADMIN_BODY_LIMIT: usize = 64 * 1024;

/// Longest a single request may occupy a worker and a pool connection.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is required")?;
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8081);

    let pool = PgPoolOptions::new()
        .max_connections(
            std::env::var("DATABASE_MAX_CONNECTIONS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(10),
        )
        .acquire_timeout(Duration::from_secs(5))
        // Nothing else bounds a slow query, and a query that never returns
        // holds one of ten pool connections until the process restarts.
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET statement_timeout = '15s'")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await?;

    migrate(&pool).await?;
    bootstrap(&pool).await?;

    // A sealing key that is present but malformed is a mistake, and the right
    // response to a mistake is to refuse to start rather than silently store
    // the next billing credential without protection.
    let sealing = secret::key_from_env()?;
    if sealing.is_none() {
        tracing::warn!(
            "{} is not set; billing credentials cannot be stored until it is",
            secret::KEY_VAR
        );
    }
    let allow_loopback_destinations = std::env::var("ALLOW_LOOPBACK_DESTINATIONS")
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    if allow_loopback_destinations {
        tracing::warn!("loopback export destinations are enabled; this is for tests only");
    }

    let plane_billing = billing::PlaneBilling::from_env();
    tracing::info!(?plane_billing, "plane billing configuration");

    let state = AppState {
        pool,
        sealing,
        allow_loopback_destinations,
        billing: plane_billing,
        health: std::sync::Arc::new(throttle::HealthProbe::default()),
        admission: std::sync::Arc::new(throttle::Admission::default()),
    };
    let app = Router::new()
        .route("/healthz", routing::get(healthz))
        .merge(tenants::router())
        .merge(usage::router())
        .merge(edge::router())
        .merge(export::router())
        .merge(billing::router())
        .merge(tokens::router())
        .merge(pricing::router())
        .layer(axum::extract::DefaultBodyLimit::max(ADMIN_BODY_LIMIT))
        // Outermost, so it also bounds a client that is slow to send its body.
        // Without it a trickling request holds a pool connection for as long as
        // it likes, which is the cheapest way to exhaust the pool.
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state.clone());

    let drain_interval = Duration::from_secs(
        std::env::var("EXPORT_DRAIN_INTERVAL_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(30),
    );
    let drain = tokio::spawn(export::drain_forever(state.clone(), drain_interval));
    // The period close replaces the old per-unit upstream drip. Running both
    // would charge every account twice: once per processed unit and again for
    // the period those units are in.
    let biller = tokio::spawn(pricing::close_forever(state.clone(), drain_interval));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "control plane ready");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // The drain marks rows settled only after the provider has accepted them,
    // so stopping mid-cycle costs at most one repeat submission, which every
    // provider deduplicates on the identifier.
    drain.abort();
    biller.abort();
    // Draining the pool lets in-flight transactions finish rather than being
    // cut off mid-commit, which for the usage ledger is the difference between
    // a retryable batch and a silently lost one.
    state.pool.close().await;
    tracing::info!("shutdown complete");
    Ok(())
}

/// Liveness. Deliberately touches the database: a plane that cannot reach
/// Postgres cannot serve a snapshot, and reporting healthy would keep a broken
/// instance in rotation.
async fn healthz(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<serde_json::Value>, error::ApiError> {
    // Cached, because the platform now polls this and the endpoint is
    // unauthenticated: without a cache it is a `SELECT 1` and a pool connection
    // per request, from anyone. The window is short enough that a database
    // outage is still reported within one health-check interval.
    if let Some(cached) = state.health.recent() {
        return cached
            .then(|| Json(serde_json::json!({ "status": "ok" })))
            .ok_or(error::ApiError::Internal);
    }

    let reachable = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .is_ok();
    state.health.record(reachable);

    if reachable {
        Ok(Json(serde_json::json!({ "status": "ok" })))
    } else {
        tracing::error!("health probe could not reach the database");
        Err(error::ApiError::Internal)
    }
}

async fn migrate(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::var("MIGRATIONS_DIR").unwrap_or_else(|_| "./migrations".to_owned());
    let migrator = sqlx::migrate::Migrator::new(std::path::Path::new(&dir)).await?;
    migrator.run(pool).await?;
    tracing::info!(dir, "migrations applied");
    Ok(())
}

/// Ensure a first account and its tokens exist.
///
/// Idempotent, and a no-op unless all three variables are set. This is how an
/// operator gets their first credential without a chicken-and-egg problem, and
/// how the integration suite seeds a known account.
async fn bootstrap(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let (Ok(account), Ok(admin), Ok(edge)) = (
        std::env::var("PLANE_BOOTSTRAP_ACCOUNT_ID"),
        std::env::var("PLANE_BOOTSTRAP_ADMIN_TOKEN"),
        std::env::var("PLANE_BOOTSTRAP_EDGE_TOKEN"),
    ) else {
        return Ok(());
    };

    sqlx::query("INSERT INTO accounts (id, name) VALUES ($1, $1) ON CONFLICT (id) DO NOTHING")
        .bind(&account)
        .execute(pool)
        .await?;

    for (token, scope) in [(&admin, "admin"), (&edge, "edge")] {
        sqlx::query(
            "INSERT INTO account_tokens (token_sha256, account_id, scope, label)
             VALUES ($1, $2, $3, 'bootstrap')
             ON CONFLICT (token_sha256) DO NOTHING",
        )
        .bind(auth::hash_token(token))
        .bind(&account)
        .bind(scope)
        .execute(pool)
        .await?;
    }

    tracing::info!(account, "bootstrap account ensured");
    Ok(())
}

async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::warn!(%error, "cannot listen for SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
    tracing::info!("shutdown requested");
}
