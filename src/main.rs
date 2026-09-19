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
mod edge;
mod error;
mod tenants;
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
}

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
        .connect(&database_url)
        .await?;

    migrate(&pool).await?;
    bootstrap(&pool).await?;

    let state = AppState { pool };
    let app = Router::new()
        .route("/healthz", routing::get(healthz))
        .merge(tenants::router())
        .merge(usage::router())
        .merge(edge::router())
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "control plane ready");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

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
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
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
