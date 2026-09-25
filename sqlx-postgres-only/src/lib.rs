//! PostgreSQL-only SQLx facade for the control plane.
//!
//! The upstream `sqlx` facade declares every database driver as an optional
//! dependency. Cargo therefore retains MySQL and its RSA implementation in the
//! lockfile even when only the `postgres` feature is enabled, which shows up as
//! RUSTSEC-2023-0071 in `cargo audit` forever. This facade exposes the small
//! surface the plane uses without resolving those packages.
//!
//! Lifted from the same trick in `bm-purchasing/sqlx-postgres-only`.

pub use sqlx_core::error::{self, Error, Result};
pub use sqlx_core::executor::{Execute, Executor};
pub use sqlx_core::from_row::FromRow;
pub use sqlx_core::migrate;
pub use sqlx_core::query::{query, query_with};
pub use sqlx_core::query_as::{query_as, query_as_with};
pub use sqlx_core::query_scalar::{query_scalar, query_scalar_with};
pub use sqlx_core::row::Row;
pub use sqlx_core::transaction::Transaction;
pub use sqlx_postgres::{
    self as postgres, PgConnection, PgExecutor, PgPool, PgPoolOptions, PgRow, PgTransaction,
    Postgres,
};

pub mod types {
    pub use sqlx_core::types::*;
}
