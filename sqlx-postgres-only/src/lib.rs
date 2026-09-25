//! PostgreSQL-only SQLx facade, so MySQL and its RSA dependency stay out of
//! the lockfile.
//!
//! The upstream `sqlx` facade declares every database driver as an optional
//! dependency. Cargo records optional dependencies in `Cargo.lock` whatever
//! features are selected, so a Postgres-only project still resolves
//! `sqlx-mysql`, and with it `rsa` and its open advisory RUSTSEC-2023-0071.
//! `cargo audit` reads the lockfile, so the finding is reported forever even
//! though nothing built can reach the code.
//!
//! Note that `cargo tree -i rsa` reports nothing either way: it resolves the
//! build graph for one target, which is not what `cargo audit` reads.
//!
//! This crate depends on `sqlx-core` and `sqlx-postgres` directly and
//! re-exports the surface a Postgres application uses. It declares
//! `[lib] name = "sqlx"`, so `sqlx::` paths resolve unchanged.
//!
//! The `query!` and `migrate!` macros are deliberately absent: they live in
//! `sqlx-macros`, which depends on `sqlx-mysql`. See the README for how to
//! build a `Migrator` without the macro.

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
