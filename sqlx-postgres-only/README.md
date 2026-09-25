# plane-sqlx-postgres

A PostgreSQL-only [SQLx](https://github.com/launchbadge/sqlx) facade, so MySQL
and its RSA dependency stay out of your lockfile.

```toml
[dependencies]
sqlx = { package = "plane-sqlx-postgres", version = "0.1" }
```

The crate declares `[lib] name = "sqlx"`, so `sqlx::query`, `sqlx::PgPool` and
the rest resolve exactly as they would with the upstream crate. Renaming it in
`Cargo.toml` is the whole integration.

## Why this exists

The upstream `sqlx` facade declares every database driver as an *optional*
dependency. Cargo records optional dependencies in `Cargo.lock` whatever
features you select, so a Postgres-only project still ends up with `sqlx-mysql`
in the lockfile, and `sqlx-mysql` brings `rsa`.

`rsa` has an open advisory, [RUSTSEC-2023-0071][adv] (Marvin Attack, a timing
sidechannel that can recover a key). `cargo audit` reads the lockfile, so the
finding is reported against your project even though nothing you build can
reach the code. There is no patched version to upgrade to, which means the
choice is to ignore the advisory indefinitely or to stop resolving the package.

This crate does the latter by depending on `sqlx-core` and `sqlx-postgres`
directly and re-exporting the surface a Postgres application uses.

[adv]: https://rustsec.org/advisories/RUSTSEC-2023-0071

### `cargo tree` will tell you there is no problem

This is the part worth internalising, because it is what makes the issue easy
to dismiss:

```
cargo tree -i rsa        # nothing
cargo tree -i sqlx-mysql # nothing
```

`cargo tree` resolves the build graph for one target. The lockfile is not that
graph, and `cargo audit` reads the lockfile. A clean tree is not a clean audit.
Check with `grep 'name = "rsa"' Cargo.lock` instead.

## What you get

Re-exported from `sqlx-core`:

| Path | Contents |
|---|---|
| `sqlx::{Error, Result}`, `sqlx::error` | error types |
| `sqlx::{Execute, Executor}` | the executor traits |
| `sqlx::FromRow` | the row-mapping trait |
| `sqlx::Row` | the row trait |
| `sqlx::Transaction` | transactions |
| `sqlx::migrate` | `Migrator`, `Migration`, `MigrationType` |
| `sqlx::types` | the full `sqlx_core::types` module |
| `sqlx::query*` | `query`, `query_as`, `query_scalar`, and their `_with` forms |

Re-exported from `sqlx-postgres`:

`sqlx::postgres`, `PgConnection`, `PgExecutor`, `PgPool`, `PgPoolOptions`,
`PgRow`, `PgTransaction`, `Postgres`.

Both dependencies are pinned at `=0.8.6`, because the facade re-exports private
feature combinations (`_rt-tokio`, `_tls-rustls-ring-webpki`) that upstream may
rename between patch releases. Features enabled: `chrono`, `json`, `migrate`,
Tokio, and rustls with ring and webpki roots.

## What you do not get

**The `sqlx::query!` family of macros, and `sqlx::migrate!`.** They live in
`sqlx-macros`, which depends on `sqlx-mysql`, which is the thing this crate
exists to avoid. Pulling them back in would undo the point.

For queries, use the non-macro functions above. They lose compile-time
verification against a live database, which is a real cost worth weighing.

For migrations, build a `Migrator` yourself. `include_str!` also embeds the SQL
into the binary, so an installed executable carries its own migrations rather
than reading a directory that may not exist next to it:

```rust
use sqlx::migrate::{Migration, MigrationType, Migrator};

const FILES: &[(&str, &str)] = &[
    ("0001_initial.sql", include_str!("../migrations/0001_initial.sql")),
];

fn migrator() -> Migrator {
    let migrations: Vec<Migration> = FILES
        .iter()
        .map(|(name, sql)| {
            let (version, rest) = name.split_once('_').expect("NNNN_name.sql");
            let migration_type = MigrationType::from_filename(rest);
            let description = rest
                .trim_end_matches(migration_type.suffix())
                .replace('_', " ");
            Migration::new(
                version.parse().expect("numeric version"),
                description.into(),
                migration_type,
                (*sql).into(),
                sql.starts_with("-- no-transaction"),
            )
        })
        .collect();

    Migrator { migrations: migrations.into(), ignore_missing: false, locking: true, no_tx: false }
}
```

## Scope

This is a narrow facade covering what one Postgres service needs, not a
drop-in replacement for `sqlx`. If something you use is missing, an issue or a
pull request adding the re-export is welcome.

It is published so that [`mcp-usage-plane`](https://github.com/pokitappz/mcp-usage-plane)
can depend on it, because crates.io refuses path dependencies. It is not
affiliated with the SQLx project.

## License

MIT OR Apache-2.0, matching SQLx itself.
