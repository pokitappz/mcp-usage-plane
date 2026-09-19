# mcp-usage-plane

Hosted usage and entitlement control plane for MCP servers. The paid half of
the open-core split: the metering crates and the sidecar are Apache-2.0, this
service is not.

```
                          [ control plane ]        <- this service
                          axum + Postgres
                          keys | prices | limits | ledger
                             ^            |
          usage aggregates   |            |  snapshot
                             |            v
  [ agent ] --MCP--> [ mcp-usage-edge ] --MCP--> [ customer MCP server ]
```

It depends on `mcp-usage-core` and `mcp-usage-export` **from crates.io**, not by
path. That keeps the open-core boundary honest: if the published crates were not
enough to build a control plane, anyone self-hosting the free sidecar would hit
the same wall.

## The one rule

The sidecar sits on the customer's hot path and this service does not. Every
contract here is pull-based, idempotent and free of session state, so that **the
plane being down never fails a customer's MCP call**. An outage costs freshness
and delayed invoicing, not availability.

The single deliberate exception lives in the sidecar: a snapshot older than its
`max_stale` budget stops authenticating, because serving hours-old revocations
is worse than refusing.

## Endpoints

Tokens are scoped. `admin` manages tenants and prices; `edge` may only pull a
snapshot and post usage. A sidecar runs in customer infrastructure and is the
most exposed component, so it never holds a credential that could rewrite
prices.

| Route | Scope | Purpose |
|---|---|---|
| `GET /healthz` | none | Liveness, including a database round trip |
| `POST /v1/tenants` | admin | Create a tenant |
| `GET /v1/tenants` | admin | List tenants |
| `PATCH /v1/tenants/{key}` | admin | Update prices and limits |
| `DELETE /v1/tenants/{key}` | admin | Revoke a tenant |
| `POST /v1/tenants/{key}/keys` | admin | Mint a key; the plaintext appears once |
| `DELETE /v1/tenants/{key}/keys/{digest}` | admin | Revoke one key |
| `GET /v1/usage` | admin | Rollup by bucket, customer and meter |
| `GET /v1/usage/quota` | admin | Committed totals and current admission verdict |
| `GET /v1/edge/snapshot` | edge | Everything a sidecar needs to price and admit |
| `POST /v1/edge/usage` | edge | Idempotent aggregate ingest |

Revocation is absence: a revoked tenant or key simply stops appearing in the
snapshot, and the sidecar cannot authenticate a key it was never given.

## Idempotency

`AggregatedUsage::identifier` is stable across retries, so it is the primary key
of `usage_events`. A replayed batch inserts nothing and moves no counter. A
failed commit withdraws every accepted verdict in that batch and returns
`retry`, because reporting "accepted" for a row that rolled back is the one
outcome that loses money silently.

## Grain, and what is deliberately not reported

There is no per-tool breakdown. An `AggregatedUsage` carries only its
identifier, billing customer, meter name, unit count and timestamp: the meter
aggregates on the billing customer and meter name, and the library keeps tool
names, prompt names and resource URIs out of anything it persists or exports.
Reporting per tool would mean changing what the edge sends and giving that up.
An operator who wants the breakdown prices tools onto distinct meter names
instead, which keeps the names on their side of the wire.

Counters key on the billing customer, which is the grain usage actually arrives
at. Tenants sharing a billing customer therefore share a quota pool, which is
the correct reading of "this customer's quota". Where such tenants disagree on
unit price the highest applies, because over-stating spend is the safe direction
for a spend cap.

## Running it

```sh
createdb mcp_usage_plane
DATABASE_URL='postgres://localhost/mcp_usage_plane' \
PLANE_BOOTSTRAP_ACCOUNT_ID=acct_1 \
PLANE_BOOTSTRAP_ADMIN_TOKEN="$(openssl rand -base64 32)" \
PLANE_BOOTSTRAP_EDGE_TOKEN="$(openssl rand -base64 32)" \
  cargo run
```

The bootstrap variables are idempotent and optional; they exist so an operator
gets a first credential without a chicken-and-egg problem.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | required | Postgres connection string |
| `PORT` | `8081` | Listen port |
| `DATABASE_MAX_CONNECTIONS` | `10` | Pool size |
| `MIGRATIONS_DIR` | `./migrations` | Where migrations are read from at startup |

## Tests

```sh
createdb mcp_plane_test
TEST_DATABASE_URL='postgres://localhost/mcp_plane_test' cargo test
```

The suite boots the compiled binary against a scratch database per test and
talks to it over HTTP, so tenancy scoping in SQL, scope enforcement in the
extractor and idempotency in the primary key are all exercised for real. Without
`TEST_DATABASE_URL` the database-backed tests skip themselves and the rest still
run.
