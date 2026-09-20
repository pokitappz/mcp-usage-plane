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
| `PUT /v1/export/destination` | admin | Configure where usage is forwarded |
| `GET /v1/export/destination` | admin | Destination, pending count, dead letters |
| `GET /v1/export/dead-letters` | admin | Aggregates awaiting reconciliation |
| `POST /v1/export/dead-letters/{id}/resolve` | admin | Mark one reconciled |
| `GET /v1/billing` | admin | Subscription status and unbilled units |
| `PUT /v1/billing` | admin | Link the account to a Stripe customer |
| `POST /v1/signup` | none | Self-serve signup, gated by a shared secret |
| `POST /v1/stripe/webhook` | signature | Subscription lifecycle from Stripe |

Revocation is absence: a revoked tenant or key simply stops appearing in the
snapshot, and the sidecar cannot authenticate a key it was never given.

## Billing export

Usage flows in two directions from the same ledger row, and they are kept apart
on purpose:

- **Downstream** is the product. An account's usage reaches *its own* billing
  provider, priced and named the way that account wants.
- **Upstream** is the revenue. The same usage, re-attributed to the account's
  own Stripe customer, reaches the plane's provider.

They use different credentials, different Stripe accounts and different columns
on the ledger, so neither can settle or replay the other. The upstream event
identifier is namespaced (`plane:<identifier>`) so that an account forwarding to
the same Stripe account the plane bills through does not have one of the two
silently deduplicated away.

Two destinations exist. `stripe` posts Billing Meter Events. `webhook` posts
signed JSON to a customer-supplied endpoint, for a billing system with no
first-class provider here, carrying `X-Usage-Signature: sha256=<hex>` over the
raw body.

There is deliberately **no MPP destination**. MPP is an *inbound* payment
protocol: it standardizes HTTP 402, where an agent calls an endpoint, gets a
challenge, pays, and retries with `Authorization: Payment` to receive a
`Payment-Receipt`. There is no usage-ingest endpoint on the other side to export
aggregates to, so an "MPP export" would have nothing to talk to. Supporting MPP
means answering 402 at the sidecar, which is edge work, not a destination here.

### Credentials

A customer's billing credential is sealed with ChaCha20-Poly1305 under
`SECRET_SEALING_KEY` and stored as `enc:<base64(nonce||ciphertext)>`, the same
envelope Backstock uses for POS tokens. It is never returned by any endpoint;
the API reports only whether one is stored. A key that is set but malformed
stops the service from starting rather than silently storing the next credential
unprotected.

A webhook endpoint is supplied by the customer, so it is checked against
loopback, private and link-local ranges before anything is dialled: without that
the plane is an SSRF proxy into its own network. A hostname that *resolves* to a
private address is not covered, which would need a resolving connector.

### Reconciliation

A provider outcome is one of three things, and the difference is money:

| Outcome | Meaning | What happens |
|---|---|---|
| Accepted | Delivered | The row is marked settled |
| Retryable | The request or the account failed | The row stays pending and is retried |
| Permanent rejection | *This event* is invalid and always will be | Recorded in `export_dead_letters`, then settled |

Quarantining is a one-way door, so only statuses that describe the event itself
qualify. `401`, `402`, `403`, `404`, `408`, `424` and `429` describe the request
or the account and apply identically to a whole batch, so they stay retryable: a
mistyped path answering `404` for every event would otherwise quarantine all
usage and report success.

This drives `MeterEventProvider` directly rather than going through
`MeterEventExporter`. That exporter exists so an in-process pipeline can keep
partial retry progress and a bounded dead letter queue in memory; the plane has
a database, and a second weaker copy of that state would only add something to
disagree with the ledger and die with the process.

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
| `SECRET_SEALING_KEY` | none | Seals customer billing credentials. Required before one can be stored |
| `EXPORT_DRAIN_INTERVAL_SECONDS` | `30` | How often usage is forwarded |
| `ALLOW_LOOPBACK_DESTINATIONS` | off | Tests only. Permits a loopback export destination |
| `PLANE_STRIPE_SECRET_KEY` | none | The plane's own Stripe key. Upstream billing is idle without it |
| `PLANE_STRIPE_METER_NAME` | none | Meter the plane records processed units against |
| `PLANE_STRIPE_WEBHOOK_SECRET` | none | Verifies inbound Stripe webhooks. The endpoint 404s without it |
| `PLANE_SIGNUP_SECRET` | none | Gates `/v1/signup`. Signup is closed without it |

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
