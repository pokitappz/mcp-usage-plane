# mcp-usage-plane

Usage and entitlement control plane for MCP servers. The paid half of the
open-core split: the metering crates and the proxy are Apache-2.0, this service
is source-available under the [Business Source License](#licence). You run it
yourself; there is no hosted version at the moment. Read it, build it and run it
outside production for free; production use is **$299 a month** per deployment;
each version becomes Apache-2.0 four years after it ships.

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
| `GET /healthz` | none | Liveness, including a database round trip. Polled by the platform; the probe is cached briefly so it is not a free pool connection per call |
| `POST /v1/tokens` | admin | Mint an account credential; the plaintext appears once |
| `GET /v1/tokens` | admin | List account credentials, never the credentials themselves |
| `DELETE /v1/tokens/{digest}` | admin | Revoke one. The last live admin token is refused |
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
| `GET /v1/pricing` | admin | The account's terms |
| `PUT /v1/pricing` | admin | Set rate, floor and when the terms apply |
| `GET /v1/pricing/invoices` | admin | Closed periods and what each was charged |
| `GET /v1/billing` | admin | Subscription status and unbilled units |
| `PUT /v1/billing` | admin | Link the account to a Stripe customer |
| `POST /v1/auth/code` | none | Email a sign-in code to a known address |
| `POST /v1/auth/verify` | none | Redeem a code for a browser session |
| `GET /v1/auth/session` | session | Who the caller is and which account they act on |
| `DELETE /v1/auth/session` | session | Sign out, deleting the session server side |
| `POST /v1/accounts` | secret | Create an account, its two tokens, and optionally the person who signs in. Closed unless a secret is set |
| `POST /v1/stripe/webhook` | signature | Subscription lifecycle and invoice outcomes from Stripe |

Revocation is absence: a revoked tenant or key simply stops appearing in the
snapshot, and the sidecar cannot authenticate a key it was never given.

## Pages

The service renders three things in a browser: sign-in, the dashboard, and a
404. The marketing site it used to serve lives in its own repository, so a
crate somebody installs carries what runs the service and nothing else.

| Route | Who | Purpose |
|---|---|---|
| `GET /` | anyone | Redirects to sign-in |
| `GET /signin` | anyone | Ask for a sign-in code |
| `POST /signin` | anyone | Send one, then show the code form |
| `POST /signin/verify` | anyone | Redeem a code and open a session |
| `POST /signout` | anyone | End the session and clear the cookie |
| `GET /app` | session | The dashboard. Anonymous gets a redirect, never markup |
| `POST /app/tokens` | session | Mint an account credential, shown once on the page |
| `POST /app/tokens/{digest}/revoke` | session | Revoke one |
| `POST /app/tenants/{key}/keys` | session | Mint a customer key, shown once on the page |
| `POST /app/dead-letters/{id}/resolve` | session | Mark one handled |
| `GET /assets/{file}` | anyone | The stylesheet and icon, compiled into the binary |

Three properties hold across all of them.

**The dashboard is gated by the server.** An anonymous request to `/app` gets a
redirect and an empty body, not the shell with a client-side bounce.

**Nothing inline.** Every response carries a content security policy with no
`unsafe-inline` and no `unsafe-eval`. There is no JavaScript at all: every
action is a form post that redirects, and the `SameSite=Lax` cookie plus an
`Origin` check that fails closed is the whole CSRF story. A test renders the
pages and fails the build on an inline script, style or handler, and another
fails if a class reaches the markup without a rule in the stylesheet.

**A minted credential is rendered, never redirected with.** A redirect would
carry it in a query string, which puts it in browser history and proxy logs.

Page handlers call the same functions the JSON handlers call rather than a
second copy of the SQL, and a test asserts the figures on the page match the
figures `GET /v1/usage` returns.

## Two kinds of caller

Machines present a bearer token. People present a session cookie. They are
separate systems on purpose, and neither opens the other's routes.

A bearer token is a long-lived credential that is also a full admin credential
for its account. That is right for a sidecar and wrong for a browser: any script
on the page could read it, it does not expire, and it cannot be attributed to a
person. So the dashboard uses a session instead.

Sign-in is passwordless. A six digit code is emailed to a **known** address,
redeemed once, and exchanged for an opaque session. Only the session's SHA-256
reaches the database, the same property `account_tokens` already has, so a
database disclosure does not hand over live sessions.

| Property | Value |
|---|---|
| Cookie | `HttpOnly`, `SameSite=Lax`, `Secure` when `APP_PUBLIC_URL` is https |
| Session lifetime | 7 days |
| Code lifetime | 10 minutes, one use |
| Wrong guesses | 5, then the code is spent rather than reset |
| Resend cooldown | 60 seconds, enforced in SQL so a race cannot beat it |

Two deliberate refusals. An unknown address gets the same answer as a known one,
because anything else makes the endpoint an account-existence oracle. And a
state-changing request with **no** `Origin` header is refused rather than assumed
friendly, so the CSRF check fails closed.

An address is matched case-insensitively. The columns are `CITEXT`, but that is
not enough on its own: a bound parameter arrives as `text`, and Postgres
resolves `citext = text` by casting the *column* down to text, which compares
case-sensitively. Every lookup therefore casts the parameter with `$1::citext`.
Without it somebody invited as `Person@Example.com` who types
`person@example.com` is simply not found, and because an unknown address is
answered identically to a known one, they are told a code was sent and wait for
mail that was never generated.

## Creating the first account

Nothing can sign in to an empty database, so provisioning creates the account,
its two tokens and its owner in one request.

```sh
curl -fsS -X POST "$PLANE_URL/v1/accounts" \
  -H 'content-type: application/json' \
  -d '{"name":"Northwind Tools",
       "provision_secret":"'"$PLANE_PROVISION_SECRET"'",
       "owner_email":"founder@northwind.example"}'
```

The two tokens come back once and are not recoverable. `owner_email` is
optional: leave it out for an account that only serves machines, and no person
is created. Supply it and that address can sign in at `/signin` immediately.

The route answers 404 unless `PLANE_PROVISION_SECRET` is set, which is the
default, so a fresh deployment is not an open account factory.

## Request bounds

Every request is admitted through a per-token budget and a short-lived
authentication cache, both process-local.

| Bound | Value | Why |
|---|---|---|
| Requests per token | 240 / minute | Refused with `429` and a `Retry-After`. Per token, so one customer's sidecar cannot deny service to another |
| Failed authentications | 120 / minute, process-wide | Counted globally, not per credential. A per-credential budget gives every distinct guess a fresh allowance, which bounds nothing; success uses a separate budget, so this cannot deny a valid caller |
| Account provisioning | 20 / minute, process-wide | Same reason. There is one operator, so a shared bound cannot lock out a legitimate user |
| Sign-in codes | 5 / minute per address | Taken explicitly. The per-token budget is spent inside `auth::resolve`, so a route with no bearer extractor never reaches it |
| Code redemptions | 20 / minute per address | Same reason |
| Authentication cache | 10 seconds | Removes a database round trip from every request. Revoking a token calls through to drop the entry, so revocation does not wait for the TTL |
| Request body | 64 KiB, or 4 MiB on `/v1/edge/usage` | Only the usage post legitimately carries a large body |
| Request timeout | 30 seconds | Outermost, so a client that trickles its body cannot hold a pool connection indefinitely |
| Statement timeout | 15 seconds | A query that never returns would otherwise hold one of ten pool connections until restart |

The budgets are per instance. At `min_machines_running = 1` that is the whole
service; scaling out makes each machine enforce its own, so treat them as
self-protection rather than a fairness guarantee between customers. The same is
true of the cache: a second instance still honours a revoked token until its own
entry expires, which is why the window is ten seconds and not ten minutes.

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

## What the plane charges

```
max(floor_micros,
    max(0, units - included_units) * per_event_micros
    + revenue_micros * rate_bps / 10_000)
```

per account per calendar month. `units` is metered events; `revenue_micros` is
the account's **own** metered revenue, the sum of what it charged its customers,
which the plane already computes into `usage_counters.spend_micros` for spend
caps.

Two priced dimensions, summed, then floored. An account normally uses one:

| Model | Terms |
|---|---|
| Published price: free under 50k events, then $0.50 per 10k | `per_event_micros = 50`, `included_units = 50_000`, `rate_bps = 0` |
| Negotiated percentage of revenue, with a minimum | `rate_bps = 150`, `floor_micros = 49_000_000`, `per_event_micros = 0` |

Summing rather than choosing means a hybrid needs no mode flag, and a mode flag
is the kind of thing that ends up disagreeing with the invoice.

Everything is integer arithmetic in millionths, via `i128` for the multiply.
This multiplies money, and a rounding nobody can reproduce from an invoice is a
support ticket. The charge is converted to whole cents, rounded half up, only at
the moment it is handed to Stripe, because meter values are integers.

**This used to be a drip and is now a close.** Upstream billing forwarded one
meter event per processed unit, 1:1, continuously, with the actual rate living
in a Stripe dashboard object. That shape cannot express a minimum, because a
floor is a property of a period and a drip has no periods. The event ledger in
`usage_events` is unchanged and is still the audit trail; what became
period-grained is the charge.

Three properties worth knowing:

- **Only finished months are charged.** The current month is still accruing, and
  invoicing it would bill a partial period.
- **Terms have a `starts_at`, defaulting to now.** The close walks back several
  finished periods, so without this, agreeing terms today would invoice an
  account a floor for each of the months before it had any. Backdating is
  explicit and supported, because onboarding mid-month and migrating an existing
  customer both need it.
- **A period is charged once.** `plane_invoices` is keyed on
  `(account_id, period_start)` and carries the identifier the provider
  deduplicates on. A period that already has a row is never recomputed, so
  changing an account's rate cannot restate what it was already charged.

The model depends on a customer's `unit_price_micros` being truthful, because
that declared price is what the percentage is taken of. That is a commercial
property of charging a percentage of someone's revenue, not something this code
can enforce.

## Stripe

The outbound `Stripe-Version` is pinned at `2026-08-26.dahlia`. The inbound
check on a webhook's `api_version` is against the **release suffix** only, not
the dated version: within a release every later monthly version is additive, so
matching the exact date would raise a false alarm the moment Stripe ships the
next one. Bumping the pin is therefore a one-constant change, and a recurring
monthly calendar item rather than a migration.

Two Stripe details this code learned the hard way, recorded so they are not
re-derived:

- **`current_period_end` is not on the Subscription object.** It lives on each
  subscription item, at `items.data[].current_period_end`
  (<https://docs.stripe.com/api/subscriptions/object>). Reading it from the top
  level yields `None` on every delivery, and a `COALESCE` in the UPDATE then
  swallows that silently, leaving the column NULL forever. The maximum across
  items is used, because items can bill on different anchors.
- **The meter-error notification is a v2 thin event.** Stripe reports rejected
  meter events as `v1.billing.meter.error_report_triggered`, which despite the
  `v1.` prefix is delivered to a v2 event destination and does not appear in
  the v1 snapshot event list at all. It is *not* handled here yet; until it is,
  meter events Stripe drops are invisible.

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
| `SECRET_SEALING_KEY` | none | Seals customer billing credentials. Required before one can be stored |
| `EXPORT_DRAIN_INTERVAL_SECONDS` | `30` | How often usage is forwarded |
| `ALLOW_LOOPBACK_DESTINATIONS` | off | Tests only. Permits a loopback export destination |
| `PLANE_STRIPE_RESTRICTED_KEY` | none | This service's own Stripe **restricted** key, for billing its own customers. Billing is idle without it, and a secret key is refused |
| `PLANE_STRIPE_METER_NAME` | none | Meter the plane records processed units against |
| `PLANE_STRIPE_WEBHOOK_SECRET` | none | Verifies inbound Stripe webhooks. The endpoint 404s without it |
| `PLANE_PROVISION_SECRET` | none | Gates `/v1/accounts`. Provisioning is closed without it, which is the default |
| `PLANE_PRODUCT_NAME` | `Usage control plane` | What this deployment calls itself, in the wordmark, page titles and outgoing mail |
| `PLANE_PRODUCT_SUFFIX` | none | A second word set apart in the wordmark, as "Cloud" is in "UsageKit Cloud" |
| `EMAIL_SERVICE_URL` | none | Your transactional email service. Any https endpoint; plaintext only on loopback |
| `EMAIL_SERVICE_TOKEN` | none | Bearer token for it. Must be set together with the URL |
| `EMAIL_FROM_ADDRESS` | required with email | The address mail is sent from. No default, because sending as an address you do not own is how a deployment gets blocklisted |
| `EMAIL_PRODUCT_NAME` | `Usage control plane` | What the mail calls itself, in subjects and bodies |
| `EMAIL_OPERATOR_ADDRESS` | the from address | Where operational notices are sent |
| `EMAIL_ALLOW_PLAINTEXT` | off | Permits a plaintext endpoint off loopback, for a mail relay on a private network. The service token then crosses that network in the clear |

## Running it yourself

This is how the service is meant to be run: your Postgres, your Stripe account,
no credential of yours anywhere near us.

Everything below is free. Putting it in front of real customers needs a
subscription; see [Licence](#licence).

```sh
cargo install mcp-usage-plane

DATABASE_URL='postgres://...' \
SECRET_SEALING_KEY="$(head -c 32 /dev/urandom | base64)" \
  mcp-usage-plane
```

The migrations, the templates and the stylesheet are compiled into the binary,
so that is the whole install: one file, a Postgres, and two variables. There is
no directory to place beside it and nothing to keep in sync.

Then create your first account and its owner, as above, and sign in at
`/signin`.

Two things are worth knowing, both deliberate:

- **No branding of ours.** The wordmark, page titles and outgoing mail all read
  `PLANE_PRODUCT_NAME`, which defaults to something generic rather than to us.
  `EMAIL_FROM_ADDRESS` has no default at all, because sending as an address you
  do not own is how a deployment gets blocklisted.
- **The billing of customers is dormant.** `PLANE_STRIPE_RESTRICTED_KEY` and
  `PLANE_PROVISION_SECRET` are how this service charges *its* customers and
  provisions accounts. Leave them unset and the monthly close returns
  immediately and the provisioning route answers 404. The machinery is there if
  you later want to bill your own downstream customers with it.

## Licence

[Business Source License 1.1](LICENSE.md), converting to Apache-2.0.

| | |
|---|---|
| **Free** | Reading, modifying, building and running it outside production. Evaluation, development, testing and staging need no subscription and no conversation |
| **Paid** | Production use, at **$299 per month per deployment**. That is the whole price: no per-event charge, no percentage of what you bill, no seat count |
| **Eventually free** | Each version converts to Apache-2.0 on its Change Date, four years after it ships, and stays that way |

The Additional Use Grant is `None`, which means the licence's own terms decide
what is free: BSL grants non-production use to everybody, and production use is
what a subscription buys. There is deliberately nothing to measure or report.

Buying it is an email to support@pokitapps.com. There is no licence key, no
phone-home check and no audit clause, because a self-hosted deployment cannot
be policed and pretending otherwise would only inconvenience the people who do
pay.

The dependency tree is entirely permissive, which is what makes distributing it
possible at all, and `cargo deny` fails the build if a copyleft-only dependency
ever arrives. `mcp-usage-core` and `mcp-usage-export`, the crates that decide
what counts as billable, remain Apache-2.0 on crates.io and are unaffected.

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
