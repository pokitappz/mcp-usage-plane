-- Control plane schema.
--
-- Grain note: `AggregatedUsage` carries (identifier, customer_id, meter, units,
-- timestamp) and deliberately drops the tenant id and the tool name, because the
-- meter aggregates on (customer_id, meter) and the library keeps tool names,
-- prompt names and resource URIs out of anything it persists or exports. The
-- counters below therefore key on the billing customer, which is the grain the
-- usage actually arrives at. Tenants that share a billing customer share a quota
-- pool, which is the correct reading of "this customer's quota".

CREATE TABLE accounts (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tokens an operator or an edge presents to this plane. `admin` manages
-- tenants; `edge` may only pull a snapshot and post usage. Separating them
-- means a compromised sidecar cannot rewrite prices.
CREATE TABLE account_tokens (
    token_sha256 TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    scope        TEXT NOT NULL CHECK (scope IN ('admin', 'edge')),
    label        TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX account_tokens_account_idx ON account_tokens (account_id);

CREATE TABLE tenants (
    id                  BIGSERIAL PRIMARY KEY,
    account_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- The `Tenant.id` the meter reports back on every usage event.
    tenant_key          TEXT NOT NULL,
    billing_customer_id TEXT NOT NULL,
    -- A serialized `mcp_usage_core::PriceBook`. Stored whole rather than
    -- normalized: it is a versioned document the edge receives verbatim, and
    -- splitting it into rows would invite the plane to invent pricing semantics
    -- that `units_for` already defines.
    prices              JSONB NOT NULL DEFAULT '{"default_units":1}'::jsonb,
    price_version       INTEGER NOT NULL DEFAULT 1,
    -- NULL means unbounded, matching `Limits`.
    max_units           BIGINT CHECK (max_units IS NULL OR max_units >= 0),
    max_spend_micros    BIGINT CHECK (max_spend_micros IS NULL OR max_spend_micros >= 0),
    unit_price_micros   BIGINT NOT NULL DEFAULT 0 CHECK (unit_price_micros >= 0),
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, tenant_key)
);

CREATE INDEX tenants_account_idx ON tenants (account_id);
CREATE INDEX tenants_customer_idx ON tenants (account_id, billing_customer_id);

-- Keys are stored only as digests. A key is high-entropy, so a fast lookup hash
-- is the right primitive; this is not a password. Rotation is insert-then-revoke
-- rather than update, so an in-flight caller keeps working during a rollover.
CREATE TABLE tenant_api_keys (
    key_sha256 TEXT PRIMARY KEY,
    tenant_id  BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    label      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX tenant_api_keys_tenant_idx ON tenant_api_keys (tenant_id);

-- The idempotent usage ledger. `identifier` is `AggregatedUsage::identifier`,
-- which the exporter guarantees is stable across retries, so the primary key is
-- the whole deduplication story: a replayed batch is a no-op.
CREATE TABLE usage_events (
    identifier  TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    customer_id TEXT NOT NULL,
    meter       TEXT NOT NULL,
    units       BIGINT NOT NULL CHECK (units >= 0),
    event_at    TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX usage_events_rollup_idx ON usage_events (account_id, customer_id, event_at);
CREATE INDEX usage_events_meter_idx ON usage_events (account_id, meter, event_at);

-- Authoritative committed totals. Maintained transactionally alongside the
-- ledger insert so a replayed identifier cannot double-count.
CREATE TABLE usage_counters (
    account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    customer_id  TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    units        BIGINT NOT NULL DEFAULT 0 CHECK (units >= 0),
    spend_micros BIGINT NOT NULL DEFAULT 0 CHECK (spend_micros >= 0),
    PRIMARY KEY (account_id, customer_id, window_start)
);
