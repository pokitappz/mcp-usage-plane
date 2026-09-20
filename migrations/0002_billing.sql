-- Billing export and the plane's own subscription state.
--
-- Two distinct relationships live here and are deliberately not conflated:
--
--   downstream: an account's usage is forwarded to *its own* billing provider,
--               which is the product feature customers pay for.
--   upstream:   the plane bills *its* customers for the usage it processed,
--               which is how the plane earns.
--
-- Both ride the same `MeterEventProvider` machinery and both key on the same
-- stable `AggregatedUsage::identifier`, so a replay is a no-op in either
-- direction. They are tracked in separate columns so one can be retried,
-- reset, or replayed without disturbing the other.

CREATE TABLE export_destinations (
    account_id    TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('none', 'stripe', 'webhook')),
    -- Sealed with ChaCha20-Poly1305. Never returned by any endpoint, and the
    -- plane refuses to start if the sealing key is present but unusable.
    secret_sealed TEXT,
    -- Meter event name sent to the destination. Defaults to whatever the edge
    -- reported, which keeps a customer's existing meter names working.
    meter_name    TEXT,
    -- Webhook endpoint. Customer-supplied, so allowlisted at use against
    -- loopback and private ranges: the plane must not become an SSRF proxy.
    endpoint      TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- A destination that sends anywhere needs a credential; 'none' must not.
    CONSTRAINT export_destination_needs_secret
        CHECK (kind = 'none' OR secret_sealed IS NOT NULL),
    -- A webhook destination is nothing without somewhere to post to.
    CONSTRAINT export_webhook_needs_endpoint
        CHECK (kind <> 'webhook' OR endpoint IS NOT NULL)
);

-- Export progress rides on the ledger rather than a queue table: the ledger is
-- already the durable, idempotent record of what happened, and a second copy
-- would only invite the two to disagree.
ALTER TABLE usage_events ADD COLUMN exported_at     TIMESTAMPTZ;
ALTER TABLE usage_events ADD COLUMN plane_billed_at TIMESTAMPTZ;

-- Partial indexes, because the interesting set is always the small unfinished
-- tail rather than the whole ledger.
CREATE INDEX usage_events_pending_export_idx
    ON usage_events (account_id, event_at) WHERE exported_at IS NULL;
CREATE INDEX usage_events_pending_plane_billing_idx
    ON usage_events (account_id, event_at) WHERE plane_billed_at IS NULL;

-- Permanently rejected exports. The library's in-process dead letter queue is
-- bounded and dies with the process; this is where reconciliation data has to
-- live to be worth anything.
CREATE TABLE export_dead_letters (
    identifier  TEXT NOT NULL,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    customer_id TEXT NOT NULL,
    meter       TEXT NOT NULL,
    units       BIGINT NOT NULL CHECK (units >= 0),
    event_at    TIMESTAMPTZ NOT NULL,
    direction   TEXT NOT NULL CHECK (direction IN ('downstream', 'upstream')),
    destination TEXT NOT NULL,
    -- A static, low-cardinality category. Never a provider message or body.
    reason      TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolved_by TEXT,
    -- Keyed by direction too: the same aggregate can fail downstream and
    -- upstream for different reasons, and a bare identifier key would silently
    -- drop the second record.
    PRIMARY KEY (identifier, direction)
);

CREATE INDEX export_dead_letters_open_idx
    ON export_dead_letters (account_id, recorded_at) WHERE resolved_at IS NULL;

-- The plane's own billing relationship with an account.
CREATE TABLE account_billing (
    account_id             TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    stripe_customer_id     TEXT,
    stripe_subscription_id TEXT,
    status                 TEXT NOT NULL DEFAULT 'none'
        CHECK (status IN ('none', 'trialing', 'active', 'past_due', 'canceled')),
    current_period_end     TIMESTAMPTZ,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX account_billing_customer_idx ON account_billing (stripe_customer_id);

-- Applied webhook events, so a Stripe redelivery cannot double-apply.
CREATE TABLE stripe_webhook_events (
    event_id   TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
