-- What the plane charges, and what it has charged.
--
-- Until now the plane's own price existed nowhere in this system: upstream
-- billing forwarded one meter event per processed unit, 1:1, under a single
-- global meter name, and the actual rate lived in a Stripe dashboard object.
-- That shape cannot express a floor, because a floor is a property of a period
-- and a continuous drip has no periods.

-- Per-account terms. Absent means the account is not billed at all, which is
-- the right default for an account that exists but has not been sold anything.
CREATE TABLE plane_pricing (
    account_id   TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    -- Basis points of the account's own metered revenue. 150 = 1.5%.
    -- Basis points rather than a decimal percentage so the arithmetic stays in
    -- integers: this multiplies money, and a float here would round in ways
    -- nobody could reproduce from an invoice.
    rate_bps     INTEGER NOT NULL DEFAULT 0 CHECK (rate_bps >= 0 AND rate_bps <= 10000),
    -- The monthly minimum, in millionths of the billing currency. Charged when
    -- the percentage comes to less, including when it comes to nothing.
    floor_micros BIGINT NOT NULL DEFAULT 0 CHECK (floor_micros >= 0),
    -- Terms apply from here. Defaults to now, so agreeing terms today does
    -- NOT retroactively invoice an account for months before it had any -
    -- the close walks back several periods, and without this a new account
    -- is billed a floor for each of them the moment it is priced.
    -- Settable, because onboarding mid-month and migrating an existing
    -- customer are both real and both need a deliberate backdate.
    starts_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Terms stop applying after this, so an account that churns mid-month is
    -- not billed for the month after. NULL means open-ended.
    ends_at      TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One row per account per closed month. This table is the invoice record and
-- the idempotency key together: a period that already has a row is never
-- charged again, however many times the close runs.
CREATE TABLE plane_invoices (
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- `date_trunc('month', ...)`, matching usage_counters.window_start.
    period_start    TIMESTAMPTZ NOT NULL,
    period_end      TIMESTAMPTZ NOT NULL,
    -- The account's own metered revenue for the period: what it charged its
    -- customers, summed from usage_counters.
    revenue_micros  BIGINT NOT NULL CHECK (revenue_micros >= 0),
    -- Units the plane metered for it, recorded for the invoice line rather
    -- than because the charge depends on them.
    units           BIGINT NOT NULL CHECK (units >= 0),
    -- The terms applied, copied rather than referenced. Changing an account's
    -- rate must not silently restate what it was already invoiced.
    rate_bps        INTEGER NOT NULL CHECK (rate_bps >= 0),
    floor_micros    BIGINT NOT NULL CHECK (floor_micros >= 0),
    -- max(floor_micros, revenue_micros * rate_bps / 10000).
    charge_micros   BIGINT NOT NULL CHECK (charge_micros >= 0),
    -- Stable identifier presented to the billing provider, so a retry after a
    -- transport failure deduplicates rather than double-charging.
    identifier      TEXT NOT NULL UNIQUE,
    -- NULL until the provider has accepted it. A row that exists but is
    -- unsettled is a charge that was computed and not yet delivered.
    settled_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (account_id, period_start)
);

CREATE INDEX plane_invoices_unsettled_idx
    ON plane_invoices (account_id, period_start) WHERE settled_at IS NULL;
