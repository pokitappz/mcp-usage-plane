-- Per-event pricing, with a free allowance.
--
-- The existing terms multiply the customer's own metered *revenue*, which
-- expresses "a percentage of what you bill, with a monthly minimum". It cannot
-- express "$0.50 per 10,000 events, free under 50,000", because that multiplies
-- *units*. Both are wanted: the published price is per event, because a visitor
-- can forecast it and it works identically for a free MCP server that only uses
-- quota control; the percentage stays for negotiated deals.
--
-- The charge becomes, all in millionths and all integer:
--
--   max(floor_micros,
--       max(0, units - included_units) * per_event_micros
--       + revenue_micros * rate_bps / 10000)
--
-- Backwards compatible in both directions. An existing row has
-- per_event_micros = 0 and included_units = 0, so it keeps charging exactly
-- what it charged. A per-event account sets rate_bps = 0.

ALTER TABLE plane_pricing
    ADD COLUMN per_event_micros BIGINT NOT NULL DEFAULT 0
        CHECK (per_event_micros >= 0);

-- Metered events included before per_event_micros starts applying. The free
-- allowance, and the reason a small server pays nothing rather than pennies.
ALTER TABLE plane_pricing
    ADD COLUMN included_units BIGINT NOT NULL DEFAULT 0
        CHECK (included_units >= 0);

-- An invoice copies the terms it applied rather than referencing them, so
-- publishing a price change never restates what an account was already
-- charged. These two have to be copied for the same reason.
ALTER TABLE plane_invoices
    ADD COLUMN per_event_micros BIGINT NOT NULL DEFAULT 0
        CHECK (per_event_micros >= 0);

ALTER TABLE plane_invoices
    ADD COLUMN included_units BIGINT NOT NULL DEFAULT 0
        CHECK (included_units >= 0);
