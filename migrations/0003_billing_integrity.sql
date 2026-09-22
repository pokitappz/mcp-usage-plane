-- Billing integrity fixes.
--
-- Two problems, both of which cost money rather than availability.

-- 1. A Stripe customer could be claimed by more than one account.
--
-- `PUT /v1/billing` checked only the `cus_` prefix, and nothing stopped two
-- accounts naming the same customer. The subscription webhook then updates by
-- customer id:
--
--     UPDATE account_billing ... WHERE stripe_customer_id = $1
--
-- which would touch both rows, and upstream billing would invoice one party for
-- the other's usage. A partial unique index is the fix: NULL is the ordinary
-- state for an unlinked account and many rows hold it, so the constraint has to
-- apply only where a customer is actually named.
CREATE UNIQUE INDEX account_billing_customer_unique_idx
    ON account_billing (stripe_customer_id)
    WHERE stripe_customer_id IS NOT NULL;

-- 2. A failed payment left no trace.
--
-- Only three subscription events were handled, so `invoice.payment_failed`
-- passed through to a debug log and vanished. Recording it gives the operator
-- something to see before a subscription transitions, and gives entitlement
-- enforcement something to read later.
ALTER TABLE account_billing ADD COLUMN last_payment_failure_at TIMESTAMPTZ;
ALTER TABLE account_billing ADD COLUMN last_payment_success_at TIMESTAMPTZ;
