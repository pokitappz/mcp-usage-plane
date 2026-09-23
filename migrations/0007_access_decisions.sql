-- Deciding an access request.
--
-- `access_requests` could be written to and never read. A row recorded that
-- somebody asked, and nothing in the service could act on it: granting access
-- meant connecting to Postgres and writing a `users` row and a `memberships`
-- row by hand, because no code path creates either. The README described that
-- flow as though it existed.
--
-- Two columns were already here for the outcome, `granted_at` and
-- `granted_account`. What was missing is the other answer. Without it the queue
-- only grows: a request that will never be granted stays pending forever, and
-- the pending index below would keep returning it.

ALTER TABLE access_requests
    ADD COLUMN declined_at TIMESTAMPTZ;

-- A request has at most one outcome. Enforced here rather than in a handler,
-- so two concurrent decisions cannot each believe they were first and leave a
-- row that is somehow both granted and declined.
ALTER TABLE access_requests
    ADD CONSTRAINT access_requests_one_outcome
    CHECK (granted_at IS NULL OR declined_at IS NULL);

-- The old index treated "not granted" as "pending", which would have kept
-- declined requests in the queue forever.
DROP INDEX IF EXISTS access_requests_pending_idx;
CREATE INDEX access_requests_pending_idx
    ON access_requests (created_at)
    WHERE granted_at IS NULL AND declined_at IS NULL;

-- Granting looks up whether this address already belongs to an account before
-- creating another one, and the landing form is unauthenticated, so this is a
-- lookup an anonymous caller can cause. Without the index it is a sequential
-- scan of every request ever submitted.
CREATE INDEX access_requests_email_idx ON access_requests (email);
