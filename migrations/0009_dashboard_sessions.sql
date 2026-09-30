-- The dashboard is authenticated by the account's own admin token.
--
-- What came before this was a person: a `users` row, an emailed code, then a
-- password. Both were a second credential invented to reach a subset of what the
-- operator could already do, because every dashboard action has a `/v1/*`
-- equivalent that an admin token already performs. So the token is the
-- credential, and a session is just a browser-shaped receipt for having
-- presented it.
--
-- That removes the identity system rather than reworking it. Once any holder of
-- an admin token can open a session, all holders are indistinguishable, so there
-- is no person for `users` to describe and no membership for `memberships` to
-- record. A table nothing can write to is a trap for whoever reads the schema
-- next, so they go rather than sitting dormant.

-- Keyed on the account, because that is all a session now knows. `account_id`
-- rather than a user, cascading with the account, and only the SHA-256 of the
-- token is stored, so a database disclosure hands over no live session.
CREATE TABLE dashboard_sessions (
    session_sha256 TEXT PRIMARY KEY,
    account_id     TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Sweeping expired rows needs this, and so does showing an operator what is
-- currently signed in to their account.
CREATE INDEX dashboard_sessions_by_account ON dashboard_sessions (account_id, expires_at);

-- Order matters: `user_sessions` references `users`, so it goes first.
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS user_login_codes;
DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS users;
