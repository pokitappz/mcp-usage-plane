-- People.
--
-- Until now this service had no concept of one. `accounts` has two columns, an
-- opaque id and a display name, and the only credential is a bearer token that
-- is also a full admin credential for the account. Two humans share an account
-- by sharing the same token string, and nothing can tell them apart.
--
-- That is fine for a machine API and impossible for a dashboard, which needs
-- something a browser can hold safely and something that can be attributed.

-- Case-insensitive email comparison without lowercasing at every call site.
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id          TEXT PRIMARY KEY,
    email       CITEXT NOT NULL UNIQUE,
    -- NULL until a login code has been redeemed. A user row exists from the
    -- moment an invite is created, so this is what separates "invited" from
    -- "has proven they read that mailbox".
    verified_at TIMESTAMPTZ,
    -- Set instead of deleting, so sessions and membership history survive a
    -- deactivation and can be reasoned about afterwards.
    disabled_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ
);

-- Which accounts a person may act on.
--
-- Separate from `users` because an account can have several people and a person
-- can belong to several accounts. Neither is possible today and both are
-- ordinary; modelling it now costs one table and avoids a migration later that
-- would have to rewrite every authorization check.
CREATE TABLE memberships (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- `owner` may manage people and credentials; `member` may not. Deliberately
    -- two values: a role system nobody has asked for is a liability, and
    -- widening a CHECK later is easy.
    role       TEXT NOT NULL DEFAULT 'owner' CHECK (role IN ('owner', 'member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, account_id)
);

CREATE INDEX memberships_account_idx ON memberships (account_id);

-- Browser sessions.
--
-- The primary key is the SHA-256 of the cookie value, never the value itself,
-- so a database disclosure does not hand over live sessions. Same property the
-- `account_tokens` table already has, and the same digest function.
CREATE TABLE user_sessions (
    session_sha256 TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX user_sessions_user_idx ON user_sessions (user_id);
CREATE INDEX user_sessions_expiry_idx ON user_sessions (expires_at);

-- One live login code per user.
--
-- Keyed on the user rather than appended to, so requesting a new code replaces
-- the old one instead of leaving several valid at once. `attempts` bounds
-- guessing on a six digit code, which is the whole reason it is not unbounded.
CREATE TABLE user_login_codes (
    user_id     TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    code_sha256 TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    expires_at  TIMESTAMPTZ NOT NULL,
    -- Enforces the resend cooldown in SQL rather than in a handler, so a
    -- concurrent pair of requests cannot both pass the check.
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Interest from the landing page.
--
-- Access is granted by hand for now, so this is a queue rather than a funnel.
-- Nothing here grants anything: a row is a person asking, and provisioning is
-- a separate deliberate act.
CREATE TABLE access_requests (
    id              BIGSERIAL PRIMARY KEY,
    email           CITEXT NOT NULL,
    company         TEXT,
    expected_events BIGINT CHECK (expected_events IS NULL OR expected_events >= 0),
    note            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Set when an account has been created for this request.
    granted_at      TIMESTAMPTZ,
    granted_account TEXT REFERENCES accounts(id) ON DELETE SET NULL
);

CREATE INDEX access_requests_pending_idx
    ON access_requests (created_at) WHERE granted_at IS NULL;
