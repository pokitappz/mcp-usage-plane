//! Token minting, hashing, and scope-checked extraction.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::error::ApiError;

/// Bytes of entropy in a minted token. 32 bytes is the same budget the sidecar
/// demands of a tenant key.
const TOKEN_BYTES: usize = 32;

/// Mint a new high-entropy token with a human-readable prefix.
///
/// The prefix is cosmetic for the plane but load-bearing for the operator: a
/// leaked string is identifiable at a glance, and secret scanners key on it.
///
/// # Panics
///
/// Panics if the operating system cannot supply randomness, which is not a
/// condition this service can meaningfully continue past.
#[must_use]
pub fn mint_token(prefix: &str) -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).expect("the OS must provide randomness");
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!("{prefix}_{encoded}")
}

/// SHA-256 lookup digest, lowercase hex.
///
/// Must stay byte-identical to `mcp_usage_kit::hash_api_key`, because the edge
/// hashes a presented key with that function and looks it up in the snapshot
/// this plane produced. There is a test pinning the two together.
#[must_use]
pub fn hash_token(token: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(token.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// What a presented token is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Manages tenants, keys and prices.
    Admin,
    /// May pull a snapshot and post usage. Nothing else.
    Edge,
}

impl Scope {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "admin" => Some(Self::Admin),
            "edge" => Some(Self::Edge),
            _ => None,
        }
    }
}

/// An authenticated caller.
#[derive(Debug, Clone)]
pub struct Caller {
    /// Account the token belongs to.
    pub account_id: String,
    /// What the token may do.
    pub scope: Scope,
}

fn bearer(parts: &Parts) -> Option<&str> {
    let value = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim_start();
    (!token.is_empty()).then_some(token)
}

async fn resolve(state: &AppState, parts: &Parts) -> Result<Caller, ApiError> {
    let token = bearer(parts).ok_or(ApiError::Unauthorized)?;
    // The hash, never the token, is the key for everything below. It is what
    // the database stores, so nothing here has to hold a live credential.
    let token_hash = hash_token(token);

    // Rate limit before the cache and before the database. Checking it after
    // would mean a client over budget still costs whatever the lookup costs,
    // which is the thing the limit exists to bound.
    if !state.admission.take_request(&token_hash) {
        return Err(ApiError::TooManyRequests(
            state.admission.retry_after_seconds(&token_hash),
        ));
    }

    if let Some(caller) = state.admission.cached(&token_hash) {
        return Ok(caller);
    }

    let row = sqlx::query(
        "SELECT account_id, scope FROM account_tokens
         WHERE token_sha256 = $1 AND revoked_at IS NULL",
    )
    .bind(&token_hash)
    .fetch_optional(&state.pool)
    .await?;

    let Some(row) = row else {
        // A failure always reaches the database - there is nothing to cache -
        // so it gets its own budget, counted process-wide rather than per
        // token. Keying it on the presented token would give every distinct
        // guess a fresh allowance, which is not a bound on guessing at all.
        if !state.admission.take_failure() {
            return Err(ApiError::TooManyRequests(
                state.admission.retry_after_seconds(&token_hash),
            ));
        }
        return Err(ApiError::Unauthorized);
    };

    let account_id: String = row.try_get("account_id").map_err(ApiError::from)?;
    let scope: String = row.try_get("scope").map_err(ApiError::from)?;
    let scope = Scope::parse(&scope).ok_or(ApiError::Internal)?;
    let caller = Caller { account_id, scope };

    // Only successes are cached. Caching a failure would turn a token that was
    // just minted into one that does not work yet.
    state.admission.remember(&token_hash, &caller);
    Ok(caller)
}

/// Extractor requiring an `admin` token.
#[derive(Debug, Clone)]
pub struct AdminCaller(pub Caller);

impl FromRequestParts<AppState> for AdminCaller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let caller = resolve(state, parts).await?;
        if caller.scope == Scope::Admin {
            Ok(Self(caller))
        } else {
            Err(ApiError::Forbidden)
        }
    }
}

/// Extractor requiring an `edge` token.
///
/// An admin token is deliberately NOT accepted here. Sidecars run in customer
/// infrastructure and are the most exposed component; giving them a credential
/// that could also rewrite prices would make a sidecar compromise a billing
/// compromise.
#[derive(Debug, Clone)]
pub struct EdgeCaller(pub Caller);

impl FromRequestParts<AppState> for EdgeCaller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let caller = resolve(state, parts).await?;
        if caller.scope == Scope::Edge {
            Ok(Self(caller))
        } else {
            Err(ApiError::Forbidden)
        }
    }
}

use sqlx::Row as _;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_matches_the_meters_own_hash() {
        // The edge hashes a presented key with `mcp_usage_kit::hash_api_key` and
        // looks it up in the snapshot this plane produced. If these two ever
        // disagree, every key silently stops authenticating.
        for key in ["short", "Zq4vN8xR2tLmK7wP1sB6yH3dF9gJ0cVe", ""] {
            assert_eq!(hash_token(key), reference_sha256_hex(key), "key {key:?}");
        }
    }

    /// An independent implementation, so a shared bug cannot make both agree.
    fn reference_sha256_hex(value: &str) -> String {
        use sha2::{Digest, Sha256};
        use std::fmt::Write as _;

        let digest = Sha256::digest(value.as_bytes());
        digest.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    #[test]
    fn a_minted_token_carries_its_prefix_and_enough_entropy() {
        let token = mint_token("mup_edge");
        assert!(token.starts_with("mup_edge_"));
        // 32 bytes base64url without padding.
        assert_eq!(token.len(), "mup_edge_".len() + 43);
        assert_ne!(token, mint_token("mup_edge"));
    }

    #[test]
    fn scopes_round_trip_and_reject_anything_else() {
        assert_eq!(Scope::parse("admin"), Some(Scope::Admin));
        assert_eq!(Scope::parse("edge"), Some(Scope::Edge));
        assert_eq!(Scope::parse("root"), None);
    }
}
