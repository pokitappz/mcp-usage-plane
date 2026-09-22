//! Per-token admission: a short-lived authentication cache and a rate limit.
//!
//! # Why both live here
//!
//! They solve one problem from two directions. Every request used to authenticate
//! with a database round trip, and Fly admits 128 concurrent requests against a
//! pool of 10 connections with a five second acquire timeout - so ordinary
//! traffic, not an attack, could exhaust the pool and start returning errors.
//! The cache removes the round trip from the common case; the limiter bounds
//! what a single credential can ask for in the first place.
//!
//! # Scope
//!
//! Both are process-local. At `min_machines_running = 1` that is the whole
//! service, but scaling out makes each instance enforce its own budget, so treat
//! the limit as a self-protection bound rather than a fairness guarantee between
//! customers. Moving it to a shared counter means Redis or a Postgres table, and
//! neither is worth it until there is more than one machine.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::auth::Caller;

/// How long an authentication result is trusted without asking the database.
///
/// This is a revocation window: a token revoked through the API keeps working
/// for up to this long on any instance that had already cached it. Ten seconds
/// is deliberately short, and [`Admission::forget`] makes revocation immediate
/// on the instance that served it.
pub const AUTH_CACHE_TTL: Duration = Duration::from_secs(10);

/// Requests one token may make per [`RATE_WINDOW`].
pub const RATE_BURST: u32 = 240;

/// The window a burst is measured over.
pub const RATE_WINDOW: Duration = Duration::from_secs(60);

/// Failed authentications one client may make per [`RATE_WINDOW`].
///
/// Tighter than the success budget and counted separately. Tokens carry 256
/// bits of entropy so guessing is not the threat; the cost of a failure is,
/// because a failure always reaches the database - there is nothing to cache.
pub const FAILURE_BURST: u32 = 20;

/// Most distinct keys tracked at once, for both maps.
///
/// Bounds the memory an unauthenticated caller can cause to be allocated by
/// presenting an endless supply of distinct bad tokens.
const MAX_TRACKED: usize = 10_000;

#[derive(Debug)]
struct Cached {
    caller: Caller,
    expires_at: Instant,
}

#[derive(Debug)]
struct Bucket {
    spent: u32,
    window_ends: Instant,
}

/// Process-local authentication cache and rate limiter.
#[derive(Debug, Default)]
pub struct Admission {
    cache: Mutex<HashMap<String, Cached>>,
    requests: Mutex<HashMap<String, Bucket>>,
    failures: Mutex<HashMap<String, Bucket>>,
}

impl Admission {
    /// A cached authentication for this token hash, if one is still live.
    #[must_use]
    pub fn cached(&self, token_hash: &str) -> Option<Caller> {
        let now = Instant::now();
        let mut cache = lock(&self.cache);
        match cache.get(token_hash) {
            Some(entry) if entry.expires_at > now => Some(entry.caller.clone()),
            // Drop the expired entry on the way past rather than sweeping the
            // whole map on every lookup, which would make the cost of a read
            // scale with how many tokens the process has ever seen.
            Some(_) => {
                cache.remove(token_hash);
                None
            }
            None => None,
        }
    }

    /// Remember a successful authentication for [`AUTH_CACHE_TTL`].
    pub fn remember(&self, token_hash: &str, caller: &Caller) {
        let Some(expires_at) = Instant::now().checked_add(AUTH_CACHE_TTL) else {
            return;
        };
        let mut cache = lock(&self.cache);
        evict_if_full(&mut cache, |entry| entry.expires_at);
        cache.insert(
            token_hash.to_owned(),
            Cached {
                caller: caller.clone(),
                expires_at,
            },
        );
    }

    /// Drop a cached authentication, making a revocation effective at once.
    ///
    /// Only on this instance. A deployment with several machines still waits out
    /// [`AUTH_CACHE_TTL`] on the others, which is why the TTL is short.
    pub fn forget(&self, token_hash: &str) {
        lock(&self.cache).remove(token_hash);
    }

    /// Take one unit of the request budget. `false` means refuse with 429.
    pub fn take_request(&self, token_hash: &str) -> bool {
        take(&self.requests, token_hash, RATE_BURST)
    }

    /// Take one unit of the failed-authentication budget.
    pub fn take_failure(&self, fingerprint: &str) -> bool {
        take(&self.failures, fingerprint, FAILURE_BURST)
    }

    /// Seconds a refused caller should wait, for `Retry-After`.
    #[must_use]
    pub fn retry_after_seconds(&self, token_hash: &str) -> u64 {
        let now = Instant::now();
        lock(&self.requests)
            .get(token_hash)
            .filter(|bucket| bucket.window_ends > now)
            .map_or(1, |bucket| {
                // Round up: advising zero would invite an immediate retry.
                bucket
                    .window_ends
                    .saturating_duration_since(now)
                    .as_secs()
                    .max(1)
            })
    }

    /// Entries currently held, for tests and diagnostics.
    #[must_use]
    pub fn tracked(&self) -> (usize, usize, usize) {
        (
            lock(&self.cache).len(),
            lock(&self.requests).len(),
            lock(&self.failures).len(),
        )
    }
}

/// How long a health probe result is reused.
///
/// Short enough that a database outage surfaces inside one health-check
/// interval, long enough that polling the endpoint is not a way to take pool
/// connections from an unauthenticated position.
pub const HEALTH_CACHE_TTL: Duration = Duration::from_secs(2);

/// The most recent database reachability probe.
#[derive(Debug, Default)]
pub struct HealthProbe {
    last: Mutex<Option<(bool, Instant)>>,
}

impl HealthProbe {
    /// The last result, if it is still fresh.
    #[must_use]
    pub fn recent(&self) -> Option<bool> {
        let now = Instant::now();
        lock(&self.last).and_then(|(healthy, at)| {
            (now.duration_since(at) < HEALTH_CACHE_TTL).then_some(healthy)
        })
    }

    /// Record a fresh probe.
    pub fn record(&self, healthy: bool) {
        *lock(&self.last) = Some((healthy, Instant::now()));
    }
}

fn take(buckets: &Mutex<HashMap<String, Bucket>>, key: &str, burst: u32) -> bool {
    let now = Instant::now();
    let Some(window_ends) = now.checked_add(RATE_WINDOW) else {
        return true;
    };
    let mut buckets = lock(buckets);

    if let Some(bucket) = buckets.get_mut(key) {
        if bucket.window_ends <= now {
            bucket.spent = 1;
            bucket.window_ends = window_ends;
            return true;
        }
        if bucket.spent >= burst {
            return false;
        }
        bucket.spent += 1;
        return true;
    }

    evict_if_full(&mut buckets, |bucket| bucket.window_ends);
    buckets.insert(
        key.to_owned(),
        Bucket {
            spent: 1,
            window_ends,
        },
    );
    true
}

/// Make room by dropping the entry that expires soonest.
///
/// A fixed ceiling matters more than the eviction policy here: the keys are
/// caller-supplied token hashes, so without a bound an unauthenticated client
/// could grow either map without limit just by presenting new bad tokens.
fn evict_if_full<T>(map: &mut HashMap<String, T>, expiry: impl Fn(&T) -> Instant) {
    if map.len() < MAX_TRACKED {
        return;
    }
    let oldest = map
        .iter()
        .min_by_key(|(_, value)| expiry(value))
        .map(|(key, _)| key.clone());
    if let Some(key) = oldest {
        map.remove(&key);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Scope;

    fn caller() -> Caller {
        Caller {
            account_id: "acct".to_owned(),
            scope: Scope::Admin,
        }
    }

    #[test]
    fn a_health_probe_is_reused_briefly_and_reports_failure_too() {
        // The endpoint is unauthenticated and the platform polls it, so the
        // cache is what stops it being a free pool connection per request.
        let probe = HealthProbe::default();
        assert_eq!(probe.recent(), None, "nothing probed yet");

        probe.record(true);
        assert_eq!(probe.recent(), Some(true));

        // A failure is cached exactly like a success. Reprobing on every
        // failed poll is the moment the database is least able to serve it.
        probe.record(false);
        assert_eq!(probe.recent(), Some(false));
    }

    #[test]
    fn a_remembered_caller_is_returned_without_the_database() {
        let admission = Admission::default();
        assert!(admission.cached("hash").is_none());
        admission.remember("hash", &caller());
        assert_eq!(admission.cached("hash").unwrap().account_id, "acct");
    }

    #[test]
    fn forgetting_makes_a_revocation_immediate() {
        // The cache is a revocation window. `forget` is what stops a revoked
        // token from being honoured for the rest of the TTL on this instance.
        let admission = Admission::default();
        admission.remember("hash", &caller());
        admission.forget("hash");
        assert!(admission.cached("hash").is_none());
    }

    #[test]
    fn the_request_budget_refuses_only_the_token_that_spent_it() {
        let admission = Admission::default();
        for _ in 0..RATE_BURST {
            assert!(admission.take_request("noisy"));
        }
        assert!(
            !admission.take_request("noisy"),
            "the burst must be a bound"
        );
        assert!(
            admission.take_request("quiet"),
            "one token's spending must not refuse another's"
        );
    }

    #[test]
    fn the_failure_budget_is_tighter_than_the_request_budget() {
        let admission = Admission::default();
        for _ in 0..FAILURE_BURST {
            assert!(admission.take_failure("client"));
        }
        assert!(!admission.take_failure("client"));
        // The two budgets are independent: spending one must not spend the other.
        assert!(admission.take_request("client"));
    }

    #[test]
    fn a_refused_caller_is_told_to_wait_at_least_a_second() {
        let admission = Admission::default();
        assert!(admission.take_request("token"));
        let wait = admission.retry_after_seconds("token");
        assert!((1..=RATE_WINDOW.as_secs()).contains(&wait), "got {wait}");
        // An unknown token has no window to wait out.
        assert_eq!(admission.retry_after_seconds("never-seen"), 1);
    }

    #[test]
    fn neither_map_grows_without_bound() {
        // The keys are caller-supplied. Without a ceiling, presenting an endless
        // supply of distinct bad tokens is an allocation attack.
        let admission = Admission::default();
        for attempt in 0..(MAX_TRACKED + 500) {
            admission.take_failure(&format!("token-{attempt}"));
        }
        let (_, _, failures) = admission.tracked();
        assert!(failures <= MAX_TRACKED, "tracked {failures} keys");
    }

    #[test]
    fn an_expired_cache_entry_is_not_served_and_does_not_linger() {
        let admission = Admission::default();
        admission.cache.lock().unwrap().insert(
            "stale".to_owned(),
            Cached {
                caller: caller(),
                expires_at: Instant::now()
                    .checked_sub(Duration::from_secs(1))
                    .expect("the clock is past the epoch"),
            },
        );
        assert!(admission.cached("stale").is_none());
        let (cached, _, _) = admission.tracked();
        assert_eq!(cached, 0, "the expired entry must be dropped on read");
    }
}
