//! Outbound billing providers.
//!
//! Both implement `MeterEventProvider`, so the library owns buffering, ordered
//! per-event outcomes, partial-batch retry progress and the dead letter queue,
//! and everything provider-specific lives here. Both key on the stable
//! [`AggregatedUsage::identifier`], which is what makes a retry safe when the
//! transport fails after the provider already accepted the request.
//!
//! ## Why there is no MPP provider
//!
//! MPP is an *inbound* payment protocol: it standardizes HTTP 402, where an
//! agent calls an endpoint, receives a challenge, pays, and retries with an
//! `Authorization: Payment` header to get a `Payment-Receipt` back. There is no
//! usage-ingest endpoint on the other side to export aggregates to, so an "MPP
//! export" would have nothing to talk to. Supporting MPP means answering 402 at
//! the sidecar, which is edge work, not a destination here.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::digest::KeyInit as _;
use hmac::{Hmac, Mac};
use mcp_usage_export::{
    AggregatedUsage, MeterEventOutcome, MeterEventProvider, MeterEventProviderError,
    MeterEventProviderFuture,
};
use serde::Serialize;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The Stripe release this code's request and response shapes target.
pub const STRIPE_API_VERSION: &str = "2026-08-26.dahlia";
/// Only the first version in a release carries breaking changes and every later
/// monthly version in it is additive, so the inbound check is against the
/// release rather than one dated version. Matching the exact version would
/// raise a false alarm the moment Stripe ships the next additive one.
pub const STRIPE_API_RELEASE_SUFFIX: &str = ".dahlia";

const STRIPE_METER_ENDPOINT: &str = "https://api.stripe.com/v1/billing/meter_events";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Stripe rejects meter events stamped more than 35 days in the past.
const MAX_EVENT_AGE_SECONDS: u64 = 35 * 24 * 60 * 60;
/// ...or more than five minutes in the future.
const MAX_FUTURE_SECONDS: u64 = 5 * 60;

/// The signature header on a webhook destination's request.
pub const SIGNATURE_HEADER: &str = "X-Usage-Signature";

/// Whether an inbound Stripe event was rendered at a version this code parses.
///
/// Stripe dates every version and suffixes it with its release, as in
/// `2026-07-29.dahlia`. A bare release name, or a longer word that merely starts
/// with one, is not a version Stripe emits, so both are rejected rather than
/// treated as current.
#[must_use]
pub fn stripe_version_is_current(api_version: Option<&str>) -> bool {
    api_version.is_some_and(|version| {
        version
            .strip_suffix(STRIPE_API_RELEASE_SUFFIX)
            .is_some_and(|date| !date.is_empty())
    })
}

/// A client that refuses redirects.
///
/// Following a 3xx would carry the request, including a billing credential and
/// a customer identifier, to a host the allowlist never checked.
fn strict_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .build()
}

/// Sanitized transport failure category.
///
/// reqwest's own error carries the URL and can carry the credential, so only
/// the category survives into a log line.
fn transport_failure_code(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "transport_timeout"
    } else if error.is_connect() {
        "transport_connect"
    } else if error.is_request() {
        "transport_request"
    } else if error.is_body() {
        "transport_body"
    } else {
        "transport_failed"
    }
}

/// Statuses that describe the request or the account rather than one event.
///
/// Quarantining is a one-way door for revenue: the exporter treats a quarantined
/// event as resolved and drops it, so anything misclassified here is eventually
/// discarded. Every status below applies identically to a whole batch, so none
/// of them may be read as "this event is invalid".
fn retryable_client_error(status: reqwest::StatusCode) -> Option<&'static str> {
    match status {
        reqwest::StatusCode::UNAUTHORIZED => Some("unauthorized"),
        reqwest::StatusCode::PAYMENT_REQUIRED => Some("payment_required"),
        reqwest::StatusCode::FORBIDDEN => Some("forbidden"),
        reqwest::StatusCode::NOT_FOUND => Some("not_found"),
        reqwest::StatusCode::REQUEST_TIMEOUT => Some("request_timeout"),
        reqwest::StatusCode::FAILED_DEPENDENCY => Some("failed_dependency"),
        reqwest::StatusCode::TOO_MANY_REQUESTS => Some("rate_limited"),
        _ => None,
    }
}

fn permanent_event_rejection(status: reqwest::StatusCode) -> bool {
    status.is_client_error() && retryable_client_error(status).is_none()
}

fn retryable_status_code(status: reqwest::StatusCode) -> &'static str {
    retryable_client_error(status).unwrap_or({
        if status.is_server_error() {
            "server_error"
        } else {
            "unexpected_status"
        }
    })
}

const fn timestamp_too_old(timestamp: u64, now: u64) -> bool {
    timestamp < now.saturating_sub(MAX_EVENT_AGE_SECONDS)
}

const fn timestamp_too_far_in_future(timestamp: u64, now: u64) -> bool {
    timestamp > now.saturating_add(MAX_FUTURE_SECONDS)
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ------------------------------------------------------------------ Stripe

/// Submits pre-aggregated usage to Stripe's v1 Billing Meter Events API.
///
/// Stripe deduplicates meter-event identifiers for at least 24 hours, so a
/// retry after a transport failure cannot double-bill.
pub struct StripeMeterProvider {
    http: reqwest::Client,
    secret_key: String,
    endpoint: String,
    meter_override: Option<String>,
}

impl fmt::Debug for StripeMeterProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StripeMeterProvider")
            .field("secret_key", &"[REDACTED]")
            .field("endpoint", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Only Stripe itself, or a loopback test server.
///
/// The check exists so a configuration mistake cannot send a customer's Stripe
/// secret to an unrelated host.
#[must_use]
pub fn stripe_endpoint_is_allowed(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    if url.scheme() == "https" && url.host_str() == Some("api.stripe.com") {
        return true;
    }
    matches!(url.scheme(), "http" | "https")
        && host_ip(&url).is_some_and(|address| address.is_loopback())
}

/// The host as an IP address, when it is a literal rather than a name.
///
/// `Url::host_str` returns an IPv6 literal still wrapped in its brackets, so
/// parsing that string as an `IpAddr` always fails and every IPv6 address looks
/// like a hostname. `Url::host` has already done the parsing, so it is the only
/// safe way to ask this question.
fn host_ip(url: &reqwest::Url) -> Option<std::net::IpAddr> {
    match url.host()? {
        url::Host::Ipv4(address) => Some(std::net::IpAddr::V4(address)),
        url::Host::Ipv6(address) => Some(std::net::IpAddr::V6(address)),
        url::Host::Domain(_) => None,
    }
}

impl StripeMeterProvider {
    /// Target Stripe's production meter-event endpoint.
    ///
    /// # Errors
    ///
    /// Returns the underlying client build error.
    pub fn new(secret_key: String, meter_override: Option<String>) -> Result<Self, reqwest::Error> {
        Ok(Self {
            http: strict_client()?,
            secret_key,
            endpoint: STRIPE_METER_ENDPOINT.to_owned(),
            meter_override,
        })
    }

    /// Point at a loopback test server.
    ///
    /// # Errors
    ///
    /// Returns an error for any endpoint off the allowlist, at construction
    /// time rather than at the first flush.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Result<Self, &'static str> {
        let endpoint = endpoint.into();
        if !stripe_endpoint_is_allowed(&endpoint) {
            return Err("Stripe endpoint must be api.stripe.com or a loopback test server");
        }
        self.endpoint = endpoint;
        Ok(self)
    }

    fn form_fields(&self, usage: &AggregatedUsage) -> [(&'static str, String); 5] {
        [
            (
                "event_name",
                self.meter_override
                    .clone()
                    .unwrap_or_else(|| usage.meter.clone()),
            ),
            ("payload[stripe_customer_id]", usage.customer_id.clone()),
            ("payload[value]", usage.units.to_string()),
            ("identifier", usage.identifier.clone()),
            ("timestamp", usage.timestamp.to_string()),
        ]
    }

    async fn submit_one(&self, usage: &AggregatedUsage, now: u64) -> MeterEventOutcome {
        if timestamp_too_old(usage.timestamp, now) {
            return MeterEventOutcome::PermanentRejection {
                code: "timestamp_too_old",
            };
        }
        if timestamp_too_far_in_future(usage.timestamp, now) {
            return MeterEventOutcome::PermanentRejection {
                code: "timestamp_too_far_in_future",
            };
        }

        let response = match self
            .http
            .post(&self.endpoint)
            .basic_auth(&self.secret_key, Some(""))
            .header("Stripe-Version", STRIPE_API_VERSION)
            .form(&self.form_fields(usage))
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let code = transport_failure_code(&error);
                tracing::warn!(
                    stripe_transport_failure = code,
                    "Stripe meter event could not be delivered"
                );
                return MeterEventOutcome::RetryableFailure { code };
            }
        };

        let status = response.status();
        if status.is_success() {
            return MeterEventOutcome::Accepted;
        }

        // Only the status and the request id are logged, never Stripe's message
        // or body: those carry customer data.
        let request_id = response
            .headers()
            .get("request-id")
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.starts_with("req_"))
            .map(str::to_owned);
        let permanent = permanent_event_rejection(status);
        tracing::warn!(
            stripe_http_status = status.as_u16(),
            stripe_request_id = request_id.as_deref(),
            permanent,
            "Stripe rejected a meter event"
        );

        if permanent {
            MeterEventOutcome::PermanentRejection {
                code: "invalid_request",
            }
        } else {
            MeterEventOutcome::RetryableFailure {
                code: retryable_status_code(status),
            }
        }
    }
}

impl MeterEventProvider for StripeMeterProvider {
    fn submit<'a>(&'a self, batch: &'a [AggregatedUsage]) -> MeterEventProviderFuture<'a> {
        Box::pin(async move {
            // Re-checked here, where the secret is actually sent, so the
            // guarantee is local to the code that could leak it.
            if !stripe_endpoint_is_allowed(&self.endpoint) {
                return Err(MeterEventProviderError::new("endpoint_not_allowed"));
            }
            let now = now_seconds();

            // Once an event fails in a way that will fail for the rest of the
            // batch too - a bad key, an outage, a rate limit - stop issuing
            // requests and report the remainder as retryable, rather than
            // hammering the provider with the same failure N more times.
            // Per-event outcomes beat a batch-wide error here because they keep
            // the progress already confirmed for events that were accepted.
            let mut outcomes = Vec::with_capacity(batch.len());
            let mut halted = false;
            for usage in batch {
                if halted {
                    outcomes.push(MeterEventOutcome::RetryableFailure {
                        code: "halted_after_failure",
                    });
                    continue;
                }
                let outcome = self.submit_one(usage, now).await;
                halted = matches!(outcome, MeterEventOutcome::RetryableFailure { .. });
                outcomes.push(outcome);
            }
            Ok(outcomes)
        })
    }
}

// ----------------------------------------------------------------- webhook

#[derive(Debug, Serialize)]
struct WebhookEvent<'a> {
    identifier: &'a str,
    customer_id: &'a str,
    meter: &'a str,
    units: u64,
    timestamp: u64,
}

#[derive(Debug, Serialize)]
struct WebhookBatch<'a> {
    events: Vec<WebhookEvent<'a>>,
}

/// Posts aggregates as signed JSON to a customer-supplied endpoint.
///
/// The generic destination, for a billing system with no first-class provider
/// here. The receiver deduplicates on `identifier` exactly as Stripe does.
pub struct WebhookProvider {
    http: reqwest::Client,
    endpoint: String,
    secret: String,
    meter_override: Option<String>,
    allow_loopback: bool,
}

impl fmt::Debug for WebhookProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookProvider")
            .field("endpoint", &self.endpoint)
            .field("secret", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Whether a customer-supplied webhook endpoint may be dialled.
///
/// The endpoint comes from the customer, so without this the plane is an SSRF
/// proxy into its own network. HTTPS is required, and an IP literal in a
/// loopback, private or link-local range is refused. `allow_loopback` is passed
/// in rather than read from the environment so the decision is explicit at the
/// call site and testable without mutating process-global state; the binary
/// sets it once at startup and the test suite turns it on.
///
/// This does not cover a hostname that *resolves* to a private address; closing
/// that needs a resolving connector that re-checks after DNS.
#[must_use]
pub fn webhook_endpoint_is_allowed(endpoint: &str, allow_loopback: bool) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };

    if let Some(address) = host_ip(&url) {
        if address.is_loopback() {
            return allow_loopback && matches!(url.scheme(), "http" | "https");
        }
        if is_private_or_local(address) {
            return false;
        }
    }
    url.scheme() == "https"
}

fn is_private_or_local(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(v4) => {
            v4.is_private() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast()
        }
        // Unique-local (fc00::/7) and link-local (fe80::/10) have no stable
        // std predicates, so they are matched on their prefixes directly.
        std::net::IpAddr::V6(v6) => {
            v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The `X-Usage-Signature` value (`sha256=<lowercase hex>`) over a raw body.
#[must_use]
pub fn sign_body(secret: &str, body: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    let mut encoded = String::with_capacity(7 + digest.len() * 2);
    encoded.push_str("sha256=");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

impl WebhookProvider {
    /// Build a provider for a customer-supplied endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for an endpoint the allowlist refuses, or if the client
    /// cannot be built.
    pub fn new(
        endpoint: String,
        secret: String,
        meter_override: Option<String>,
        allow_loopback: bool,
    ) -> Result<Self, &'static str> {
        if !webhook_endpoint_is_allowed(&endpoint, allow_loopback) {
            return Err("webhook endpoint must be an https URL on a public host");
        }
        Ok(Self {
            http: strict_client().map_err(|_| "could not build an HTTP client")?,
            endpoint,
            secret,
            meter_override,
            allow_loopback,
        })
    }
}

impl MeterEventProvider for WebhookProvider {
    fn submit<'a>(&'a self, batch: &'a [AggregatedUsage]) -> MeterEventProviderFuture<'a> {
        Box::pin(async move {
            if !webhook_endpoint_is_allowed(&self.endpoint, self.allow_loopback) {
                return Err(MeterEventProviderError::new("endpoint_not_allowed"));
            }
            let now = now_seconds();

            // Timestamp bounds are a provider concern and this provider has
            // none, but an event far in the future is a clock bug rather than
            // usage, and forwarding it would poison the customer's invoice.
            if let Some(position) = batch
                .iter()
                .position(|usage| timestamp_too_far_in_future(usage.timestamp, now))
            {
                let mut outcomes = vec![MeterEventOutcome::Accepted; batch.len()];
                outcomes[position] = MeterEventOutcome::PermanentRejection {
                    code: "timestamp_too_far_in_future",
                };
                // Only that one event is settled; the rest stay unresolved so
                // the next attempt sends a clean batch.
                for (index, outcome) in outcomes.iter_mut().enumerate() {
                    if index != position {
                        *outcome = MeterEventOutcome::RetryableFailure {
                            code: "halted_after_failure",
                        };
                    }
                }
                return Ok(outcomes);
            }

            let payload = WebhookBatch {
                events: batch
                    .iter()
                    .map(|usage| WebhookEvent {
                        identifier: &usage.identifier,
                        customer_id: &usage.customer_id,
                        meter: self.meter_override.as_deref().unwrap_or(&usage.meter),
                        units: usage.units,
                        timestamp: usage.timestamp,
                    })
                    .collect(),
            };
            let body = serde_json::to_vec(&payload)
                .map_err(|_| MeterEventProviderError::new("encode_failed"))?;
            let signature = sign_body(&self.secret, &body);

            let response = match self
                .http
                .post(&self.endpoint)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(SIGNATURE_HEADER, signature)
                .body(body)
                .send()
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    let code = transport_failure_code(&error);
                    tracing::warn!(webhook_transport_failure = code, "usage webhook failed");
                    return Err(MeterEventProviderError::new("unavailable"));
                }
            };

            let status = response.status();
            let outcome = if status.is_success() {
                MeterEventOutcome::Accepted
            } else if permanent_event_rejection(status) {
                tracing::warn!(
                    webhook_http_status = status.as_u16(),
                    "usage webhook permanently rejected a batch"
                );
                MeterEventOutcome::PermanentRejection {
                    code: "invalid_request",
                }
            } else {
                MeterEventOutcome::RetryableFailure {
                    code: retryable_status_code(status),
                }
            };
            Ok(vec![outcome; batch.len()])
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stripe_versions_are_matched_on_the_release_not_the_date() {
        assert!(stripe_version_is_current(Some("2026-07-29.dahlia")));
        // Additive later versions in the same release parse identically.
        assert!(stripe_version_is_current(Some("2026-11-30.dahlia")));
        // A bare release name is not a version Stripe emits.
        assert!(!stripe_version_is_current(Some(".dahlia")));
        assert!(!stripe_version_is_current(Some("dahlia")));
        assert!(!stripe_version_is_current(Some("2026-07-29.acacia")));
        assert!(!stripe_version_is_current(None));
    }

    #[test]
    fn the_stripe_allowlist_accepts_only_stripe_or_loopback() {
        assert!(stripe_endpoint_is_allowed(
            "https://api.stripe.com/v1/billing/meter_events"
        ));
        assert!(stripe_endpoint_is_allowed("http://127.0.0.1:9000/v1"));
        assert!(stripe_endpoint_is_allowed("http://[::1]:9000/v1"));
        // A lookalike host must not receive a Stripe secret.
        assert!(!stripe_endpoint_is_allowed(
            "https://api.stripe.com.evil.example"
        ));
        assert!(!stripe_endpoint_is_allowed("http://api.stripe.com/v1"));
        assert!(!stripe_endpoint_is_allowed("https://example.com/v1"));
        assert!(!stripe_endpoint_is_allowed("not a url"));
    }

    #[test]
    fn statuses_are_split_into_per_event_and_whole_batch_failures() {
        use reqwest::StatusCode;
        // Describes this event, and always will.
        assert!(permanent_event_rejection(StatusCode::BAD_REQUEST));
        assert!(permanent_event_rejection(StatusCode::CONFLICT));
        // Describes the request or the account, so it must stay retryable:
        // quarantining these would silently discard every event in the batch.
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::PAYMENT_REQUIRED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::FAILED_DEPENDENCY,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            assert!(!permanent_event_rejection(status), "{status}");
            assert!(retryable_client_error(status).is_some(), "{status}");
        }
        assert_eq!(
            retryable_status_code(StatusCode::INTERNAL_SERVER_ERROR),
            "server_error"
        );
    }

    #[test]
    fn stripe_timestamp_bounds_match_what_stripe_accepts() {
        let now = 1_800_000_000;
        assert!(!timestamp_too_old(now, now));
        assert!(!timestamp_too_old(now - MAX_EVENT_AGE_SECONDS, now));
        assert!(timestamp_too_old(now - MAX_EVENT_AGE_SECONDS - 1, now));
        assert!(!timestamp_too_far_in_future(now + MAX_FUTURE_SECONDS, now));
        assert!(timestamp_too_far_in_future(
            now + MAX_FUTURE_SECONDS + 1,
            now
        ));
    }

    #[test]
    fn a_signature_is_stable_and_key_dependent() {
        let body = br#"{"events":[]}"#;
        let signature = sign_body("topsecret", body);
        assert!(signature.starts_with("sha256="));
        assert_eq!(signature, sign_body("topsecret", body), "stable");
        assert_ne!(signature, sign_body("other", body), "key dependent");
        assert_ne!(signature, sign_body("topsecret", b"{}"), "body dependent");
    }

    #[test]
    fn the_webhook_allowlist_refuses_the_plane_s_own_network() {
        // A customer supplies this URL, so without the guard the plane is an
        // SSRF proxy into whatever it can reach.
        for endpoint in [
            "http://127.0.0.1:9000/hook",
            "https://10.0.0.5/hook",
            "https://192.168.1.10/hook",
            "https://169.254.169.254/latest/meta-data",
            "https://[fd00::1]/hook",
            "https://[fe80::1]/hook",
            "http://billing.example.com/hook",
            "not a url",
        ] {
            assert!(!webhook_endpoint_is_allowed(endpoint, false), "{endpoint}");
        }
        assert!(webhook_endpoint_is_allowed(
            "https://billing.example.com/hook",
            false
        ));
    }

    #[test]
    fn loopback_opens_only_loopback_and_never_a_private_range() {
        assert!(webhook_endpoint_is_allowed(
            "http://127.0.0.1:9000/hook",
            true
        ));
        assert!(webhook_endpoint_is_allowed("http://[::1]:9000/hook", true));
        // The test escape hatch must not also open the metadata service or a
        // private network, which is what would make it dangerous in production.
        assert!(!webhook_endpoint_is_allowed("https://10.0.0.5/hook", true));
        assert!(!webhook_endpoint_is_allowed(
            "https://169.254.169.254/latest/meta-data",
            true
        ));
    }
}
