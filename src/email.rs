//! Transactional email through the studio's `pokit_apps_email` service.
//!
//! A thin `reqwest` client rather than an email SDK, matching how the sibling
//! applications talk to the same service. There is exactly one message type
//! today: the sign-in code.
//!
//! # Absent configuration is a real state
//!
//! Without `EMAIL_SERVICE_URL` and `EMAIL_SERVICE_TOKEN` there is no client,
//! and asking for a sign-in code fails loudly rather than silently accepting a
//! request whose code can never arrive. In a debug build against localhost the
//! code is returned in the response instead, so the flow is testable without a
//! mail service; that path is compiled out of a release build.

use std::time::Duration;

use serde::Serialize;

/// The production endpoint, on the internal network.
const PRODUCTION_ENDPOINT: &str = "http://pokit-apps-email.flycast/send";
/// Shortest token that could plausibly be real.
const MIN_TOKEN_LEN: usize = 24;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

const FROM_EMAIL: &str = "support@pokitapps.com";
const FROM_NAME: &str = "UsageKit";
const SIGN_IN_SUBJECT: &str = "Your UsageKit sign-in code";

/// Where an access request is announced.
///
/// The operator, not the person who asked: access is granted by hand, so this
/// is the only thing that moves a queued row in front of somebody. The visitor
/// gets their confirmation from the page, which is already rendered by the time
/// this is attempted.
const OPERATOR_EMAIL: &str = "support@pokitapps.com";
const ACCESS_SUBJECT: &str = "UsageKit Cloud access request";

/// Why a message could not be sent. Never carries message content.
#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    /// The service did not answer in time.
    #[error("email service timed out")]
    Timeout,
    /// The request never reached the service.
    #[error("email service unreachable")]
    Transport,
    /// The service answered with a failure status.
    #[error("email service returned {0}")]
    HttpStatus(u16),
    /// The service answered with something unusable.
    #[error("email service returned an unusable response")]
    InvalidResponse,
}

#[derive(Debug, Serialize)]
struct Recipient<'a> {
    email: &'a str,
}

#[derive(Debug, Serialize)]
struct Message<'a> {
    from_name: &'a str,
    from_email: &'a str,
    to: Vec<Recipient<'a>>,
    subject: &'a str,
    text_content: String,
    html_content: String,
}

/// A configured sender.
pub struct EmailClient {
    http: reqwest::Client,
    endpoint: String,
    token: String,
}

impl std::fmt::Debug for EmailClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EmailClient")
            .field("http", &"<client>")
            .field("endpoint", &self.endpoint)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl EmailClient {
    /// Build from the environment, or `None` when email is not configured.
    ///
    /// # Errors
    ///
    /// Returns a message when one variable is set and the other is not, or when
    /// the endpoint or token is unusable. Half-configured email is a mistake
    /// worth failing startup for: the alternative is discovering it when the
    /// first customer cannot sign in.
    pub fn from_env() -> Result<Option<Self>, String> {
        let url = std::env::var("EMAIL_SERVICE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let token = std::env::var("EMAIL_SERVICE_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty());

        let (url, token) = match (url, token) {
            (None, None) => return Ok(None),
            (Some(url), Some(token)) => (url, token),
            _ => {
                return Err(
                    "EMAIL_SERVICE_URL and EMAIL_SERVICE_TOKEN must be set together".to_owned(),
                );
            }
        };

        if token.trim().len() != token.len() {
            return Err("EMAIL_SERVICE_TOKEN has surrounding whitespace".to_owned());
        }
        if token.len() < MIN_TOKEN_LEN {
            return Err(format!(
                "EMAIL_SERVICE_TOKEN must be at least {MIN_TOKEN_LEN} characters"
            ));
        }
        if !endpoint_is_allowed(&url) {
            return Err(format!(
                "EMAIL_SERVICE_URL must be {PRODUCTION_ENDPOINT} or a loopback /send endpoint"
            ));
        }

        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            // A redirect would carry the service token somewhere the allowlist
            // never checked.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "could not build the email client".to_owned())?;

        Ok(Some(Self {
            http,
            endpoint: url,
            token,
        }))
    }

    /// Send a sign-in code.
    ///
    /// # Errors
    ///
    /// Returns an [`EmailError`] category. The code never appears in one.
    pub async fn send_sign_in_code(&self, to: &str, code: &str) -> Result<(), EmailError> {
        let message = Message {
            from_name: FROM_NAME,
            from_email: FROM_EMAIL,
            to: vec![Recipient { email: to }],
            subject: SIGN_IN_SUBJECT,
            text_content: format!(
                "Your UsageKit sign-in code is {code}\n\n\
                 It expires in 10 minutes and can be used once.\n\n\
                 If you did not ask to sign in, you can ignore this message."
            ),
            html_content: format!(
                "<p>Your UsageKit sign-in code is <strong>{}</strong></p>\
                 <p>It expires in 10 minutes and can be used once.</p>\
                 <p>If you did not ask to sign in, you can ignore this message.</p>",
                escape_html(code)
            ),
        };

        self.deliver(&message).await
    }

    /// Tell the operator that somebody asked for access.
    ///
    /// # Errors
    ///
    /// Returns an [`EmailError`] category. The caller treats a failure as
    /// non-fatal: the request is already recorded, and losing the notification
    /// delays a reply rather than losing the lead.
    pub async fn send_access_request(
        &self,
        from_address: &str,
        company: Option<&str>,
        expected_events: Option<i64>,
        note: Option<&str>,
    ) -> Result<(), EmailError> {
        let company = company.unwrap_or("not given");
        let expected =
            expected_events.map_or_else(|| "not given".to_owned(), |value| value.to_string());
        let note = note.unwrap_or("none");

        let message = Message {
            from_name: FROM_NAME,
            from_email: FROM_EMAIL,
            to: vec![Recipient {
                email: OPERATOR_EMAIL,
            }],
            subject: ACCESS_SUBJECT,
            text_content: format!(
                "Access request\n\n\
                 Email: {from_address}\n\
                 Company: {company}\n\
                 Expected metered events per month: {expected}\n\n\
                 Note:\n{note}\n"
            ),
            // Every interpolated value here was typed by an anonymous visitor,
            // so all four are escaped. The text part carries the same content
            // without markup, which is what a mail client that refuses HTML
            // will show.
            html_content: format!(
                "<p><strong>Access request</strong></p>\
                 <p>Email: {}<br>Company: {}<br>Expected metered events per month: {}</p>\
                 <p>Note:<br>{}</p>",
                escape_html(from_address),
                escape_html(company),
                escape_html(&expected),
                escape_html(note)
            ),
        };

        self.deliver(&message).await
    }

    /// Post one message and insist the service actually queued it.
    async fn deliver(&self, message: &Message<'_>) -> Result<(), EmailError> {
        let response = self
            .http
            .post(&self.endpoint)
            .bearer_auth(&self.token)
            .json(message)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    EmailError::Timeout
                } else {
                    EmailError::Transport
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(EmailError::HttpStatus(status.as_u16()));
        }

        // A 200 with no message id means the service accepted the request and
        // did not queue anything, which is a failure wearing a success status.
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|_| EmailError::InvalidResponse)?;
        let queued = body
            .get("message_id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|id| !id.trim().is_empty());
        if queued {
            Ok(())
        } else {
            Err(EmailError::InvalidResponse)
        }
    }
}

/// Whether an endpoint may be dialled.
///
/// The production URL exactly, or a loopback address for tests. Anything else
/// would send a bearer token to a host nobody reviewed.
fn endpoint_is_allowed(url: &str) -> bool {
    if url == PRODUCTION_ENDPOINT {
        return true;
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    if parsed.path() != "/send" {
        return false;
    }
    match parsed.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        // `Url::host_str` returns a bracketed IPv6 literal, which is why this
        // matches on `host()` instead.
        Some(url::Host::Domain(name)) => name == "localhost",
        None => false,
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_production_endpoint_or_loopback_is_dialled() {
        assert!(endpoint_is_allowed(PRODUCTION_ENDPOINT));
        assert!(endpoint_is_allowed("http://127.0.0.1:9000/send"));
        assert!(endpoint_is_allowed("http://localhost:9000/send"));
        assert!(endpoint_is_allowed("http://[::1]:9000/send"));

        for attempt in [
            "http://evil.example/send",
            "https://pokit-apps-email.flycast.evil.example/send",
            "http://127.0.0.1:9000/collect",
            "http://8.8.8.8/send",
            "not a url",
        ] {
            assert!(!endpoint_is_allowed(attempt), "{attempt} was allowed");
        }
    }

    #[test]
    fn debug_output_never_carries_the_token() {
        let client = EmailClient {
            http: reqwest::Client::new(),
            endpoint: PRODUCTION_ENDPOINT.to_owned(),
            token: "a_real_looking_service_token_value".to_owned(),
        };
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("a_real_looking_service_token_value"));
    }

    #[test]
    fn the_code_is_escaped_before_it_reaches_html() {
        assert_eq!(escape_html("1<2&3"), "1&lt;2&amp;3");
    }
}
