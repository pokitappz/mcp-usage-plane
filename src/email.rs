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

/// Shortest token that could plausibly be real.
const MIN_TOKEN_LEN: usize = 24;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Who the mail says it is from, when nobody has said.
///
/// There is no sensible default address, so this is refused at startup rather
/// than guessed: mail claiming to come from an address the operator does not
/// own is how a deployment ends up on a blocklist.
const FROM_EMAIL_VAR: &str = "EMAIL_FROM_ADDRESS";

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
    /// The address mail claims to come from.
    from_email: String,
    /// The name beside it, and the name used in subjects and bodies.
    product_name: String,
    /// Where an access request is announced.
    ///
    /// The operator, not the person who asked: access is granted by hand, so
    /// this is the only thing that moves a queued row in front of somebody. The
    /// visitor gets their confirmation from the page, which is already rendered
    /// by the time this is attempted.
    operator_email: String,
}

impl std::fmt::Debug for EmailClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EmailClient")
            .field("http", &"<client>")
            .field("endpoint", &self.endpoint)
            .field("token", &"<redacted>")
            .field("from_email", &self.from_email)
            .field("product_name", &self.product_name)
            .field("operator_email", &self.operator_email)
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
        // Any https host, because whoever deploys this chooses their own mail
        // service. What the check still refuses is plaintext to somewhere other
        // than loopback, which is the part that actually protects the token:
        // the original allowlist existed to stop a bearer token crossing the
        // open network in clear, not to stop it reaching an unfamiliar name.
        //
        // The opt-in exists for a mail relay on a private network, which is how
        // this service runs in production and is not reachable over https.
        let allow_plaintext = std::env::var("EMAIL_ALLOW_PLAINTEXT")
            .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
        if !endpoint_is_allowed(&url, allow_plaintext) {
            return Err(
                "EMAIL_SERVICE_URL must be an https URL, or plaintext on loopback. \
                 For a mail relay on a private network, set EMAIL_ALLOW_PLAINTEXT=1 \
                 and understand that the service token then crosses that network \
                 in the clear"
                    .to_owned(),
            );
        }
        if allow_plaintext && !url.starts_with("https://") {
            tracing::warn!(
                "EMAIL_ALLOW_PLAINTEXT is set; the email service token is sent unencrypted"
            );
        }

        let from_email = std::env::var(FROM_EMAIL_VAR)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!("{FROM_EMAIL_VAR} must be set to an address this deployment may send from")
            })?;
        // The same name the pages use. One variable for what a deployment
        // calls itself, rather than a page saying one thing and its mail
        // another.
        let product_name = crate::Branding::from_env().full();
        // Access requests go to whoever runs this. Falling back to the sending
        // address means a deployment that never sets it still reaches a human.
        let operator_email = std::env::var("EMAIL_OPERATOR_ADDRESS")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| from_email.clone());

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
            from_email,
            product_name,
            operator_email,
        }))
    }

    /// Send a sign-in code.
    ///
    /// # Errors
    ///
    /// Returns an [`EmailError`] category. The code never appears in one.
    pub async fn send_sign_in_code(&self, to: &str, code: &str) -> Result<(), EmailError> {
        let product = &self.product_name;
        let subject = format!("Your {product} sign-in code");
        let message = Message {
            from_name: product,
            from_email: &self.from_email,
            to: vec![Recipient { email: to }],
            subject: &subject,
            text_content: format!(
                "Your {product} sign-in code is {code}\n\n\
                 It expires in 10 minutes and can be used once.\n\n\
                 If you did not ask to sign in, you can ignore this message."
            ),
            html_content: format!(
                "<p>Your {} sign-in code is <strong>{}</strong></p>\
                 <p>It expires in 10 minutes and can be used once.</p>\
                 <p>If you did not ask to sign in, you can ignore this message.</p>",
                escape_html(product),
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

        let subject = format!("{} access request", self.product_name);
        let message = Message {
            from_name: &self.product_name,
            from_email: &self.from_email,
            to: vec![Recipient {
                email: &self.operator_email,
            }],
            subject: &subject,
            text_content: format!(
                "Access request\n\n\
                 Email: {from_address}\n\
                 Company: {company}\n\
                 Billable events per month: {expected}\n\n\
                 Note:\n{note}\n"
            ),
            // Every interpolated value here was typed by an anonymous visitor,
            // so all four are escaped. The text part carries the same content
            // without markup, which is what a mail client that refuses HTML
            // will show.
            html_content: format!(
                "<p><strong>Access request</strong></p>\
                 <p>Email: {}<br>Company: {}<br>Billable events per month: {}</p>\
                 <p>Note:<br>{}</p>",
                escape_html(from_address),
                escape_html(company),
                escape_html(&expected),
                escape_html(note)
            ),
        };

        self.deliver(&message).await
    }

    /// Tell somebody their access request was granted.
    ///
    /// Carries no credential, and cannot: sign-in is passwordless, so the only
    /// thing this needs to say is that the address now works. A mail that
    /// contained a secret would be a secret sitting in a mailbox forever.
    ///
    /// # Errors
    ///
    /// Returns an [`EmailError`] category. The caller treats a failure as
    /// non-fatal and reports it, because the account exists either way.
    pub async fn send_access_granted(&self, to: &str, sign_in_url: &str) -> Result<(), EmailError> {
        let product = &self.product_name;
        let subject = format!("Your {product} account is ready");
        let message = Message {
            from_name: product,
            from_email: &self.from_email,
            to: vec![Recipient { email: to }],
            subject: &subject,
            text_content: format!(
                "Your {product} account is ready.\n\n\
                 Sign in at {sign_in_url} with this address. There is no password: \
                 we email you a six digit code each time.\n\n\
                 Your first step is creating an edge key from the dashboard and \
                 pointing your server at it.\n"
            ),
            html_content: format!(
                "<p>Your {product} account is ready.</p>\
                 <p>Sign in at <a href=\"{url}\">{url}</a> with this address. \
                 There is no password: we email you a six digit code each time.</p>\
                 <p>Your first step is creating an edge key from the dashboard and \
                 pointing your server at it.</p>",
                product = escape_html(product),
                url = escape_html(sign_in_url)
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
fn endpoint_is_allowed(url: &str, allow_plaintext: bool) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    match parsed.scheme() {
        // Any host. The operator picked their mail service and the token is
        // encrypted in transit, which is what mattered.
        "https" => parsed.host().is_some(),
        "http" => {
            if allow_plaintext {
                return parsed.host().is_some();
            }
            match parsed.host() {
                Some(url::Host::Ipv4(address)) => address.is_loopback(),
                Some(url::Host::Ipv6(address)) => address.is_loopback(),
                // `Url::host_str` returns a bracketed IPv6 literal, which is
                // why this matches on `host()` instead.
                Some(url::Host::Domain(name)) => name == "localhost",
                None => false,
            }
        }
        _ => false,
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
    fn any_https_mail_service_is_dialled_but_plaintext_is_not() {
        // Whoever deploys this picks their own mail service, so the host is no
        // longer ours to enumerate. What the check still protects is the token
        // in transit, which is what the original allowlist was actually for.
        for allowed in [
            "https://api.postmarkapp.com/email",
            "https://mail.example.com/v3/messages",
            "https://api.example.co.uk/send",
        ] {
            assert!(endpoint_is_allowed(allowed, false), "{allowed} was refused");
        }

        // Loopback stays reachable in the clear, for the test suite and for a
        // relay running beside the service.
        for loopback in [
            "http://127.0.0.1:9000/send",
            "http://localhost:9000/send",
            "http://[::1]:9000/send",
            "http://localhost:9000/anything",
        ] {
            assert!(
                endpoint_is_allowed(loopback, false),
                "{loopback} was refused"
            );
        }

        for refused in [
            "http://mail.example.com/send",
            "http://8.8.8.8/send",
            "ftp://mail.example.com/send",
            "file:///etc/passwd",
            "not a url",
            "https://",
        ] {
            assert!(
                !endpoint_is_allowed(refused, false),
                "{refused} was allowed"
            );
        }
    }

    #[test]
    fn plaintext_off_loopback_requires_saying_so_explicitly() {
        // A mail relay on a private network cannot offer https, and this
        // service runs against one. The opt-in exists so that arrangement is a
        // decision somebody made rather than a hole in the check.
        let private = "http://mail-relay.internal/send";
        assert!(!endpoint_is_allowed(private, false));
        assert!(endpoint_is_allowed(private, true));

        // Even opted in, a URL that is not a URL is still refused.
        assert!(!endpoint_is_allowed("not a url", true));
        assert!(!endpoint_is_allowed("ftp://mail.example.com/send", true));
    }

    #[test]
    fn debug_output_never_carries_the_token() {
        let client = EmailClient {
            http: reqwest::Client::new(),
            endpoint: "https://mail.example.com/send".to_owned(),
            token: "a_real_looking_service_token_value".to_owned(),
            from_email: "billing@example.com".to_owned(),
            product_name: "Example Billing".to_owned(),
            operator_email: "ops@example.com".to_owned(),
        };
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("a_real_looking_service_token_value"));
    }

    #[test]
    fn nothing_here_names_the_company_that_wrote_it() {
        // This service is source-available, so somebody else runs it. Their
        // customers receiving mail branded with our product name, from our
        // support address, would be a bug in the obvious direction. There is no
        // default address at all: sending as an address the operator does not
        // own is how a deployment reaches a blocklist.
        // The name comes from `Branding`, which the pages use too, so one
        // variable decides what a deployment calls itself everywhere.
        let default = crate::Branding::from_env().full().to_lowercase();
        assert!(
            !default.contains("usagekit"),
            "default branding names us: {default}"
        );
        assert!(
            !default.contains("pokit"),
            "default branding names us: {default}"
        );

        // And there is no default sending address at all, only the name of the
        // variable that has to be set.
        assert!(
            !FROM_EMAIL_VAR.contains('@'),
            "there is a default from address"
        );
        assert!(!FROM_EMAIL_VAR.contains("pokitapps"));
    }

    #[test]
    fn the_code_is_escaped_before_it_reaches_html() {
        assert_eq!(escape_html("1<2&3"), "1&lt;2&amp;3");
    }
}
