//! The page shell: what every rendered page has in common.
//!
//! Server rendered with compile-time templates, so a typo in a page is a build
//! failure rather than a 500 in front of somebody. There is no client side
//! framework, no build step, and no JavaScript: every page works with scripting
//! disabled, which is why the dashboard's actions are real form posts.
//!
//! This used to serve a marketing site as well. Those pages live in their own
//! repository now, because a crate somebody installs should carry what runs the
//! service and nothing else. What is left is the shell the dashboard, sign-in
//! and the 404 are rendered into.

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sha2::{Digest as _, Sha256};

use crate::AppState;

/// Where the site lives when `APP_PUBLIC_URL` is unset.
///
/// Only reachable in development: `public_url_from_env` refuses to start with a
/// value that is neither https nor loopback.
const DEV_BASE_URL: &str = "http://localhost:8081";

/// Everything the shared page shell needs.
///
/// Nested on each page struct rather than flattened into it, so adding a head
/// element changes one struct instead of every one.
pub struct Shell {
    /// Contents of `<title>`.
    pub title: String,
    /// Meta description.
    pub description: &'static str,
    /// Absolute canonical URL.
    pub canonical: String,
    /// Robots directive.
    pub robots: &'static str,
    /// What this deployment calls itself, for the wordmark.
    pub product: crate::Branding,
}

impl Shell {
    /// A public, indexable page.
    pub fn new(
        state: &AppState,
        path: &'static str,
        title: &str,
        description: &'static str,
    ) -> Self {
        let base = state.public_url.as_deref().unwrap_or(DEV_BASE_URL);
        Self {
            title: format!("{title} | {}", state.product.full()),
            description,
            canonical: format!("{base}{path}"),
            robots: "index,follow",
            product: state.product.clone(),
        }
    }

    /// A page behind a session.
    ///
    /// `noindex, nofollow` in the markup as well as the header, because the two
    /// are read by different things and a dashboard should be absent from a
    /// search index whichever one is consulted. The middleware also serves
    /// these `no-store`.
    pub fn private(
        state: &AppState,
        path: &'static str,
        title: &str,
        description: &'static str,
    ) -> Self {
        Self {
            robots: "noindex,nofollow",
            ..Self::new(state, path, title, description)
        }
    }
}

#[derive(Template)]
#[template(path = "message.html")]
struct MessageTemplate {
    shell: Shell,
    eyebrow: &'static str,
    heading: &'static str,
    message: &'static str,
}

/// Render a template, or say so plainly if it cannot be rendered.
///
/// The `ETag` is the digest of the body, so it is correct by construction: a
/// page that renders the same bytes keeps its tag whatever else changed, and a
/// page whose content moved gets a new one without anyone remembering to bump
/// a version.
pub fn render<T: Template>(template: &T, status: StatusCode) -> Response {
    match template.render() {
        Ok(body) => {
            let etag = format!("\"{}\"", hex_digest(&body));
            let mut response = (
                status,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                body,
            )
                .into_response();
            let headers = response.headers_mut();
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=0, must-revalidate"),
            );
            if let Ok(value) = HeaderValue::from_str(&etag) {
                headers.insert(header::ETAG, value);
            }
            response
        }
        Err(error) => {
            // A compile-time template that fails at runtime means a value it
            // formats misbehaved, which is a bug here rather than a bad
            // request. Saying so in plain text beats a blank page.
            tracing::error!(%error, "page render failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "This page could not be rendered.",
            )
                .into_response()
        }
    }
}

fn hex_digest(body: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(body.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

// ----------------------------------------------------------------- pages

/// Anything with no route.
///
/// A bare framework 404 on a public domain reads as a broken deployment, which
/// is the wrong thing to tell someone evaluating whether to trust the service.
pub async fn not_found(State(state): State<AppState>) -> Response {
    let mut shell = Shell::new(
        &state,
        "/",
        "Page not found",
        "That page does not exist on UsageKit Cloud.",
    );
    shell.robots = "noindex,follow";
    render(
        &MessageTemplate {
            shell,
            eyebrow: "404",
            heading: "There is nothing at that address.",
            message: "The link may be out of date, or the page may have moved. \
                      Everything that does exist is linked below.",
        },
        StatusCode::NOT_FOUND,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every class the templates use has a rule in the stylesheet.
    ///
    /// The marketing pages and their styles were split into a separate
    /// repository, and trimming a shared stylesheet by hand is exactly the kind
    /// of edit that removes one rule too many. The failure is silent: the page
    /// still renders, just wrong, and only on a screen nobody looked at.
    #[test]
    fn nothing_rendered_here_is_left_without_styling() {
        use std::collections::BTreeSet;

        let css = include_str!("../static/assets/usagekit.css");
        let defined: BTreeSet<&str> = css
            .split('.')
            .skip(1)
            .filter_map(|rest| {
                let end =
                    rest.find(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')?;
                Some(&rest[..end]).filter(|name| !name.is_empty())
            })
            .collect();

        // Structural hooks that never had a rule. Named rather than filtered by
        // a pattern, so adding an unstyled class is a deliberate act.
        let hooks: BTreeSet<&str> = ["footer-block", "wordmark-name"].into_iter().collect();

        let templates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
        let mut missing: BTreeSet<String> = BTreeSet::new();
        let mut seen = 0usize;
        for entry in std::fs::read_dir(&templates).expect("templates are readable") {
            let body = std::fs::read_to_string(entry.expect("an entry").path()).expect("readable");
            for (index, _) in body.match_indices("class=\"") {
                let rest = &body[index + 7..];
                let Some(end) = rest.find('"') else { continue };

                // A class attribute can carry template logic, as in
                // `class="stat {% if .. %}stat-alarm{% endif %}"`. Strip the
                // expressions before splitting, or `if` and `endif` look like
                // class names.
                let mut attribute = rest[..end].to_owned();
                for (open, close) in [("{%", "%}"), ("{{", "}}")] {
                    while let Some(start) = attribute.find(open) {
                        let Some(stop) = attribute[start..].find(close) else {
                            break;
                        };
                        attribute.replace_range(start..start + stop + close.len(), " ");
                    }
                }

                for token in attribute.split_whitespace() {
                    if !token.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
                        continue;
                    }
                    seen += 1;
                    if !defined.contains(token) && !hooks.contains(token) {
                        missing.insert(token.to_owned());
                    }
                }
            }
        }

        assert!(
            seen > 50,
            "only {seen} classes found; the scan is not working"
        );
        assert!(
            missing.is_empty(),
            "templates use classes with no rule: {missing:?}"
        );
    }

    #[test]
    fn the_etag_follows_the_body() {
        assert_eq!(hex_digest("same"), hex_digest("same"));
        assert_ne!(hex_digest("one"), hex_digest("two"));
        assert_eq!(hex_digest("").len(), 64);
    }
}
