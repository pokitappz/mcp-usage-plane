//! Response policy for everything this service serves.
//!
//! One middleware, applied outside the router, so a header cannot be forgotten
//! by a handler that did not know it existed. It runs after the handler, which
//! means it overwrites rather than defaults: a route cannot opt out of the
//! content security policy by setting its own.
//!
//! # Why the policy has no escape hatches
//!
//! There is no `unsafe-inline` and no `unsafe-eval`, for styles or for scripts.
//! That is a constraint on how the pages are written rather than a setting:
//! every style lives in the stylesheet and every handler lives in a file under
//! `/assets`, so a value that reaches the page from the database can never be
//! executed even if it escapes its quoting. A rendered-page test enforces the
//! writing side, since a policy the markup quietly violates is worse than none:
//! it looks like protection and reports nothing.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

/// The content security policy served with every response.
///
/// `frame-ancestors 'none'` and `form-action 'self'` are the two that matter
/// for a dashboard: the first stops the page being framed for a clickjacked
/// click, and the second stops a compromised page posting a form somewhere
/// else. `base-uri 'self'` stops an injected `<base>` rewriting every relative
/// URL on the page, which includes the form targets.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
img-src 'self' data:; \
style-src 'self'; \
script-src 'self'; \
connect-src 'self'; \
form-action 'self'; \
frame-ancestors 'none'; \
base-uri 'self'";

/// Whether a path serves something specific to one caller.
///
/// Anything true here is kept out of every cache and out of every index. The
/// dashboard is the reason: it renders one account's revenue, and a shared
/// cache holding that page would serve it to the next person through the same
/// proxy.
fn is_private(path: &str) -> bool {
    path == "/app" || path.starts_with("/app/") || path.starts_with("/v1/") || path == "/healthz"
}

/// Apply the response policy.
pub async fn response_policy(request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    let status = response.status();
    let headers = response.headers_mut();

    for (name, value) in [
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "strict-origin-when-cross-origin"),
        (
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains",
        ),
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );

    if is_private(&path) {
        headers.insert(
            "x-robots-tag",
            HeaderValue::from_static("noindex, nofollow"),
        );
        // Last word on caching for these routes, deliberately after anything a
        // handler set. A dashboard page in a shared cache is a disclosure.
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    } else if status.is_client_error() || status.is_server_error() {
        // A 404 that gets indexed is a page nobody wrote competing with one
        // somebody did.
        headers.insert("x-robots-tag", HeaderValue::from_static("noindex, follow"));
    }

    // The stylesheet is not fingerprinted, so it must be revalidated rather
    // than held for a year; shipping a design change that a browser refuses to
    // fetch for twelve months is not a tradeoff worth the round trip saved.
    if path.starts_with("/assets/") && status.is_success() {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=0, must-revalidate"),
        );
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_permits_no_inline_or_eval_anywhere() {
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe-inline"));
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe-eval"));
        // Every fetch directive that matters is present, so a missing one
        // cannot fall back to a permissive default-src that someone widens
        // later for an unrelated reason.
        for directive in [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
        ] {
            assert!(
                CONTENT_SECURITY_POLICY.contains(directive),
                "{directive} is missing"
            );
        }
    }

    #[test]
    fn caller_specific_paths_are_private_and_marketing_paths_are_not() {
        for path in ["/app", "/app/tenants", "/v1/usage", "/healthz"] {
            assert!(is_private(path), "{path} should be private");
        }
        for path in [
            "/",
            "/pricing",
            "/security",
            "/docs",
            "/assets/usagekit.css",
        ] {
            assert!(!is_private(path), "{path} should be public");
        }
        // A public path that merely starts with the same letters must not be
        // swept in, and more importantly a private one must not be swept out.
        assert!(!is_private("/applications"));
    }
}
