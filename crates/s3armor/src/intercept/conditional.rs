//! `If-Match`/`If-None-Match` conditional-request evaluation
//! (`docs/ARCHITECTURE.md` "ETag policy"). Every conditional a client sends is compared
//! against the *effective* ETag this proxy hands out
//! (`intercept::effective_etag`) — the plaintext MD5 for a v1 single-part
//! object with `s3a-emd5`, the backend's own ETag for everything else —
//! never the raw ciphertext ETag a client never saw. Existence-only
//! conditionals (`If-Match: *`, `If-None-Match: *`) are left untouched for
//! the backend to answer; only a real ETag list is intercepted.
//!
//! `If-Modified-Since`/`If-Unmodified-Since` are not handled here — they
//! compare `Last-Modified`, which this proxy never rewrites, so the
//! backend's own answer is already correct. `If-Range` is also not
//! handled — no target client (Nextcloud, rclone, restic, s3cmd, aws-cli)
//! is known to send it.

use http::{Response, StatusCode};

use crate::intercept::normalize_etag;
use crate::proxy::body::{self, ProxyBody};
use crate::proxy::header_value;

/// What a conditional GET/HEAD should do once its ETag comparison is known.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Precondition {
    Proceed,
    NotModified,
    Failed,
}

/// A request's `If-Match`/`If-None-Match` headers, taken out of the
/// outbound header list — so they are never forwarded to a backend that
/// only knows the ciphertext ETag — and evaluated instead against this
/// proxy's effective ETag.
pub(crate) struct Conditionals {
    if_match: Option<String>,
    if_none_match: Option<String>,
}

impl Conditionals {
    /// Removes `if-match`/`if-none-match` from `headers` and returns their
    /// values — except a bare `*`, which is existence-based (not
    /// content-based) and left in place for the backend to answer, already
    /// correctly.
    pub(crate) fn take(headers: &mut Vec<(String, String)>) -> Self {
        Self {
            if_match: take_header(headers, "if-match"),
            if_none_match: take_header(headers, "if-none-match"),
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.if_match.is_none() && self.if_none_match.is_none()
    }

    /// RFC 9110 §13.2's evaluation order for a safe (GET/HEAD) request:
    /// `If-Match` first, then `If-None-Match`.
    pub(crate) fn evaluate(&self, etag: &str) -> Precondition {
        let target = normalize_tag(etag);
        if let Some(list) = &self.if_match {
            if !list_contains(list, target) {
                return Precondition::Failed;
            }
        }
        if let Some(list) = &self.if_none_match {
            if list_contains(list, target) {
                return Precondition::NotModified;
            }
        }
        Precondition::Proceed
    }
}

fn take_header(headers: &mut Vec<(String, String)>, name: &str) -> Option<String> {
    let idx = headers
        .iter()
        .position(|(k, v)| k.eq_ignore_ascii_case(name) && v.trim() != "*")?;
    Some(headers.remove(idx).1)
}

/// Strips an optional weak (`W/`) prefix and surrounding quotes, so
/// `"abc"`, `W/"abc"`, and a bare `abc` all compare equal — real clients
/// mix these forms and this proxy's own ETags are always strong.
fn normalize_tag(s: &str) -> &str {
    let s = s.trim();
    let s = s.strip_prefix("W/").unwrap_or(s);
    normalize_etag(s)
}

fn list_contains(list: &str, target: &str) -> bool {
    list.split(',').any(|raw| normalize_tag(raw) == target)
}

/// Builds the `304 Not Modified` response: no body, just the identifying
/// headers a client needs to keep its cached copy.
pub(crate) fn not_modified_response(
    resp_headers: &[(String, String)],
    etag: &str,
    request_id: &str,
) -> Response<ProxyBody> {
    let mut builder = Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header("etag", etag)
        .header("x-amz-request-id", request_id);
    if let Some(lm) = header_value(resp_headers, "last-modified") {
        builder = builder.header("last-modified", lm);
    }
    if let Some(cc) = header_value(resp_headers, "cache-control") {
        builder = builder.header("cache-control", cc);
    }
    #[expect(
        clippy::expect_used,
        reason = "a 304 built from a handful of known-valid header values never fails"
    )]
    builder
        .body(body::empty())
        .expect("a 304 built from a handful of known-valid header values never fails")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_is_left_for_the_backend() {
        let mut headers = vec![("if-none-match".to_string(), "*".to_string())];
        let conds = Conditionals::take(&mut headers);
        assert!(conds.is_empty());
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn no_conditional_headers_evaluates_to_proceed() {
        let mut headers = vec![];
        let conds = Conditionals::take(&mut headers);
        assert!(conds.is_empty());
        assert_eq!(conds.evaluate("\"x\""), Precondition::Proceed);
    }

    #[test]
    fn if_none_match_hit_is_not_modified() {
        let mut headers = vec![("if-none-match".to_string(), "\"abc\"".to_string())];
        let conds = Conditionals::take(&mut headers);
        assert!(headers.is_empty());
        assert_eq!(conds.evaluate("\"abc\""), Precondition::NotModified);
    }

    #[test]
    fn if_none_match_miss_proceeds() {
        let mut headers = vec![("if-none-match".to_string(), "\"abc\"".to_string())];
        let conds = Conditionals::take(&mut headers);
        assert_eq!(conds.evaluate("\"def\""), Precondition::Proceed);
    }

    #[test]
    fn if_match_miss_fails() {
        let mut headers = vec![("if-match".to_string(), "\"abc\"".to_string())];
        let conds = Conditionals::take(&mut headers);
        assert_eq!(conds.evaluate("\"def\""), Precondition::Failed);
    }

    #[test]
    fn if_match_hit_proceeds() {
        let mut headers = vec![("if-match".to_string(), "\"abc\"".to_string())];
        let conds = Conditionals::take(&mut headers);
        assert_eq!(conds.evaluate("\"abc\""), Precondition::Proceed);
    }

    #[test]
    fn if_match_wins_precedence_over_if_none_match() {
        let mut headers = vec![
            ("if-match".to_string(), "\"abc\"".to_string()),
            ("if-none-match".to_string(), "\"def\"".to_string()),
        ];
        let conds = Conditionals::take(&mut headers);
        // If-Match fails first, before If-None-Match is even considered.
        assert_eq!(conds.evaluate("\"zzz\""), Precondition::Failed);
    }

    #[test]
    fn weak_prefix_is_ignored() {
        let mut headers = vec![("if-none-match".to_string(), "W/\"abc\"".to_string())];
        let conds = Conditionals::take(&mut headers);
        assert_eq!(conds.evaluate("\"abc\""), Precondition::NotModified);
    }

    #[test]
    fn comma_list_matches_any_member() {
        let mut headers = vec![("if-match".to_string(), "\"a\", \"b\", \"c\"".to_string())];
        let conds = Conditionals::take(&mut headers);
        assert_eq!(conds.evaluate("\"b\""), Precondition::Proceed);
    }
}
