//! The one SigV4 canonicalizer, shared by inbound verification (`verify.rs`)
//! and outbound re-signing (`sign.rs`).
//!
//! `docs/ARCHITECTURE.md` "Crate choices" lists `aws-sigv4` as the outbound-signing dependency.
//! This module deviates: one canonicalizer serves both directions, and
//! `aws-sigv4` is a dev-dependency oracle only (see `tests/conformance.rs`).
//! Verifying an incoming signature is the harder direction — it must match
//! whatever the client did — so once it exists, adding a second signer for
//! the outbound direction would be a second implementation of the same
//! algorithm plus a runtime dependency on ~10 transitive smithy crates in a
//! security product. Cross-checking against `aws-sigv4` in tests keeps the
//! independent-check property docs/ARCHITECTURE.md "Crate choices" wanted without shipping it.
//!
//! A 403 on object keys with space/`~`/`!`/`(`/`)`/`*` is a common
//! implementation mistake: form-encoding (e.g. a language's own URL
//! query-escaper) applied to an already-percent-**decoded** path. That is
//! the double mistake this module avoids: canonicalize from the raw
//! request target, and use RFC 3986 path encoding, never form encoding.

use hmac::{Hmac, Mac};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha2::{Digest, Sha256};

/// RFC 3986 unreserved set: `A-Za-z0-9-._~`. Everything else — including
/// `/` when it appears inside a decoded segment or query value, and `%`
/// itself in double-encode mode — gets percent-encoded, uppercase hex.
/// Bytes outside ASCII are always encoded by `percent_encoding` regardless
/// of this set, which is what a raw UTF-8 path segment needs.
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

fn encode_component(bytes: &[u8]) -> String {
    // percent_encoding operates on &str; our inputs are either already str
    // or raw bytes reinterpreted losslessly — see callers.
    utf8_percent_encode(
        // SAFETY-free: we only ever feed this valid UTF-8 (str inputs, or
        // bytes produced by percent-decoding a str, which percent_decode's
        // caller below re-validates via from_utf8_lossy).
        std::str::from_utf8(bytes).unwrap_or_default(),
        UNRESERVED,
    )
    .to_string()
}

/// Path normalization, operating on the raw path string so `.`/`..` and
/// repeated `/` are recognized before any percent-decoding. Empirically
/// pinned against the vendored suite: `normalize: true` collapses repeated
/// slashes (`//example//` -> `/example/`) *and* resolves `.`/`..` segments
/// (`/./` -> `/`, `/a/..` -> `/`) — broader than plain RFC 3986
/// `remove_dot_segments`, which does not touch repeated slashes. A single
/// trailing slash is preserved when the input had one. AWS's own wording:
/// normalize URI paths for every service except S3; S3 does not normalize.
/// Production code always passes `normalize = false`; the flag exists so
/// the vendored AWS conformance suite (which includes explicit
/// `normalize: true` cases) can drive both paths.
fn normalize_path(raw: &str) -> String {
    let had_trailing_slash = raw.len() > 1 && raw.ends_with('/');
    let mut segments: Vec<&str> = Vec::new();
    for seg in raw.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    let mut result = format!("/{}", segments.join("/"));
    if had_trailing_slash && !result.ends_with('/') {
        result.push('/');
    }
    result
}

/// Canonical URI from a raw (as received on the wire) request-target path.
///
/// `decode_existing`: S3 mode (`true`) percent-decodes each path segment
/// before re-encoding it, so a client's already-correctly-encoded byte (any
/// case of hex digit) comes out in canonical uppercase form without being
/// escaped a second time. Generic/non-S3 mode (`false`) encodes the raw
/// segment bytes directly, including any literal `%`, which is the "double
/// encode" behavior the vendored `double-encode-path`/`double-url-encode`
/// cases exist to pin down. Production S3 traffic always uses `true`.
pub fn canonical_uri(raw_path: &str, normalize: bool, decode_existing: bool) -> String {
    let path = if raw_path.is_empty() { "/" } else { raw_path };
    let path = if normalize {
        normalize_path(path)
    } else {
        path.to_string()
    };
    path.split('/')
        .map(|seg| {
            if decode_existing {
                let decoded = percent_decode_str(seg).collect::<Vec<u8>>();
                encode_component(&decoded)
            } else {
                encode_component(seg.as_bytes())
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Canonical query string: RFC 3986-decode every key/value once, re-encode
/// with the unreserved-safe set, sort by (encoded key, encoded value), join
/// with `&`. `exclude` drops params that must not sign themselves — a
/// presigned URL's own `X-Amz-Signature`.
pub fn canonical_query(raw_query: &str, exclude: &[&str]) -> String {
    if raw_query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = raw_query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let dk = percent_decode_str(k).decode_utf8_lossy().into_owned();
            let dv = percent_decode_str(v).decode_utf8_lossy().into_owned();
            (dk, dv)
        })
        .filter(|(k, _)| !exclude.contains(&k.as_str()))
        .map(|(k, v)| {
            (
                encode_component(k.as_bytes()),
                encode_component(v.as_bytes()),
            )
        })
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.trim().chars() {
        if c == ' ' || c == '\t' {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out
}

/// Builds the canonical-headers block and the `;`-joined signed-headers
/// list. `signed_names` must already be lowercase; order does not matter,
/// this function sorts and dedups. Multi-valued headers are joined with
/// `,` in the order they appear on the request (AWS does not sort values,
/// only header names) after each value is trimmed and internally
/// whitespace-collapsed.
pub fn canonical_headers(
    headers: &[(String, String)],
    signed_names: &[String],
) -> (String, String) {
    let mut names: Vec<String> = signed_names
        .iter()
        .map(|n| n.to_ascii_lowercase())
        .collect();
    names.sort();
    names.dedup();
    canonical_headers_in_order(headers, &names)
}

/// Same output shape as [`canonical_headers`], but emits the block and the
/// `SignedHeaders` line in exactly the order `names` is given, without
/// sorting or deduping. `sigv4::verify` uses this to mirror a client's own
/// (possibly unsorted) `SignedHeaders` order — as long as that order is
/// what the client itself signed, its canonical request still only
/// verifies against the client's own signature, so this doesn't weaken
/// signature integrity. Callers own the uniqueness/lowercase invariants on
/// `names`.
pub fn canonical_headers_in_order(
    headers: &[(String, String)],
    names: &[String],
) -> (String, String) {
    let mut block = String::new();
    for name in names {
        let joined = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| collapse_whitespace(v))
            .collect::<Vec<_>>()
            .join(",");
        block.push_str(name);
        block.push(':');
        block.push_str(&joined);
        block.push('\n');
    }
    (block, names.join(";"))
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `METHOD\nCANONICAL_URI\nCANONICAL_QUERY\nCANONICAL_HEADERS\n
/// SIGNED_HEADERS\nPAYLOAD_HASH`. `canonical_headers_block` must already
/// end in `\n` per header line (the output of [`canonical_headers`]).
pub fn canonical_request(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    canonical_headers_block: &str,
    signed_headers: &str,
    payload_hash: &str,
) -> String {
    format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers_block}\n{signed_headers}\n{payload_hash}"
    )
}

pub fn string_to_sign(timestamp: &str, credential_scope: &str, canonical_request: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{}",
        hex_sha256(canonical_request.as_bytes())
    )
}

type HmacSha256 = Hmac<Sha256>;

#[expect(
    clippy::expect_used,
    reason = "HMAC accepts a key of any length; this can never fail"
)]
fn hmac_raw(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

pub fn signing_key(secret: &str, date8: &str, region: &str, service: &str) -> [u8; 32] {
    let k_date = hmac_raw(format!("AWS4{secret}").as_bytes(), date8.as_bytes());
    let k_region = hmac_raw(&k_date, region.as_bytes());
    let k_service = hmac_raw(&k_region, service.as_bytes());
    hmac_raw(&k_service, b"aws4_request")
}

pub fn signature_hex(signing_key: &[u8; 32], string_to_sign: &str) -> String {
    hex::encode(hmac_raw(signing_key, string_to_sign.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_path_unchanged() {
        assert_eq!(canonical_uri("/", false, true), "/");
    }

    #[test]
    fn unreserved_chars_pass_through() {
        let p = "/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        assert_eq!(canonical_uri(p, true, true), p);
    }

    #[test]
    fn space_gets_encoded() {
        assert_eq!(
            canonical_uri("/example space/", false, true),
            "/example%20space/"
        );
    }

    #[test]
    fn utf8_gets_byte_encoded() {
        // The vendored `get-utf8` case: raw path is one Ethiopic character.
        assert_eq!(canonical_uri("/ሴ", true, true), "/%E1%88%B4");
    }

    #[test]
    fn dot_segment_normalized_when_requested() {
        assert_eq!(canonical_uri("/./example", true, true), "/example");
        assert_eq!(canonical_uri("/example/..", true, true), "/");
    }

    #[test]
    fn dot_segment_kept_literal_without_normalize() {
        assert_eq!(canonical_uri("/./example", false, true), "/./example");
        assert_eq!(canonical_uri("/example/..", false, true), "/example/..");
    }

    #[test]
    fn s3_mode_single_encodes_existing_percent_triplet() {
        // A client that already encoded a literal '/' inside a key as
        // %2F must see that preserved as %2F, not treated as a path
        // separator and not double-escaped to %252F.
        assert_eq!(canonical_uri("/key%2Fname", false, true), "/key%2Fname");
    }

    #[test]
    fn double_encode_mode_escapes_percent_itself() {
        assert_eq!(canonical_uri("/a%40b", false, false), "/a%2540b");
    }

    #[test]
    fn query_sorted_by_key_after_decoding() {
        assert_eq!(
            canonical_query("Param-3=Value3&Param=Value2&%E1%88%B4=Value1", &[]),
            "%E1%88%B4=Value1&Param=Value2&Param-3=Value3"
        );
    }

    #[test]
    fn query_empty_value_kept() {
        assert_eq!(canonical_query("acl", &[]), "acl=");
    }

    #[test]
    fn query_excludes_signature() {
        assert_eq!(
            canonical_query("X-Amz-Signature=abc&Foo=bar", &["X-Amz-Signature"]),
            "Foo=bar"
        );
    }

    #[test]
    fn headers_collapsed_and_sorted() {
        let headers = vec![
            ("X-Amz-Date".to_string(), "20150830T123600Z".to_string()),
            ("Host".to_string(), "example.amazonaws.com".to_string()),
        ];
        let (block, signed) = canonical_headers(&headers, &["host".into(), "x-amz-date".into()]);
        assert_eq!(
            block,
            "host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n"
        );
        assert_eq!(signed, "host;x-amz-date");
    }

    #[test]
    fn header_values_collapse_internal_whitespace() {
        let headers = vec![("X".to_string(), "  a   b  ".to_string())];
        let (block, _) = canonical_headers(&headers, &["x".into()]);
        assert_eq!(block, "x:a b\n");
    }

    #[test]
    fn in_order_variant_preserves_listed_order_while_sorted_variant_sorts() {
        let headers = vec![
            ("X-Amz-Date".to_string(), "20150830T123600Z".to_string()),
            ("Host".to_string(), "example.amazonaws.com".to_string()),
        ];
        let unsorted = vec!["x-amz-date".to_string(), "host".to_string()];

        let (_, signed_in_order) = canonical_headers_in_order(&headers, &unsorted);
        assert_eq!(signed_in_order, "x-amz-date;host");

        let (_, signed_sorted) = canonical_headers(&headers, &unsorted);
        assert_eq!(signed_sorted, "host;x-amz-date");
    }

    #[test]
    fn known_signature_matches_aws_worked_example() {
        // AWS SigV4 worked example (get-vanilla): the value every
        // implementation is checked against first.
        let key = signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "service",
        );
        let cr = canonical_request(
            "GET",
            "/",
            "",
            "host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n",
            "host;x-amz-date",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        let sts = string_to_sign(
            "20150830T123600Z",
            "20150830/us-east-1/service/aws4_request",
            &cr,
        );
        assert_eq!(
            signature_hex(&key, &sts),
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    /// Regression table for key-shape 403s caused by a form-encoding
    /// query-escaper run on an already-decoded path.
    ///
    /// A compliant SDK percent-encodes every non-unreserved byte of an
    /// object key exactly once, uppercase hex, before putting it on the
    /// wire and before computing its own canonical request. So the
    /// property that must hold for every one of these characters: a
    /// correctly single-encoded wire path round-trips through
    /// `canonical_uri` unchanged. A form-encoding escaper breaks this for
    /// space (→ `+`) and for `! ( ) *` (escaped when RFC 3986's unreserved
    /// set says they must not be, since form encoding targets HTML forms,
    /// not RFC 3986 path encoding).
    #[test]
    fn correctly_encoded_key_paths_round_trip_through_canonical_uri_unchanged() {
        let cases = [
            ("/key%20with%20space", "space"),
            ("/tilde~unreserved", "~ is unreserved, never encoded"),
            ("/bang%21end", "!"),
            ("/paren%28%29end", "( )"),
            ("/star%2Aend", "*"),
            ("/plus%2Bend", "+"),
            ("/key%2Fname", "%2F inside a single key, not a separator"),
        ];
        for (wire_path, label) in cases {
            assert_eq!(
                canonical_uri(wire_path, false, true),
                wire_path,
                "correctly-encoded wire path for {label} must round-trip unchanged"
            );
        }
    }

    /// Same regression, from the other direction: a raw (unencoded) byte
    /// must come out RFC 3986-encoded, never as form encoding would
    /// have produced it (`+` for space; `!()*` left raw).
    #[test]
    fn raw_key_bytes_are_rfc3986_encoded_never_form_encoded() {
        let cases: &[(&str, &str)] = &[
            ("/a b", "/a%20b"),     // form encoding: "/a+b" — wrong
            ("/a!b", "/a%21b"),     // form encoding: "/a!b" — wrong (not encoded)
            ("/a(b)", "/a%28b%29"), // form encoding: "/a(b)" — wrong
            ("/a*b", "/a%2Ab"),     // form encoding: "/a*b" — wrong
            ("/a+b", "/a%2Bb"),     // form encoding: "/a+b" — wrong (ambiguous with space)
        ];
        for (raw, expected) in cases {
            assert_eq!(canonical_uri(raw, false, true), *expected);
        }
    }
}
