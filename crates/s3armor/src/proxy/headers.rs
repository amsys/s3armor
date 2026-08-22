//! Header handling shared by the request-rewrite path: converting an
//! `http::HeaderMap` to the `Vec<(String, String)>` the SigV4 canonicalizer
//! wants, and the strip/rewrite rules from `docs/ARCHITECTURE.md`
//! "Architecture: re-signing streaming reverse proxy" (the "verify first,
//! strip second" ordering — the client's signature covers `Content-MD5`
//! and the checksum headers, so removing them before verification would
//! invalidate it).

use http::HeaderMap;

/// Headers stripped before forwarding to the backend: auth (the proxy
/// re-signs with its own credentials), checksum headers that no longer
/// match ciphertext, and hop-by-hop headers (RFC 7230 §6.1) that must never
/// be forwarded by an intermediary.
const STRIP_ALWAYS: &[&str] = &[
    "authorization",
    "content-md5",
    "x-amz-sdk-checksum-algorithm",
    // The plain (no "sdk") spelling: aws-cli's `CreateMultipartUpload`
    // sends this to declare the whole upload's checksum algorithm — found
    // running crypto-check.sh's real-aws-cli multipart smoke test.
    // Left unstripped, the backend remembers the declared algorithm and
    // then rejects every `UploadPart` for having no checksum, since this
    // proxy also strips the per-part `x-amz-checksum-*` value header (it
    // describes ciphertext, not what the backend actually receives).
    "x-amz-checksum-algorithm",
    "expect",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
];

const fn is_checksum_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("x-amz-checksum-crc32")
        || name.eq_ignore_ascii_case("x-amz-checksum-crc32c")
        || name.eq_ignore_ascii_case("x-amz-checksum-crc64nvme")
        || name.eq_ignore_ascii_case("x-amz-checksum-sha1")
        || name.eq_ignore_ascii_case("x-amz-checksum-sha256")
}

/// Converts an `http::HeaderMap` to the ordered pair list the SigV4
/// canonicalizer and outbound builder both use. Non-UTF-8 header values are
/// lossily converted — S3 metadata and control headers are ASCII in
/// practice, and a byte that fails this conversion will also fail
/// canonicalization identically on both the verify and sign sides.
pub fn to_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// Removes headers that must never reach the backend as the client sent
/// them. Call this *after* SigV4 verification — see the module doc comment.
pub fn strip_for_backend(headers: &mut Vec<(String, String)>) {
    headers.retain(|(name, _)| {
        !STRIP_ALWAYS.iter().any(|s| name.eq_ignore_ascii_case(s)) && !is_checksum_header(name)
    });
}

/// Removes only the `aws-chunked` token from a `Content-Encoding` value
/// (which may be combined, e.g. `aws-chunked,gzip`), dropping the header
/// entirely when nothing is left. Returns `None` when the header should be
/// removed, `Some(new_value)` otherwise.
pub fn strip_aws_chunked_token(content_encoding: &str) -> Option<String> {
    let remaining: Vec<&str> = content_encoding
        .split(',')
        .map(str::trim)
        .filter(|tok| !tok.eq_ignore_ascii_case("aws-chunked") && !tok.is_empty())
        .collect();
    if remaining.is_empty() {
        None
    } else {
        Some(remaining.join(","))
    }
}

/// Whether an `x-amz-meta-*` header name is one of this crate's own
/// bookkeeping keys — v1's fixed `s3a-` prefix. Shared by
/// [`strip_s3armor_metadata`] and `tools::rewrap`, so both agree on exactly
/// what "our own metadata" means.
pub fn is_own_metadata_header(header_name: &str) -> bool {
    let lower = header_name.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("x-amz-meta-") else {
        return false;
    };
    rest.starts_with("s3a-")
}

/// Removes every `x-amz-meta-s3a-*` header (the crate's own v1 bookkeeping
/// keys, `docs/ARCHITECTURE.md` "Object metadata v1") and every
/// `x-amz-checksum-*` header from a response whose body this proxy has
/// decrypted.
///
/// The checksum headers matter for a reason distinct from the metadata
/// keys: they describe the backend's **stored ciphertext**, not the
/// plaintext this response actually carries. A checksum-validating SDK —
/// the modern default for `PutObject`/`GetObject` — computes its own
/// checksum over what it received and rejects the response on a mismatch,
/// so a decrypted GET response carrying its ciphertext's checksum header
/// fails client-side even though nothing is actually wrong. Found while
/// building the integration tests, seeding objects that carried a
/// checksum from an unrelated direct `PutObject`.
pub fn strip_s3armor_metadata(headers: &mut HeaderMap) {
    let doomed: Vec<http::HeaderName> = headers
        .iter()
        .filter(|(k, _)| is_own_metadata_header(k.as_str()) || is_checksum_header(k.as_str()))
        .map(|(k, _)| k.clone())
        .collect();
    for name in doomed {
        headers.remove(name);
    }
}

/// Presigned-auth query parameters, stripped before the request is
/// forwarded (the backend gets its own fresh signature).
pub const PRESIGNED_QUERY_PARAMS: &[&str] = &[
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-SignedHeaders",
    "X-Amz-Signature",
    "X-Amz-Security-Token",
];

/// Drops query parameters whose (percent-decoded) key is in `drop_keys`,
/// preserving the raw encoding of everything else and its original order —
/// sub-resource query flags like `?acl` are order- and case-sensitive
/// enough on some backends that a decode/re-encode round trip is not worth
/// the risk here, unlike the SigV4 canonical query string.
pub fn filter_query(raw_query: &str, drop_keys: &[&str]) -> String {
    raw_query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter(|pair| {
            let key = pair.split('=').next().unwrap_or("");
            let decoded = percent_encoding::percent_decode_str(key).decode_utf8_lossy();
            !drop_keys.iter().any(|d| d.eq_ignore_ascii_case(&decoded))
        })
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_auth_and_checksum_and_hop_by_hop() {
        let mut headers = vec![
            ("Authorization".to_string(), "AWS4-...".to_string()),
            ("Content-MD5".to_string(), "abc".to_string()),
            ("x-amz-checksum-crc32".to_string(), "AAAA".to_string()),
            // aws-cli's CreateMultipartUpload declares the whole upload's
            // algorithm this way — must be stripped too, or the backend
            // expects a checksum every UploadPart never carries.
            (
                "x-amz-checksum-algorithm".to_string(),
                "CRC64NVME".to_string(),
            ),
            ("Connection".to_string(), "keep-alive".to_string()),
            ("Host".to_string(), "example.com".to_string()),
            ("Content-Type".to_string(), "text/plain".to_string()),
        ];
        strip_for_backend(&mut headers);
        let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["Host", "Content-Type"]);
    }

    #[test]
    fn strips_only_the_aws_chunked_token() {
        assert_eq!(
            strip_aws_chunked_token("aws-chunked,gzip"),
            Some("gzip".to_string())
        );
        assert_eq!(
            strip_aws_chunked_token("gzip,aws-chunked"),
            Some("gzip".to_string())
        );
        assert_eq!(strip_aws_chunked_token("aws-chunked"), None);
    }

    #[test]
    fn strip_s3armor_metadata_drops_only_s3armor_keys() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-meta-s3a-v", "1".parse().unwrap());
        headers.insert("x-amz-meta-s3a-kid", "abc".parse().unwrap());
        headers.insert("x-amz-meta-app-id", "42".parse().unwrap());
        headers.insert("content-type", "text/plain".parse().unwrap());
        strip_s3armor_metadata(&mut headers);
        assert!(headers.get("x-amz-meta-s3a-v").is_none());
        assert!(headers.get("x-amz-meta-s3a-kid").is_none());
        assert!(headers.get("x-amz-meta-app-id").is_some());
        assert!(headers.get("content-type").is_some());
    }

    #[test]
    fn filter_query_drops_only_named_keys() {
        assert_eq!(
            filter_query(
                "X-Amz-Signature=abc&prefix=foo&X-Amz-Date=x",
                PRESIGNED_QUERY_PARAMS
            ),
            "prefix=foo"
        );
        assert_eq!(filter_query("acl", &[]), "acl");
    }
}
