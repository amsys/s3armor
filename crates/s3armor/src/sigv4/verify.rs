//! Inbound SigV4 verification: `Authorization` header and presigned query
//! auth — both are supported, since Nextcloud uses presigned URLs.

use std::collections::BTreeMap;
use std::time::SystemTime;

use percent_encoding::percent_decode_str;
use subtle::ConstantTimeEq;

use super::canonical;
use super::time::{date8, parse_amz_date, skew_seconds};
use crate::config::ClientCredentials;
#[cfg(test)]
use crate::config::DEFAULT_BACKEND_NAME;

const MAX_SKEW_SECS: u64 = 15 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub access_key: String,
    /// The backend `client`'s credentials resolved to
    /// (`ClientCredentials::backend`) — never empty, `Config::load`
    /// validates every client names a configured backend.
    pub backend: String,
    /// Everything needed to seed a `chunked::ChunkVerifier` for the
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` body scheme: the client's
    /// derived signing key, the request's own computed signature (the
    /// chain's seed), the `X-Amz-Date` value, and the credential scope.
    /// Always populated — building it is nearly free compared to the HMAC
    /// chain itself, and every caller of `verify()` either uses it or
    /// drops it.
    pub chunk_seed: ChunkSeed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkSeed {
    pub signing_key: [u8; 32],
    pub seed_signature: String,
    pub amz_date: String,
    pub credential_scope: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("no Authorization header and no presigned query auth")]
    NoAuth,
    #[error("malformed Authorization header")]
    MalformedAuthHeader,
    #[error("malformed presigned query parameters")]
    MalformedPresignedQuery,
    #[error("unknown access key")]
    UnknownAccessKey,
    #[error("SignedHeaders must be lowercase, unique, and include host (got: {0})")]
    BadSignedHeaders(String),
    #[error("missing required header: {0}")]
    MissingHeader(&'static str),
    #[error("timestamp is outside the +/-15 minute skew window")]
    ClockSkew,
    #[error("credential scope date does not match the request date")]
    DateMismatch,
    #[error("credential scope service must be s3")]
    BadScope,
    #[error("signature does not match")]
    BadSignature,
    #[error("presigned URL has expired")]
    Expired,
    #[error("invalid X-Amz-Expires value")]
    BadExpires,
    #[error("request has an x-amz-* header that is not in SignedHeaders: {0}")]
    UnsignedAmzHeader(String),
}

/// AWS requires every `x-amz-*` request header to appear in `SignedHeaders`.
/// `signed_names` is already lowercase (see [`validate_signed_headers`]), so
/// an unsigned `x-amz-*` header — e.g. an `x-amz-copy-source` added to a
/// presigned PUT that only signed `host` — is rejected instead of being
/// forwarded to the backend and re-signed with backend credentials.
fn unsigned_amz_header(headers: &[(String, String)], signed_names: &[String]) -> Option<String> {
    headers.iter().find_map(|(k, _)| {
        let lower = k.to_ascii_lowercase();
        (lower.starts_with("x-amz-") && !signed_names.iter().any(|s| s == &lower)).then_some(lower)
    })
}

/// `pub` (rather than the crate-internal default every other helper here
/// keeps) solely so `crates/s3armor/fuzz`'s `sigv4_parsers` target can drive it
/// directly from outside this crate, the same way it drives
/// `validate_signed_headers`/`parse_query_pairs` below — untrusted-input
/// parsers, fuzzed instead of widening `verify` itself, which needs a
/// whole `Config` (`docs/ARCHITECTURE.md` "Fuzz-target policy").
pub struct Credential {
    pub access_key: String,
    pub date8: String,
    pub region: String,
    pub service: String,
}

/// Parses `ACCESS/DATE/REGION/SERVICE/aws4_request`. `pub` — see
/// [`Credential`]'s doc comment.
pub fn parse_credential(s: &str) -> Option<Credential> {
    let mut parts = s.splitn(5, '/');
    let access_key = parts.next()?.to_string();
    let date8 = parts.next()?.to_string();
    let region = parts.next()?.to_string();
    let service = parts.next()?.to_string();
    let terminator = parts.next()?;
    if terminator != "aws4_request" || parts.next().is_some() {
        return None;
    }
    Some(Credential {
        access_key,
        date8,
        region,
        service,
    })
}

/// Lowercase, non-empty, unique, contains `host`. Order is *not* enforced —
/// unlike the AWS worked examples, real S3 clients vary on whether they
/// sort `SignedHeaders` before signing, and the value verified here is the
/// client's own signed order, mirrored back into the canonical request by
/// `canonical::canonical_headers_in_order` (see [`verify_header`] /
/// [`verify_presigned`]). An attacker cannot exploit reordering without
/// the secret key, since the `SignedHeaders` line itself is part of what
/// gets signed — so this is a spec-conformance relaxation, not a
/// signature-integrity one. `pub` — see [`Credential`]'s doc comment.
pub fn validate_signed_headers(raw: &str) -> Option<Vec<String>> {
    let names: Vec<&str> = raw.split(';').collect();
    if names.is_empty() || !names.contains(&"host") {
        return None;
    }
    if names
        .iter()
        .any(|n| n.is_empty() || n.to_ascii_lowercase() != *n)
    {
        return None;
    }
    let mut dedup_check = names.clone();
    dedup_check.sort_unstable();
    dedup_check.dedup();
    if dedup_check.len() != names.len() {
        return None; // duplicate header name
    }
    Some(names.iter().map(ToString::to_string).collect())
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// `pub` — see [`Credential`]'s doc comment.
pub fn parse_query_pairs(raw_query: &str) -> BTreeMap<String, String> {
    raw_query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let k = percent_decode_str(k).decode_utf8_lossy().into_owned();
            let v = percent_decode_str(v).decode_utf8_lossy().into_owned();
            (k, v)
        })
        .collect()
}

fn resolve_client<'a>(
    clients: &'a BTreeMap<String, ClientCredentials>,
    access_key: &str,
) -> Option<&'a ClientCredentials> {
    clients.values().find(|c| c.access_key == access_key)
}

fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Verifies a request's SigV4 authentication, header-based or presigned
/// query-based. `payload_hash` is the value to place in the canonical
/// request's trailing line — for header auth this is whatever
/// `x-amz-content-sha256` the client sent (or `UNSIGNED-PAYLOAD` if
/// absent); presigned S3 URLs carry no body, so callers pass
/// `"UNSIGNED-PAYLOAD"` for those.
pub fn verify(
    method: &str,
    raw_path: &str,
    raw_query: &str,
    headers: &[(String, String)],
    payload_hash: &str,
    clients: &BTreeMap<String, ClientCredentials>,
    now: SystemTime,
) -> Result<Identity, VerifyError> {
    let query = parse_query_pairs(raw_query);
    if query.contains_key("X-Amz-Signature") {
        verify_presigned(method, raw_path, raw_query, &query, headers, clients, now)
    } else if let Some(auth) = header_value(headers, "authorization") {
        verify_header(
            method,
            raw_path,
            raw_query,
            headers,
            auth,
            payload_hash,
            clients,
            now,
        )
    } else {
        Err(VerifyError::NoAuth)
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "mirrors sign.rs's authorization_header: every SigV4 canonicalization input (method, path, query, headers, the raw Authorization value, payload hash, credentials, clock) must be passed explicitly rather than bundled, so nothing here can drift from the exact request being verified"
)]
fn verify_header(
    method: &str,
    raw_path: &str,
    raw_query: &str,
    headers: &[(String, String)],
    auth: &str,
    payload_hash: &str,
    clients: &BTreeMap<String, ClientCredentials>,
    now: SystemTime,
) -> Result<Identity, VerifyError> {
    let rest = auth
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or(VerifyError::MalformedAuthHeader)?;

    let mut credential = None;
    let mut signed_headers_raw = None;
    let mut signature = None;
    // Split on a bare `,`, not `", "` — the AWS SDKs' own example always
    // has a space after the comma, but the spec never requires it, and at
    // least one real client (Stalwart) sends `Credential=...,SignedHeaders=...`
    // with none. Trimming both sides of `=` catches the same class of
    // whitespace variance if it ever shows up there too.
    for field in rest.split(',') {
        let (key, value) = field
            .split_once('=')
            .ok_or(VerifyError::MalformedAuthHeader)?;
        match key.trim() {
            "Credential" => credential = Some(value.trim()),
            "SignedHeaders" => signed_headers_raw = Some(value.trim()),
            "Signature" => signature = Some(value.trim()),
            _ => {}
        }
    }
    let credential = parse_credential(credential.ok_or(VerifyError::MalformedAuthHeader)?)
        .ok_or(VerifyError::MalformedAuthHeader)?;
    let signed_headers_raw = signed_headers_raw.ok_or(VerifyError::MalformedAuthHeader)?;
    let signature = signature.ok_or(VerifyError::MalformedAuthHeader)?;
    let signed_names = validate_signed_headers(signed_headers_raw)
        .ok_or_else(|| VerifyError::BadSignedHeaders(signed_headers_raw.to_string()))?;
    if let Some(name) = unsigned_amz_header(headers, &signed_names) {
        return Err(VerifyError::UnsignedAmzHeader(name));
    }

    if credential.service != "s3" {
        return Err(VerifyError::BadScope);
    }

    let amz_date =
        header_value(headers, "x-amz-date").ok_or(VerifyError::MissingHeader("x-amz-date"))?;
    let request_time = parse_amz_date(amz_date).ok_or(VerifyError::MissingHeader("x-amz-date"))?;
    if date8(amz_date) != credential.date8 {
        return Err(VerifyError::DateMismatch);
    }
    if skew_seconds(now, request_time) > MAX_SKEW_SECS {
        return Err(VerifyError::ClockSkew);
    }

    let client =
        resolve_client(clients, &credential.access_key).ok_or(VerifyError::UnknownAccessKey)?;

    let canonical_uri = canonical::canonical_uri(raw_path, false, true);
    let canonical_query = canonical::canonical_query(raw_query, &[]);
    let (headers_block, signed_headers_joined) =
        canonical::canonical_headers_in_order(headers, &signed_names);
    let cr = canonical::canonical_request(
        method,
        &canonical_uri,
        &canonical_query,
        &headers_block,
        &signed_headers_joined,
        payload_hash,
    );
    let scope = format!(
        "{}/{}/{}/aws4_request",
        credential.date8, credential.region, credential.service
    );
    let sts = canonical::string_to_sign(amz_date, &scope, &cr);
    let key = canonical::signing_key(
        &client.secret_key,
        &credential.date8,
        &credential.region,
        &credential.service,
    );
    let expected = canonical::signature_hex(&key, &sts);

    if !constant_time_eq_hex(&expected, signature) {
        return Err(VerifyError::BadSignature);
    }
    Ok(Identity {
        access_key: credential.access_key,
        backend: client.backend.clone(),
        chunk_seed: ChunkSeed {
            signing_key: key,
            seed_signature: expected,
            amz_date: amz_date.to_string(),
            credential_scope: scope,
        },
    })
}

fn verify_presigned(
    method: &str,
    raw_path: &str,
    raw_query: &str,
    query: &BTreeMap<String, String>,
    headers: &[(String, String)],
    clients: &BTreeMap<String, ClientCredentials>,
    now: SystemTime,
) -> Result<Identity, VerifyError> {
    let algorithm = query
        .get("X-Amz-Algorithm")
        .ok_or(VerifyError::MalformedPresignedQuery)?;
    if algorithm != "AWS4-HMAC-SHA256" {
        return Err(VerifyError::MalformedPresignedQuery);
    }
    let credential = parse_credential(
        query
            .get("X-Amz-Credential")
            .ok_or(VerifyError::MalformedPresignedQuery)?,
    )
    .ok_or(VerifyError::MalformedPresignedQuery)?;
    let amz_date = query
        .get("X-Amz-Date")
        .ok_or(VerifyError::MalformedPresignedQuery)?;
    let signed_headers_raw = query
        .get("X-Amz-SignedHeaders")
        .ok_or(VerifyError::MalformedPresignedQuery)?;
    let signature = query
        .get("X-Amz-Signature")
        .ok_or(VerifyError::MalformedPresignedQuery)?;
    let expires: u64 = query
        .get("X-Amz-Expires")
        .ok_or(VerifyError::MalformedPresignedQuery)?
        .parse()
        .map_err(|_| VerifyError::BadExpires)?;
    // Real S3 caps a presigned URL at 7 days. An unbounded lifetime turns a
    // leaked URL (logs, referrers, history) into a near-permanent credential.
    if expires == 0 || expires > 604_800 {
        return Err(VerifyError::BadExpires);
    }

    let signed_names = validate_signed_headers(signed_headers_raw)
        .ok_or_else(|| VerifyError::BadSignedHeaders(signed_headers_raw.clone()))?;
    if let Some(name) = unsigned_amz_header(headers, &signed_names) {
        return Err(VerifyError::UnsignedAmzHeader(name));
    }
    if credential.service != "s3" {
        return Err(VerifyError::BadScope);
    }

    let request_time = parse_amz_date(amz_date).ok_or(VerifyError::MalformedPresignedQuery)?;
    if date8(amz_date) != credential.date8 {
        return Err(VerifyError::DateMismatch);
    }
    // A presigned URL issued in the future beyond the skew window is as
    // suspicious as an expired one. Check this first: `duration_since`
    // below only succeeds when `request_time <= now`, so a signed-skew
    // check placed after it would never run for a future-dated request.
    if request_time > now && skew_seconds(now, request_time) > MAX_SKEW_SECS {
        return Err(VerifyError::ClockSkew);
    }
    let age = now
        .duration_since(request_time)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs();
    if age > expires {
        return Err(VerifyError::Expired);
    }

    let client =
        resolve_client(clients, &credential.access_key).ok_or(VerifyError::UnknownAccessKey)?;

    let canonical_uri = canonical::canonical_uri(raw_path, false, true);
    let canonical_query = canonical::canonical_query(raw_query, &["X-Amz-Signature"]);
    let (headers_block, signed_headers_joined) =
        canonical::canonical_headers_in_order(headers, &signed_names);
    let cr = canonical::canonical_request(
        method,
        &canonical_uri,
        &canonical_query,
        &headers_block,
        &signed_headers_joined,
        "UNSIGNED-PAYLOAD",
    );
    let scope = format!(
        "{}/{}/{}/aws4_request",
        credential.date8, credential.region, credential.service
    );
    let sts = canonical::string_to_sign(amz_date, &scope, &cr);
    let key = canonical::signing_key(
        &client.secret_key,
        &credential.date8,
        &credential.region,
        &credential.service,
    );
    let expected = canonical::signature_hex(&key, &sts);

    if !constant_time_eq_hex(&expected, signature) {
        return Err(VerifyError::BadSignature);
    }
    Ok(Identity {
        access_key: credential.access_key,
        backend: client.backend.clone(),
        chunk_seed: ChunkSeed {
            signing_key: key,
            seed_signature: expected,
            amz_date: amz_date.clone(),
            credential_scope: scope,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn client_map() -> BTreeMap<String, ClientCredentials> {
        let mut m = BTreeMap::new();
        m.insert(
            "NEXTCLOUD".to_string(),
            ClientCredentials {
                access_key: "AKIDEXAMPLE".to_string(),
                secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
                backend: DEFAULT_BACKEND_NAME.to_string(),
            },
        );
        m
    }

    fn amz_now() -> SystemTime {
        parse_amz_date("20150830T123600Z").unwrap()
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "test helper that builds a real SigV4 signature to feed into verify_header's own test cases; it needs every canonicalization input as a separate argument for the same reason authorization_header does"
    )]
    fn sign_for_test(
        method: &str,
        path: &str,
        query: &str,
        headers: &[(String, String)],
        signed_names: &[String],
        payload_hash: &str,
        secret: &str,
        date8: &str,
        region: &str,
        service: &str,
        amz_date: &str,
    ) -> String {
        let uri = canonical::canonical_uri(path, false, true);
        let cq = canonical::canonical_query(query, &["X-Amz-Signature"]);
        let (block, signed) = canonical::canonical_headers_in_order(headers, signed_names);
        let cr = canonical::canonical_request(method, &uri, &cq, &block, &signed, payload_hash);
        let scope = format!("{date8}/{region}/{service}/aws4_request");
        let sts = canonical::string_to_sign(amz_date, &scope, &cr);
        let key = canonical::signing_key(secret, date8, region, service);
        canonical::signature_hex(&key, &sts)
    }

    #[test]
    fn header_auth_round_trips() {
        let headers = vec![
            ("Host".to_string(), "example.amazonaws.com".to_string()),
            ("X-Amz-Date".to_string(), "20150830T123600Z".to_string()),
        ];
        let sig = sign_for_test(
            "GET",
            "/",
            "",
            &headers,
            &["host".into(), "x-amz-date".into()],
            "UNSIGNED-PAYLOAD",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "s3",
            "20150830T123600Z",
        );
        let mut req_headers = headers;
        req_headers.push((
            "Authorization".to_string(),
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature={sig}"
            ),
        ));
        let id = verify(
            "GET",
            "/",
            "",
            &req_headers,
            "UNSIGNED-PAYLOAD",
            &client_map(),
            amz_now(),
        )
        .unwrap();
        assert_eq!(id.access_key, "AKIDEXAMPLE");
    }

    #[test]
    fn unsigned_amz_header_is_rejected() {
        // Sign only host;x-amz-date, then add an unsigned x-amz-copy-source
        // (the presigned-PUT-to-CopyObject escalation). Verification must
        // reject it rather than forward it to the backend re-signed.
        let headers = vec![
            ("Host".to_string(), "example.amazonaws.com".to_string()),
            ("X-Amz-Date".to_string(), "20150830T123600Z".to_string()),
        ];
        let sig = sign_for_test(
            "PUT",
            "/bucket/key",
            "",
            &headers,
            &["host".into(), "x-amz-date".into()],
            "UNSIGNED-PAYLOAD",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "s3",
            "20150830T123600Z",
        );
        let mut req_headers = headers;
        req_headers.push((
            "x-amz-copy-source".to_string(),
            "/other-bucket/secret".to_string(),
        ));
        req_headers.push((
            "Authorization".to_string(),
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature={sig}"
            ),
        ));
        let err = verify(
            "PUT",
            "/bucket/key",
            "",
            &req_headers,
            "UNSIGNED-PAYLOAD",
            &client_map(),
            amz_now(),
        )
        .unwrap_err();
        assert!(matches!(err, VerifyError::UnsignedAmzHeader(_)), "{err:?}");
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let headers = vec![
            ("Host".to_string(), "example.amazonaws.com".to_string()),
            ("X-Amz-Date".to_string(), "20150830T123600Z".to_string()),
            (
                "Authorization".to_string(),
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
        ];
        let err = verify(
            "GET",
            "/",
            "",
            &headers,
            "UNSIGNED-PAYLOAD",
            &client_map(),
            amz_now(),
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::BadSignature);
    }

    /// Regression test for the Stalwart PUT bug (`SIG-PROBLEM.md`): a
    /// client that signs `SignedHeaders` in insertion order rather than
    /// ASCII-sorted order must still verify, as long as the canonical
    /// request mirrors that same order — which is exactly what a client
    /// itself would have hashed.
    #[test]
    fn unsorted_signed_headers_round_trip_in_client_order() {
        let headers = vec![
            ("Host".to_string(), "example.amazonaws.com".to_string()),
            ("X-Amz-Date".to_string(), "20150830T123600Z".to_string()),
        ];
        let sig = sign_for_test(
            "GET",
            "/",
            "",
            &headers,
            &["x-amz-date".into(), "host".into()], // unsorted: not ASCII order
            "UNSIGNED-PAYLOAD",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "s3",
            "20150830T123600Z",
        );
        let mut req_headers = headers;
        req_headers.push((
            "Authorization".to_string(),
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, SignedHeaders=x-amz-date;host, Signature={sig}"
            ),
        ));
        let id = verify(
            "GET",
            "/",
            "",
            &req_headers,
            "UNSIGNED-PAYLOAD",
            &client_map(),
            amz_now(),
        )
        .unwrap();
        assert_eq!(id.access_key, "AKIDEXAMPLE");
    }

    #[test]
    fn signed_headers_invariants_still_enforced() {
        let cases = [
            ("host;host", "duplicate header name"),
            ("Host", "uppercase header name"),
            ("x-amz-date", "missing host"),
        ];
        for (signed_headers, label) in cases {
            let headers = vec![
                ("Host".to_string(), "example.amazonaws.com".to_string()),
                ("X-Amz-Date".to_string(), "20150830T123600Z".to_string()),
                (
                    "Authorization".to_string(),
                    format!(
                        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, SignedHeaders={signed_headers}, Signature=abc"
                    ),
                ),
            ];
            let err = verify(
                "GET",
                "/",
                "",
                &headers,
                "UNSIGNED-PAYLOAD",
                &client_map(),
                amz_now(),
            )
            .unwrap_err();
            assert!(
                matches!(err, VerifyError::BadSignedHeaders(_)),
                "{label}: expected BadSignedHeaders, got {err:?}"
            );
        }
    }

    #[test]
    fn clock_skew_beyond_15_minutes_rejected() {
        let headers = vec![
            ("Host".to_string(), "example.amazonaws.com".to_string()),
            ("X-Amz-Date".to_string(), "20150830T123600Z".to_string()),
            (
                "Authorization".to_string(),
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc".to_string(),
            ),
        ];
        let far_future = amz_now() + Duration::from_hours(1);
        let err = verify(
            "GET",
            "/",
            "",
            &headers,
            "UNSIGNED-PAYLOAD",
            &client_map(),
            far_future,
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::ClockSkew);
    }

    #[test]
    fn unknown_access_key_rejected() {
        let headers = vec![
            ("Host".to_string(), "example.amazonaws.com".to_string()),
            ("X-Amz-Date".to_string(), "20150830T123600Z".to_string()),
            (
                "Authorization".to_string(),
                "AWS4-HMAC-SHA256 Credential=NOBODY/20150830/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc".to_string(),
            ),
        ];
        let err = verify(
            "GET",
            "/",
            "",
            &headers,
            "UNSIGNED-PAYLOAD",
            &client_map(),
            amz_now(),
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::UnknownAccessKey);
    }

    #[test]
    fn presigned_round_trips() {
        let headers = vec![("Host".to_string(), "example.amazonaws.com".to_string())];
        let query_no_sig = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host";
        let sig = sign_for_test(
            "GET",
            "/obj",
            query_no_sig,
            &headers,
            &["host".into()],
            "UNSIGNED-PAYLOAD",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "s3",
            "20150830T123600Z",
        );
        let full_query = format!("{query_no_sig}&X-Amz-Signature={sig}");
        let id = verify(
            "GET",
            "/obj",
            &full_query,
            &headers,
            "UNSIGNED-PAYLOAD",
            &client_map(),
            amz_now(),
        )
        .unwrap();
        assert_eq!(id.access_key, "AKIDEXAMPLE");
    }

    #[test]
    fn expired_presigned_url_rejected() {
        let headers = vec![("Host".to_string(), "example.amazonaws.com".to_string())];
        let query_no_sig = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host";
        let sig = sign_for_test(
            "GET",
            "/obj",
            query_no_sig,
            &headers,
            &["host".into()],
            "UNSIGNED-PAYLOAD",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "s3",
            "20150830T123600Z",
        );
        let full_query = format!("{query_no_sig}&X-Amz-Signature={sig}");
        let later = amz_now() + Duration::from_mins(2);
        let err = verify(
            "GET",
            "/obj",
            &full_query,
            &headers,
            "UNSIGNED-PAYLOAD",
            &client_map(),
            later,
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::Expired);
    }

    #[test]
    fn presigned_url_slightly_in_the_future_is_accepted() {
        let headers = vec![("Host".to_string(), "example.amazonaws.com".to_string())];
        let query_no_sig = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host";
        let sig = sign_for_test(
            "GET",
            "/obj",
            query_no_sig,
            &headers,
            &["host".into()],
            "UNSIGNED-PAYLOAD",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "s3",
            "20150830T123600Z",
        );
        let full_query = format!("{query_no_sig}&X-Amz-Signature={sig}");
        // The client's clock runs a minute fast: `X-Amz-Date` is a minute
        // ahead of the proxy's `now`, well inside the +/-15 minute window.
        let earlier = amz_now() - Duration::from_mins(1);
        let id = verify(
            "GET",
            "/obj",
            &full_query,
            &headers,
            "UNSIGNED-PAYLOAD",
            &client_map(),
            earlier,
        )
        .unwrap();
        assert_eq!(id.access_key, "AKIDEXAMPLE");
    }

    #[test]
    fn presigned_url_far_in_the_future_rejected() {
        let headers = vec![("Host".to_string(), "example.amazonaws.com".to_string())];
        let query_no_sig = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host";
        let sig = sign_for_test(
            "GET",
            "/obj",
            query_no_sig,
            &headers,
            &["host".into()],
            "UNSIGNED-PAYLOAD",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "s3",
            "20150830T123600Z",
        );
        let full_query = format!("{query_no_sig}&X-Amz-Signature={sig}");
        let earlier = amz_now() - Duration::from_mins(30);
        let err = verify(
            "GET",
            "/obj",
            &full_query,
            &headers,
            "UNSIGNED-PAYLOAD",
            &client_map(),
            earlier,
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::ClockSkew);
    }

    #[test]
    fn no_auth_at_all_rejected() {
        let headers = vec![("Host".to_string(), "example.amazonaws.com".to_string())];
        let err = verify(
            "GET",
            "/",
            "",
            &headers,
            "UNSIGNED-PAYLOAD",
            &client_map(),
            amz_now(),
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::NoAuth);
    }
}
