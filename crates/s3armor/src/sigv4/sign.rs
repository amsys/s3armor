//! Outbound re-signing: builds the `Authorization` header the proxy sends
//! to the backend, using the backend's own credentials. Always S3
//! (`disableDoubleEncoding`, no path normalization) via the shared
//! [`canonical`] module — see that module's doc comment for why this isn't
//! a second, `aws-sigv4`-based implementation.

use super::canonical;

/// Builds the `Authorization` header value for a request about to be sent
/// to the backend. `headers` and `signed_header_names` must reflect the
/// request exactly as it will be sent — a signed-header set that omits a
/// header the client actually receives (or vice versa) produces a
/// signature the backend rejects. Building the final header set first and
/// signing that removes the possibility of the two drifting apart.
#[expect(
    clippy::too_many_arguments,
    reason = "every SigV4 canonicalization input (method, path, query, headers, signed-header names, payload hash, credentials) must be passed explicitly, or the exact request that gets signed drifts from the exact request that gets sent — the bug class this function exists to close"
)]
pub fn authorization_header(
    method: &str,
    raw_path: &str,
    raw_query: &str,
    headers: &[(String, String)],
    signed_header_names: &[String],
    payload_hash: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    amz_date: &str,
) -> String {
    let canonical_uri = canonical::canonical_uri(raw_path, false, true);
    let canonical_query = canonical::canonical_query(raw_query, &[]);
    let (headers_block, signed_headers) =
        canonical::canonical_headers(headers, signed_header_names);
    let cr = canonical::canonical_request(
        method,
        &canonical_uri,
        &canonical_query,
        &headers_block,
        &signed_headers,
        payload_hash,
    );
    let date8 = super::time::date8(amz_date);
    let scope = format!("{date8}/{region}/{service}/aws4_request");
    let sts = canonical::string_to_sign(amz_date, &scope, &cr);
    let key = canonical::signing_key(secret_key, date8, region, service);
    let signature = canonical::signature_hex(&key, &sts);

    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_aws_worked_example() {
        let headers = vec![
            ("Host".to_string(), "example.amazonaws.com".to_string()),
            ("X-Amz-Date".to_string(), "20150830T123600Z".to_string()),
        ];
        let auth = authorization_header(
            "GET",
            "/",
            "",
            &headers,
            &["host".into(), "x-amz-date".into()],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "service",
            "20150830T123600Z",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }
}
