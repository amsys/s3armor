//! Runs the vendored AWS SigV4 test suite
//! (`testdata/aws-sig-v4-test-suite/`, extracted from the `aws-sigv4` 1.5.1
//! crate tarball's `aws-signing-test-suite/v4/`) through `sigv4::canonical`
//! directly. See `docs/ARCHITECTURE.md` "Testing strategy": 40 cases, header and
//! query (presigned) variants.
//!
//! Each case's expected outputs come from the CRT reference implementation
//! (`aws-c-auth`), not from `aws-sigv4` — but a handful of representative
//! cases are cross-checked against `aws-sigv4` too, as the independent
//! oracle `canonical.rs`'s doc comment promises.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "test code: a failed assumption should abort the test; slices are byte-precise ASCII test fixtures"
)]

use std::fs;
use std::path::{Path, PathBuf};

use s3armor::sigv4::canonical;

const SUITE_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/aws-sig-v4-test-suite"
);

struct ParsedRequest {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: String,
}

/// Parses the suite's `request.txt`: an HTTP/1.1 request head (request
/// line + headers, each on its own line, `Name:Value` with no space
/// requirement) followed by a blank line and an optional body.
fn parse_request(text: &str) -> ParsedRequest {
    let mut lines = text.split('\n');
    let request_line = lines.next().expect("request.txt has a request line");
    // "METHOD SP request-target SP HTTP-version". `get-space-unnormalized`
    // deliberately puts a literal, unescaped space inside the target to
    // test that encoding path — so the target can't be found by splitting
    // on the first two spaces; take the method from the front and the
    // HTTP version from the back, and treat everything between as target.
    let request_line = request_line.trim_end_matches('\r');
    let method_end = request_line.find(' ').expect("request line has a method");
    let method = request_line[..method_end].to_string();
    let version_start = request_line
        .rfind(' ')
        .expect("request line has an HTTP version");
    let target = request_line[method_end + 1..version_start].to_string();
    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
    let (path, query) = (path.to_string(), query.to_string());

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body_lines = Vec::new();
    let mut in_body = false;
    for line in lines {
        let line = line.trim_end_matches('\r');
        if in_body {
            body_lines.push(line);
            continue;
        }
        if line.is_empty() {
            in_body = true;
            continue;
        }
        // Obsolete HTTP line folding (RFC 7230 §3.2.4): a line starting
        // with whitespace continues the previous header's value. Real
        // clients don't generate this and hyper won't hand it to the
        // production server, but the vendored `get-header-value-multiline`
        // case uses it, so the test parser needs to unfold it.
        if line.starts_with([' ', '\t']) {
            let last = headers
                .last_mut()
                .expect("continuation line with no preceding header");
            last.1.push(' ');
            last.1.push_str(line.trim());
            continue;
        }
        let (name, value) = line.split_once(':').expect("header line has a colon");
        headers.push((name.to_string(), value.to_string()));
    }
    // The suite's request.txt files end each header line with '\n' and use
    // a trailing blank body section even when there is no body; trim that.
    while body_lines.last().is_some_and(|l| l.is_empty()) {
        body_lines.pop();
    }
    ParsedRequest {
        method,
        path,
        query,
        headers,
        body: body_lines.join("\n"),
    }
}

#[derive(serde::Deserialize)]
struct Context {
    credentials: Credentials,
    region: String,
    service: String,
    timestamp: String,
    #[serde(default)]
    normalize: bool,
    #[serde(default)]
    sign_body: bool,
    #[serde(default)]
    omit_session_token: bool,
}

#[derive(serde::Deserialize)]
struct Credentials {
    access_key_id: String,
    secret_access_key: String,
    token: Option<String>,
}

/// `2015-08-30T12:36:00Z` -> `20150830T123600Z`.
fn amz_date_from_iso(iso: &str) -> String {
    let digits: String = iso.chars().filter(char::is_ascii_digit).collect();
    format!("{}T{}Z", &digits[0..8], &digits[8..14])
}

/// Reproduces the request-building synthesis the reference suite's
/// generator performs before signing: an `X-Amz-Date` header is always
/// added, `X-Amz-Content-Sha256` is added iff `sign_body`, and
/// `X-Amz-Security-Token` is added iff a session token is present and not
/// omitted. Confirmed against `post-vanilla` (neither flag: signed headers
/// = `host;x-amz-date`), `post-x-www-form-urlencoded` (`sign_body`: adds
/// `x-amz-content-sha256`), and `post-sts-header-before` (token: adds
/// `x-amz-security-token`).
fn synthesize_header_variant(
    req: &ParsedRequest,
    ctx: &Context,
    amz_date: &str,
) -> Vec<(String, String)> {
    let mut headers = req.headers.clone();
    headers.push(("X-Amz-Date".to_string(), amz_date.to_string()));
    if ctx.sign_body {
        headers.push((
            "X-Amz-Content-Sha256".to_string(),
            canonical::hex_sha256(req.body.as_bytes()),
        ));
    }
    if let (Some(token), false) = (&ctx.credentials.token, ctx.omit_session_token) {
        headers.push(("X-Amz-Security-Token".to_string(), token.clone()));
    }
    headers
}

fn signed_names_from(headers: &[(String, String)]) -> Vec<String> {
    let mut names: Vec<String> = headers
        .iter()
        .map(|(k, _)| k.to_ascii_lowercase())
        .collect();
    names.sort();
    names.dedup();
    names
}

fn payload_hash_for(req: &ParsedRequest, ctx: &Context) -> String {
    if ctx.sign_body {
        canonical::hex_sha256(req.body.as_bytes())
    } else {
        canonical::hex_sha256(b"")
    }
}

fn read_case(dir: &Path) -> (ParsedRequest, Option<Context>) {
    let req = parse_request(&fs::read_to_string(dir.join("request.txt")).unwrap());
    let ctx = fs::read_to_string(dir.join("context.json"))
        .ok()
        .map(|s| serde_json::from_str(&s).unwrap());
    (req, ctx)
}

fn assert_case_file(dir: &Path, name: &str, actual: &str) {
    let path = dir.join(name);
    let Ok(expected) = fs::read_to_string(&path) else {
        return; // not every case has every file (e.g. no query-* for legacy cases)
    };
    assert_eq!(
        actual,
        expected.as_str(),
        "{} mismatch in {}",
        name,
        dir.display()
    );
}

/// Runs the header-auth (`Authorization` header) variant of one case.
fn run_header_variant(dir: &Path) {
    let (req, ctx) = read_case(dir);
    let Some(ctx) = ctx else {
        return; // legacy double-encode-* cases handled separately
    };
    let amz_date = amz_date_from_iso(&ctx.timestamp);
    let headers = synthesize_header_variant(&req, &ctx, &amz_date);
    let signed_names = signed_names_from(&headers);
    let payload_hash = payload_hash_for(&req, &ctx);

    let uri = canonical::canonical_uri(&req.path, ctx.normalize, true);
    let query = canonical::canonical_query(&req.query, &[]);
    let (block, signed) = canonical::canonical_headers(&headers, &signed_names);
    let cr =
        canonical::canonical_request(&req.method, &uri, &query, &block, &signed, &payload_hash);
    assert_case_file(dir, "header-canonical-request.txt", &cr);

    let scope = format!(
        "{}/{}/{}/aws4_request",
        &amz_date[..8],
        ctx.region,
        ctx.service
    );
    let sts = canonical::string_to_sign(&amz_date, &scope, &cr);
    assert_case_file(dir, "header-string-to-sign.txt", &sts);

    let key = canonical::signing_key(
        &ctx.credentials.secret_access_key,
        &amz_date[..8],
        &ctx.region,
        &ctx.service,
    );
    let sig = canonical::signature_hex(&key, &sts);
    if let Ok(expected) = fs::read_to_string(dir.join("header-signature.txt")) {
        assert_eq!(
            sig,
            expected.trim(),
            "signature mismatch in {}",
            dir.display()
        );
    }
    let _ = ctx.credentials.access_key_id; // used only to build Authorization in a live request
}

/// Runs the presigned-query variant of one case (only present for cases
/// with a `context.json`; the two legacy double-encode cases have none).
fn run_query_variant(dir: &Path) {
    let (req, ctx) = read_case(dir);
    let Some(ctx) = ctx else { return };
    if !dir.join("query-canonical-request.txt").exists() {
        return;
    }
    let amz_date = amz_date_from_iso(&ctx.timestamp);
    let scope = format!(
        "{}/{}/{}/aws4_request",
        &amz_date[..8],
        ctx.region,
        ctx.service
    );

    let mut signing_params = vec![
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        (
            "X-Amz-Credential".to_string(),
            format!("{}/{}", ctx.credentials.access_key_id, scope),
        ),
        ("X-Amz-Date".to_string(), amz_date.clone()),
        ("X-Amz-Expires".to_string(), ctx_expires(dir).to_string()),
    ];
    let signed_names = signed_names_from(&req.headers);
    signing_params.push(("X-Amz-SignedHeaders".to_string(), signed_names.join(";")));
    if let (Some(token), false) = (&ctx.credentials.token, ctx.omit_session_token) {
        signing_params.push(("X-Amz-Security-Token".to_string(), token.clone()));
    }

    let mut full_query = req.query.clone();
    for (k, v) in &signing_params {
        if !full_query.is_empty() {
            full_query.push('&');
        }
        full_query.push_str(
            &percent_encoding::utf8_percent_encode(k, percent_encoding::NON_ALPHANUMERIC)
                .to_string(),
        );
        full_query.push('=');
        full_query.push_str(
            &percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)
                .to_string(),
        );
    }

    let payload_hash = payload_hash_for(&req, &ctx);
    let uri = canonical::canonical_uri(&req.path, ctx.normalize, true);
    let query = canonical::canonical_query(&full_query, &["X-Amz-Signature"]);
    let (block, signed) = canonical::canonical_headers(&req.headers, &signed_names);
    let cr =
        canonical::canonical_request(&req.method, &uri, &query, &block, &signed, &payload_hash);
    assert_case_file(dir, "query-canonical-request.txt", &cr);

    let sts = canonical::string_to_sign(&amz_date, &scope, &cr);
    assert_case_file(dir, "query-string-to-sign.txt", &sts);

    let key = canonical::signing_key(
        &ctx.credentials.secret_access_key,
        &amz_date[..8],
        &ctx.region,
        &ctx.service,
    );
    let sig = canonical::signature_hex(&key, &sts);
    if let Ok(expected) = fs::read_to_string(dir.join("query-signature.txt")) {
        assert_eq!(
            sig,
            expected.trim(),
            "presigned signature mismatch in {}",
            dir.display()
        );
    }
}

fn ctx_expires(dir: &Path) -> u64 {
    let raw = fs::read_to_string(dir.join("context.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    v["expiration_in_seconds"].as_u64().unwrap_or(3600)
}

fn all_case_dirs() -> Vec<PathBuf> {
    fs::read_dir(SUITE_ROOT)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect()
}

#[test]
fn header_variant_matches_every_vendored_case() {
    let dirs = all_case_dirs();
    assert!(
        dirs.len() >= 30,
        "expected the full vendored suite, found {}",
        dirs.len()
    );
    for dir in &dirs {
        run_header_variant(dir);
    }
}

#[test]
fn query_variant_matches_every_vendored_case_that_has_one() {
    for dir in all_case_dirs() {
        run_query_variant(&dir);
    }
}

/// The two legacy cases test the *non-S3* profile: double percent-encoding
/// of an already-encoded path (`decode_existing = false`), fixed classic
/// test credentials, no `context.json`. Production S3 traffic never uses
/// this mode; these exist so `canonical_uri`'s `decode_existing` flag is
/// exercised against a real reference vector, not just the hand-written
/// unit test in `canonical.rs`.
#[test]
fn double_encode_mode_matches_both_legacy_vendored_canonical_uris() {
    // These two have no context.json (the README: "migrated from the old
    // format" specifically to test double-encoding). Only the canonical
    // URI line (line 2) is asserted: `double-encode-path`'s own
    // request.txt carries `X-amz-date:20150830T123600Z`, but that case's
    // header-canonical-request.txt was generated against
    // `20210511T154045Z` — a self-inconsistency in the fixture itself
    // (this pair is reused across the CRT suite's other timestamp/header
    // tests, per its README note, and this checked-in request.txt is not
    // 1:1 with this one derived-output file). The property these two
    // cases actually exist to pin down — double percent-encoding of an
    // already-encoded path — lives entirely in that one line.
    for name in ["double-encode-path", "double-url-encode"] {
        let dir = Path::new(SUITE_ROOT).join(name);
        let req = parse_request(&fs::read_to_string(dir.join("request.txt")).unwrap());
        let uri = canonical::canonical_uri(&req.path, false, false);
        let expected = fs::read_to_string(dir.join("header-canonical-request.txt")).unwrap();
        let expected_uri = expected.lines().nth(1).unwrap();
        assert_eq!(
            uri,
            expected_uri,
            "canonical URI mismatch in {}",
            dir.display()
        );
    }
}

/// Cross-checks the HMAC signing-key chain against `aws-sigv4`'s own
/// `generate_signing_key`/`calculate_signature` primitives — the
/// independent oracle `canonical.rs`'s doc comment promises in exchange for
/// not shipping that crate at runtime. (Canonicalization itself is already
/// checked far more strongly above, against the 40 vendored CRT-derived
/// vectors; this test isolates just the signing-key math using a different
/// implementation of the same AWS4-HMAC-SHA256 chain.)
#[test]
fn signing_key_chain_matches_aws_sigv4_oracle() {
    use aws_sigv4::sign::v4::{calculate_signature, generate_signing_key};

    for (secret, date8, region, service) in [
        (
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "service",
        ),
        (
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "s3",
        ),
        ("anothersecretkey", "20260101", "eu-central-1", "s3"),
    ] {
        let time = s3armor::sigv4::time::parse_amz_date(&format!("{date8}T000000Z")).unwrap();
        let string_to_sign = "AWS4-HMAC-SHA256\nsome-request-hash-placeholder";

        let ours_key = canonical::signing_key(secret, date8, region, service);
        let ours_sig = canonical::signature_hex(&ours_key, string_to_sign);

        let oracle_key = generate_signing_key(secret, time, region, service);
        let oracle_sig = calculate_signature(oracle_key, string_to_sign.as_bytes());

        assert_eq!(
            ours_sig, oracle_sig,
            "signing key chain diverges for {region}/{service}/{date8}"
        );
    }
}
