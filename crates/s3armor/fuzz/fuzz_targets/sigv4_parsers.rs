//! Fuzz target: the three small SigV4 string parsers that run on
//! attacker-controlled input before any signature is checked —
//! `Authorization`'s `Credential=`, `SignedHeaders=`, and a request's raw
//! query string. Widening `sigv4::verify::verify` itself would need a
//! whole `Config`; these are the parsers that actually see untrusted bytes
//! first (`docs/ARCHITECTURE.md` "Fuzz-target policy").

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use s3armor::sigv4::verify::{parse_credential, parse_query_pairs, validate_signed_headers};

#[derive(Arbitrary, Debug)]
struct Input {
    credential: String,
    signed_headers: String,
    raw_query: String,
}

fuzz_target!(|input: Input| {
    let _ = parse_credential(&input.credential);
    let _ = validate_signed_headers(&input.signed_headers);
    let _ = parse_query_pairs(&input.raw_query);
});
