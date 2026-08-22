//! Fuzz target: the aws-chunked decoder (`Dechunker`) must never panic on
//! arbitrary bytes fed in arbitrary splits — a real TCP stream hands it
//! whatever the kernel buffered between reads, not chunk-boundary-aligned
//! pieces. Untrusted client input, `docs/ARCHITECTURE.md` "Fuzz-target policy".

#![no_main]

use libfuzzer_sys::fuzz_target;
use s3armor::chunked::Dechunker;

fuzz_target!(|feeds: Vec<Vec<u8>>| {
    let mut d = Dechunker::new();
    for feed in &feeds {
        match d.feed(feed) {
            Ok(_) => {}
            Err(_) => break, // a decode error is a fine outcome; a panic is not
        }
    }
    // No production caller reads trailers today (checksum trailers are
    // stripped, not validated — docs/ARCHITECTURE.md "S3 operation matrix (v1)") but the method is `pub`
    // API of a type built from untrusted bytes, so it stays in scope here.
    let _ = d.trailers();
});
