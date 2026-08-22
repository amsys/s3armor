//! Fuzz target: footer trailer parse and footer decode must never panic on
//! arbitrary bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use s3armor_format::v1::{Alg, Footer};

fuzz_target!(|data: &[u8]| {
    let key = [0x5Bu8; 32];
    if data.len() >= 16 {
        let trailer = &data[data.len() - 16..];
        if let Ok(footer_len) = Footer::parse_trailer(trailer) {
            let body = &data[..data.len() - 16];
            if (footer_len as usize) <= body.len() {
                let frame = &body[body.len() - footer_len as usize..];
                let _ = Footer::open(Alg::Aes256Gcm, &key, frame);
            }
        }
    }
    // Also feed the whole input directly as a candidate frame, independent
    // of trailer parsing.
    let _ = Footer::open(Alg::Aes256Gcm, &key, data);
});
