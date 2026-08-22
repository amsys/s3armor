//! Fuzz target: the v1 frame decoder must never panic on arbitrary bytes,
//! for any combination of AAD inputs and frame content.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use s3armor_format::v1::{open_frame, Alg};

#[derive(Arbitrary, Debug)]
struct Input {
    use_xchacha: bool,
    part_number: u32,
    chunk_index: u64,
    last: bool,
    frame: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let alg = if input.use_xchacha {
        Alg::XChaCha20Poly1305
    } else {
        Alg::Aes256Gcm
    };
    let key = [0x5Au8; 32];
    let _ = open_frame(alg, &key, input.part_number, input.chunk_index, input.last, &input.frame);
});
