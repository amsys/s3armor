//! Multipart layout: footer invariants, part_layout/plan_multipart_range
//! math, and the corruption cases specific to a multi-part object (part
//! swap, part truncation). See docs/ARCHITECTURE.md "Multipart v1".

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "test code: a failed assumption should abort the test"
)]

use s3armor_format::v1::{
    decrypt_all, encrypt_all, n_chunks, part_layout, plan_multipart_range, Alg, Decryptor, Footer,
};

const KEY: [u8; 32] = [0x22; 32];
const CHUNK: usize = 16;

/// One encrypted test part: its client part number, plaintext, and the
/// sealed ciphertext produced under that part number.
type TestPart = (u32, Vec<u8>, Vec<u8>);

/// Encrypt three parts with non-contiguous client part numbers (1, 5, 9),
/// each under its own part number in the AAD, and return the parts plus
/// the concatenated object bytes.
fn build_object() -> (Vec<TestPart>, Vec<u8>) {
    let plaintexts: [&[u8]; 3] = [
        b"first part, short",
        b"second part is a good bit longer than one chunk so it spans several frames",
        b"", // a legal, empty final part
    ];
    let numbers = [1u32, 5, 9];
    let parts: Vec<TestPart> = numbers
        .iter()
        .zip(plaintexts.iter())
        .map(|(&n, &pt)| {
            let ct = encrypt_all(Alg::Aes256Gcm, &KEY, n, CHUNK, pt);
            (n, pt.to_vec(), ct)
        })
        .collect();
    let object: Vec<u8> = parts.iter().flat_map(|(_, _, ct)| ct.clone()).collect();
    (parts, object)
}

#[test]
fn footer_round_trip_with_noncontiguous_part_numbers() {
    let (parts, _) = build_object();
    let entries: Vec<(u32, u64)> = parts
        .iter()
        .map(|(n, pt, _)| (*n, pt.len() as u64))
        .collect();
    let total_pt: u64 = parts.iter().map(|(_, pt, _)| pt.len() as u64).sum();
    let footer = Footer {
        alg: Alg::Aes256Gcm,
        parts: entries.clone(),
        total_pt,
        md5: None,
    };
    let sealed = footer.seal(&KEY);
    let footer_len = Footer::parse_trailer(&sealed[sealed.len() - 16..]).unwrap() as usize;
    let frame = &sealed[sealed.len() - 16 - footer_len..sealed.len() - 16];
    let decoded = Footer::open(Alg::Aes256Gcm, &KEY, frame).unwrap();
    assert_eq!(decoded.parts, entries);
    assert_eq!(decoded.total_pt, total_pt);
}

#[test]
fn footer_total_pt_mismatch_is_rejected() {
    let footer = Footer {
        alg: Alg::Aes256Gcm,
        parts: vec![(1, 10), (2, 20)],
        total_pt: 999, // wrong: should be 30
        md5: None,
    };
    let sealed = footer.seal(&KEY);
    let footer_len = Footer::parse_trailer(&sealed[sealed.len() - 16..]).unwrap() as usize;
    let frame = &sealed[sealed.len() - 16 - footer_len..sealed.len() - 16];
    assert!(Footer::open(Alg::Aes256Gcm, &KEY, frame).is_err());
}

#[test]
fn footer_out_of_order_part_numbers_are_rejected() {
    let footer = Footer {
        alg: Alg::Aes256Gcm,
        parts: vec![(5, 10), (1, 10)], // descending — not the upload order
        total_pt: 20,
        md5: None,
    };
    let sealed = footer.seal(&KEY);
    let footer_len = Footer::parse_trailer(&sealed[sealed.len() - 16..]).unwrap() as usize;
    let frame = &sealed[sealed.len() - 16 - footer_len..sealed.len() - 16];
    assert!(Footer::open(Alg::Aes256Gcm, &KEY, frame).is_err());
}

#[test]
fn part_layout_offsets_are_cumulative() {
    let (parts, _) = build_object();
    let entries: Vec<(u32, u64)> = parts
        .iter()
        .map(|(n, pt, _)| (*n, pt.len() as u64))
        .collect();
    let spans = part_layout(Alg::Aes256Gcm, CHUNK as u64, &entries);
    assert_eq!(spans.len(), 3);
    let mut pt_off = 0u64;
    let mut ct_off = 0u64;
    for (span, (_, _, ct)) in spans.iter().zip(parts.iter()) {
        assert_eq!(span.pt_start, pt_off);
        assert_eq!(span.ct_start, ct_off);
        assert_eq!(span.ct_len, ct.len() as u64);
        pt_off += span.pt_len;
        ct_off += span.ct_len;
    }
}

/// A range that spans a part boundary decrypts to exactly the same bytes
/// as slicing the full concatenated plaintext.
#[test]
fn plan_multipart_range_matches_full_decrypt_slice() {
    let (parts, _) = build_object();
    let entries: Vec<(u32, u64)> = parts
        .iter()
        .map(|(n, pt, _)| (*n, pt.len() as u64))
        .collect();
    let full_plaintext: Vec<u8> = parts.iter().flat_map(|(_, pt, _)| pt.clone()).collect();
    let spans = part_layout(Alg::Aes256Gcm, CHUNK as u64, &entries);

    // Range starting inside part 1 (index 0) and ending inside part 5 (index 1).
    let start = 5u64;
    let end = (parts[0].1.len() + 10) as u64;
    let plan = plan_multipart_range(&spans, Alg::Aes256Gcm, CHUNK as u64, start, end).unwrap();
    assert_eq!(plan.len(), 2, "range should touch exactly two parts");

    let mut got = Vec::new();
    for (span, range_plan) in &plan {
        let ct = &parts.iter().find(|(n, _, _)| *n == span.number).unwrap().2
            [range_plan.ct_start as usize..range_plan.ct_end as usize];
        let total_chunks = n_chunks(span.pt_len, CHUNK as u64);
        let final_frame_is_object_end = range_plan.last_chunk + 1 == total_chunks;
        let mut d = Decryptor::new_at(
            Alg::Aes256Gcm,
            KEY,
            span.number,
            CHUNK,
            range_plan.first_chunk,
            final_frame_is_object_end,
        );
        let mut decrypted = d.push(ct).unwrap();
        decrypted.extend(d.finish().unwrap());
        let last_chunk_pt_len =
            decrypted.len() - (range_plan.last_chunk - range_plan.first_chunk) as usize * CHUNK;
        let end_pos = decrypted.len() - last_chunk_pt_len + range_plan.trim_end;
        got.extend_from_slice(&decrypted[range_plan.trim_start..end_pos]);
    }
    assert_eq!(got, full_plaintext[start as usize..end as usize]);
}

#[test]
fn plan_multipart_range_rejects_out_of_bounds() {
    let (parts, _) = build_object();
    let entries: Vec<(u32, u64)> = parts
        .iter()
        .map(|(n, pt, _)| (*n, pt.len() as u64))
        .collect();
    let spans = part_layout(Alg::Aes256Gcm, CHUNK as u64, &entries);
    let total_pt: u64 = parts.iter().map(|(_, pt, _)| pt.len() as u64).sum();
    assert!(plan_multipart_range(&spans, Alg::Aes256Gcm, CHUNK as u64, 0, total_pt + 1).is_err());
}

// --- corruption: multipart-specific classes ------------------------------

/// Swapping the ciphertext of two equal-length parts must fail
/// authentication: the AAD binds each frame to its own part number, so a
/// part decrypted under the wrong part's ciphertext cannot verify.
#[test]
fn part_ciphertext_swap_fails() {
    let a = encrypt_all(Alg::Aes256Gcm, &KEY, 1, CHUNK, b"part one is here");
    let b = encrypt_all(Alg::Aes256Gcm, &KEY, 2, CHUNK, b"part two is here");
    assert_eq!(a.len(), b.len(), "test needs equal-length parts");
    // Decrypt part 1's slot using part 2's bytes.
    assert!(decrypt_all(Alg::Aes256Gcm, &KEY, 1, CHUNK, &b).is_err());
    assert!(decrypt_all(Alg::Aes256Gcm, &KEY, 2, CHUNK, &a).is_err());
}

/// Truncating a part's ciphertext must fail closed, not release a short
/// plaintext.
#[test]
fn part_truncation_fails() {
    let ct = encrypt_all(
        Alg::Aes256Gcm,
        &KEY,
        1,
        CHUNK,
        b"a plaintext spanning more than a single sixteen byte chunk",
    );
    let truncated = &ct[..ct.len() - 1];
    let mut d = Decryptor::new(Alg::Aes256Gcm, KEY, 1, CHUNK);
    let mut got_err = false;
    match d.push(truncated) {
        Err(_) => got_err = true,
        Ok(out) => {
            if d.finish().is_err() {
                got_err = true;
            }
            let _ = out;
        }
    }
    assert!(
        got_err,
        "truncated part ciphertext must not decrypt cleanly"
    );
}
