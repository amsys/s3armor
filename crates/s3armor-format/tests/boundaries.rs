//! Deterministic ±1-byte boundary coverage at the real 64 KiB chunk size
//! (`crates/s3armor/src/config.rs`'s `S3A_CHUNK_SIZE` minimum, and what the
//! proxy actually runs) — `proptest_v1.rs` sweeps `chunk_size in 1..64`
//! against small plaintexts, which exercises the size-math algebra but
//! never at the size the format ships at, and never pins the exact
//! boundary lengths a regression could silently shift.

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
    ciphertext_len, decrypt_all, encrypt_all, n_chunks, part_layout, plaintext_len,
    plan_multipart_range, plan_range, Alg, Decryptor, Encryptor,
};

const KEY: [u8; 32] = [0x5a; 32];
const CHUNK: u64 = 65_536;

const fn algs() -> [Alg; 2] {
    [Alg::Aes256Gcm, Alg::XChaCha20Poly1305]
}

/// The plaintext lengths that matter: 0, 1, and one byte on either side of
/// one and two full chunks.
const fn boundary_lengths() -> [u64; 8] {
    [
        0,
        1,
        CHUNK - 1,
        CHUNK,
        CHUNK + 1,
        2 * CHUNK - 1,
        2 * CHUNK,
        2 * CHUNK + 1,
    ]
}

const fn expected_n_chunks(pt_len: u64) -> u64 {
    // Mirrors n_chunks's own contract (div_ceil, floor 1) independently of
    // its implementation, so this test can't just be checking the function
    // against itself.
    if pt_len == 0 {
        1
    } else {
        pt_len.div_ceil(CHUNK)
    }
}

#[test]
fn chunk_count_matches_the_expected_count_at_every_boundary() {
    for pt_len in boundary_lengths() {
        assert_eq!(
            n_chunks(pt_len, CHUNK),
            expected_n_chunks(pt_len),
            "pt_len={pt_len}"
        );
    }
}

#[test]
fn ciphertext_and_plaintext_len_invert_at_every_boundary() {
    for alg in algs() {
        for pt_len in boundary_lengths() {
            let ct_len = ciphertext_len(alg, pt_len, CHUNK);
            let expected_ct_len = pt_len + expected_n_chunks(pt_len) * alg.overhead() as u64;
            assert_eq!(ct_len, expected_ct_len, "alg={alg:?} pt_len={pt_len}");
            assert_eq!(
                plaintext_len(alg, ct_len, CHUNK).unwrap(),
                pt_len,
                "alg={alg:?} pt_len={pt_len}"
            );
        }
    }
}

#[test]
fn plaintext_len_rejects_a_truncated_ciphertext() {
    // A ciphertext cut to exactly `k*full + overhead` (k >= 1) is a length
    // no encoder produces: the final frame would carry zero plaintext bytes,
    // yet earlier full frames exist. Accepting it would report `k*CHUNK`
    // plaintext and stream a short body under a satisfied Content-Length.
    for alg in algs() {
        let overhead = alg.overhead() as u64;
        let full = CHUNK + overhead;
        for k in 1..=3u64 {
            let truncated = k * full + overhead;
            assert!(
                plaintext_len(alg, truncated, CHUNK).is_err(),
                "alg={alg:?} k={k}: truncated ct_len {truncated} must be rejected"
            );
        }
        // An empty object is a single zero-plaintext frame — still valid.
        assert_eq!(
            plaintext_len(alg, overhead, CHUNK).unwrap(),
            0,
            "alg={alg:?}"
        );
    }
}

#[test]
fn one_shot_round_trip_at_every_boundary() {
    for alg in algs() {
        for pt_len in boundary_lengths() {
            let plaintext = vec![0xab; pt_len as usize];
            let ct = encrypt_all(alg, &KEY, 0, CHUNK as usize, &plaintext);
            assert_eq!(ct.len() as u64, ciphertext_len(alg, pt_len, CHUNK));
            let pt = decrypt_all(alg, &KEY, 0, CHUNK as usize, &ct).unwrap();
            assert_eq!(pt, plaintext, "alg={alg:?} pt_len={pt_len}");
        }
    }
}

/// Feeds the streaming `Encryptor`/`Decryptor` one byte at a time and
/// checks the result matches the one-shot pair exactly — the streaming
/// state machine (`buf` held back "in case it's the last chunk") is where
/// an off-by-one would actually surface, not the one-shot wrapper.
#[test]
#[expect(
    clippy::similar_names,
    reason = "streamed_ct/streamed_pt mirror the crate's own ciphertext/plaintext vocabulary"
)]
fn streaming_one_byte_at_a_time_matches_one_shot_at_every_boundary() {
    for alg in algs() {
        for pt_len in boundary_lengths() {
            let plaintext: Vec<u8> = (0..pt_len).map(|i| (i % 256) as u8).collect();

            let mut enc = Encryptor::new(alg, KEY, 0, CHUNK as usize);
            let mut streamed_ct = Vec::new();
            for byte in &plaintext {
                streamed_ct.extend(enc.push(std::slice::from_ref(byte)));
            }
            streamed_ct.extend(enc.finish());

            // Nonces are random per frame (`seal_frame`'s doc comment), so
            // two independent encryptions of the same plaintext never
            // produce identical ciphertext — only their length, and what
            // they decrypt back to, are comparable.
            let one_shot_ct = encrypt_all(alg, &KEY, 0, CHUNK as usize, &plaintext);
            assert_eq!(
                streamed_ct.len(),
                one_shot_ct.len(),
                "alg={alg:?} pt_len={pt_len}"
            );
            assert_eq!(
                decrypt_all(alg, &KEY, 0, CHUNK as usize, &streamed_ct).unwrap(),
                plaintext,
                "alg={alg:?} pt_len={pt_len}"
            );

            let mut dec = Decryptor::new(alg, KEY, 0, CHUNK as usize);
            let mut streamed_pt = Vec::new();
            for byte in &streamed_ct {
                streamed_pt.extend(dec.push(std::slice::from_ref(byte)).unwrap());
            }
            streamed_pt.extend(dec.finish().unwrap());
            assert_eq!(streamed_pt, plaintext, "alg={alg:?} pt_len={pt_len}");
        }
    }
}

/// `plan_range` at the first byte, straddling a chunk boundary, and the
/// last byte, checked against the full-decrypt slice — the same property
/// `proptest_v1.rs::range_slice_equals_full_decrypt_slice` checks at random
/// small sizes, pinned here at the real chunk size and its boundaries.
#[test]
fn range_at_every_boundary_matches_full_decrypt_slice() {
    for alg in algs() {
        for pt_len in boundary_lengths() {
            if pt_len == 0 {
                continue; // no byte ranges to probe on an empty object
            }
            let plaintext: Vec<u8> = (0..pt_len).map(|i| (i % 256) as u8).collect();
            let ct = encrypt_all(alg, &KEY, 0, CHUNK as usize, &plaintext);
            let total_chunks = n_chunks(pt_len, CHUNK);

            let ranges: Vec<(u64, u64)> = [
                (0, 1),
                (pt_len.saturating_sub(1), pt_len),
                (CHUNK.saturating_sub(1), (CHUNK + 1).min(pt_len)),
            ]
            .into_iter()
            .filter(|&(s, e)| s < e && e <= pt_len)
            .collect();

            for (start, end) in ranges {
                let plan = plan_range(alg, pt_len, CHUNK, start, end).unwrap();
                let final_frame_is_object_end = plan.last_chunk + 1 == total_chunks;
                let mut dec = Decryptor::new_at(
                    alg,
                    KEY,
                    0,
                    CHUNK as usize,
                    plan.first_chunk,
                    final_frame_is_object_end,
                );
                let covered = &ct[plan.ct_start as usize..plan.ct_end as usize];
                let mut decrypted = dec.push(covered).unwrap();
                decrypted.extend(dec.finish().unwrap());
                let last_chunk_len = decrypted.len()
                    - (plan.last_chunk - plan.first_chunk) as usize * CHUNK as usize;
                let last_chunk_start = decrypted.len() - last_chunk_len;
                let trimmed = &decrypted
                    [plan.trim_start..(last_chunk_start + plan.trim_end).min(decrypted.len())];
                assert_eq!(
                    trimmed,
                    &plaintext[start as usize..end as usize],
                    "alg={alg:?} pt_len={pt_len} range=[{start},{end})"
                );
            }
        }
    }
}

// --- multipart layout boundaries (task 1b) ---

/// `part_layout`'s cumulative offsets at ±1-byte part sizes, including one
/// part that lands exactly on a chunk multiple next to one that doesn't.
#[test]
fn part_layout_offsets_stay_cumulative_at_boundary_part_sizes() {
    let alg = Alg::Aes256Gcm;
    let parts = [
        (1u32, CHUNK - 1),
        (2u32, CHUNK), // exact chunk multiple, next to one that isn't
        (3u32, CHUNK + 1),
    ];
    let spans = part_layout(alg, CHUNK, &parts);
    assert_eq!(spans.len(), 3);

    let mut pt_off = 0u64;
    let mut ct_off = 0u64;
    for (span, &(number, pt_len)) in spans.iter().zip(parts.iter()) {
        assert_eq!(span.number, number);
        assert_eq!(span.pt_start, pt_off);
        assert_eq!(span.pt_len, pt_len);
        assert_eq!(span.ct_start, ct_off);
        assert_eq!(span.ct_len, ciphertext_len(alg, pt_len, CHUNK));
        pt_off += pt_len;
        ct_off += span.ct_len;
    }
}

/// A plaintext range that straddles the boundary between the first and
/// second part (one byte on each side) resolves to exactly those two
/// parts' local plans, and decrypting through them reproduces the source
/// bytes — the same property `plan_multipart_range_matches_full_decrypt_slice`
/// in `tests/multipart.rs` checks, pinned at a part boundary instead of an
/// interior offset.
#[test]
fn multipart_range_straddling_a_part_boundary_matches_source_bytes() {
    let alg = Alg::Aes256Gcm;
    let key = KEY;
    let part_a: Vec<u8> = (0..=CHUNK).map(|i| (i % 256) as u8).collect();
    let part_b: Vec<u8> = (0..CHUNK - 1).map(|i| ((i + 7) % 256) as u8).collect();
    let ct_a = encrypt_all(alg, &key, 1, CHUNK as usize, &part_a);
    let ct_b = encrypt_all(alg, &key, 2, CHUNK as usize, &part_b);

    let spans = part_layout(
        alg,
        CHUNK,
        &[(1, part_a.len() as u64), (2, part_b.len() as u64)],
    );
    let total_pt = part_a.len() as u64 + part_b.len() as u64;

    let start = part_a.len() as u64 - 1;
    let end = part_a.len() as u64 + 1;
    assert!(end <= total_pt);
    let plan = plan_multipart_range(&spans, alg, CHUNK, start, end).unwrap();
    assert_eq!(
        plan.len(),
        2,
        "range must touch exactly the two straddled parts"
    );

    let mut out = Vec::new();
    for (i, (span, range_plan)) in plan.iter().enumerate() {
        let ct = if span.number == 1 { &ct_a } else { &ct_b };
        let total_chunks = n_chunks(span.pt_len, CHUNK);
        let final_frame_is_part_end = range_plan.last_chunk + 1 == total_chunks;
        let mut dec = Decryptor::new_at(
            alg,
            key,
            span.number,
            CHUNK as usize,
            range_plan.first_chunk,
            final_frame_is_part_end,
        );
        let covered = &ct[range_plan.ct_start as usize..range_plan.ct_end as usize];
        let mut decrypted = dec.push(covered).unwrap();
        decrypted.extend(dec.finish().unwrap());
        let last_chunk_len = decrypted.len()
            - (range_plan.last_chunk - range_plan.first_chunk) as usize * CHUNK as usize;
        let last_chunk_start = decrypted.len() - last_chunk_len;
        let start_trim = if i == 0 { range_plan.trim_start } else { 0 };
        let end_trim = if i + 1 == plan.len() {
            (last_chunk_start + range_plan.trim_end).min(decrypted.len())
        } else {
            decrypted.len()
        };
        out.extend_from_slice(&decrypted[start_trim..end_trim]);
    }

    let mut expected = part_a;
    expected.extend_from_slice(&part_b);
    assert_eq!(out, expected[start as usize..end as usize]);
}
