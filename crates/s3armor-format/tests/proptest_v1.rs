//! Property tests: round-trip, size-math inversion, range-slice
//! equivalence, footer round-trip, and decoder robustness against
//! arbitrary byte mutation. See docs/ARCHITECTURE.md "Testing strategy".

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

use proptest::prelude::*;
use s3armor_format::v1::{
    ciphertext_len, decrypt_all, encrypt_all, n_chunks, open_frame, plaintext_len, plan_range, Alg,
    Decryptor, Footer,
};

const KEY: [u8; 32] = [0x55; 32];

fn any_alg() -> impl Strategy<Value = Alg> {
    prop_oneof![Just(Alg::Aes256Gcm), Just(Alg::XChaCha20Poly1305)]
}

proptest! {
    /// Round-trip over interesting lengths around the chunk boundary.
    #[test]
    fn encrypt_then_decrypt_returns_the_original_plaintext(
        alg in any_alg(),
        chunk_size in 1usize..64,
        len in prop_oneof![Just(0usize), Just(1usize), 0usize..300],
        seed in any::<u8>(),
    ) {
        let plaintext: Vec<u8> = (0..len).map(|i| seed.wrapping_add(i as u8)).collect();
        let ct = encrypt_all(alg, &KEY, 0, chunk_size, &plaintext);
        let pt = decrypt_all(alg, &KEY, 0, chunk_size, &ct).unwrap();
        prop_assert_eq!(pt, plaintext);
    }

    /// `plaintext_len` inverts `ciphertext_len` for every length.
    #[test]
    fn plaintext_len_inverts_ciphertext_len_for_every_length(alg in any_alg(), chunk_size in 1u64..64, pt_len in 0u64..300) {
        let ct_len = ciphertext_len(alg, pt_len, chunk_size);
        prop_assert_eq!(plaintext_len(alg, ct_len, chunk_size).unwrap(), pt_len);
    }

    /// A range slice, decrypted only over its covering chunks and trimmed,
    /// equals the same slice of a full decrypt.
    #[test]
    fn range_slice_equals_full_decrypt_slice(
        alg in any_alg(),
        chunk_size in 1u64..32,
        pt_len in 0u64..200,
        a in 0u64..200,
        b in 0u64..200,
    ) {
        let start = a.min(pt_len);
        let end = b.min(pt_len).max(start);
        let plaintext: Vec<u8> = (0..pt_len).map(|i| i as u8).collect();
        let ct = encrypt_all(alg, &KEY, 0, chunk_size as usize, &plaintext);

        // A zero-length range sitting exactly past the last byte of a
        // non-empty object names no chunk; plan_range rejects it (see its
        // doc comment) rather than the caller synthesizing an empty read.
        let Ok(plan) = plan_range(alg, pt_len, chunk_size, start, end) else {
            prop_assert_eq!(start, end);
            prop_assert_eq!(start, pt_len);
            prop_assert!(pt_len > 0);
            return Ok(());
        };
        let covering = &ct[plan.ct_start as usize..plan.ct_end as usize];
        let total_chunks = n_chunks(pt_len, chunk_size);
        let mut decrypted = Vec::new();
        let mut idx = plan.first_chunk;
        let mut off = 0usize;
        let mut last_chunk_pt_len = 0usize;
        while idx <= plan.last_chunk {
            let is_last_of_object = idx + 1 == total_chunks;
            let frame_len = if is_last_of_object {
                covering.len() - off
            } else {
                chunk_size as usize + alg.overhead()
            };
            let frame = &covering[off..off + frame_len];
            let pt = open_frame(alg, &KEY, 0, idx, is_last_of_object, frame).unwrap();
            last_chunk_pt_len = pt.len();
            decrypted.extend(pt);
            off += frame_len;
            idx += 1;
        }
        // trim_end is an offset within the *last decrypted chunk*, not
        // within the concatenated `decrypted` buffer.
        let end_pos = decrypted.len() - last_chunk_pt_len + plan.trim_end;
        let trimmed = &decrypted[plan.trim_start..end_pos];
        prop_assert_eq!(trimmed, &plaintext[start as usize..end as usize]);
    }

    /// Same scenario as `range_slice_equals_full_decrypt_slice`, but driven
    /// through `Decryptor::new_at` (what the proxy's ranged-GET path
    /// actually uses) instead of hand-looping `open_frame`.
    #[test]
    fn range_decrypt_via_streaming_type_matches_full_decrypt_slice(
        alg in any_alg(),
        chunk_size in 1u64..32,
        pt_len in 0u64..200,
        a in 0u64..200,
        b in 0u64..200,
    ) {
        let start = a.min(pt_len);
        let end = b.min(pt_len).max(start);
        let plaintext: Vec<u8> = (0..pt_len).map(|i| i as u8).collect();
        let ct = encrypt_all(alg, &KEY, 0, chunk_size as usize, &plaintext);

        let Ok(plan) = plan_range(alg, pt_len, chunk_size, start, end) else {
            prop_assert_eq!(start, end);
            prop_assert_eq!(start, pt_len);
            prop_assert!(pt_len > 0);
            return Ok(());
        };
        let covering = &ct[plan.ct_start as usize..plan.ct_end as usize];
        let total_chunks = n_chunks(pt_len, chunk_size);
        let final_frame_is_object_end = plan.last_chunk + 1 == total_chunks;

        let mut d = Decryptor::new_at(
            alg,
            KEY,
            0,
            chunk_size as usize,
            plan.first_chunk,
            final_frame_is_object_end,
        );
        let mut decrypted = d.push(covering).unwrap();
        decrypted.extend(d.finish().unwrap());

        let last_chunk_pt_len = decrypted.len()
            - (plan.last_chunk - plan.first_chunk) as usize * chunk_size as usize;
        let end_pos = decrypted.len() - last_chunk_pt_len + plan.trim_end;
        let trimmed = &decrypted[plan.trim_start..end_pos];
        prop_assert_eq!(trimmed, &plaintext[start as usize..end as usize]);
    }

    /// Footer round-trips through seal/parse_trailer/open.
    #[test]
    fn sealed_footer_reparses_to_the_same_footer(
        alg in any_alg(),
        part_sizes in prop::collection::vec(0u64..1_000_000, 0..8),
        has_md5 in any::<bool>(),
        md5 in prop::array::uniform16(any::<u8>()),
    ) {
        // Part numbers must be strictly ascending and total_pt must equal
        // their sum — both are footer invariants, not just wire encoding.
        let parts: Vec<(u32, u64)> = part_sizes
            .iter()
            .enumerate()
            .map(|(i, &size)| (i as u32 + 1, size))
            .collect();
        let total_pt = part_sizes.iter().sum();
        let footer = Footer {
            alg,
            parts,
            total_pt,
            md5: if has_md5 { Some(md5) } else { None },
        };
        let sealed = footer.seal(&KEY);
        let footer_len = Footer::parse_trailer(&sealed[sealed.len() - 16..]).unwrap() as usize;
        let frame = &sealed[sealed.len() - 16 - footer_len..sealed.len() - 16];
        let decoded = Footer::open(alg, &KEY, frame).unwrap();
        prop_assert_eq!(decoded, footer);
    }

    /// Arbitrary byte mutation of a sealed frame never panics; it either
    /// decodes (for a mutation the AEAD tag happens not to catch — none
    /// should exist below, but the property is "no panic", not "no
    /// false-accept") or returns an `Err`.
    #[test]
    fn frame_decoder_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        let _ = open_frame(Alg::Aes256Gcm, &KEY, 0, 0, true, &bytes);
    }

    /// Same, for the footer decoder.
    #[test]
    fn footer_decoder_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        if bytes.len() >= 16 {
            let _ = Footer::parse_trailer(&bytes[bytes.len() - 16..]);
        }
        let _ = Footer::open(Alg::Aes256Gcm, &KEY, &bytes);
    }
}
