//! Corruption suite: every byte-region class must fail closed, before any
//! plaintext is released. See docs/ARCHITECTURE.md "Testing strategy".

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
    encrypt_all, open_emd5, open_frame, seal_emd5, seal_frame, Alg, Decryptor, Footer,
};

const KEY: [u8; 32] = [0x11; 32];
const CHUNK: usize = 16;

fn flip(bytes: &mut [u8], i: usize) {
    bytes[i] ^= 0x01;
}

// --- v1 frame ---------------------------------------------------------

#[test]
fn frame_nonce_corruption_fails() {
    let mut f = seal_frame(Alg::Aes256Gcm, &KEY, 0, 0, true, b"hello");
    flip(&mut f, 0);
    assert!(open_frame(Alg::Aes256Gcm, &KEY, 0, 0, true, &f).is_err());
}

#[test]
fn frame_ciphertext_corruption_fails() {
    let mut f = seal_frame(Alg::Aes256Gcm, &KEY, 0, 0, true, b"hello");
    let ct_start = Alg::Aes256Gcm.nonce_len();
    flip(&mut f, ct_start);
    assert!(open_frame(Alg::Aes256Gcm, &KEY, 0, 0, true, &f).is_err());
}

#[test]
fn frame_tag_corruption_fails() {
    let mut f = seal_frame(Alg::Aes256Gcm, &KEY, 0, 0, true, b"hello");
    let last = f.len() - 1;
    flip(&mut f, last);
    assert!(open_frame(Alg::Aes256Gcm, &KEY, 0, 0, true, &f).is_err());
}

#[test]
fn frame_truncation_fails() {
    let f = seal_frame(Alg::Aes256Gcm, &KEY, 0, 0, true, b"hello");
    let short = &f[..f.len() - 1];
    assert!(open_frame(Alg::Aes256Gcm, &KEY, 0, 0, true, short).is_err());
    assert!(open_frame(Alg::Aes256Gcm, &KEY, 0, 0, true, &[]).is_err());
}

#[test]
fn frame_aad_input_mismatches_fail() {
    let f = seal_frame(Alg::Aes256Gcm, &KEY, 3, 7, false, b"hello");
    // Wrong algorithm id in AAD.
    assert!(open_frame(Alg::XChaCha20Poly1305, &KEY, 3, 7, false, &f).is_err());
    // Wrong part number: a footer/part swap.
    assert!(open_frame(Alg::Aes256Gcm, &KEY, 4, 7, false, &f).is_err());
    // Wrong chunk index: a chunk swap/reorder.
    assert!(open_frame(Alg::Aes256Gcm, &KEY, 3, 8, false, &f).is_err());
    // Wrong last flag: truncation disguised as completion, or vice versa.
    assert!(open_frame(Alg::Aes256Gcm, &KEY, 3, 7, true, &f).is_err());
    // Correct on every axis: succeeds.
    assert!(open_frame(Alg::Aes256Gcm, &KEY, 3, 7, false, &f).is_ok());
}

/// A corrupted frame in a streaming decode must release no plaintext for
/// that frame; only bytes from already-verified prior frames are ever
/// returned.
#[test]
fn streaming_decoder_releases_nothing_from_a_corrupted_frame() {
    let ct = encrypt_all(Alg::Aes256Gcm, &KEY, 0, CHUNK, &[7u8; CHUNK * 3]);
    let frame_size = CHUNK + Alg::Aes256Gcm.overhead();
    let mut corrupted = ct;
    flip(&mut corrupted, frame_size + 2); // inside the second frame

    let mut d = Decryptor::new(Alg::Aes256Gcm, KEY, 0, CHUNK);
    // Push one byte past the first frame: enough to know frame 0 isn't
    // last, so it drains and releases normally.
    let first = d.push(&corrupted[..=frame_size]).unwrap();
    assert_eq!(first.len(), CHUNK);
    // Feeding the corrupted second frame's remaining bytes must error, and
    // any partial output on that call must not contain chunk-1 plaintext.
    let mut got_err = false;
    match d.push(&corrupted[frame_size + 1..]) {
        Err(_) => got_err = true,
        Ok(out) => assert!(out.is_empty(), "corrupted frame must not release plaintext"),
    }
    // If push() didn't already error (buffering may defer to finish()),
    // finish() must.
    if !got_err {
        assert!(d.finish().is_err());
    }
}

// --- v1 footer ----------------------------------------------------------

fn make_footer_bytes() -> Vec<u8> {
    Footer {
        alg: Alg::Aes256Gcm,
        parts: vec![(1, 100), (2, 100), (3, 37)],
        total_pt: 237,
        md5: None,
    }
    .seal(&KEY)
}

#[test]
fn footer_trailer_magic_corruption_fails() {
    let mut sealed = make_footer_bytes();
    let magic_start = sealed.len() - 16;
    flip(&mut sealed, magic_start); // first byte of the magic
    let trailer = &sealed[sealed.len() - 16..];
    assert!(Footer::parse_trailer(trailer).is_err());
}

#[test]
fn footer_frame_corruption_fails() {
    let sealed = make_footer_bytes();
    let footer_len = Footer::parse_trailer(&sealed[sealed.len() - 16..]).unwrap() as usize;
    let mut frame = sealed[sealed.len() - 16 - footer_len..sealed.len() - 16].to_vec();
    flip(&mut frame, 0);
    assert!(Footer::open(Alg::Aes256Gcm, &KEY, &frame).is_err());
}

#[test]
#[expect(
    clippy::integer_division,
    reason = "halving MAX to get a large-but-valid u64"
)]
fn footer_trailer_length_field_corruption_fails() {
    let sealed = make_footer_bytes();
    let mut trailer = sealed[sealed.len() - 16..].to_vec();
    // Claim a footer frame far larger than what actually precedes it.
    trailer[8..16].copy_from_slice(&(u64::MAX / 2).to_le_bytes());
    let claimed_len = Footer::parse_trailer(&trailer).unwrap();
    assert!(claimed_len as usize > sealed.len());
}

// --- v1 emd5 --------------------------------------------------------------

#[test]
fn a_corrupted_encrypted_md5_frame_fails_to_open() {
    let md5 = [0x44u8; 16];
    let mut sealed = seal_emd5(Alg::Aes256Gcm, &KEY, &md5);
    flip(&mut sealed, 0);
    assert!(open_emd5(Alg::Aes256Gcm, &KEY, &sealed).is_err());
}

// --- v1 ranged decrypt ------------------------------------------------

/// A range decrypt that stops before the object's actual last chunk must
/// fail if told (incorrectly) that its last frame is the object's end —
/// the `last` flag is part of the AAD, so this is exactly a corruption
/// class, not a usage mistake caught elsewhere.
#[test]
fn ranged_decrypt_with_wrong_final_flag_fails() {
    let pt = [7u8; CHUNK * 3];
    let ct = encrypt_all(Alg::Aes256Gcm, &KEY, 0, CHUNK, &pt);
    let frame_size = CHUNK + Alg::Aes256Gcm.overhead();
    // Chunks 0 and 1 only (chunk 2 is the real object end).
    let first_two = &ct[..frame_size * 2];

    let mut correct = Decryptor::new_at(Alg::Aes256Gcm, KEY, 0, CHUNK, 0, false);
    let mut out = correct.push(first_two).unwrap();
    out.extend(correct.finish().unwrap());
    assert_eq!(out, pt[..CHUNK * 2]);

    let mut wrong = Decryptor::new_at(Alg::Aes256Gcm, KEY, 0, CHUNK, 0, true);
    let _ = wrong.push(first_two);
    assert!(wrong.finish().is_err());
}

// --- v1 DEK wrap ----------------------------------------------------------

#[test]
fn wrapped_dek_corruption_fails() {
    let master = s3armor_format::v1::MasterKey::new([0x22; 32]);
    let dek = [0x33u8; 32];
    let mut wrapped = master.wrap(&dek, &[]);
    flip(&mut wrapped, 0);
    assert!(master.unwrap(&wrapped, &[]).is_err());
}
