//! v1 chunk framing, size math, and range mapping. See docs/ARCHITECTURE.md "Data: chunked AEAD".

use crate::{Error, Result};
use aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::XChaCha20Poly1305;
use rand_core::{OsRng, RngCore};

/// AEAD tag length, both algorithms.
pub const TAG_LEN: usize = 16;

/// Frame AAD length: `"s3a1"(4) ‖ alg(1) ‖ part_number(4) ‖ chunk_index(8) ‖ last(1)`.
const FRAME_AAD_LEN: usize = 4 + 1 + 4 + 8 + 1;

/// Data encryption algorithm. The id is part of the wire format — never
/// renumber an existing variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Aes256Gcm = 1,
    XChaCha20Poly1305 = 2,
}

impl Alg {
    pub const fn id(self) -> u8 {
        self as u8
    }

    pub const fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::Aes256Gcm),
            2 => Ok(Self::XChaCha20Poly1305),
            other => Err(Error::UnknownAlg(other)),
        }
    }

    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    /// Bytes a frame adds on top of its plaintext chunk: nonce plus tag.
    pub const fn overhead(self) -> usize {
        self.nonce_len() + TAG_LEN
    }
}

fn frame_aad(alg: Alg, part_number: u32, chunk_index: u64, last: bool) -> [u8; FRAME_AAD_LEN] {
    let mut aad = [0u8; FRAME_AAD_LEN];
    aad[0..4].copy_from_slice(b"s3a1");
    aad[4] = alg.id();
    aad[5..9].copy_from_slice(&part_number.to_le_bytes());
    aad[9..17].copy_from_slice(&chunk_index.to_le_bytes());
    aad[17] = u8::from(last);
    aad
}

/// Seal one chunk into a frame: `nonce ‖ ciphertext ‖ tag`. The nonce is
/// random per call, so retried or parallel parts never reuse (key, nonce).
pub fn seal_frame(
    alg: Alg,
    key: &[u8; 32],
    part_number: u32,
    chunk_index: u64,
    last: bool,
    plaintext: &[u8],
) -> Vec<u8> {
    let aad = frame_aad(alg, part_number, chunk_index, last);
    let mut nonce = vec![0u8; alg.nonce_len()];
    OsRng.fill_bytes(&mut nonce);
    let payload = Payload {
        msg: plaintext,
        aad: &aad,
    };
    #[expect(
        clippy::expect_used,
        reason = "AEAD encrypt cannot fail for a valid key and nonce, only for an over-length plaintext far beyond S3's own object size limit"
    )]
    let ct = match alg {
        Alg::Aes256Gcm => Aes256Gcm::new(key.into())
            .encrypt(aes_gcm::Nonce::from_slice(&nonce), payload)
            .expect("AEAD encrypt cannot fail for a valid key and nonce"),
        Alg::XChaCha20Poly1305 => XChaCha20Poly1305::new(key.into())
            .encrypt(chacha20poly1305::XNonce::from_slice(&nonce), payload)
            .expect("AEAD encrypt cannot fail for a valid key and nonce"),
    };
    let mut frame = nonce;
    frame.extend_from_slice(&ct);
    frame
}

/// Open one frame. Fails closed: on any authentication or length error, no
/// plaintext is returned.
pub fn open_frame(
    alg: Alg,
    key: &[u8; 32],
    part_number: u32,
    chunk_index: u64,
    last: bool,
    frame: &[u8],
) -> Result<Vec<u8>> {
    let nl = alg.nonce_len();
    if frame.len() < nl + TAG_LEN {
        return Err(Error::Truncated {
            need: nl + TAG_LEN,
            got: frame.len(),
        });
    }
    let (nonce, ct) = frame.split_at(nl);
    let aad = frame_aad(alg, part_number, chunk_index, last);
    let payload = Payload { msg: ct, aad: &aad };
    let pt = match alg {
        Alg::Aes256Gcm => Aes256Gcm::new(key.into())
            .decrypt(aes_gcm::Nonce::from_slice(nonce), payload)
            .map_err(|_| Error::AuthFailed)?,
        Alg::XChaCha20Poly1305 => XChaCha20Poly1305::new(key.into())
            .decrypt(chacha20poly1305::XNonce::from_slice(nonce), payload)
            .map_err(|_| Error::AuthFailed)?,
    };
    Ok(pt)
}

/// Number of chunks a plaintext of `pt_len` bytes splits into at
/// `chunk_size`. Always at least 1: an empty object still seals to one
/// empty, `last`-flagged frame, so truncating an object to zero frames is
/// itself detectable.
pub fn n_chunks(pt_len: u64, chunk_size: u64) -> u64 {
    debug_assert!(chunk_size > 0);
    pt_len.div_ceil(chunk_size).max(1)
}

/// Ciphertext length for a plaintext of `pt_len` bytes. Exact, no probing.
pub fn ciphertext_len(alg: Alg, pt_len: u64, chunk_size: u64) -> u64 {
    pt_len + n_chunks(pt_len, chunk_size) * alg.overhead() as u64
}

/// Inverse of [`ciphertext_len`]: recovers the plaintext length from a
/// ciphertext length. Rejects any `ct_len` that no valid encoding could have
/// produced (corruption/truncation), rather than guessing.
#[expect(
    clippy::integer_division,
    reason = "floor division by design — see the comment on n_minus_1 below for why it recovers the unique split"
)]
pub fn plaintext_len(alg: Alg, ct_len: u64, chunk_size: u64) -> Result<u64> {
    debug_assert!(chunk_size > 0);
    let overhead = alg.overhead() as u64;
    let full = chunk_size + overhead;
    if ct_len < overhead {
        return Err(Error::InvalidLength);
    }
    // ct_len = (n-1)*full + last, where last is the final frame's total
    // size and lies in [overhead, full]. That range makes the (n-1, last)
    // split unique: floor division below always finds the same n the
    // encoder used.
    let n_minus_1 = (ct_len - overhead) / full;
    let last = ct_len - n_minus_1 * full;
    // `last == overhead` means a final frame with zero plaintext bytes. Only
    // an empty object encodes that way, and an empty object is a single
    // frame (`n_minus_1 == 0`). With earlier frames present, `last ==
    // overhead` is a truncation no encoder produces, so reject it — else a
    // ciphertext cut to `k*full + overhead` would report `k*chunk_size`
    // plaintext and stream short under a satisfied Content-Length.
    if last < overhead || last > full || (last == overhead && n_minus_1 > 0) {
        return Err(Error::InvalidLength);
    }
    Ok(n_minus_1 * chunk_size + (last - overhead))
}

/// A plan for serving a plaintext byte range: which ciphertext bytes to
/// fetch, which chunks they decrypt to, and where to trim the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangePlan {
    /// Ciphertext byte span to fetch from the backend: `[ct_start, ct_end)`.
    pub ct_start: u64,
    pub ct_end: u64,
    pub first_chunk: u64,
    pub last_chunk: u64,
    /// Byte offset to trim from the start of the decrypted first chunk.
    pub trim_start: usize,
    /// Exclusive byte offset to trim to in the decrypted last chunk.
    pub trim_end: usize,
}

/// Map a plaintext range `[start, end)` to the ciphertext bytes that cover
/// it and the trim needed after decrypting those chunks. Rejects
/// `start == end == pt_len` for a non-empty object: that position names no
/// chunk (an HTTP range parser should reject it as unsatisfiable before it
/// ever reaches here).
#[expect(
    clippy::integer_division,
    clippy::cast_possible_truncation,
    reason = "start/end are checked <= pt_len above; chunk_size is a config value far below usize::MAX on every supported (64-bit) target"
)]
pub fn plan_range(
    alg: Alg,
    pt_len: u64,
    chunk_size: u64,
    start: u64,
    end: u64,
) -> Result<RangePlan> {
    // `start == pt_len` (a zero-length range sitting exactly past the last
    // byte) names no chunk to decrypt, except for an empty object, where
    // `start == end == 0 == pt_len` is the only — and valid — range.
    if start > end || end > pt_len || (start == pt_len && pt_len > 0) {
        return Err(Error::InvalidLength);
    }
    let total_chunks = n_chunks(pt_len, chunk_size);
    let ct_len = ciphertext_len(alg, pt_len, chunk_size);
    let last_byte = end.saturating_sub(1);
    let first_chunk = start / chunk_size;
    let last_chunk = if end == start {
        first_chunk
    } else {
        last_byte / chunk_size
    };
    let trim_start = (start % chunk_size) as usize;
    let trim_end = if end == start {
        trim_start
    } else {
        (last_byte % chunk_size) as usize + 1
    };
    let full = chunk_size + alg.overhead() as u64;
    let ct_start = first_chunk * full;
    let ct_end = if last_chunk + 1 == total_chunks {
        ct_len
    } else {
        (last_chunk + 1) * full
    };
    Ok(RangePlan {
        ct_start,
        ct_end,
        first_chunk,
        last_chunk,
        trim_start,
        trim_end,
    })
}

/// Sans-io streaming encryptor for one part (or a whole single-part object,
/// with `part_number = 0`). Feed plaintext with [`push`](Self::push); call
/// [`finish`](Self::finish) exactly once, after the last byte.
pub struct Encryptor {
    alg: Alg,
    key: [u8; 32],
    part_number: u32,
    chunk_size: usize,
    chunk_index: u64,
    buf: Vec<u8>,
}

impl Encryptor {
    pub fn new(alg: Alg, key: [u8; 32], part_number: u32, chunk_size: usize) -> Self {
        assert!(chunk_size > 0, "chunk_size must be positive");
        // u32::MAX is reserved for the footer frame (see footer.rs). A caller
        // must reject an out-of-range client part number at its own trust
        // boundary; this belt stops a footer-forgery frame if one slips past.
        debug_assert!(
            part_number != u32::MAX,
            "part_number u32::MAX is reserved for the footer frame"
        );
        Self {
            alg,
            key,
            part_number,
            chunk_size,
            chunk_index: 0,
            buf: Vec::with_capacity(chunk_size),
        }
    }

    /// Feed plaintext bytes. Returns any full, non-final frames now ready
    /// to write out. One full chunk is always held back, because it might
    /// turn out to be the last one.
    #[expect(
        clippy::indexing_slicing,
        reason = "the loop guard checks buf.len() > chunk_size, so ..chunk_size is always in bounds"
    )]
    pub fn push(&mut self, data: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        while self.buf.len() > self.chunk_size {
            // Seal directly off the buffer instead of draining a scratch
            // `Vec` first — `seal_frame` only borrows, so there is no
            // ownership reason to copy the whole chunk before it does.
            out.extend(seal_frame(
                self.alg,
                &self.key,
                self.part_number,
                self.chunk_index,
                false,
                &self.buf[..self.chunk_size],
            ));
            self.buf.drain(..self.chunk_size);
            self.chunk_index += 1;
        }
        out
    }

    /// Seal whatever plaintext remains (0..=chunk_size bytes) as the final,
    /// `last`-flagged frame.
    pub fn finish(self) -> Vec<u8> {
        seal_frame(
            self.alg,
            &self.key,
            self.part_number,
            self.chunk_index,
            true,
            &self.buf,
        )
    }
}

/// Sans-io streaming decryptor, the mirror of [`Encryptor`]. Feed
/// ciphertext with [`push`](Self::push); call [`finish`](Self::finish)
/// exactly once, after the last byte. Every frame is verified before its
/// plaintext is returned.
pub struct Decryptor {
    alg: Alg,
    key: [u8; 32],
    part_number: u32,
    chunk_size: usize,
    chunk_index: u64,
    buf: Vec<u8>,
    /// Whether [`finish`](Self::finish) should verify its frame with
    /// `last = true`. `true` for a full-object decrypt; `false` for a
    /// ranged decrypt that stops before the object's actual last chunk —
    /// see [`new_at`](Self::new_at).
    final_frame_is_object_end: bool,
}

impl Decryptor {
    pub fn new(alg: Alg, key: [u8; 32], part_number: u32, chunk_size: usize) -> Self {
        Self::new_at(alg, key, part_number, chunk_size, 0, true)
    }

    /// Like [`new`](Self::new), but starts at `first_chunk` instead of
    /// chunk 0 — for decrypting a ciphertext byte range produced by
    /// [`plan_range`]. `final_frame_is_object_end` must be `true` only when
    /// the last frame fed to this decryptor really is the object's final
    /// chunk (the one sealed with `last = true` on encrypt); a range that
    /// stops short of the object's end must pass `false`, or verification
    /// fails against the wrong AAD.
    pub fn new_at(
        alg: Alg,
        key: [u8; 32],
        part_number: u32,
        chunk_size: usize,
        first_chunk: u64,
        final_frame_is_object_end: bool,
    ) -> Self {
        assert!(chunk_size > 0, "chunk_size must be positive");
        Self {
            alg,
            key,
            part_number,
            chunk_size,
            chunk_index: first_chunk,
            buf: Vec::with_capacity(chunk_size + alg.overhead()),
            final_frame_is_object_end,
        }
    }

    /// Feed ciphertext bytes. Returns the plaintext of any full, verified,
    /// non-final frames. Errs closed: an authentication failure returns an
    /// error and releases nothing from the failing frame.
    #[expect(
        clippy::indexing_slicing,
        reason = "the loop guard checks buf.len() > frame_size, so ..frame_size is always in bounds"
    )]
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.buf.extend_from_slice(data);
        let frame_size = self.chunk_size + self.alg.overhead();
        let mut out = Vec::new();
        while self.buf.len() > frame_size {
            // Open directly off the buffer instead of draining a scratch
            // `Vec` first (same reasoning as `Encryptor::push`). The `?`
            // must come before the `drain`: on an auth failure the buffer
            // is left untouched rather than partly advanced.
            let pt = open_frame(
                self.alg,
                &self.key,
                self.part_number,
                self.chunk_index,
                false,
                &self.buf[..frame_size],
            )?;
            self.buf.drain(..frame_size);
            out.extend(pt);
            self.chunk_index += 1;
        }
        Ok(out)
    }

    /// Verify and decrypt the final frame from whatever bytes remain.
    pub fn finish(self) -> Result<Vec<u8>> {
        open_frame(
            self.alg,
            &self.key,
            self.part_number,
            self.chunk_index,
            self.final_frame_is_object_end,
            &self.buf,
        )
    }
}

/// One-shot encrypt of a whole plaintext buffer. Convenience wrapper over
/// [`Encryptor`] for the small-object fast path and for tests.
pub fn encrypt_all(
    alg: Alg,
    key: &[u8; 32],
    part_number: u32,
    chunk_size: usize,
    plaintext: &[u8],
) -> Vec<u8> {
    let mut e = Encryptor::new(alg, *key, part_number, chunk_size);
    let mut out = e.push(plaintext);
    out.extend(e.finish());
    out
}

/// One-shot decrypt of a whole ciphertext buffer. Convenience wrapper over
/// [`Decryptor`].
pub fn decrypt_all(
    alg: Alg,
    key: &[u8; 32],
    part_number: u32,
    chunk_size: usize,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut d = Decryptor::new(alg, *key, part_number, chunk_size);
    let mut out = d.push(ciphertext)?;
    out.extend(d.finish()?);
    Ok(out)
}
