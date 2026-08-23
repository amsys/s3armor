//! Request-body transforms: verify-while-streaming (`hashing`) and
//! dechunk-and-verify-while-streaming (`dechunking`). Both keep memory at
//! O(chunk) — no whole-body buffer anywhere in this module — and both
//! reject a tampered body *before* forwarding completes, by ending the
//! outbound body stream with an `Err` frame instead of a clean EOF. Hyper's
//! client sees that as a failed send and aborts the connection to the
//! backend rather than completing it, so a tampered PUT never commits.
//!
//! Both are implemented as a spawned task feeding a channel, not a
//! hand-written `poll_frame` state machine — simpler to get right, and the
//! backpressure from a bounded channel already gives O(chunk) memory.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body::Frame;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::Incoming;
// MD5 here is the S3 Content-MD5/ETag protocol contract, not a security
// control (see `check_md5`'s doc comment and `docs/ARCHITECTURE.md`
// "ETag policy") — a client-supplied value that must be reproduced
// byte-for-byte to interoperate, not a hash s3armor is free to strengthen.
use md5::Md5;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use s3armor_format::v1::{n_chunks, Alg, Decryptor, Encryptor, PartSpan, RangePlan};

use crate::chunked::{ChunkVerifier, ChunkedError, Dechunker};

pub type ProxyBody = BoxBody<Bytes, std::io::Error>;

fn io_err(msg: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(msg.to_string())
}

pub fn empty() -> ProxyBody {
    Empty::new()
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed()
}

pub fn full(bytes: Bytes) -> ProxyBody {
    Full::new(bytes)
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed()
}

/// Passes an incoming body straight through, only adapting its error type.
/// Used for `UNSIGNED-PAYLOAD` and any request with no body.
pub fn passthrough(incoming: Incoming) -> ProxyBody {
    incoming.map_err(io_err).boxed()
}

/// Verifies `expected_sha256_hex` against the streamed body's hash. On
/// mismatch, ends the stream with an error instead of `None` — see the
/// module doc comment for why that's enough to stop the write reaching the
/// backend.
pub fn hashing(mut inner: Incoming, expected_sha256_hex: String) -> ProxyBody {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    tokio::spawn(async move {
        let mut hasher = Sha256::new();
        loop {
            match inner.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        hasher.update(data);
                    }
                    if tx.send(Ok(frame)).await.is_err() {
                        return;
                    }
                }
                Some(Err(e)) => {
                    let _ = tx.send(Err(io_err(e))).await;
                    return;
                }
                None => {
                    let digest = hex::encode(hasher.finalize());
                    if digest != expected_sha256_hex {
                        let _ = tx
                            .send(Err(io_err(format!(
                                "payload hash mismatch: expected {expected_sha256_hex}, got {digest}"
                            ))))
                            .await;
                    }
                    return;
                }
            }
        }
    });
    StreamBody::new(ReceiverStream(rx)).boxed()
}

/// Dechunks an `aws-chunked` body, verifying each chunk's
/// `chunk-signature=` (when `verifier` is `Some`) before that chunk's
/// decoded bytes are forwarded. `verifier` is `None` for
/// `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, whose chunks carry no signature.
pub fn dechunking<B>(mut inner: B, mut verifier: Option<ChunkVerifier>) -> ProxyBody
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::fmt::Display + Send,
{
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    tokio::spawn(async move {
        let mut dechunker = Dechunker::new();
        loop {
            let Some(raw) = next_raw_frame(&mut inner, &tx, &dechunker).await else {
                return;
            };
            let chunks = match dechunker.feed(&raw) {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Err(io_err(chunk_error_message(&e)))).await;
                    return;
                }
            };
            if !forward_chunks(chunks, &mut verifier, &tx).await {
                return;
            }
        }
    });
    StreamBody::new(ReceiverStream(rx)).boxed()
}

/// Pulls the next raw wire-format frame from `inner`, skipping trailers
/// frames. Sends an `Err` frame and returns `None` on a transport error or
/// on EOF before `dechunker` has seen the aws-chunked terminator; `None` on
/// a clean, already-terminated EOF stops the caller with nothing more to
/// send.
async fn next_raw_frame<B>(
    inner: &mut B,
    tx: &mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
    dechunker: &Dechunker,
) -> Option<Bytes>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    loop {
        match inner.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    return Some(data);
                }
                // else: a trailers frame on the raw wire body; ignore, loop for the next one
            }
            Some(Err(e)) => {
                let _ = tx.send(Err(io_err(e))).await;
                return None;
            }
            None => {
                if !dechunker.is_done() {
                    let _ = tx
                        .send(Err(io_err("aws-chunked body ended before its terminator")))
                        .await;
                }
                return None;
            }
        }
    }
}

/// Verifies (when `verifier` is `Some`) and forwards each decoded chunk.
/// Returns `false` to stop the caller — either the receiver is gone, or a
/// chunk failed verification (its `Err` frame has already been sent).
async fn forward_chunks(
    chunks: Vec<crate::chunked::DecodedChunk>,
    verifier: &mut Option<ChunkVerifier>,
    tx: &mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
) -> bool {
    for (data, signature) in chunks {
        if let (Some(v), Some(sig)) = (verifier.as_mut(), signature.as_deref()) {
            if let Err(e) = v.verify_and_advance(&data, sig) {
                let _ = tx.send(Err(io_err(chunk_error_message(&e)))).await;
                return false;
            }
        }
        if data.is_empty() {
            continue; // the terminating zero-length chunk carries no bytes to forward
        }
        if tx.send(Ok(Frame::data(Bytes::from(data)))).await.is_err() {
            return false;
        }
    }
    true
}

/// Encrypts a plaintext request body into v1 ciphertext frames while
/// streaming, `chunk_size` bytes of plaintext at a time — O(chunk) memory,
/// same shape as `hashing`/`dechunking` above. Composes *on top of*
/// whatever `build_outbound_body` already produced, so aws-chunked
/// dechunking and chunk-signature verification still run first: this wraps
/// verified *plaintext*, never raw wire bytes.
///
/// `part_number` is `0` for a single-part object, or the client's multipart
/// part number (`docs/ARCHITECTURE.md` "Multipart v1") — each part is an independent
/// stream, its own chunk indices starting at 0.
///
/// `expected_md5`, when set, is checked against the streamed plaintext (the
/// client's own `Content-MD5`, `docs/ARCHITECTURE.md` "ETag policy") and, on mismatch,
/// aborted via the same Err-frame protocol as `hashing`/`dechunking`: the
/// PUT never commits.
///
/// `expected_pt_len` is the plaintext length the caller already promised
/// downstream (the outbound ciphertext `Content-Length`, and for multipart
/// the part's persisted `pt_len`) — checked against the real byte count as
/// it streams, and again at EOF, so a client whose `x-amz-decoded-content-length`
/// diverges from what its aws-chunked body actually contains can never
/// desync the recorded plaintext length from the real ciphertext on the
/// backend.
///
/// `trailer`, when set, is appended after the final frame — lets a caller
/// concatenate a sealed footer onto a part's ciphertext stream without an
/// extra buffering pass. The proxy's own multipart write path
/// (`intercept::mpu`) never needs this: it either uploads the footer as
/// its own part, or merges it into a buffered small tail with
/// `body::full`. No caller in this tree currently passes `Some` here.
#[expect(
    clippy::too_many_arguments,
    reason = "one streaming encrypt step: alg/dek/chunk_size describe the cipher, expected_md5/expected_pt_len/trailer are independent EOF checks and appends; splitting would fragment a single auditable pipeline"
)]
pub fn encrypting(
    mut inner: ProxyBody,
    alg: Alg,
    dek: [u8; 32],
    chunk_size: usize,
    expected_md5: Option<[u8; 16]>,
    expected_pt_len: u64,
    part_number: u32,
    trailer: Option<Bytes>,
) -> ProxyBody {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    tokio::spawn(async move {
        let mut enc = Encryptor::new(alg, dek, part_number, chunk_size);
        let mut hasher = expected_md5.is_some().then(Md5::new);
        let mut seen: u64 = 0;
        loop {
            match inner.frame().await {
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue; // a trailers frame; ignore
                    };
                    seen += data.len() as u64;
                    if seen > expected_pt_len {
                        let _ = tx
                            .send(Err(io_err(
                                "streamed plaintext exceeds the declared decoded length",
                            )))
                            .await;
                        return;
                    }
                    if let Some(h) = hasher.as_mut() {
                        h.update(&data);
                    }
                    let ct = enc.push(&data);
                    if !ct.is_empty() && tx.send(Ok(Frame::data(Bytes::from(ct)))).await.is_err() {
                        return;
                    }
                }
                Some(Err(e)) => {
                    let _ = tx.send(Err(io_err(e))).await;
                    return;
                }
                None => {
                    finish_encrypting(
                        enc,
                        hasher,
                        expected_md5,
                        seen,
                        expected_pt_len,
                        trailer,
                        &tx,
                    )
                    .await;
                    return;
                }
            }
        }
    });
    StreamBody::new(ReceiverStream(rx)).boxed()
}

/// Finalises an `encrypting` stream at EOF: verifies the client's
/// `Content-MD5` when one was given and that the streamed byte count
/// matched the declared decoded length, then sends the last frame — the
/// encryptor's tail plus `trailer`, when set.
async fn finish_encrypting(
    enc: Encryptor,
    hasher: Option<Md5>,
    expected_md5: Option<[u8; 16]>,
    seen: u64,
    expected_pt_len: u64,
    trailer: Option<Bytes>,
    tx: &mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
) {
    if seen != expected_pt_len {
        let _ = tx
            .send(Err(io_err(
                "streamed plaintext is shorter than the declared decoded length",
            )))
            .await;
        return;
    }
    if let Err(msg) = check_md5(hasher, expected_md5) {
        let _ = tx.send(Err(io_err(msg))).await;
        return;
    }
    let mut out = enc.finish();
    if let Some(t) = &trailer {
        out.extend_from_slice(t);
    }
    let _ = tx.send(Ok(Frame::data(Bytes::from(out)))).await;
}

/// Checks a finished MD5 hasher against the client's `Content-MD5`, when
/// both are present. `Ok(())` when there's nothing to check (no hasher
/// means `expected_md5` was `None` to begin with).
///
/// MD5 is required here for S3 API compatibility, not for integrity: the
/// client picks the hash (`Content-MD5`), and the same 16 bytes become the
/// plaintext ETag returned on PUT/HEAD/GET (`docs/ARCHITECTURE.md` "ETag
/// policy") — a stronger hash would produce an ETag no S3 client expects.
/// Actual integrity rests on AES-256-GCM/XChaCha20-Poly1305 AEAD per chunk
/// plus SigV4 SHA-256 on the request; the ETag itself is stored AEAD-sealed
/// (`s3a-emd5`), so it isn't a content-guessing oracle for the operator.
fn check_md5(hasher: Option<Md5>, expected: Option<[u8; 16]>) -> Result<(), &'static str> {
    let (Some(h), Some(expected)) = (hasher, expected) else {
        return Ok(());
    };
    let got: [u8; 16] = h.finalize().into();
    if got == expected {
        Ok(())
    } else {
        Err("Content-MD5 does not match the streamed plaintext")
    }
}

/// Decrypts a full-object v1 ciphertext response stream, O(chunk) memory —
/// every frame is verified before its plaintext is released. `part_number`
/// is `0` for a single-part object; multipart full reads go through
/// [`decrypting_multipart`] instead, one part at a time.
pub fn decrypting(
    mut inner: Incoming,
    alg: Alg,
    dek: [u8; 32],
    chunk_size: usize,
    part_number: u32,
    on_verify_failure: Option<Arc<AtomicU64>>,
) -> ProxyBody {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    tokio::spawn(async move {
        let mut dec = Decryptor::new(alg, dek, part_number, chunk_size);
        loop {
            match inner.frame().await {
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    match dec.push(&data) {
                        Ok(pt) => {
                            if !pt.is_empty()
                                && tx.send(Ok(Frame::data(Bytes::from(pt)))).await.is_err()
                            {
                                return;
                            }
                        }
                        Err(e) => {
                            note_chunk_verify_failure(on_verify_failure.as_ref());
                            let _ = tx.send(Err(io_err(decrypt_error_message(&e)))).await;
                            return;
                        }
                    }
                }
                Some(Err(e)) => {
                    let _ = tx.send(Err(io_err(e))).await;
                    return;
                }
                None => {
                    match dec.finish() {
                        Ok(pt) => {
                            let _ = tx.send(Ok(Frame::data(Bytes::from(pt)))).await;
                        }
                        Err(e) => {
                            note_chunk_verify_failure(on_verify_failure.as_ref());
                            let _ = tx.send(Err(io_err(decrypt_error_message(&e)))).await;
                        }
                    }
                    return;
                }
            }
        }
    });
    StreamBody::new(ReceiverStream(rx)).boxed()
}

/// Decrypts a ciphertext byte range from a v1 object and trims it to the
/// exact plaintext bytes the client asked for. `plan` is
/// [`s3armor_format::v1::plan_range`]'s own output; `total_chunks` (the
/// object's full chunk count) is needed alongside it only to tell whether
/// `plan.last_chunk` is the object's actual last chunk — i.e. whether the
/// final frame in this range was sealed with `last = true` on encrypt.
///
/// # ponytail
/// Buffers the whole covered ciphertext span in memory before trimming —
/// O(range), not O(chunk). A range is a client-requested window, not the
/// whole object (video seeking, resumable downloads), so this is a
/// deliberate ceiling, not the hot path (`decrypting` above stays
/// O(chunk)). Upgrade path: stream every fully-covered middle chunk
/// untouched and only special-case the first/last chunk's trim, if a
/// benchmark shows large ranged reads need it.
#[expect(
    clippy::indexing_slicing,
    reason = "start/end are both clamped to buf.len() by .min() just above"
)]
pub fn decrypting_range(
    mut inner: Incoming,
    alg: Alg,
    dek: [u8; 32],
    chunk_size: usize,
    plan: &RangePlan,
    total_chunks: u64,
    on_verify_failure: Option<Arc<AtomicU64>>,
) -> ProxyBody {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    let first_chunk = plan.first_chunk;
    let final_frame_is_object_end = plan.last_chunk + 1 == total_chunks;
    let (trim_start, trim_end) = (plan.trim_start, plan.trim_end);
    tokio::spawn(async move {
        let mut dec = Decryptor::new_at(
            alg,
            dek,
            0,
            chunk_size,
            first_chunk,
            final_frame_is_object_end,
        );
        let mut buf = Vec::new();
        loop {
            match inner.frame().await {
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    match dec.push(&data) {
                        Ok(pt) => buf.extend(pt),
                        Err(e) => {
                            note_chunk_verify_failure(on_verify_failure.as_ref());
                            let _ = tx.send(Err(io_err(decrypt_error_message(&e)))).await;
                            return;
                        }
                    }
                }
                Some(Err(e)) => {
                    let _ = tx.send(Err(io_err(e))).await;
                    return;
                }
                None => {
                    // `trim_end` is an offset *within the last decrypted
                    // chunk* (`plan_range`'s doc comment), not a global
                    // offset into `buf` — it only coincides with a global
                    // offset when the range covers exactly one chunk.
                    // `trim_start` has no such caveat: the first chunk
                    // always starts at `buf[0]`.
                    let last_chunk_len = match dec.finish() {
                        Ok(pt) => {
                            let len = pt.len();
                            buf.extend(pt);
                            len
                        }
                        Err(e) => {
                            note_chunk_verify_failure(on_verify_failure.as_ref());
                            let _ = tx.send(Err(io_err(decrypt_error_message(&e)))).await;
                            return;
                        }
                    };
                    let last_chunk_start = buf.len() - last_chunk_len;
                    let end = (last_chunk_start + trim_end).min(buf.len());
                    let start = trim_start.min(end);
                    let _ = tx
                        .send(Ok(Frame::data(Bytes::from(buf[start..end].to_vec()))))
                        .await;
                    return;
                }
            }
        }
    });
    StreamBody::new(ReceiverStream(rx)).boxed()
}

/// Decrypts a full multipart v1 object response stream: walks `spans`
/// (ascending part order, footer excluded — `s3armor_format::v1::part_layout`'s
/// output) as a sequence of independent `Decryptor`s, one per part, each
/// keyed by that part's own client part number. Stops as soon as the last
/// span's ciphertext is consumed — the footer and trailer bytes that follow
/// in the backend's response are never decrypted or forwarded. O(chunk)
/// memory, same Err-frame abort protocol as `decrypting`.
pub fn decrypting_multipart<B>(
    mut inner: B,
    alg: Alg,
    dek: [u8; 32],
    chunk_size: usize,
    spans: Vec<PartSpan>,
    on_verify_failure: Option<Arc<AtomicU64>>,
) -> ProxyBody
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::fmt::Display + Send,
{
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    tokio::spawn(async move {
        let Some(mut cursor) = MultipartCursor::new(alg, dek, chunk_size, spans) else {
            return; // an empty multipart object (no parts) — nothing to decrypt
        };
        loop {
            match inner.frame().await {
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    if !cursor.feed(data, &tx, on_verify_failure.as_ref()).await {
                        return;
                    }
                }
                Some(Err(e)) => {
                    let _ = tx.send(Err(io_err(e))).await;
                    return;
                }
                None => {
                    if cursor.ended_early() {
                        let _ = tx
                            .send(Err(io_err(
                                "multipart object body ended before its last part",
                            )))
                            .await;
                    }
                    return;
                }
            }
        }
    });
    StreamBody::new(ReceiverStream(rx)).boxed()
}

/// The per-part cursor `decrypting_multipart` walks: the current span, its
/// `Decryptor`, and how much of that span's ciphertext has been consumed so
/// far.
struct MultipartCursor {
    alg: Alg,
    dek: [u8; 32],
    chunk_size: usize,
    spans: std::vec::IntoIter<PartSpan>,
    span: PartSpan,
    dec: Decryptor,
    consumed_ct: u64,
}

impl MultipartCursor {
    /// `None` for an empty multipart object (no parts) — nothing to decrypt.
    fn new(alg: Alg, dek: [u8; 32], chunk_size: usize, spans: Vec<PartSpan>) -> Option<Self> {
        let mut spans = spans.into_iter();
        let span = spans.next()?;
        let dec = Decryptor::new(alg, dek, span.number, chunk_size);
        Some(Self {
            alg,
            dek,
            chunk_size,
            spans,
            span,
            dec,
            consumed_ct: 0,
        })
    }

    /// Feeds one inbound frame's data through the per-part decryptors,
    /// advancing to the next span each time a part's ciphertext is fully
    /// consumed. Returns `false` when the stream must stop: a decrypt
    /// failure, a closed receiver, or the last part finished (everything
    /// after it is the footer and trailer, never forwarded).
    async fn feed(
        &mut self,
        mut data: Bytes,
        tx: &mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
        on_verify_failure: Option<&Arc<AtomicU64>>,
    ) -> bool {
        while !data.is_empty() {
            let piece = take_for_span(&mut data, &self.span, self.consumed_ct);
            self.consumed_ct += piece.len() as u64;
            if !emit_decrypt_result(self.dec.push(&piece), tx, on_verify_failure).await {
                return false;
            }
            if self.consumed_ct < self.span.ct_len {
                continue;
            }
            // `finish()` takes `Decryptor` by value; swap in a fresh one
            // (for the current span — cheap, just field init) so `self.dec`
            // stays initialized while the old one is consumed. Overwritten
            // below once the real next-span `Decryptor` is known, or the
            // whole cursor is dropped when there's no next span.
            let placeholder = Decryptor::new(self.alg, self.dek, self.span.number, self.chunk_size);
            let dec = std::mem::replace(&mut self.dec, placeholder);
            if !emit_decrypt_result(dec.finish(), tx, on_verify_failure).await {
                return false;
            }
            // Every part decrypted — whatever remains in `data` (or
            // arrives in a later frame) is the footer and trailer. Stop
            // here.
            let Some(next) = self.spans.next() else {
                return false;
            };
            self.span = next;
            self.consumed_ct = 0;
            self.dec = Decryptor::new(self.alg, self.dek, self.span.number, self.chunk_size);
        }
        true
    }

    /// True at EOF only when the last part ended mid-ciphertext.
    const fn ended_early(&self) -> bool {
        self.consumed_ct != self.span.ct_len
    }
}

/// Splits off the front of `data` for the current span, bounded by how much
/// of that span's ciphertext is still unconsumed — the piece a single
/// `Decryptor::push` should see next.
#[expect(
    clippy::cast_possible_truncation,
    reason = "take = min(data.len(), remaining) as usize is bounded by data.len(), an already-usize value"
)]
fn take_for_span(data: &mut Bytes, span: &PartSpan, consumed_ct: u64) -> Bytes {
    let remaining = span.ct_len - consumed_ct;
    let take = (data.len() as u64).min(remaining) as usize;
    data.split_to(take)
}

/// Sends a `Decryptor::push`/`finish` result on: forwards non-empty
/// plaintext, or reports a verify failure and ends the stream with an `Err`
/// frame. Returns `false` to stop the caller.
async fn emit_decrypt_result(
    result: s3armor_format::Result<Vec<u8>>,
    tx: &mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
    on_verify_failure: Option<&Arc<AtomicU64>>,
) -> bool {
    match result {
        Ok(pt) => pt.is_empty() || tx.send(Ok(Frame::data(Bytes::from(pt)))).await.is_ok(),
        Err(e) => {
            note_chunk_verify_failure(on_verify_failure);
            let _ = tx.send(Err(io_err(decrypt_error_message(&e)))).await;
            false
        }
    }
}

/// Decrypts a ciphertext byte range spanning one or more parts of a
/// multipart v1 object. `plan` is
/// [`s3armor_format::v1::plan_multipart_range`]'s output; the caller has
/// already issued one backend ranged GET covering exactly the concatenation
/// of each entry's local `[ct_start, ct_end)` (contiguous by construction —
/// see `plan_multipart_range`'s doc comment) so `inner` yields precisely
/// that span, in part order, no more.
///
/// # ponytail
/// Buffers the whole covered ciphertext span, same ceiling as
/// `decrypting_range` and for the same reason: a range is a bounded,
/// client-requested window, not the whole object.
#[expect(
    clippy::cast_possible_truncation,
    reason = "span/chunk sizes are config-bounded well under usize::MAX on every supported (64-bit) target"
)]
#[expect(
    clippy::indexing_slicing,
    reason = "start/end are both derived from and clamped to decrypted.len() just above"
)]
pub fn decrypting_multipart_range(
    mut inner: Incoming,
    alg: Alg,
    dek: [u8; 32],
    chunk_size: usize,
    plan: Vec<(PartSpan, RangePlan)>,
    on_verify_failure: Option<Arc<AtomicU64>>,
) -> ProxyBody {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    tokio::spawn(async move {
        let mut buf = Vec::new();
        loop {
            match inner.frame().await {
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    buf.extend_from_slice(&data);
                }
                Some(Err(e)) => {
                    let _ = tx.send(Err(io_err(e))).await;
                    return;
                }
                None => break,
            }
        }
        let mut out = Vec::new();
        let mut offset = 0usize;
        let n = plan.len();
        for (i, (span, range_plan)) in plan.iter().enumerate() {
            let span_len = (range_plan.ct_end - range_plan.ct_start) as usize;
            let Some(slice) = buf.get(offset..offset + span_len) else {
                let _ = tx
                    .send(Err(io_err("multipart ranged read ended before its span")))
                    .await;
                return;
            };
            offset += span_len;
            let total_chunks = n_chunks(span.pt_len, chunk_size as u64);
            let final_frame_is_part_end = range_plan.last_chunk + 1 == total_chunks;
            let mut dec = Decryptor::new_at(
                alg,
                dek,
                span.number,
                chunk_size,
                range_plan.first_chunk,
                final_frame_is_part_end,
            );
            let mut decrypted = match dec.push(slice) {
                Ok(pt) => pt,
                Err(e) => {
                    note_chunk_verify_failure(on_verify_failure.as_ref());
                    let _ = tx.send(Err(io_err(decrypt_error_message(&e)))).await;
                    return;
                }
            };
            match dec.finish() {
                Ok(pt) => decrypted.extend(pt),
                Err(e) => {
                    note_chunk_verify_failure(on_verify_failure.as_ref());
                    let _ = tx.send(Err(io_err(decrypt_error_message(&e)))).await;
                    return;
                }
            }
            let last_chunk_pt_len = decrypted.len()
                - (range_plan.last_chunk - range_plan.first_chunk) as usize * chunk_size;
            let start = if i == 0 { range_plan.trim_start } else { 0 };
            let end = if i + 1 == n {
                (decrypted.len() - last_chunk_pt_len + range_plan.trim_end).min(decrypted.len())
            } else {
                decrypted.len()
            };
            out.extend_from_slice(&decrypted[start..end]);
        }
        let _ = tx.send(Ok(Frame::data(Bytes::from(out)))).await;
    });
    StreamBody::new(ReceiverStream(rx)).boxed()
}

/// Increments `counter`, when given one — `docs/ARCHITECTURE.md`
/// "Observability"'s "chunk verify failures (alert on any)". `None` for a
/// caller with no live `ProxyState` to report to — a CLI tool decrypting
/// outside a running proxy, where nothing is scraping metrics anyway.
fn note_chunk_verify_failure(counter: Option<&Arc<AtomicU64>>) {
    if let Some(c) = counter {
        c.fetch_add(1, Ordering::Relaxed);
    }
}

fn decrypt_error_message(e: &s3armor_format::Error) -> String {
    format!("v1 decrypt failed: {e}")
}

fn chunk_error_message(e: &ChunkedError) -> String {
    format!("aws-chunked decode failed: {e}")
}

/// A minimal `futures_core::Stream` over an `mpsc::Receiver`, so this
/// module doesn't need the `tokio-stream` crate for one adapter.
struct ReceiverStream<T>(mpsc::Receiver<T>);

impl<T> futures_util::Stream for ReceiverStream<T> {
    type Item = T;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<T>> {
        self.0.poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    use futures_util::stream;
    use s3armor_format::v1::{decrypt_all, encrypt_all, part_layout};

    use super::*;
    use crate::chunked::ChunkVerifier;
    use crate::sigv4::canonical;

    const KEY: [u8; 32] = [0x22; 32];
    const CHUNK: usize = 16;

    fn chunk_wire(data: &[u8], sig: Option<&str>) -> Vec<u8> {
        let mut out = sig
            .map_or_else(
                || format!("{:x}\r\n", data.len()),
                |s| format!("{:x};chunk-signature={s}\r\n", data.len()),
            )
            .into_bytes();
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
        out
    }

    fn final_chunk(sig: Option<&str>) -> Vec<u8> {
        sig.map_or_else(
            || "0\r\n\r\n".to_string(),
            |s| format!("0;chunk-signature={s}\r\n\r\n"),
        )
        .into_bytes()
    }

    /// Yields each byte slice as its own frame — lets a test drive several
    /// `.frame()` reads instead of one, exercising the state `dechunking`
    /// and `decrypting_multipart` carry across calls.
    fn body_from_frames(frames: Vec<Vec<u8>>) -> ProxyBody {
        let s = stream::iter(
            frames
                .into_iter()
                .map(|f| Ok::<_, std::io::Error>(Frame::data(Bytes::from(f)))),
        );
        StreamBody::new(s).boxed()
    }

    async fn collect_ok(body: ProxyBody) -> Vec<u8> {
        body.collect()
            .await
            .expect("expected a clean stream")
            .to_bytes()
            .to_vec()
    }

    fn verifier(seed: &str) -> ChunkVerifier {
        ChunkVerifier::new(
            KEY,
            "20150830T123600Z".to_string(),
            "20150830/us-east-1/s3/aws4_request".to_string(),
            seed.to_string(),
        )
    }

    /// The same chained signature `ChunkVerifier::verify_and_advance`
    /// checks internally — its `expected` is private to `chunked`, so this
    /// reproduces the formula documented at the top of that file.
    fn chain_signature(prev: &str, data: &[u8]) -> String {
        let sts = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n20150830T123600Z\n20150830/us-east-1/s3/aws4_request\n{prev}\n{}\n{}",
            canonical::hex_sha256(b""),
            canonical::hex_sha256(data)
        );
        canonical::signature_hex(&KEY, &sts)
    }

    #[tokio::test]
    async fn dechunking_forwards_unsigned_chunks_across_multiple_frames() {
        let mut wire = chunk_wire(b"hello ", None);
        wire.extend(chunk_wire(b"world", None));
        wire.extend(final_chunk(None));
        // split mid-stream: Dechunker::feed is called more than once
        // before the first chunk completes.
        let (a, b) = wire.split_at(5);
        let body = body_from_frames(vec![a.to_vec(), b.to_vec()]);
        let out = collect_ok(dechunking(body, None)).await;
        assert_eq!(out, b"hello world");
    }

    #[tokio::test]
    async fn dechunking_verifies_a_real_chunk_signature_chain() {
        let seed = "0".repeat(64);
        let sig1 = chain_signature(&seed, b"payload");
        let mut wire = chunk_wire(b"payload", Some(&sig1));
        wire.extend(final_chunk(Some(&chain_signature(&sig1, b""))));
        let out = collect_ok(dechunking(full(Bytes::from(wire)), Some(verifier(&seed)))).await;
        assert_eq!(out, b"payload");
    }

    #[tokio::test]
    async fn dechunking_rejects_a_bad_chunk_signature() {
        let seed = "0".repeat(64);
        let wire = chunk_wire(b"payload", Some(&"f".repeat(64)));
        let res = dechunking(full(Bytes::from(wire)), Some(verifier(&seed)))
            .collect()
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn dechunking_errors_on_eof_before_the_terminator() {
        // a well-formed header with data short of its declared length, and
        // no terminating zero-chunk behind it
        let body = full(Bytes::from_static(b"5\r\nhel"));
        let res = dechunking(body, None).collect().await;
        assert!(res.is_err());
    }

    fn md5_of(data: &[u8]) -> [u8; 16] {
        Md5::digest(data).into()
    }

    #[tokio::test]
    async fn encrypting_round_trips_through_decryptor() {
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let body = full(Bytes::from_static(plaintext));
        let ct = collect_ok(encrypting(
            body,
            Alg::Aes256Gcm,
            KEY,
            CHUNK,
            None,
            plaintext.len() as u64,
            0,
            None,
        ))
        .await;
        let pt = decrypt_all(Alg::Aes256Gcm, &KEY, 0, CHUNK, &ct).expect("decrypts");
        assert_eq!(pt, plaintext);
    }

    #[tokio::test]
    async fn encrypting_rejects_a_body_longer_than_the_declared_length() {
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let body = full(Bytes::from_static(plaintext));
        // A claimed decoded length shorter than the real body — the client's
        // `x-amz-decoded-content-length` understating what its aws-chunked
        // stream actually contains.
        let res = encrypting(
            body,
            Alg::Aes256Gcm,
            KEY,
            CHUNK,
            None,
            plaintext.len() as u64 - 1,
            0,
            None,
        )
        .collect()
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn encrypting_rejects_a_body_shorter_than_the_declared_length() {
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let body = full(Bytes::from_static(plaintext));
        // A claimed decoded length longer than the real body — the reverse
        // direction of the same declared-vs-real-bytes mismatch.
        let res = encrypting(
            body,
            Alg::Aes256Gcm,
            KEY,
            CHUNK,
            None,
            plaintext.len() as u64 + 1,
            0,
            None,
        )
        .collect()
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn encrypting_rejects_a_content_md5_mismatch() {
        let body = full(Bytes::from_static(b"payload"));
        let wrong = [0u8; 16];
        let res = encrypting(body, Alg::Aes256Gcm, KEY, CHUNK, Some(wrong), 7, 0, None)
            .collect()
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn encrypting_accepts_a_matching_content_md5() {
        let plaintext = b"payload";
        let body = full(Bytes::from_static(plaintext));
        let expected = md5_of(plaintext);
        let ct = collect_ok(encrypting(
            body,
            Alg::Aes256Gcm,
            KEY,
            CHUNK,
            Some(expected),
            plaintext.len() as u64,
            0,
            None,
        ))
        .await;
        let pt = decrypt_all(Alg::Aes256Gcm, &KEY, 0, CHUNK, &ct).expect("decrypts");
        assert_eq!(pt, plaintext);
    }

    #[tokio::test]
    async fn encrypting_appends_the_trailer_after_the_final_frame() {
        // AEAD sealing uses a fresh random nonce per frame, so ciphertext
        // bytes aren't reproducible across two independent runs — but the
        // framed length is deterministic, which is enough to locate the
        // trailer split and decrypt the part in front of it.
        let plaintext = b"payload";
        let ct_len = encrypt_all(Alg::Aes256Gcm, &KEY, 0, CHUNK, plaintext).len();
        let body = full(Bytes::from_static(plaintext));
        let trailer = Bytes::from_static(b"TRAILER-BYTES");
        let out = collect_ok(encrypting(
            body,
            Alg::Aes256Gcm,
            KEY,
            CHUNK,
            None,
            plaintext.len() as u64,
            0,
            Some(trailer.clone()),
        ))
        .await;
        assert_eq!(out.len(), ct_len + trailer.len());
        let pt = decrypt_all(Alg::Aes256Gcm, &KEY, 0, CHUNK, &out[..ct_len]).expect("decrypts");
        assert_eq!(pt, plaintext);
        assert_eq!(&out[ct_len..], trailer.as_ref());
    }

    type TwoPartObject = (Vec<(u32, &'static [u8])>, Vec<Vec<u8>>);

    fn two_part_object() -> TwoPartObject {
        let parts: Vec<(u32, &[u8])> = vec![
            (1, b"first part plaintext"),
            (2, b"second part, a bit longer than the first"),
        ];
        let cts = parts
            .iter()
            .map(|(n, pt)| encrypt_all(Alg::Aes256Gcm, &KEY, *n, CHUNK, pt))
            .collect();
        (parts, cts)
    }

    #[tokio::test]
    async fn decrypting_multipart_walks_a_frame_that_straddles_a_span_boundary() {
        let (parts, cts) = two_part_object();
        let object: Vec<u8> = cts.iter().flatten().copied().collect();
        let entries: Vec<(u32, u64)> = parts.iter().map(|(n, pt)| (*n, pt.len() as u64)).collect();
        let spans = part_layout(Alg::Aes256Gcm, CHUNK as u64, &entries);

        // fed as a single frame: its bytes straddle the part boundary,
        // exercising the inner split/rollover loop.
        let body = full(Bytes::from(object));
        let out = collect_ok(decrypting_multipart(
            body,
            Alg::Aes256Gcm,
            KEY,
            CHUNK,
            spans,
            None,
        ))
        .await;

        let expected: Vec<u8> = parts
            .iter()
            .flat_map(|(_, pt)| pt.iter().copied())
            .collect();
        assert_eq!(out, expected);
    }

    #[tokio::test]
    async fn decrypting_multipart_reports_a_corrupted_part_and_stops() {
        let (parts, mut cts) = two_part_object();
        cts[0][0] ^= 0xFF; // corrupt a byte inside the first part's ciphertext
        let object: Vec<u8> = cts.iter().flatten().copied().collect();
        let entries: Vec<(u32, u64)> = parts.iter().map(|(n, pt)| (*n, pt.len() as u64)).collect();
        let spans = part_layout(Alg::Aes256Gcm, CHUNK as u64, &entries);

        let counter = Arc::new(AtomicU64::new(0));
        let body = full(Bytes::from(object));
        let res = decrypting_multipart(
            body,
            Alg::Aes256Gcm,
            KEY,
            CHUNK,
            spans,
            Some(counter.clone()),
        )
        .collect()
        .await;

        assert!(res.is_err());
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }
}
