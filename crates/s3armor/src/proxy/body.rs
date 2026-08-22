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
pub fn dechunking(mut inner: Incoming, mut verifier: Option<ChunkVerifier>) -> ProxyBody {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    tokio::spawn(async move {
        let mut dechunker = Dechunker::new();
        loop {
            let raw = match inner.frame().await {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => data,
                    Err(_) => continue, // a trailers frame on the raw wire body; ignore
                },
                Some(Err(e)) => {
                    let _ = tx.send(Err(io_err(e))).await;
                    return;
                }
                None => {
                    if !dechunker.is_done() {
                        let _ = tx
                            .send(Err(io_err("aws-chunked body ended before its terminator")))
                            .await;
                    }
                    return;
                }
            };
            let chunks = match dechunker.feed(&raw) {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Err(io_err(chunk_error_message(&e)))).await;
                    return;
                }
            };
            for (data, signature) in chunks {
                if let (Some(v), Some(sig)) = (verifier.as_mut(), signature.as_deref()) {
                    if let Err(e) = v.verify_and_advance(&data, sig) {
                        let _ = tx.send(Err(io_err(chunk_error_message(&e)))).await;
                        return;
                    }
                }
                if data.is_empty() {
                    continue; // the terminating zero-length chunk carries no bytes to forward
                }
                if tx.send(Ok(Frame::data(Bytes::from(data)))).await.is_err() {
                    return;
                }
            }
        }
    });
    StreamBody::new(ReceiverStream(rx)).boxed()
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
/// `trailer`, when set, is appended after the final frame — lets a caller
/// concatenate a sealed footer onto a part's ciphertext stream without an
/// extra buffering pass. The proxy's own multipart write path
/// (`intercept::mpu`) never needs this: it either uploads the footer as
/// its own part, or merges it into a buffered small tail with
/// `body::full`. No caller in this tree currently passes `Some` here.
pub fn encrypting(
    mut inner: ProxyBody,
    alg: Alg,
    dek: [u8; 32],
    chunk_size: usize,
    expected_md5: Option<[u8; 16]>,
    part_number: u32,
    trailer: Option<Bytes>,
) -> ProxyBody {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    tokio::spawn(async move {
        let mut enc = Encryptor::new(alg, dek, part_number, chunk_size);
        let mut hasher = expected_md5.is_some().then(Md5::new);
        loop {
            match inner.frame().await {
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue; // a trailers frame; ignore
                    };
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
                    if let (Some(h), Some(expected)) = (hasher, expected_md5) {
                        let got: [u8; 16] = h.finalize().into();
                        if got != expected {
                            let _ = tx
                                .send(Err(io_err(
                                    "Content-MD5 does not match the streamed plaintext",
                                )))
                                .await;
                            return;
                        }
                    }
                    let mut out = enc.finish();
                    if let Some(t) = &trailer {
                        out.extend_from_slice(t);
                    }
                    let _ = tx.send(Ok(Frame::data(Bytes::from(out)))).await;
                    return;
                }
            }
        }
    });
    StreamBody::new(ReceiverStream(rx)).boxed()
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
#[expect(
    clippy::cast_possible_truncation,
    reason = "take = min(data.len(), remaining) as usize is bounded by data.len(), an already-usize value"
)]
pub fn decrypting_multipart(
    mut inner: Incoming,
    alg: Alg,
    dek: [u8; 32],
    chunk_size: usize,
    spans: Vec<PartSpan>,
    on_verify_failure: Option<Arc<AtomicU64>>,
) -> ProxyBody {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    tokio::spawn(async move {
        let mut spans = spans.into_iter();
        let Some(mut span) = spans.next() else {
            return; // an empty multipart object (no parts) — nothing to decrypt
        };
        let mut dec = Decryptor::new(alg, dek, span.number, chunk_size);
        let mut consumed_ct = 0u64;
        loop {
            match inner.frame().await {
                Some(Ok(frame)) => {
                    let Ok(mut data) = frame.into_data() else {
                        continue;
                    };
                    while !data.is_empty() {
                        let remaining = span.ct_len - consumed_ct;
                        let take = (data.len() as u64).min(remaining) as usize;
                        let piece = data.split_to(take);
                        consumed_ct += take as u64;
                        match dec.push(&piece) {
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
                        if consumed_ct < span.ct_len {
                            continue;
                        }
                        match dec.finish() {
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
                        match spans.next() {
                            Some(next) => {
                                span = next;
                                consumed_ct = 0;
                                dec = Decryptor::new(alg, dek, span.number, chunk_size);
                            }
                            // Every part decrypted — whatever remains in
                            // `data` (or arrives in a later frame) is the
                            // footer and trailer. Stop here.
                            None => return,
                        }
                    }
                }
                Some(Err(e)) => {
                    let _ = tx.send(Err(io_err(e))).await;
                    return;
                }
                None => {
                    if consumed_ct != span.ct_len {
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
