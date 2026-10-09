//! Request-body transforms: verify-while-streaming (`hashing`) and
//! dechunk-and-verify-while-streaming (`dechunking`). Both keep memory at
//! O(chunk) — no whole-body buffer anywhere in this module — and both
//! reject a tampered body *before* forwarding completes, by ending the
//! outbound body stream with an `Err` frame instead of a clean EOF. Hyper's
//! client sees that as a failed send and aborts the connection to the
//! backend rather than completing it, so a tampered PUT never commits.
//! Every such client-caused abort also records its typed reason in the
//! request's [`AbortSlot`], so `proxy::forward` answers with the S3 code
//! for that failure instead of a generic `502`.
//!
//! Both are implemented as a spawned task feeding a channel, not a
//! hand-written `poll_frame` state machine — simpler to get right, and the
//! backpressure from a bounded channel already gives O(chunk) memory.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

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
use crate::proxy::error::S3Error;

pub type ProxyBody = BoxBody<Bytes, std::io::Error>;

/// Where a verifying wrapper records *why* it ended the outbound stream.
/// The wrapper runs in a spawned task with no path back to the request, so
/// the typed reason travels here instead. `proxy::forward` reads the slot
/// when the backend request fails: a stored reason is the client's fault
/// and answers with its own S3 code, an empty slot is a real upstream
/// failure and stays a `502`.
type AbortSlot = Arc<OnceLock<S3Error>>;

tokio::task_local! {
    static ABORT_REASON: AbortSlot;
}

/// Runs one request with its own abort slot. Called once, from
/// `proxy::handle`.
pub(crate) async fn with_abort_slot<T>(fut: impl Future<Output = T>) -> T {
    ABORT_REASON.scope(AbortSlot::default(), fut).await
}

/// Why a verifying body aborted this request, when one did. `None` outside
/// a request — the CLI tools call `forward` with no slot in scope.
pub(crate) fn abort_reason() -> Option<S3Error> {
    ABORT_REASON
        .try_with(|slot| slot.get().cloned())
        .ok()
        .flatten()
}

fn io_err(msg: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(msg.to_string())
}

/// The outbound half of a verifying body: the frame channel, plus this
/// request's [`AbortSlot`].
struct Outbound {
    tx: mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
    abort: AbortSlot,
}

impl Outbound {
    /// Builds the channel and captures the current request's slot. Call
    /// before the wrapper task is spawned — the slot is a task-local, and a
    /// spawned task does not inherit one.
    fn new() -> (Self, mpsc::Receiver<Result<Frame<Bytes>, std::io::Error>>) {
        let (tx, rx) = mpsc::channel(4);
        let abort = ABORT_REASON.try_with(Clone::clone).unwrap_or_default();
        (Self { tx, abort }, rx)
    }

    /// Forwards one frame. `false` when the receiver is gone and the task
    /// must stop.
    async fn send(&self, frame: Frame<Bytes>) -> bool {
        self.tx.send(Ok(frame)).await.is_ok()
    }

    /// Ends the stream because the client sent something that failed
    /// verification. Records the reason first: `proxy::forward` reads the
    /// slot as soon as it sees the request fail.
    async fn fail(&self, reason: S3Error) {
        let message = reason.message.clone();
        let _ = self.abort.set(reason);
        let _ = self.tx.send(Err(io_err(message))).await;
    }

    /// Ends the stream on a transport error reading the client's body. No
    /// typed reason, so the request stays a `502`.
    async fn fail_transport(&self, e: impl std::fmt::Display) {
        let _ = self.tx.send(Err(io_err(e))).await;
    }
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
    let (out, rx) = Outbound::new();
    tokio::spawn(async move {
        let mut hasher = Sha256::new();
        // Hold the most recent frame back. The outbound stream must not
        // satisfy content-length until the digest is verified at EOF —
        // otherwise hyper stops polling the body and a mismatch reported
        // after the last byte is never seen, so a tampered passthrough PUT
        // would commit. Same discipline as `finish_encrypting`.
        let mut pending: Option<Frame<Bytes>> = None;
        loop {
            match inner.frame().await {
                Some(Ok(frame)) => {
                    if !push_hashing_frame(frame, &mut hasher, &mut pending, &out).await {
                        return;
                    }
                }
                Some(Err(e)) => {
                    out.fail_transport(e).await;
                    return;
                }
                None => {
                    finish_hashing(hasher, pending, &expected_sha256_hex, &out).await;
                    return;
                }
            }
        }
    });
    StreamBody::new(ReceiverStream(rx)).boxed()
}

/// Feeds one inbound frame's data into `hasher`, then forwards whichever
/// frame `pending` was already holding back — see `hashing`'s doc comment
/// for why the most recent frame is always held one step behind. Returns
/// `false` to stop the caller: the receiver is gone.
async fn push_hashing_frame(
    frame: Frame<Bytes>,
    hasher: &mut Sha256,
    pending: &mut Option<Frame<Bytes>>,
    out: &Outbound,
) -> bool {
    if let Some(data) = frame.data_ref() {
        hasher.update(data);
    }
    let Some(prev) = pending.replace(frame) else {
        return true;
    };
    out.send(prev).await
}

/// Finalises a `hashing` stream at EOF: verifies the digest, then sends the
/// one frame still held back.
async fn finish_hashing(
    hasher: Sha256,
    pending: Option<Frame<Bytes>>,
    expected_sha256_hex: &str,
    out: &Outbound,
) {
    let digest = hex::encode(hasher.finalize());
    if digest != expected_sha256_hex {
        out.fail(S3Error::payload_hash_mismatch(expected_sha256_hex, &digest))
            .await;
        return;
    }
    if let Some(last) = pending {
        out.send(last).await;
    }
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
    let (out, rx) = Outbound::new();
    tokio::spawn(async move {
        let mut dechunker = Dechunker::new();
        loop {
            let Some(raw) = next_raw_frame(&mut inner, &out, &dechunker).await else {
                return;
            };
            let chunks = match dechunker.feed(&raw) {
                Ok(c) => c,
                Err(e) => {
                    out.fail(S3Error::incomplete_body(chunk_error_message(&e)))
                        .await;
                    return;
                }
            };
            if !forward_chunks(chunks, &mut verifier, &out).await {
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
async fn next_raw_frame<B>(inner: &mut B, out: &Outbound, dechunker: &Dechunker) -> Option<Bytes>
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
                out.fail_transport(e).await;
                return None;
            }
            None => {
                if !dechunker.is_done() {
                    out.fail(S3Error::incomplete_body(
                        "aws-chunked body ended before its terminator",
                    ))
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
    out: &Outbound,
) -> bool {
    for (data, signature) in chunks {
        if let Some(v) = verifier.as_mut() {
            // A signed stream (STREAMING-AWS4-HMAC-SHA256-PAYLOAD, which the
            // signed `x-amz-content-sha256` locks in) must carry a signature
            // on every chunk, the zero-length terminator included. A missing
            // signature means an attacker stripped it; fail closed rather
            // than forward the chunk unverified.
            let Some(sig) = signature.as_deref() else {
                out.fail(S3Error::signature_does_not_match()).await;
                return false;
            };
            if v.verify_and_advance(&data, sig).is_err() {
                out.fail(S3Error::signature_does_not_match()).await;
                return false;
            }
        }
        if data.is_empty() {
            continue; // the terminating zero-length chunk carries no bytes to forward
        }
        if !out.send(Frame::data(Bytes::from(data))).await {
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
    let (out, rx) = Outbound::new();
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
                        out.fail(S3Error::incomplete_body(
                            "streamed plaintext exceeds the declared decoded length",
                        ))
                        .await;
                        return;
                    }
                    if let Some(h) = hasher.as_mut() {
                        h.update(&data);
                    }
                    let ct = enc.push(&data);
                    if !ct.is_empty() && !out.send(Frame::data(Bytes::from(ct))).await {
                        return;
                    }
                }
                Some(Err(e)) => {
                    out.fail_transport(e).await;
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
                        &out,
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
    out: &Outbound,
) {
    if seen != expected_pt_len {
        out.fail(S3Error::incomplete_body(
            "streamed plaintext is shorter than the declared decoded length",
        ))
        .await;
        return;
    }
    if !check_md5(hasher, expected_md5) {
        out.fail(S3Error::bad_digest()).await;
        return;
    }
    let mut ct = enc.finish();
    if let Some(t) = &trailer {
        ct.extend_from_slice(t);
    }
    out.send(Frame::data(Bytes::from(ct))).await;
}

/// Checks a finished MD5 hasher against the client's `Content-MD5`, when
/// both are present. `true` when there's nothing to check (no hasher means
/// `expected_md5` was `None` to begin with).
///
/// MD5 is required here for S3 API compatibility, not for integrity: the
/// client picks the hash (`Content-MD5`), and the same 16 bytes become the
/// plaintext ETag returned on PUT/HEAD/GET (`docs/ARCHITECTURE.md` "ETag
/// policy") — a stronger hash would produce an ETag no S3 client expects.
/// Actual integrity rests on AES-256-GCM/XChaCha20-Poly1305 AEAD per chunk
/// plus SigV4 SHA-256 on the request; the ETag itself is stored AEAD-sealed
/// (`s3a-emd5`), so it isn't a content-guessing oracle for the operator.
fn check_md5(hasher: Option<Md5>, expected: Option<[u8; 16]>) -> bool {
    let (Some(h), Some(expected)) = (hasher, expected) else {
        return true;
    };
    let got: [u8; 16] = h.finalize().into();
    got == expected
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
/// Streams the range O(chunk): the `Decryptor` yields every non-final
/// covered chunk from `push` (all of them inside the requested window, so
/// they stream straight out after the leading `trim_start` is dropped), and
/// only the final chunk from `finish` needs `trim_end` applied. Each chunk
/// is verified before it is released, and a send that fails because the
/// client disconnected stops the task instead of draining the backend.
pub fn decrypting_range<B>(
    mut inner: B,
    alg: Alg,
    dek: [u8; 32],
    chunk_size: usize,
    plan: &RangePlan,
    total_chunks: u64,
    on_verify_failure: Option<Arc<AtomicU64>>,
) -> ProxyBody
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::fmt::Display + Send,
{
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
        // Leading plaintext bytes still to skip. `trim_start` is an offset
        // within the first chunk (`plan_range`'s doc comment), so it is
        // consumed from the first bytes `push` yields.
        let mut to_drop = trim_start;
        loop {
            match inner.frame().await {
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    if !push_range_frame(
                        &mut dec,
                        &data,
                        &mut to_drop,
                        &tx,
                        on_verify_failure.as_ref(),
                    )
                    .await
                    {
                        return;
                    }
                }
                Some(Err(e)) => {
                    let _ = tx.send(Err(io_err(e))).await;
                    return;
                }
                None => {
                    finish_range(dec, to_drop, trim_end, &tx, on_verify_failure.as_ref()).await;
                    return;
                }
            }
        }
    });
    StreamBody::new(ReceiverStream(rx)).boxed()
}

/// Pushes one ciphertext frame through `dec` and forwards the resulting
/// plaintext, dropping the leading `to_drop` bytes still owed from
/// `trim_start` (`to_drop` persists across calls). Returns `false` to stop
/// the caller: a verify failure (its `Err` frame is already sent) or a gone
/// receiver.
async fn push_range_frame(
    dec: &mut Decryptor,
    data: &Bytes,
    to_drop: &mut usize,
    tx: &mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
    on_verify_failure: Option<&Arc<AtomicU64>>,
) -> bool {
    let mut pt = match dec.push(data) {
        Ok(pt) => pt,
        Err(e) => {
            note_chunk_verify_failure(on_verify_failure);
            let _ = tx.send(Err(io_err(decrypt_error_message(&e)))).await;
            return false;
        }
    };
    if *to_drop >= pt.len() {
        *to_drop -= pt.len();
        return true;
    }
    pt.drain(..*to_drop);
    *to_drop = 0;
    if pt.is_empty() {
        return true;
    }
    tx.send(Ok(Frame::data(Bytes::from(pt)))).await.is_ok()
}

/// Finishes one ranged decrypt: takes the last chunk from `dec`, trims it
/// to the exact requested window, and sends it. `trim_end` is an offset
/// within this final chunk. `to_drop` is any leading trim that is still
/// pending (a range that covers a single chunk). `decrypting_range` calls
/// this once at EOF. `decrypting_multipart_range` calls it once for each
/// plan entry, when the full ciphertext of that entry has arrived. Returns
/// `false` to stop the caller: a verify failure (its `Err` frame is
/// already sent) or a gone receiver.
async fn finish_range(
    dec: Decryptor,
    to_drop: usize,
    trim_end: usize,
    tx: &mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
    on_verify_failure: Option<&Arc<AtomicU64>>,
) -> bool {
    match dec.finish() {
        Ok(mut pt) => {
            pt.truncate(trim_end);
            if to_drop < pt.len() {
                pt.drain(..to_drop);
            } else {
                pt.clear();
            }
            pt.is_empty() || tx.send(Ok(Frame::data(Bytes::from(pt)))).await.is_ok()
        }
        Err(e) => {
            note_chunk_verify_failure(on_verify_failure);
            let _ = tx.send(Err(io_err(decrypt_error_message(&e)))).await;
            false
        }
    }
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
            let piece = take_up_to(&mut data, self.span.ct_len - self.consumed_ct);
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

/// Splits off the front of `data`, at most `remaining` bytes. `remaining`
/// is the ciphertext that the current part (`MultipartCursor`) or the
/// current plan entry (`RangeCursor`) still owns. The result is the piece
/// that the next `Decryptor::push` gets.
#[expect(
    clippy::cast_possible_truncation,
    reason = "take = min(data.len(), remaining) as usize is bounded by data.len(), an already-usize value"
)]
fn take_up_to(data: &mut Bytes, remaining: u64) -> Bytes {
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

/// Decrypts a ciphertext byte range that spans one or more parts of a
/// multipart v1 object. `plan` is
/// [`s3armor_format::v1::plan_multipart_range`]'s output. The caller sends
/// one backend ranged GET that covers the local `[ct_start, ct_end)` of
/// each entry, in part order. These spans are contiguous (see the doc
/// comment of `plan_multipart_range`). So `inner` gives exactly that
/// ciphertext, and each entry owns exactly `ct_end - ct_start` bytes of it.
///
/// `handle_ranged` in `intercept::get` sends every satisfiable range of a
/// multipart object here, also a whole-object range such as `bytes=0-`.
/// Thus this function streams. It walks the entries with a [`RangeCursor`]
/// and keeps memory at O(chunk): the decryptor holds at most one frame plus
/// one incoming frame, and the channel holds at most 4 frames. The object
/// size and the part size do not change this. Each chunk is verified
/// before its plaintext leaves the task.
///
/// The task stops when the client is gone, also while the backend sends
/// nothing: it checks `tx.closed()` before each read. After the last
/// entry, the task reads the backend one more time. An EOF on that read
/// lets hyper put the backend connection back in its pool. Data on that
/// read means that the backend sent more than the plan asked for: the task
/// stops and drops `inner`, which closes that connection. The task ignores
/// a transport error on that read, because it verified and sent all
/// requested bytes before.
///
/// The `Err`-frame protocol is the same as in the other decrypt paths. A
/// verify failure increments `on_verify_failure` and ends the stream with
/// an `Err` frame. A transport error or an EOF before the last entry is
/// complete also ends the stream with an `Err` frame, but does not change
/// the counter: a body that stops early is not a tamper.
pub fn decrypting_multipart_range<B>(
    mut inner: B,
    alg: Alg,
    dek: [u8; 32],
    chunk_size: usize,
    plan: Vec<(PartSpan, RangePlan)>,
    on_verify_failure: Option<Arc<AtomicU64>>,
) -> ProxyBody
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::fmt::Display + Send,
{
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    tokio::spawn(async move {
        let Some(mut cursor) = RangeCursor::new(alg, dek, chunk_size, plan) else {
            return; // an empty plan: the caller answers an empty 206 itself
        };
        loop {
            // `biased`: when the client is gone, stop before the task
            // decrypts one more frame. `frame()` only polls the body, so a
            // dropped `frame()` future loses no bytes.
            let next = tokio::select! {
                biased;
                () = tx.closed() => return,
                next = inner.frame() => next,
            };
            match next {
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue; // a trailers frame; ignore
                    };
                    if cursor.is_done() {
                        // The backend sent more than the plan asked for.
                        // All requested bytes are already out. Dropping
                        // `inner` closes that connection. Never drain a
                        // body that has no limit.
                        return;
                    }
                    if !cursor.feed(data, &tx, on_verify_failure.as_ref()).await {
                        return;
                    }
                }
                Some(Err(e)) => {
                    if !cursor.is_done() {
                        let _ = tx.send(Err(io_err(e))).await;
                    }
                    return;
                }
                None => {
                    if !cursor.is_done() {
                        let _ = tx
                            .send(Err(io_err("multipart ranged read ended before its span")))
                            .await;
                    }
                    return;
                }
            }
        }
    });
    StreamBody::new(ReceiverStream(rx)).boxed()
}

/// The cursor that `decrypting_multipart_range` walks. It holds the
/// `Decryptor` of the current plan entry, the ciphertext that this entry
/// still owns, and the trims of this entry.
///
/// Each entry uses its own `trim_start` and `trim_end`.
/// `plan_multipart_range` sets `trim_start` to 0 for each entry after the
/// first entry. It sets `trim_end` to the real length of the last chunk
/// for each entry before the last entry. Thus the result is the same as
/// "`trim_start` only on the first entry, `trim_end` only on the last
/// entry", and the cursor needs no entry index.
struct RangeCursor {
    alg: Alg,
    dek: [u8; 32],
    chunk_size: usize,
    entries: std::vec::IntoIter<(PartSpan, RangePlan)>,
    /// The decryptor of the current entry. `None` when every entry is
    /// finished, or after `feed` returned `false`.
    dec: Option<Decryptor>,
    /// The ciphertext bytes that the current entry still owns.
    remaining: u64,
    /// The leading plaintext bytes of the current entry that the cursor
    /// must still skip. `push_range_frame` decreases it.
    to_drop: usize,
    /// The end offset in the final chunk of the current entry.
    /// `finish_range` uses it.
    trim_end: usize,
}

impl RangeCursor {
    /// `None` for an empty plan: there is nothing to decrypt.
    fn new(
        alg: Alg,
        dek: [u8; 32],
        chunk_size: usize,
        plan: Vec<(PartSpan, RangePlan)>,
    ) -> Option<Self> {
        let mut entries = plan.into_iter();
        let (span, range_plan) = entries.next()?;
        let mut cursor = Self {
            alg,
            dek,
            chunk_size,
            entries,
            dec: None,
            remaining: 0,
            to_drop: 0,
            trim_end: 0,
        };
        cursor.start(&span, &range_plan);
        Some(cursor)
    }

    /// Makes `span` and `range_plan` the current entry.
    fn start(&mut self, span: &PartSpan, range_plan: &RangePlan) {
        // The encryptor sealed the final frame of this entry with
        // `last = true` only when that frame is the final chunk of the part.
        let final_frame_is_part_end =
            range_plan.last_chunk + 1 == n_chunks(span.pt_len, self.chunk_size as u64);
        self.dec = Some(Decryptor::new_at(
            self.alg,
            self.dek,
            span.number,
            self.chunk_size,
            range_plan.first_chunk,
            final_frame_is_part_end,
        ));
        self.remaining = range_plan.ct_end - range_plan.ct_start;
        self.to_drop = range_plan.trim_start;
        self.trim_end = range_plan.trim_end;
    }

    /// Feeds one inbound frame to the decryptor of the current entry. When
    /// an entry has all of its ciphertext, the cursor finishes it and
    /// starts the next entry. One frame can hold the end of one entry and
    /// the start of the next entry. The cursor ignores the bytes of a frame
    /// that come after the last entry. Returns `false` to stop the caller:
    /// a verify failure (its `Err` frame is already sent) or a gone
    /// receiver. Do not use the cursor again after `false`.
    async fn feed(
        &mut self,
        mut data: Bytes,
        tx: &mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
        on_verify_failure: Option<&Arc<AtomicU64>>,
    ) -> bool {
        while !data.is_empty() {
            let Some(mut dec) = self.dec.take() else {
                break; // every entry is finished
            };
            let piece = take_up_to(&mut data, self.remaining);
            self.remaining -= piece.len() as u64;
            if !push_range_frame(&mut dec, &piece, &mut self.to_drop, tx, on_verify_failure).await {
                return false;
            }
            if self.remaining > 0 {
                self.dec = Some(dec);
                continue;
            }
            // The cursor calls `finish_range` only when `dec` has the full
            // ciphertext of the entry. Thus a body that stops early never
            // shows as a verify failure.
            if !finish_range(dec, self.to_drop, self.trim_end, tx, on_verify_failure).await {
                return false;
            }
            if let Some((span, range_plan)) = self.entries.next() {
                self.start(&span, &range_plan);
            }
        }
        true
    }

    /// True when every entry is finished.
    const fn is_done(&self) -> bool {
        self.dec.is_none()
    }
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
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use futures_util::stream;
    use s3armor_format::v1::{
        decrypt_all, encrypt_all, part_layout, plan_multipart_range, plan_range,
    };

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

    /// Builds a verifying body inside a request-scoped abort slot, runs it
    /// to its `Err` frame, and returns the reason the wrapper recorded —
    /// the value `proxy::forward` answers the client with. `build` must run
    /// inside the scope: the wrapper captures the slot when it is built.
    async fn abort_of(build: impl FnOnce() -> ProxyBody) -> S3Error {
        with_abort_slot(async move {
            let res = build().collect().await;
            assert!(res.is_err(), "expected an aborted stream");
            abort_reason().expect("an aborted wrapper records why")
        })
        .await
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
    async fn dechunking_rejects_a_signed_stream_whose_chunk_lost_its_signature() {
        // Verifier present (signed scheme), but the wire chunk carries no
        // ;chunk-signature= extension: an attacker stripped it. Fail closed,
        // never forward the chunk unverified.
        let seed = "0".repeat(64);
        let mut wire = chunk_wire(b"payload", None);
        wire.extend(final_chunk(None));
        let res = dechunking(full(Bytes::from(wire)), Some(verifier(&seed)))
            .collect()
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn dechunking_rejects_a_signed_stream_with_an_unsigned_terminator() {
        // A valid signed data chunk, then a terminator stripped of its
        // signature. The terminator is still checked, so this fails.
        let seed = "0".repeat(64);
        let sig1 = chain_signature(&seed, b"payload");
        let mut wire = chunk_wire(b"payload", Some(&sig1));
        wire.extend(final_chunk(None));
        let res = dechunking(full(Bytes::from(wire)), Some(verifier(&seed)))
            .collect()
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn dechunking_reports_a_bad_chunk_signature_as_signature_does_not_match() {
        let seed = "0".repeat(64);
        let wire = chunk_wire(b"payload", Some(&"f".repeat(64)));
        let err = abort_of(|| dechunking(full(Bytes::from(wire)), Some(verifier(&seed)))).await;
        assert_eq!(err.code, "SignatureDoesNotMatch");
        assert_eq!(err.status, http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_broken_client_stream_records_no_abort_reason() {
        // Nothing the proxy verifies failed — the client's own stream broke.
        // The slot stays empty, so `proxy::forward` still answers 502.
        let reason = with_abort_slot(async {
            let frames = stream::iter(vec![Err::<Frame<Bytes>, std::io::Error>(io_err(
                "client went away",
            ))]);
            let res = dechunking(StreamBody::new(frames).boxed(), None)
                .collect()
                .await;
            assert!(res.is_err());
            abort_reason()
        })
        .await;
        assert!(reason.is_none(), "a transport failure is not the client's");
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
    async fn encrypting_reports_a_content_md5_mismatch_as_bad_digest() {
        let err = abort_of(|| {
            encrypting(
                full(Bytes::from_static(b"payload")),
                Alg::Aes256Gcm,
                KEY,
                CHUNK,
                Some([0u8; 16]),
                7,
                0,
                None,
            )
        })
        .await;
        assert_eq!(err.code, "BadDigest");
        assert_eq!(err.status, http::StatusCode::BAD_REQUEST);
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

    #[tokio::test]
    #[expect(
        clippy::cast_possible_truncation,
        clippy::integer_division,
        reason = "test ranges are tiny constants; the mid split needs no precision"
    )]
    async fn decrypting_range_streams_the_exact_requested_window() {
        // 3 chunks of CHUNK=16: two full, one 8-byte final.
        let plaintext: Vec<u8> = (0u8..40).collect();
        let ct = encrypt_all(Alg::Aes256Gcm, &KEY, 0, CHUNK, &plaintext);
        let pt_len = plaintext.len() as u64;
        let total_chunks = 3;
        // Windows that exercise: trims on both edges across chunks, a
        // single middle chunk, a window ending at the object end, and a
        // whole single chunk with no trim.
        for (start, end) in [(5u64, 35u64), (18, 25), (33, 40), (16, 32)] {
            let plan = plan_range(Alg::Aes256Gcm, pt_len, CHUNK as u64, start, end).unwrap();
            let covered = ct[plan.ct_start as usize..plan.ct_end as usize].to_vec();
            // Split mid-frame so the decryptor state carries across reads.
            let mid = covered.len() / 2;
            let body = body_from_frames(vec![covered[..mid].to_vec(), covered[mid..].to_vec()]);
            let out = collect_ok(decrypting_range(
                body,
                Alg::Aes256Gcm,
                KEY,
                CHUNK,
                &plan,
                total_chunks,
                None,
            ))
            .await;
            assert_eq!(
                out,
                &plaintext[start as usize..end as usize],
                "range {start}..{end}"
            );
        }
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

    // ---- Ranged reads on a multipart object (`decrypting_multipart_range`) ----

    /// Both ciphers. Their frame overheads differ (28 and 40 bytes).
    const ALGS: [Alg; 2] = [Alg::Aes256Gcm, Alg::XChaCha20Poly1305];

    /// Part number and plaintext length of the three parts that most
    /// ranged-read tests use. The part numbers skip 3 and 4 on purpose.
    const SMALL_PARTS: [(u32, usize); 3] = [(1, 40), (2, 32), (5, 50)];

    /// The size of each body frame in the tests that feed small frames. It
    /// is smaller than one cipher frame, so most cipher frames arrive in
    /// pieces.
    const SMALL_FRAME: usize = 7;

    /// A multipart object for the ranged-read tests. It holds the plaintext,
    /// the ciphertext of each part, and the part layout.
    struct RangeObject {
        alg: Alg,
        plaintext: Vec<u8>,
        part_cts: Vec<Vec<u8>>,
        spans: Vec<PartSpan>,
    }

    impl RangeObject {
        /// `parts` lists the part number and plaintext length of each part.
        /// The plaintext bytes change from place to place, so a wrong slice
        /// shows up as a wrong byte.
        fn new(alg: Alg, parts: &[(u32, usize)]) -> Self {
            let total: usize = parts.iter().map(|&(_, len)| len).sum();
            let plaintext: Vec<u8> = (0..total)
                .map(|i| u8::try_from((i * 31 + 7) % 251).unwrap())
                .collect();
            let mut offset = 0;
            let mut part_cts = Vec::new();
            for &(number, len) in parts {
                let part = &plaintext[offset..offset + len];
                part_cts.push(encrypt_all(alg, &KEY, number, CHUNK, part));
                offset += len;
            }
            let layout: Vec<(u32, u64)> = parts.iter().map(|&(n, len)| (n, len as u64)).collect();
            let spans = part_layout(alg, CHUNK as u64, &layout);
            Self {
                alg,
                plaintext,
                part_cts,
                spans,
            }
        }

        fn plan(&self, start: usize, end: usize) -> Vec<(PartSpan, RangePlan)> {
            plan_multipart_range(
                &self.spans,
                self.alg,
                CHUNK as u64,
                start as u64,
                end as u64,
            )
            .unwrap()
        }

        /// The ciphertext bytes the backend serves for `plan`. The bounds
        /// use the same arithmetic as `handle_ranged` in `intercept/get.rs`.
        fn window(&self, plan: &[(PartSpan, RangePlan)]) -> Vec<u8> {
            let (first_span, first) = plan.first().unwrap();
            let (last_span, last) = plan.last().unwrap();
            let from = usize::try_from(first_span.ct_start + first.ct_start).unwrap();
            let to = usize::try_from(last_span.ct_start + last.ct_end).unwrap();
            self.part_cts.concat()[from..to].to_vec()
        }

        /// Reads `[start, end)` through `decrypting_multipart_range` and
        /// checks it against the same slice of the plaintext.
        async fn assert_slice(&self, start: usize, end: usize) {
            let plan = self.plan(start, end);
            let window = self.window(&plan);
            let body = body_from_frames(split_frames(&window, SMALL_FRAME));
            let out = collect_ok(decrypting_multipart_range(
                body, self.alg, KEY, CHUNK, plan, None,
            ))
            .await;
            assert_eq!(
                out,
                &self.plaintext[start..end],
                "alg {:?} range {start}..{end}",
                self.alg
            );
        }
    }

    fn split_frames(data: &[u8], frame_len: usize) -> Vec<Vec<u8>> {
        data.chunks(frame_len).map(<[u8]>::to_vec).collect()
    }

    /// Gives a spawned task time to run when the test thread has no other
    /// work: 64 yields, then a short sleep.
    async fn let_tasks_run() {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    /// A body that counts the frames the reader pulls from it. It returns
    /// `None` once every frame is out.
    struct CountingBody {
        frames: VecDeque<Bytes>,
        pulled: Arc<AtomicUsize>,
    }

    impl http_body::Body for CountingBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            let next = self.frames.pop_front();
            if next.is_some() {
                self.pulled.fetch_add(1, Ordering::SeqCst);
            }
            Poll::Ready(next.map(|data| Ok(Frame::data(data))))
        }
    }

    /// A body that never yields a frame and never wakes its reader. It
    /// records when the reader drops it.
    struct NeverBody {
        dropped: Arc<AtomicBool>,
    }

    impl http_body::Body for NeverBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Pending
        }
    }

    impl Drop for NeverBody {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn multipart_range_pulls_only_a_few_frames_without_a_reader() {
        // Part plaintext lengths 128, 136 and 128: eight full chunks, eight
        // full plus one short, eight full.
        let parts = [(1u32, 128usize), (2, 136), (3, 128)];
        for alg in ALGS {
            let obj = RangeObject::new(alg, &parts);
            // One body frame for each cipher frame. Each part ends on its
            // own frame boundary.
            let frames: VecDeque<Bytes> = obj
                .part_cts
                .iter()
                .flat_map(|ct| ct.chunks(CHUNK + alg.overhead()))
                .map(Bytes::copy_from_slice)
                .collect();
            let total_frames = frames.len();
            let pulled = Arc::new(AtomicUsize::new(0));
            let backend = CountingBody {
                frames,
                pulled: pulled.clone(),
            };
            let plan = obj.plan(0, obj.plaintext.len());
            // Keep the body alive and never read it.
            let body = decrypting_multipart_range(backend, alg, KEY, CHUNK, plan, None);
            let_tasks_run().await;
            let pulled_now = pulled.load(Ordering::SeqCst);
            // The exact count is 6: four frames wait in the channel, one is
            // blocked in `send`, and one is held back by `Decryptor::push`.
            assert!(
                pulled_now >= 4,
                "alg {alg:?}: pulled {pulled_now} of {total_frames}"
            );
            assert!(
                pulled_now <= 8,
                "alg {alg:?}: pulled {pulled_now} of {total_frames}"
            );
            assert!(
                pulled_now < total_frames,
                "alg {alg:?}: pulled {pulled_now} of {total_frames}"
            );
            drop(body);
        }
    }

    #[tokio::test]
    async fn multipart_range_matches_plaintext_slices() {
        // Ranges that touch a chunk edge, a part edge, both ends of the
        // object, and the short last chunk.
        const NAMED: [(usize, usize); 10] = [
            (3, 9),     // inside one chunk
            (10, 20),   // across a chunk boundary
            (35, 45),   // across the part boundary at 40
            (40, 72),   // exactly one whole part
            (20, 40),   // ends exactly at a part boundary
            (100, 122), // open-ended: `bytes=100-`
            (0, 122),   // the whole object
            (121, 122), // the last byte
            (120, 121), // inside the short last chunk of the last part
            (30, 100),  // through all three parts
        ];
        for alg in ALGS {
            let obj = RangeObject::new(alg, &SMALL_PARTS);
            let total = obj.plaintext.len();
            assert_eq!(total, 122);
            for (start, end) in NAMED {
                obj.assert_slice(start, end).await;
            }
            for start in 0..total {
                for end in [start + 1, (start + 17).min(total), total] {
                    obj.assert_slice(start, end).await;
                }
            }
        }
    }

    #[tokio::test]
    async fn multipart_range_tamper_in_second_part_ends_with_err() {
        for alg in ALGS {
            let obj = RangeObject::new(alg, &SMALL_PARTS);
            let plan = obj.plan(0, obj.plaintext.len());
            let mut window = obj.window(&plan);
            // The window starts at byte 0 of part 1. Flip the first
            // ciphertext byte after the nonce in the first frame of part 2.
            let part2_start = usize::try_from(obj.spans[1].ct_start).unwrap();
            window[part2_start + alg.nonce_len()] ^= 0xFF;

            let counter = Arc::new(AtomicU64::new(0));
            let body = body_from_frames(split_frames(&window, SMALL_FRAME));
            let mut out =
                decrypting_multipart_range(body, alg, KEY, CHUNK, plan, Some(counter.clone()));
            let mut got = Vec::new();
            let mut failure = None;
            while let Some(frame) = out.frame().await {
                match frame {
                    Ok(frame) => {
                        if let Ok(data) = frame.into_data() {
                            got.extend_from_slice(&data);
                        }
                    }
                    Err(e) => {
                        failure = Some(e);
                        break;
                    }
                }
            }
            let failure = failure.expect("a tampered part must end the stream with an Err");
            assert!(
                failure.to_string().contains("v1 decrypt failed"),
                "alg {alg:?}: {failure}"
            );
            // All of part 1 comes out. Nothing of part 2 comes out.
            assert_eq!(got, &obj.plaintext[..40], "alg {alg:?}");
            assert_eq!(counter.load(Ordering::SeqCst), 1, "alg {alg:?}");
        }
    }

    #[tokio::test]
    async fn multipart_range_ends_before_its_span() {
        for alg in ALGS {
            let obj = RangeObject::new(alg, &SMALL_PARTS);
            let plan = obj.plan(0, obj.plaintext.len());
            let window = obj.window(&plan);
            let half = &window[..window.len().div_ceil(2)];

            let counter = Arc::new(AtomicU64::new(0));
            let body = body_from_frames(split_frames(half, SMALL_FRAME));
            let res =
                decrypting_multipart_range(body, alg, KEY, CHUNK, plan, Some(counter.clone()))
                    .collect()
                    .await;
            let Err(failure) = res else {
                panic!("alg {alg:?}: a short backend body must end in an Err");
            };
            assert!(
                failure.to_string().contains("ended before its span"),
                "alg {alg:?}: {failure}"
            );
            // A cut-off body is not a tamper. The counter stays at 0.
            assert_eq!(counter.load(Ordering::SeqCst), 0, "alg {alg:?}");
        }
    }

    #[tokio::test]
    async fn multipart_range_releases_the_backend_when_the_client_is_gone() {
        for alg in ALGS {
            let obj = RangeObject::new(alg, &SMALL_PARTS);
            let plan = obj.plan(0, obj.plaintext.len());
            let dropped = Arc::new(AtomicBool::new(false));
            let backend = NeverBody {
                dropped: dropped.clone(),
            };
            let body = decrypting_multipart_range(backend, alg, KEY, CHUNK, plan, None);
            // The client leaves while the backend is silent.
            drop(body);
            let_tasks_run().await;
            assert!(
                dropped.load(Ordering::SeqCst),
                "alg {alg:?}: the task still holds the backend body"
            );
        }
    }
}
