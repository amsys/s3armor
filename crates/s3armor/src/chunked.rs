//! The one aws-chunked decoder — a single implementation is easier to
//! audit than several redundant ones, and it actually verifies every
//! `chunk-signature=` instead of echoing `x-amz-content-sha256` into the
//! canonical request without ever hashing the body. This module both
//! dechunks and verifies, chunk by chunk, so a tampered chunk is rejected
//! *before* its bytes are released to the caller — the property that keeps
//! payload verification compatible with O(chunk) memory (no whole-body
//! buffer).
//!
//! Wire format (`aws-chunked`, one chunk):
//! `hex(chunk-len)[;chunk-signature=<64 hex>]\r\n<chunk-data>\r\n`,
//! terminated by a zero-length chunk, optional trailer header lines, and a
//! final `\r\n`. The chunk-signature chain formula (AWS4-HMAC-SHA256-PAYLOAD,
//! confirmed against `minio-go`'s `pkg/signer/request-signature-streaming.go`,
//! since AWS's own doc page is JS-rendered and not fetchable as text):
//!
//! ```text
//! string_to_sign =
//!     "AWS4-HMAC-SHA256-PAYLOAD" \n
//!     amz_date \n
//!     credential_scope \n
//!     previous_signature \n
//!     hex_sha256("")                    <- fixed constant, every chunk
//!     hex_sha256(chunk_data)
//! signature = hex(HMAC(signing_key, string_to_sign))
//! ```
//!
//! The first chunk's `previous_signature` is the seed: the signature from
//! the request's own `Authorization` header or presigned query, computed
//! during SigV4 verification.

use subtle::ConstantTimeEq;

use crate::sigv4::canonical;

/// SHA-256 of the empty string — a fixed line in every chunk's
/// string-to-sign, not a placeholder for this chunk's own data.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChunkedError {
    #[error("malformed chunk header")]
    MalformedHeader,
    #[error("chunk data missing its terminating CRLF")]
    MissingCrlf,
    #[error("chunk signature does not match")]
    BadSignature,
    #[error("malformed trailer header line")]
    MalformedTrailer,
    #[error("more data received after the decoder finished")]
    AlreadyDone,
}

/// Verifies the rolling per-chunk signature chain. Independent of the wire
/// framing (`Dechunker` below), so it can be unit-tested against a
/// hand-built chain without a byte-level decoder in the way.
pub struct ChunkVerifier {
    signing_key: [u8; 32],
    amz_date: String,
    credential_scope: String,
    prev_signature: String,
}

impl ChunkVerifier {
    pub const fn new(
        signing_key: [u8; 32],
        amz_date: String,
        credential_scope: String,
        seed_signature: String,
    ) -> Self {
        Self {
            signing_key,
            amz_date,
            credential_scope,
            prev_signature: seed_signature,
        }
    }

    fn expected(&self, chunk_data: &[u8]) -> String {
        let sts = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{EMPTY_SHA256}\n{}",
            self.amz_date,
            self.credential_scope,
            self.prev_signature,
            canonical::hex_sha256(chunk_data)
        );
        canonical::signature_hex(&self.signing_key, &sts)
    }

    /// Checks `provided_sig_hex` against the expected next-in-chain
    /// signature. On success, advances the chain so the next chunk verifies
    /// against this one. On failure, the chain does **not** advance — the
    /// caller must abort the stream, not skip the chunk and continue.
    pub fn verify_and_advance(
        &mut self,
        chunk_data: &[u8],
        provided_sig_hex: &str,
    ) -> Result<(), ChunkedError> {
        let expected = self.expected(chunk_data);
        let ok = expected.len() == provided_sig_hex.len()
            && bool::from(expected.as_bytes().ct_eq(provided_sig_hex.as_bytes()));
        if !ok {
            return Err(ChunkedError::BadSignature);
        }
        self.prev_signature = expected;
        Ok(())
    }
}

enum State {
    Header,
    Data {
        remaining: usize,
        signature: Option<String>,
    },
    DataCrlf,
    Trailers,
    Done,
}

/// Streaming aws-chunked frame parser. Feed it bytes as they arrive; it
/// returns each chunk's data plus its claimed signature (`None` for the
/// unsigned-trailer scheme, which carries no per-chunk signature) as soon
/// as a full chunk is buffered — never the whole body. Verification against
/// [`ChunkVerifier`] is the caller's job (`proxy/mod.rs`), so this type
/// stays a pure, sans-io framer.
pub struct Dechunker {
    buf: Vec<u8>,
    state: State,
    trailers: Vec<(String, String)>,
}

/// A chunk's decoded data paired with its claimed signature (`None` for
/// the unsigned-trailer scheme, which carries no per-chunk signature).
pub type DecodedChunk = (Vec<u8>, Option<String>);

impl Default for Dechunker {
    fn default() -> Self {
        Self::new()
    }
}

impl Dechunker {
    pub const fn new() -> Self {
        Self {
            buf: Vec::new(),
            state: State::Header,
            trailers: Vec::new(),
        }
    }

    pub const fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    pub fn trailers(&self) -> &[(String, String)] {
        &self.trailers
    }

    /// Feeds newly-received bytes. Returns every chunk that became
    /// complete as a result, in order.
    #[expect(
        clippy::indexing_slicing,
        reason = "each index is bounded by a find_crlf/len check made just above it in the same arm"
    )]
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<DecodedChunk>, ChunkedError> {
        if matches!(self.state, State::Done) && !bytes.is_empty() {
            return Err(ChunkedError::AlreadyDone);
        }
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            match &self.state {
                State::Header => {
                    let Some(pos) = find_crlf(&self.buf) else {
                        break;
                    };
                    let line = std::str::from_utf8(&self.buf[..pos])
                        .map_err(|_| ChunkedError::MalformedHeader)?;
                    let (size, signature) = parse_chunk_header(line)?;
                    self.buf.drain(..pos + 2);
                    if size == 0 {
                        self.state = State::Trailers;
                        // A zero-length chunk still carries a signature to
                        // verify (over empty data) in the signed schemes.
                        if let Some(sig) = signature {
                            out.push((Vec::new(), Some(sig)));
                        }
                    } else {
                        self.state = State::Data {
                            remaining: size,
                            signature,
                        };
                    }
                }
                State::Data {
                    remaining,
                    signature,
                } => {
                    if self.buf.len() < *remaining {
                        break;
                    }
                    let data: Vec<u8> = self.buf.drain(..*remaining).collect();
                    let signature = signature.clone();
                    self.state = State::DataCrlf;
                    out.push((data, signature));
                }
                State::DataCrlf => {
                    if self.buf.len() < 2 {
                        break;
                    }
                    if &self.buf[..2] != b"\r\n" {
                        return Err(ChunkedError::MissingCrlf);
                    }
                    self.buf.drain(..2);
                    self.state = State::Header;
                }
                State::Trailers => {
                    let Some(pos) = find_crlf(&self.buf) else {
                        break;
                    };
                    let line = self.buf[..pos].to_vec();
                    self.buf.drain(..pos + 2);
                    if line.is_empty() {
                        self.state = State::Done;
                        break;
                    }
                    let line =
                        std::str::from_utf8(&line).map_err(|_| ChunkedError::MalformedTrailer)?;
                    let (name, value) =
                        line.split_once(':').ok_or(ChunkedError::MalformedTrailer)?;
                    self.trailers
                        .push((name.trim().to_string(), value.trim().to_string()));
                }
                State::Done => break,
            }
        }
        Ok(out)
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Parses `hex-size[;chunk-signature=<hex>]`. The unsigned-trailer scheme
/// sends chunk headers with no extension at all.
fn parse_chunk_header(line: &str) -> Result<(usize, Option<String>), ChunkedError> {
    let (size_hex, rest) = line.split_once(';').unwrap_or((line, ""));
    let size =
        usize::from_str_radix(size_hex.trim(), 16).map_err(|_| ChunkedError::MalformedHeader)?;
    if rest.is_empty() {
        return Ok((size, None));
    }
    let sig = rest
        .strip_prefix("chunk-signature=")
        .ok_or(ChunkedError::MalformedHeader)?;
    Ok((size, Some(sig.trim().to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_chunk(data: &[u8], sig: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(format!("{:x};chunk-signature={sig}\r\n", data.len()).as_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
        out
    }

    fn build_final(sig: &str) -> Vec<u8> {
        format!("0;chunk-signature={sig}\r\n\r\n").into_bytes()
    }

    #[test]
    fn decodes_single_chunk_fed_whole() {
        let mut d = Dechunker::new();
        let mut wire = build_chunk(b"hello", "a".repeat(64).as_str());
        wire.extend_from_slice(&build_final("b".repeat(64).as_str()));
        let chunks = d.feed(&wire).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].0, b"hello");
        assert_eq!(chunks[0].1.as_deref(), Some("a".repeat(64).as_str()));
        assert_eq!(chunks[1].0, Vec::<u8>::new());
        assert!(d.is_done());
    }

    #[test]
    fn decodes_split_across_many_small_feeds() {
        let mut d = Dechunker::new();
        let mut wire = build_chunk(b"hello world", "a".repeat(64).as_str());
        wire.extend_from_slice(&build_final("b".repeat(64).as_str()));
        let mut collected = Vec::new();
        for byte in wire {
            collected.extend(d.feed(&[byte]).unwrap());
        }
        assert_eq!(collected[0].0, b"hello world");
        assert!(d.is_done());
    }

    #[test]
    fn unsigned_scheme_has_no_signature() {
        let mut d = Dechunker::new();
        let mut wire = format!("{:x}\r\n", 3usize).into_bytes();
        wire.extend_from_slice(b"abc\r\n0\r\n\r\n");
        let chunks = d.feed(&wire).unwrap();
        assert_eq!(chunks[0].0, b"abc");
        assert_eq!(chunks[0].1, None);
    }

    #[test]
    fn trailer_lines_are_collected_and_dropped() {
        let mut d = Dechunker::new();
        let wire = b"3\r\nabc\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n";
        d.feed(wire).unwrap();
        assert!(d.is_done());
        assert_eq!(
            d.trailers(),
            &[("x-amz-checksum-crc32".to_string(), "AAAAAA==".to_string())]
        );
    }

    #[test]
    fn missing_crlf_after_data_is_rejected() {
        let mut d = Dechunker::new();
        let wire = b"3\r\nabcXX";
        let err = d.feed(wire).unwrap_err();
        assert_eq!(err, ChunkedError::MissingCrlf);
    }

    #[test]
    fn malformed_header_is_rejected() {
        let mut d = Dechunker::new();
        let err = d.feed(b"not-hex\r\n").unwrap_err();
        assert_eq!(err, ChunkedError::MalformedHeader);
    }

    // --- signature chain ---

    fn make_verifier(seed: &str) -> ChunkVerifier {
        let key = canonical::signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "s3",
        );
        ChunkVerifier::new(
            key,
            "20150830T123600Z".to_string(),
            "20150830/us-east-1/s3/aws4_request".to_string(),
            seed.to_string(),
        )
    }

    #[test]
    fn chain_verifies_and_advances_across_chunks() {
        let mut v = make_verifier(&"0".repeat(64));
        let sig1 = v.expected(b"first chunk data");
        v.verify_and_advance(b"first chunk data", &sig1).unwrap();
        // The second chunk's expected signature depends on the first
        // chunk's signature having been chained in — recomputing here
        // with the SAME verifier (now advanced) must match what a second
        // independent computation using sig1 as the seed would produce.
        let sig2 = v.expected(b"second chunk data");
        let fresh = make_verifier(&sig1);
        let sig2_independent = fresh.expected(b"second chunk data");
        assert_eq!(sig2, sig2_independent);
        v.verify_and_advance(b"second chunk data", &sig2).unwrap();
    }

    #[test]
    fn tampered_chunk_data_is_rejected() {
        let mut v = make_verifier(&"0".repeat(64));
        let sig = v.expected(b"original data");
        let err = v.verify_and_advance(b"tampered data", &sig).unwrap_err();
        assert_eq!(err, ChunkedError::BadSignature);
    }

    #[test]
    fn tampered_signature_does_not_advance_the_chain() {
        let mut v = make_verifier(&"0".repeat(64));
        assert!(v.verify_and_advance(b"data", &"f".repeat(64)).is_err());
        // Chain must still be at the seed — verifying the SAME chunk with
        // its true signature must still succeed after a rejected attempt.
        let true_sig = v.expected(b"data");
        assert!(v.verify_and_advance(b"data", &true_sig).is_ok());
    }

    #[test]
    fn reordered_chunks_fail_because_the_chain_depends_on_order() {
        let mut v = make_verifier(&"0".repeat(64));
        let sig_a = v.expected(b"chunk A");
        let sig_b_if_a_first = {
            let probe = make_verifier(&sig_a);
            probe.expected(b"chunk B")
        };
        // Swap order: verify "chunk B" first using the seed meant for A.
        let err = v
            .verify_and_advance(b"chunk B", &sig_b_if_a_first)
            .unwrap_err();
        assert_eq!(err, ChunkedError::BadSignature);
        let _ = sig_a;
    }
}
