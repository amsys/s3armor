//! Multipart-upload interception: `Create`/`UploadPart`/`Complete`/`Abort`.
//! `docs/ARCHITECTURE.md` "Multipart v1". Every part is encrypted under an
//! independent stream — its own chunk indices, its own random nonces —
//! keyed by its client part number, so retried, duplicate, and
//! out-of-order parts are all safe by construction (a shared-keystream
//! design would not be). There is no self-copy at Complete: every
//! metadata value was known at Create.
//!
//! ## The footer's 5 MiB problem, and the fix
//!
//! S3 requires every part but the last to be >= 5 MiB. Appending the
//! footer as its own extra final part would turn the client's real final
//! part — usually well under 5 MiB — into a middle part, and the backend
//! would reject the whole upload with `EntityTooSmall`. So: every
//! sub-5-MiB part's ciphertext is buffered in the session
//! (`Session::tails`, capped at `mpu::MAX_TAIL_BYTES` — the lowest part
//! number is evicted first once the cap is hit), because a legal
//! `CompleteMultipartUpload` can name any previously-uploaded part as the
//! last one, not just the highest part number ever seen — an unreferenced
//! part is simply discarded by real S3. A part re-uploaded at >= 5 MiB
//! clears its own buffer entry. At Complete, if the client's actual last
//! part is still buffered, it is re-uploaded merged with the footer under
//! the same part number (no extra part, no size problem); if it isn't
//! buffered but is itself >= 5 MiB, the footer goes up as its own — now
//! safely non-final-sized — extra part; if it isn't buffered and is still
//! under 5 MiB (evicted by the cap), Complete is rejected with
//! `InvalidPart` rather than silently producing a backend `EntityTooSmall`.
//! Either way a successful Complete's raw byte stream is identical: every
//! part's ciphertext, then the footer frame, then the trailer.
//! `decrypting_multipart` and `intercept::footer` don't need to know which
//! branch happened.

use std::fmt::Write as _;

use bytes::Bytes;
use http::Response;
use http_body_util::{BodyExt, Limited};
use quick_xml::events::Event;
use quick_xml::Reader;
use rand_core::{OsRng, RngCore};

use s3armor_format::v1::{ciphertext_len, encrypt_all, Alg, Footer, ObjectMeta};

use crate::config::Backend;
use crate::intercept::{header_u64, normalize_etag, set_response_header, write_binding};
use crate::mpu::{CachedComplete, Session, SessionKey};
use crate::proxy::body::{self, ProxyBody};
use crate::proxy::error::S3Error;
use crate::proxy::headers::to_pairs;
use crate::proxy::route;
use crate::proxy::{
    build_client_response, forward, header_value, set_header, translate_response, ProxyState,
};

/// S3's minimum size for every part but the last.
const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;

/// Largest `CompleteMultipartUpload` request body this node buffers. The XML
/// for 10000 parts is well under this; the cap stops an unknown or oversized
/// Complete from buffering a client-chosen amount of memory.
const MAX_COMPLETE_XML_BYTES: usize = 4 * 1024 * 1024;

fn bucket_key(raw_path: &str) -> Result<(String, String), S3Error> {
    let route = route::parse(raw_path);
    match (route.bucket, route.key) {
        (Some(b), Some(k)) => Ok((b, k)),
        _ => Err(S3Error::bad_gateway(
            "multipart operation with no bucket/key",
        )),
    }
}

fn query_value(raw_query: &str, name: &str) -> Option<String> {
    raw_query.split('&').find_map(|pair| {
        if pair.is_empty() {
            return None;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if !k.eq_ignore_ascii_case(name) {
            return None;
        }
        Some(
            percent_encoding::percent_decode_str(v)
                .decode_utf8_lossy()
                .into_owned(),
        )
    })
}

/// `POST ?uploads` — mint the session DEK, stamp v1 metadata exactly as a
/// single-part PUT does (`intercept::put`), and create the session once the
/// backend confirms an upload id.
pub async fn handle_create(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    raw_query: &str,
    mut outbound_headers: Vec<(String, String)>,
    request_id: &str,
) -> Result<Response<ProxyBody>, S3Error> {
    // Reject before initiating a backend upload, so a node already at the
    // session cap does not leave an orphaned multipart upload behind.
    // `make_room` first evicts the oldest finished session, so a burst of
    // completions does not block new uploads for the rest of the TTL.
    if !state.sessions.make_room() {
        return Err(S3Error::slow_down());
    }
    let alg = state.config.alg;
    let chunk_size = state.config.chunk_size;

    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);
    let binding = write_binding(state, raw_path)?;
    let (kek, kid, wrapped_dek) = state.config.keyring.wrap_active(&dek, &binding)?;

    let meta = ObjectMeta {
        alg,
        kek,
        kid,
        wrapped_dek,
        chunk_size,
        multipart: true,
        emd5: None,
    };
    for (k, v) in meta.to_map() {
        set_header(&mut outbound_headers, &format!("x-amz-meta-{k}"), &v);
    }

    let backend_resp = forward(
        state,
        backend,
        "POST",
        raw_path,
        raw_query,
        outbound_headers,
        body::empty(),
    )
    .await?;
    if !backend_resp.status().is_success() {
        return Ok(translate_response(backend_resp, request_id));
    }
    let (parts, incoming) = backend_resp.into_parts();
    let xml = incoming
        .collect()
        .await
        .map_err(|e| S3Error::bad_gateway(format!("reading InitiateMultipartUpload body: {e}")))?
        .to_bytes();
    let upload_id = parse_single_tag(&xml, b"UploadId")
        .ok_or_else(|| S3Error::bad_gateway("backend did not return an UploadId"))?;

    let (bucket, key) = bucket_key(raw_path)?;
    if !state.sessions.create(
        (backend.name.clone(), bucket, key, upload_id),
        dek,
        alg,
        chunk_size,
    ) {
        // Lost a race against the cap (no finished session was left to
        // evict) after the backend initiated the upload. The backend's own
        // incomplete-upload lifecycle reclaims the orphan.
        return Err(S3Error::slow_down());
    }
    state.record_mpu_session_created();

    Ok(build_client_response(parts, body::full(xml), request_id))
}

/// `PUT ?partNumber&uploadId` — encrypt this part under the session DEK
/// with `part_number` in the AAD. Unknown `uploadId` fails closed with
/// `NoSuchUpload`, never passthrough — a passthrough UploadPart would
/// silently store plaintext, turning a lost session (e.g. a restart) into
/// a silent data-confidentiality failure instead of a loud one.
pub async fn handle_upload_part(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    raw_query: &str,
    mut outbound_headers: Vec<(String, String)>,
    base_body: ProxyBody,
    request_id: &str,
) -> Result<Response<ProxyBody>, S3Error> {
    let upload_id =
        query_value(raw_query, "uploadId").ok_or_else(|| S3Error::bad_gateway("no uploadId"))?;
    let part_number: u32 = query_value(raw_query, "partNumber")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| S3Error::bad_gateway("no or invalid partNumber"))?;
    // S3 part numbers are 1..=10000, and the footer reserves u32::MAX. Reject
    // anything else here: a crafted partNumber would otherwise seal a frame
    // whose AAD collides with the footer, a footer-forgery oracle under the
    // session DEK.
    if !(1..=10_000).contains(&part_number) {
        return Err(S3Error::invalid_part(
            "partNumber must be between 1 and 10000",
        ));
    }
    let (bucket, key) = bucket_key(raw_path)?;
    let session_key: SessionKey = (backend.name.clone(), bucket, key, upload_id.clone());

    let (dek, alg, chunk_size) = {
        let entry = state
            .sessions
            .get(&session_key)
            .ok_or_else(|| S3Error::no_such_upload(&upload_id))?;
        let dek = entry
            .dek
            .ok_or_else(|| S3Error::no_such_upload(&upload_id))?;
        (dek, entry.alg, entry.chunk_size)
    };

    let pt_len = header_u64(&outbound_headers, "content-length")
        .ok_or_else(S3Error::missing_content_length)?;
    let ct_len = ciphertext_len(alg, pt_len, u64::from(chunk_size));

    let (backend_resp, buffered_ct) = if ct_len < MIN_PART_SIZE {
        // Small enough that this might turn out to be the client's final
        // part — buffer the ciphertext so Complete can merge it with the
        // footer instead of uploading a doomed-to-be-too-small extra part.
        //
        // `ct_len` (hence this branch) was picked from the client's own
        // declared `pt_len`, so a client can pick this branch and then
        // stream more than it declared — `Limited` caps how much of that
        // ever buffers, and the length check below catches both directions
        // of a mismatch, matching `pt_len` to the real bytes read (the
        // streaming branch's `body::encrypting` does the same check).
        let plaintext = Limited::new(base_body, usize::try_from(pt_len).unwrap_or(usize::MAX))
            .collect()
            .await
            .map_err(|e| {
                // The verifying wrapper under `base_body` reports a failed
                // client body here too (`body::AbortSlot`), so a bad
                // Content-MD5 or chunk signature keeps its own 4xx.
                body::abort_reason()
                    .unwrap_or_else(|| S3Error::bad_gateway(format!("reading part body: {e}")))
            })?
            .to_bytes();
        if plaintext.len() as u64 != pt_len {
            return Err(S3Error::bad_gateway(
                "declared decoded length does not match the streamed body",
            ));
        }
        let ct = Bytes::from(encrypt_all(
            alg,
            &dek,
            part_number,
            chunk_size as usize,
            &plaintext,
        ));
        set_header(
            &mut outbound_headers,
            "content-length",
            &ct.len().to_string(),
        );
        let resp = forward(
            state,
            backend,
            "PUT",
            raw_path,
            raw_query,
            outbound_headers,
            body::full(ct.clone()),
        )
        .await?;
        (resp, Some(ct))
    } else {
        set_header(&mut outbound_headers, "content-length", &ct_len.to_string());
        let body = body::encrypting(
            base_body,
            alg,
            dek,
            chunk_size as usize,
            None,
            pt_len,
            part_number,
            None,
        );
        let resp = forward(
            state,
            backend,
            "PUT",
            raw_path,
            raw_query,
            outbound_headers,
            body,
        )
        .await?;
        (resp, None)
    };
    if !backend_resp.status().is_success() {
        return Ok(translate_response(backend_resp, request_id));
    }
    let etag = header_value(&to_pairs(backend_resp.headers()), "etag")
        .map(str::to_string)
        .ok_or_else(|| S3Error::bad_gateway("backend UploadPart returned no ETag"))?;
    record_part(state, &session_key, part_number, pt_len, etag, buffered_ct);

    Ok(translate_response(backend_resp, request_id))
}

/// Delegates to `Session::record_part`, which does nothing once the
/// session has already finished — a late, concurrent UploadPart must not
/// repopulate state a Complete already cleared.
fn record_part(
    state: &ProxyState,
    session_key: &SessionKey,
    part_number: u32,
    pt_len: u64,
    etag: String,
    ct: Option<Bytes>,
) {
    if let Some(mut entry) = state.sessions.get_mut(session_key) {
        entry.record_part(part_number, pt_len, etag, ct);
    }
}

/// `POST ?uploadId` — validate the client's part list against what this
/// node recorded, upload the footer (merged into the buffered tail, or as
/// its own extra part), and complete. A retried Complete (real SDKs retry
/// it) returns the cached response instead of `NoSuchUpload` — the session
/// is never deleted here. `Session::finish` releases its DEK, parts and
/// tails at once and keeps only the cached response, which stays until TTL
/// sweeps it or `Sessions::make_room` evicts it under cap pressure.
pub async fn handle_complete(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    raw_query: &str,
    outbound_headers: Vec<(String, String)>,
    base_body: ProxyBody,
    request_id: &str,
) -> Result<Response<ProxyBody>, S3Error> {
    let upload_id =
        query_value(raw_query, "uploadId").ok_or_else(|| S3Error::bad_gateway("no uploadId"))?;
    let (bucket, key) = bucket_key(raw_path)?;
    let session_key: SessionKey = (backend.name.clone(), bucket, key, upload_id.clone());

    // Look the session up before reading the body: an unknown uploadId must
    // fail fast, not after buffering a client-chosen amount. A retried
    // Complete returns its cached response without reading the body at all.
    if let Some(resp) = cached_response_for_session(state, &session_key, &upload_id, request_id)? {
        return Ok(resp);
    }

    let body_bytes = Limited::new(base_body, MAX_COMPLETE_XML_BYTES)
        .collect()
        .await
        .map_err(|e| S3Error::bad_gateway(format!("reading Complete body: {e}")))?
        .to_bytes();
    let client_parts = parse_complete_xml(&body_bytes)?;
    let last_number = validate_client_parts(&client_parts)?;

    let snap = {
        let mut entry = state
            .sessions
            .get_mut(&session_key)
            .ok_or_else(|| S3Error::no_such_upload(&upload_id))?;
        entry.touch();
        if let Some(cached) = entry.completed.clone() {
            drop(entry);
            return Ok(cached_response(cached, request_id));
        }
        snapshot_for_complete(&entry, &client_parts, last_number, &upload_id)?
    };

    let total_pt: u64 = snap.parts.iter().map(|(_, size)| *size).sum();
    ensure_last_part_ok(
        snap.tail.as_ref(),
        &snap.parts,
        last_number,
        snap.alg,
        snap.chunk_size,
    )?;

    // Claim the completion so a second concurrent Complete for this upload
    // backs off instead of racing a duplicate footer upload (which would make
    // the first Complete name an ETag the backend no longer holds). A retried
    // sequential Complete still returns the cached response checked above.
    if let Some(resp) = claim_completion(state, &session_key, &upload_id, request_id)? {
        return Ok(resp);
    }

    let data = CompleteData {
        client_parts,
        last_number,
        tail: snap.tail,
        alg: snap.alg,
        dek: snap.dek,
        parts_snapshot: snap.parts,
        total_pt,
    };
    let outcome = complete_upload(
        state,
        backend,
        raw_path,
        raw_query,
        outbound_headers,
        &session_key,
        &upload_id,
        data,
        request_id,
    )
    .await;
    // On failure, release the claim so a later retry can complete.
    if outcome.is_err() {
        if let Some(mut entry) = state.sessions.get_mut(&session_key) {
            entry.completing = false;
        }
    }
    outcome
}

/// Returns the cached response for an already-completed session (a retried
/// Complete), or `None` to let the caller proceed with a fresh one.
/// `NoSuchUpload` for an unknown id.
fn cached_response_for_session(
    state: &ProxyState,
    session_key: &SessionKey,
    upload_id: &str,
    request_id: &str,
) -> Result<Option<Response<ProxyBody>>, S3Error> {
    let entry = state
        .sessions
        .get(session_key)
        .ok_or_else(|| S3Error::no_such_upload(upload_id))?;
    if let Some(cached) = entry.completed.clone() {
        drop(entry);
        return Ok(Some(cached_response(cached, request_id)));
    }
    Ok(None)
}

/// Checks the client's part list is non-empty and strictly ascending (the
/// sealed footer's format requires this — `Footer::decode_record` — so
/// `handle_complete` rejects rather than sorts, since the client's order is
/// what gets re-sent to the backend via `build_complete_xml`), and returns
/// the highest part number named.
#[expect(
    clippy::expect_used,
    reason = "client_parts.is_empty() is checked and returns early above in this function"
)]
fn validate_client_parts(client_parts: &[(u32, String)]) -> Result<u32, S3Error> {
    if client_parts.is_empty() {
        return Err(S3Error::invalid_part(
            "CompleteMultipartUpload request lists no parts",
        ));
    }
    if !parts_ascending(client_parts) {
        return Err(S3Error::invalid_part_order());
    }
    Ok(client_parts
        .iter()
        .map(|(n, _)| *n)
        .max()
        .expect("checked non-empty above"))
}

/// What `snapshot_for_complete` reads from the session under lock: what
/// `handle_complete` needs to seal the footer.
struct PartsSnapshot {
    alg: Alg,
    dek: [u8; 32],
    chunk_size: u32,
    parts: Vec<(u32, u64)>,
    tail: Option<Bytes>,
}

/// Validates `client_parts` against what this node recorded on `entry`, then
/// returns what `handle_complete` needs to seal the footer: the algorithm,
/// DEK, chunk size, each part's plaintext size, and the buffered tail for
/// the last part number (if any).
#[expect(
    clippy::indexing_slicing,
    reason = "entry.parts[n] is only reached for n already validated present in entry.parts by the loop just above"
)]
fn snapshot_for_complete(
    entry: &Session,
    client_parts: &[(u32, String)],
    last_number: u32,
    upload_id: &str,
) -> Result<PartsSnapshot, S3Error> {
    for (number, client_etag) in client_parts {
        let recorded = entry
            .parts
            .get(number)
            .ok_or_else(|| S3Error::invalid_part(format!("part {number} was never uploaded")))?;
        // Compare with surrounding quotes stripped on both sides: real S3
        // SDKs are inconsistent about whether the `<ETag>` they send back in
        // the part list is quoted (`UploadPart`'s response header is always
        // `"hex"`; the client is not required to preserve that literally).
        if normalize_etag(&recorded.etag) != normalize_etag(client_etag) {
            return Err(S3Error::invalid_part(format!(
                "part {number} ETag does not match what this node recorded"
            )));
        }
    }
    let parts_snapshot: Vec<(u32, u64)> = client_parts
        .iter()
        .map(|(n, _)| (*n, entry.parts[n].pt_len))
        .collect();
    let tail = entry.tails.get(&last_number).cloned();
    let dek = entry
        .dek
        .ok_or_else(|| S3Error::no_such_upload(upload_id))?;
    Ok(PartsSnapshot {
        alg: entry.alg,
        dek,
        chunk_size: entry.chunk_size,
        parts: parts_snapshot,
        tail,
    })
}

/// The last part not buffered: if it is still under S3's 5 MiB minimum, it
/// was evicted from the capped tail buffer (or the client re-uses a part
/// number in a way this node never buffered) — sealing the footer as its
/// own extra part would turn this last part into a middle part and the
/// backend would reject the whole upload with `EntityTooSmall`. Fail loudly
/// instead of leaving that opaque error as the client's only signal.
fn ensure_last_part_ok(
    tail: Option<&Bytes>,
    parts_snapshot: &[(u32, u64)],
    last_number: u32,
    alg: Alg,
    chunk_size: u32,
) -> Result<(), S3Error> {
    if tail.is_none() {
        let last_pt_len = parts_snapshot
            .iter()
            .find(|(n, _)| *n == last_number)
            .map_or(0, |(_, len)| *len);
        if ciphertext_len(alg, last_pt_len, u64::from(chunk_size)) < MIN_PART_SIZE {
            return Err(S3Error::invalid_part(format!(
                "part {last_number} is under S3's 5 MiB minimum and is no longer buffered on \
                 this node (displaced by a higher part number, or the session's tail buffer is \
                 full); re-upload it as the highest part number and complete again"
            )));
        }
    }
    Ok(())
}

/// Claims the completion for `session_key` so a second concurrent Complete
/// backs off instead of racing a duplicate footer upload. Returns the
/// cached response when a concurrent Complete already finished; the caller
/// proceeds, with the claim held, only on `Ok(None)`.
fn claim_completion(
    state: &ProxyState,
    session_key: &SessionKey,
    upload_id: &str,
    request_id: &str,
) -> Result<Option<Response<ProxyBody>>, S3Error> {
    let mut entry = state
        .sessions
        .get_mut(session_key)
        .ok_or_else(|| S3Error::no_such_upload(upload_id))?;
    if let Some(cached) = entry.completed.clone() {
        drop(entry);
        return Ok(Some(cached_response(cached, request_id)));
    }
    if entry.completing {
        return Err(S3Error::slow_down());
    }
    entry.completing = true;
    drop(entry);
    Ok(None)
}

/// What `complete_upload` needs beyond the plain proxy plumbing: the
/// validated part list and what `snapshot_for_complete` read from the
/// session under lock.
struct CompleteData {
    client_parts: Vec<(u32, String)>,
    last_number: u32,
    tail: Option<Bytes>,
    alg: Alg,
    dek: [u8; 32],
    parts_snapshot: Vec<(u32, u64)>,
    total_pt: u64,
}

/// Seals the footer, uploads it (merged into the buffered tail, or as its
/// own extra part), completes on the backend, and updates the session with
/// the outcome.
#[expect(
    clippy::too_many_arguments,
    reason = "one flat seal-upload-complete sequence: state, backend, path/query, headers, the session identity, the validated data, and request_id each need their own argument; splitting would fragment a single auditable path"
)]
async fn complete_upload(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    raw_query: &str,
    outbound_headers: Vec<(String, String)>,
    session_key: &SessionKey,
    upload_id: &str,
    data: CompleteData,
    request_id: &str,
) -> Result<Response<ProxyBody>, S3Error> {
    let CompleteData {
        client_parts,
        last_number,
        tail,
        alg,
        dek,
        parts_snapshot,
        total_pt,
    } = data;
    let footer = Footer {
        alg,
        parts: parts_snapshot,
        total_pt,
        md5: None,
    };
    let sealed_footer = footer.seal(&dek);

    let final_parts = finalize_parts(
        state,
        backend,
        raw_path,
        upload_id,
        last_number,
        tail,
        client_parts,
        sealed_footer,
    )
    .await?;

    let complete_xml = build_complete_xml(&final_parts);
    let mut complete_headers = outbound_headers;
    set_header(
        &mut complete_headers,
        "content-length",
        &complete_xml.len().to_string(),
    );
    let backend_resp = forward(
        state,
        backend,
        "POST",
        raw_path,
        raw_query,
        complete_headers,
        body::full(Bytes::from(complete_xml)),
    )
    .await?;
    let (parts, incoming) = backend_resp.into_parts();
    let out_bytes = incoming
        .collect()
        .await
        .map_err(|e| S3Error::bad_gateway(format!("reading Complete response: {e}")))?
        .to_bytes();

    if let Some(mut entry) = state.sessions.get_mut(session_key) {
        if parts.status.is_success() {
            entry.finish(CachedComplete {
                status: parts.status,
                headers: to_pairs(&parts.headers),
                body: out_bytes.clone(),
            });
        } else {
            // `forward` returns Ok for any backend HTTP status, so a
            // non-2xx Complete (e.g. a transient 503) reaches here as a
            // success `outcome` and would leave `completing` stuck true,
            // wedging every retry until TTL. Release the claim so the
            // client can retry.
            entry.completing = false;
        }
    }
    Ok(build_client_response(
        parts,
        body::full(out_bytes),
        request_id,
    ))
}

/// Merges the sealed footer into the buffered tail for `last_number` when
/// present, else uploads it as its own extra part. Either way, returns the
/// client's part list with the ETag for that part number updated to what
/// actually landed on the backend.
#[expect(
    clippy::too_many_arguments,
    reason = "one flat merge-or-upload sequence: state, backend, path, the target part, and the two footer-placement inputs each need their own argument; splitting would fragment a single auditable path"
)]
async fn finalize_parts(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    upload_id: &str,
    last_number: u32,
    tail: Option<Bytes>,
    mut final_parts: Vec<(u32, String)>,
    sealed_footer: Vec<u8>,
) -> Result<Vec<(u32, String)>, S3Error> {
    if let Some(tail_ct) = tail {
        let mut merged = tail_ct.to_vec();
        merged.extend_from_slice(&sealed_footer);
        let etag = upload_raw_part(
            state,
            backend,
            raw_path,
            upload_id,
            last_number,
            Bytes::from(merged),
        )
        .await?;
        for (n, e) in &mut final_parts {
            if *n == last_number {
                e.clone_from(&etag);
            }
        }
    } else {
        let footer_number = last_number
            .checked_add(1)
            .ok_or_else(|| S3Error::bad_gateway("multipart part numbers exhausted"))?;
        let etag = upload_raw_part(
            state,
            backend,
            raw_path,
            upload_id,
            footer_number,
            Bytes::from(sealed_footer),
        )
        .await?;
        final_parts.push((footer_number, etag));
    }
    Ok(final_parts)
}

async fn upload_raw_part(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    upload_id: &str,
    part_number: u32,
    ct: Bytes,
) -> Result<String, S3Error> {
    let encoded_id =
        percent_encoding::utf8_percent_encode(upload_id, percent_encoding::NON_ALPHANUMERIC);
    let query = format!("partNumber={part_number}&uploadId={encoded_id}");
    let mut headers = Vec::new();
    set_header(&mut headers, "content-length", &ct.len().to_string());
    let resp = forward(
        state,
        backend,
        "PUT",
        raw_path,
        &query,
        headers,
        body::full(ct),
    )
    .await?;
    if !resp.status().is_success() {
        return Err(S3Error::bad_gateway(format!(
            "footer part upload failed: {}",
            resp.status()
        )));
    }
    header_value(&to_pairs(resp.headers()), "etag")
        .map(str::to_string)
        .ok_or_else(|| S3Error::bad_gateway("footer part upload returned no ETag"))
}

#[expect(
    clippy::expect_used,
    reason = "headers recorded from a real backend response were already valid once; re-building them cannot fail"
)]
fn cached_response(cached: CachedComplete, request_id: &str) -> Response<ProxyBody> {
    let mut builder = Response::builder().status(cached.status);
    for (name, value) in &cached.headers {
        if crate::proxy::is_hop_by_hop_response_header(name) {
            continue;
        }
        builder = builder.header(name, value);
    }
    let mut resp = builder
        .body(body::full(cached.body))
        .expect("headers recorded from a real backend response are always valid");
    set_response_header(&mut resp, "x-amz-request-id", request_id);
    resp
}

/// `DELETE ?uploadId` — forward the abort, then drop the session (and its
/// buffered tail).
pub async fn handle_abort(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    raw_query: &str,
    outbound_headers: Vec<(String, String)>,
    request_id: &str,
) -> Result<Response<ProxyBody>, S3Error> {
    let upload_id =
        query_value(raw_query, "uploadId").ok_or_else(|| S3Error::bad_gateway("no uploadId"))?;
    let (bucket, key) = bucket_key(raw_path)?;
    let backend_resp = forward(
        state,
        backend,
        "DELETE",
        raw_path,
        raw_query,
        outbound_headers,
        body::empty(),
    )
    .await?;
    state
        .sessions
        .remove(&(backend.name.clone(), bucket, key, upload_id));
    Ok(translate_response(backend_resp, request_id))
}

/// `PUT ?partNumber&uploadId` with `x-amz-copy-source` — not supported in
/// v1: ciphertext cannot be re-chunked server-side (`docs/ARCHITECTURE.md` "S3 operation matrix (v1)").
pub fn upload_part_copy_unsupported() -> S3Error {
    S3Error::not_implemented(
        "UploadPartCopy (ciphertext cannot be re-chunked server-side; re-upload the source instead)",
    )
}

/// `GET ?partNumber` (no `uploadId`) — fetching one part of an already
/// completed object is not supported in v1.
pub fn get_part_unsupported() -> S3Error {
    S3Error::not_implemented("GetObject with partNumber (fetch the whole object instead)")
}

/// Finds the first `<Tag>text</Tag>` for a top-level-or-nested tag name —
/// enough for `InitiateMultipartUploadResult`'s flat shape.
pub(crate) fn parse_single_tag(xml: &[u8], tag: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(xml);
    let mut reader = Reader::from_str(&text);
    reader.config_mut().trim_text_start = true;
    reader.config_mut().trim_text_end = true;
    let mut current: Vec<u8> = Vec::new();
    loop {
        match reader.read_event().ok()? {
            Event::Start(e) => current = e.name().as_ref().to_vec(),
            Event::Text(t) if current == tag => {
                let decoded = t.decode().ok()?;
                return quick_xml::escape::unescape(&decoded)
                    .ok()
                    .map(std::borrow::Cow::into_owned);
            }
            Event::Eof => return None,
            _ => {}
        }
    }
}

/// True when `parts` is strictly ascending by part number — no duplicates,
/// no reordering. The sealed footer's format requires this
/// (`Footer::decode_record`); `handle_complete` rejects the request rather
/// than sort when it isn't.
#[expect(
    clippy::indexing_slicing,
    reason = "windows(2) guarantees w.len() == 2, so w[0]/w[1] are always in range"
)]
fn parts_ascending(parts: &[(u32, String)]) -> bool {
    parts.windows(2).all(|w| w[0].0 < w[1].0)
}

/// Parses `<CompleteMultipartUpload><Part><PartNumber>n</PartNumber>
/// <ETag>"..."</ETag></Part>...</CompleteMultipartUpload>`, in the order
/// the client sent it — this parser does not sort or validate order;
/// `handle_complete` rejects a non-ascending list right after calling this,
/// since the sealed footer's format requires ascending part numbers.
fn parse_complete_xml(body: &[u8]) -> Result<Vec<(u32, String)>, S3Error> {
    let text = std::str::from_utf8(body)
        .map_err(|_| S3Error::bad_gateway("CompleteMultipartUpload body is not valid UTF-8"))?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text_start = true;
    reader.config_mut().trim_text_end = true;
    let mut parts = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut number: Option<u32> = None;
    let mut etag: Option<String> = None;
    loop {
        match reader.read_event().map_err(|e| {
            S3Error::bad_gateway(format!("invalid CompleteMultipartUpload XML: {e}"))
        })? {
            Event::Start(e) => {
                current = e.name().as_ref().to_vec();
                if current == b"Part" {
                    number = None;
                    etag = None;
                }
            }
            Event::Text(t) => {
                assign_part_field(&current, event_text(&t)?, &mut number, &mut etag);
            }
            Event::End(e) => {
                if e.name().as_ref() == b"Part" {
                    if let (Some(n), Some(t)) = (number.take(), etag.take()) {
                        parts.push((n, t));
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(parts)
}

/// Decodes and unescapes an XML text event's raw bytes.
fn event_text(t: &quick_xml::events::BytesText<'_>) -> Result<String, S3Error> {
    let decoded = t
        .decode()
        .map_err(|e| S3Error::bad_gateway(e.to_string()))?;
    Ok(quick_xml::escape::unescape(&decoded)
        .map_err(|e| S3Error::bad_gateway(e.to_string()))?
        .into_owned())
}

fn assign_part_field(
    tag: &[u8],
    text: String,
    number: &mut Option<u32>,
    etag: &mut Option<String>,
) {
    match tag {
        b"PartNumber" => *number = text.parse().ok(),
        b"ETag" => *etag = Some(text),
        _ => {}
    }
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn build_complete_xml(parts: &[(u32, String)]) -> String {
    let mut xml =
        String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CompleteMultipartUpload>");
    for (number, etag) in parts {
        // write! to a String is infallible; the Result exists only for the
        // generic fmt::Write trait.
        let _ = write!(
            xml,
            "<Part><PartNumber>{number}</PartNumber><ETag>{}</ETag></Part>",
            xml_escape(etag)
        );
    }
    xml.push_str("</CompleteMultipartUpload>");
    xml
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_id_is_read_from_the_initiate_result_xml() {
        let xml = br"<InitiateMultipartUploadResult><Bucket>b</Bucket><Key>k</Key><UploadId>abc-123</UploadId></InitiateMultipartUploadResult>";
        assert_eq!(
            parse_single_tag(xml, b"UploadId"),
            Some("abc-123".to_string())
        );
    }

    fn unwrap_parts(r: Result<Vec<(u32, String)>, S3Error>) -> Vec<(u32, String)> {
        r.unwrap_or_else(|e| panic!("{}", e.message))
    }

    #[test]
    fn complete_xml_yields_part_numbers_and_etags_in_document_order() {
        let xml = br#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"aaa"</ETag></Part><Part><PartNumber>5</PartNumber><ETag>"bbb"</ETag></Part></CompleteMultipartUpload>"#;
        let parts = unwrap_parts(parse_complete_xml(xml));
        assert_eq!(
            parts,
            vec![(1, "\"aaa\"".to_string()), (5, "\"bbb\"".to_string())]
        );
    }

    #[test]
    fn empty_complete_body_yields_no_parts() {
        let xml = b"<CompleteMultipartUpload></CompleteMultipartUpload>";
        assert!(unwrap_parts(parse_complete_xml(xml)).is_empty());
    }

    #[test]
    fn build_complete_xml_escapes_etags() {
        let xml = build_complete_xml(&[(1, "\"a&b\"".to_string())]);
        assert!(xml.contains("&quot;a&amp;b&quot;"));
    }

    #[test]
    fn query_value_is_case_insensitive_and_decodes() {
        assert_eq!(
            query_value("uploadId=abc%2F1", "uploadid"),
            Some("abc/1".to_string())
        );
        assert_eq!(query_value("partNumber=3", "uploadId"), None);
    }

    #[test]
    fn complete_with_descending_parts_is_rejected() {
        let parts = vec![(5, "\"a\"".to_string()), (1, "\"b\"".to_string())];
        assert!(!parts_ascending(&parts));
    }

    #[test]
    fn complete_with_duplicate_part_number_is_rejected() {
        let parts = vec![(1, "\"a\"".to_string()), (1, "\"b\"".to_string())];
        assert!(!parts_ascending(&parts));
    }

    #[test]
    fn complete_with_ascending_parts_is_accepted() {
        let parts = vec![(1, "\"a\"".to_string()), (5, "\"b\"".to_string())];
        assert!(parts_ascending(&parts));
    }
}
