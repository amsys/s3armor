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
//! would reject the whole upload with `EntityTooSmall`. So: the
//! highest-numbered part's ciphertext is buffered in the session
//! (`Session::tail`) only while it is under 5 MiB, and dropped the moment a
//! higher part number arrives. At Complete, if the client's actual last
//! part is still buffered, it is re-uploaded merged with the footer under
//! the same part number (no extra part, no size problem); otherwise the
//! footer goes up as its own — now safely non-final-sized — extra part.
//! Either way the object's raw byte stream is identical: every part's
//! ciphertext, then the footer frame, then the trailer. `decrypting_multipart`
//! and `intercept::footer` don't need to know which branch happened.

use std::fmt::Write as _;

use bytes::Bytes;
use http::Response;
use http_body_util::{BodyExt, Limited};
use quick_xml::events::Event;
use quick_xml::Reader;
use rand_core::{OsRng, RngCore};

use s3armor_format::v1::{ciphertext_len, encrypt_all, Footer, ObjectMeta};

use crate::config::Backend;
use crate::intercept::{header_u64, normalize_etag, set_response_header, write_binding};
use crate::mpu::{CachedComplete, PartRecord, SessionKey};
use crate::proxy::body::{self, ProxyBody};
use crate::proxy::error::S3Error;
use crate::proxy::headers::to_pairs;
use crate::proxy::route;
use crate::proxy::{
    build_client_response, forward, header_value, set_header, translate_response, ProxyState,
};

/// S3's minimum size for every part but the last.
const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;

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
    state.sessions.create(
        (backend.name.clone(), bucket, key, upload_id),
        dek,
        alg,
        chunk_size,
    );
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
    let (bucket, key) = bucket_key(raw_path)?;
    let session_key: SessionKey = (backend.name.clone(), bucket, key, upload_id.clone());

    let (dek, alg, chunk_size) = {
        let entry = state
            .sessions
            .get(&session_key)
            .ok_or_else(|| S3Error::no_such_upload(&upload_id))?;
        (entry.dek, entry.alg, entry.chunk_size)
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
            .map_err(|e| S3Error::bad_gateway(format!("reading part body: {e}")))?
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

/// Records a completed part and applies the tail-buffer rule: the buffer
/// tracks only the *current* highest-numbered part, so a strictly higher
/// part number arriving always replaces (or clears) it.
#[expect(
    clippy::expect_used,
    reason = "the line above always inserts into entry.parts, so its key set is never empty here"
)]
fn record_part(
    state: &ProxyState,
    session_key: &SessionKey,
    part_number: u32,
    pt_len: u64,
    etag: String,
    ct: Option<Bytes>,
) {
    if let Some(mut entry) = state.sessions.get_mut(session_key) {
        entry.parts.insert(part_number, PartRecord { pt_len, etag });
        let highest = *entry
            .parts
            .keys()
            .next_back()
            .expect("just inserted a part, so the map is non-empty");
        if part_number == highest {
            entry.tail = ct.map(|c| (part_number, c));
        }
        entry.touch();
    }
}

/// `POST ?uploadId` — validate the client's part list against what this
/// node recorded, upload the footer (merged into the buffered tail, or as
/// its own extra part), and complete. A retried Complete (real SDKs retry
/// it) returns the cached response instead of `NoSuchUpload` — the session
/// is never deleted here, only marked completed and left to expire by TTL.
#[expect(
    clippy::too_many_lines,
    reason = "one flat sequence: validate against the recorded session, seal the footer, upload/merge the tail, complete; splitting would fragment a single auditable path"
)]
#[expect(
    clippy::indexing_slicing,
    reason = "entry.parts[n] is only reached for n already validated present in entry.parts by the loop just above"
)]
#[expect(
    clippy::expect_used,
    reason = "client_parts.is_empty() is checked and returns early at the top of this function"
)]
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

    let body_bytes = base_body
        .collect()
        .await
        .map_err(|e| S3Error::bad_gateway(format!("reading Complete body: {e}")))?
        .to_bytes();
    let client_parts = parse_complete_xml(&body_bytes)?;
    if client_parts.is_empty() {
        return Err(S3Error::invalid_part(
            "CompleteMultipartUpload request lists no parts",
        ));
    }

    let (alg, dek, parts_snapshot, tail) = {
        let mut entry = state
            .sessions
            .get_mut(&session_key)
            .ok_or_else(|| S3Error::no_such_upload(&upload_id))?;
        entry.touch();
        if let Some(cached) = entry.completed.clone() {
            drop(entry);
            return Ok(cached_response(cached, request_id));
        }
        for (number, client_etag) in &client_parts {
            let recorded = entry.parts.get(number).ok_or_else(|| {
                S3Error::invalid_part(format!("part {number} was never uploaded"))
            })?;
            // Compare with surrounding quotes stripped on both sides: real
            // S3 SDKs are inconsistent about whether the `<ETag>` they send
            // back in the part list is quoted (`UploadPart`'s response
            // header is always `"hex"`; the client is not required to
            // preserve that literally).
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
        (entry.alg, entry.dek, parts_snapshot, entry.tail.clone())
    };

    let total_pt: u64 = parts_snapshot.iter().map(|(_, size)| *size).sum();
    let last_number = client_parts
        .iter()
        .map(|(n, _)| *n)
        .max()
        .expect("checked non-empty above");
    let footer = Footer {
        alg,
        parts: parts_snapshot,
        total_pt,
        md5: None,
    };
    let sealed_footer = footer.seal(&dek);

    let mut final_parts = client_parts.clone();
    if let Some((tail_number, tail_ct)) = tail.filter(|(n, _)| *n == last_number) {
        let mut merged = tail_ct.to_vec();
        merged.extend_from_slice(&sealed_footer);
        let etag = upload_raw_part(
            state,
            backend,
            raw_path,
            &upload_id,
            tail_number,
            Bytes::from(merged),
        )
        .await?;
        for (n, e) in &mut final_parts {
            if *n == tail_number {
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
            &upload_id,
            footer_number,
            Bytes::from(sealed_footer),
        )
        .await?;
        final_parts.push((footer_number, etag));
    }

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

    if parts.status.is_success() {
        let cached = CachedComplete {
            status: parts.status,
            headers: to_pairs(&parts.headers),
            body: out_bytes.clone(),
        };
        if let Some(mut entry) = state.sessions.get_mut(&session_key) {
            entry.completed = Some(cached);
            entry.touch();
        }
    }
    Ok(build_client_response(
        parts,
        body::full(out_bytes),
        request_id,
    ))
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

/// Parses `<CompleteMultipartUpload><Part><PartNumber>n</PartNumber>
/// <ETag>"..."</ETag></Part>...</CompleteMultipartUpload>`, in the order
/// the client sent it — ascending by part number is the client's job, not
/// this parser's; `handle_complete` uses the recorded plaintext sizes keyed
/// by part number regardless of list order.
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
}
