//! GetObject interception: decrypt v1 ciphertext while streaming. A `Range`
//! request costs one extra HEAD — `alg`/`chunk_size` are needed to map a
//! plaintext range onto ciphertext bytes, and both only arrive with a
//! response (`docs/ARCHITECTURE.md` "Data: chunked AEAD" and "Multipart
//! v1"; no metadata cache yet).

use http::Response;

use s3armor_format::v1::{n_chunks, part_layout, plaintext_len, plan_multipart_range, plan_range};

use crate::config::Backend;
use crate::intercept::conditional::{not_modified_response, Conditionals, Precondition};
use crate::intercept::{
    effective_etag, emd5_etag, footer, header_u64, resolve_key, route_from_headers,
    set_response_header, Routing,
};
use crate::proxy::body::{self, ProxyBody};
use crate::proxy::error::S3Error;
use crate::proxy::headers::{strip_s3armor_metadata, to_pairs};
use crate::proxy::{
    build_client_response, forward, header_value, set_header, translate_response, ProxyState,
};

pub async fn handle(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    raw_query: &str,
    mut outbound_headers: Vec<(String, String)>,
    request_id: &str,
) -> Result<Response<ProxyBody>, S3Error> {
    let conds = Conditionals::take(&mut outbound_headers);
    if !conds.is_empty() {
        if let Some(resp) = check_preconditions(
            state,
            backend,
            raw_path,
            raw_query,
            &outbound_headers,
            &conds,
            request_id,
        )
        .await?
        {
            return Ok(resp);
        }
    }
    match header_value(&outbound_headers, "range").and_then(parse_byte_range) {
        None => {
            // No range, or a range this proxy cannot parse (e.g. a
            // multi-range). Either way serve the whole object — and strip the
            // range header so the backend returns 200 with full ciphertext.
            // Forwarding an unparseable range would make the backend answer
            // 206 with a partial body, which then fails AEAD and wrongly trips
            // the chunk-verify-failure metric.
            outbound_headers.retain(|(k, _)| !k.eq_ignore_ascii_case("range"));
            handle_full(
                state,
                backend,
                raw_path,
                raw_query,
                outbound_headers,
                request_id,
            )
            .await
        }
        Some(range) => {
            handle_ranged(
                state,
                backend,
                raw_path,
                raw_query,
                outbound_headers,
                range,
                request_id,
            )
            .await
        }
    }
}

/// A conditional GET costs one extra HEAD to learn the object's effective
/// ETag before any (possibly expensive) decrypt-and-stream begins — the
/// same precedent `handle_ranged` already sets for learning `alg`/
/// `chunk_size`. `Ok(None)` means "proceed with the real GET": either the
/// precondition holds, the HEAD itself failed (let the real GET surface
/// that error instead of this diagnostic probe), or the object has no
/// discoverable ETag.
async fn check_preconditions(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    raw_query: &str,
    outbound_headers: &[(String, String)],
    conds: &Conditionals,
    request_id: &str,
) -> Result<Option<Response<ProxyBody>>, S3Error> {
    let head_resp = forward(
        state,
        backend,
        "HEAD",
        raw_path,
        raw_query,
        outbound_headers.to_vec(),
        body::empty(),
    )
    .await?;
    if !head_resp.status().is_success() {
        return Ok(None);
    }
    let resp_headers = to_pairs(head_resp.headers());
    // A parse failure here is the same "not this diagnostic probe's job"
    // case as a failed HEAD above: let the real GET's own `route_from_headers`
    // call surface the error.
    let Ok(routing) = route_from_headers(&resp_headers) else {
        return Ok(None);
    };
    let Some(etag) = effective_etag(state, &routing, &resp_headers, raw_path) else {
        return Ok(None);
    };
    match conds.evaluate(&etag) {
        Precondition::Proceed => Ok(None),
        Precondition::NotModified => Ok(Some(not_modified_response(
            &resp_headers,
            &etag,
            request_id,
        ))),
        Precondition::Failed => Err(S3Error::precondition_failed()),
    }
}

async fn handle_full(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    raw_query: &str,
    outbound_headers: Vec<(String, String)>,
    request_id: &str,
) -> Result<Response<ProxyBody>, S3Error> {
    let backend_resp = forward(
        state,
        backend,
        "GET",
        raw_path,
        raw_query,
        outbound_headers,
        body::empty(),
    )
    .await?;
    if !backend_resp.status().is_success() {
        return Ok(translate_response(backend_resp, request_id));
    }
    let resp_headers = to_pairs(backend_resp.headers());

    match route_from_headers(&resp_headers)? {
        Routing::V1(meta) if meta.multipart => {
            let alg = meta.alg;
            let chunk_size = meta.chunk_size as usize;
            let ct_len = header_u64(&resp_headers, "content-length")
                .ok_or_else(|| S3Error::bad_gateway("backend GET returned no Content-Length"))?;
            let etag = header_value(&resp_headers, "etag")
                .unwrap_or("")
                .to_string();
            let key = resolve_key(state, &meta, raw_path)?;
            let ftr = footer::load(state, backend, raw_path, alg, &key, ct_len, &etag).await?;
            let spans = part_layout(alg, chunk_size as u64, &ftr.parts);

            let (parts, incoming) = backend_resp.into_parts();
            let decrypted = body::decrypting_multipart(
                incoming,
                alg,
                key,
                chunk_size,
                spans,
                Some(state.chunk_verify_failures_handle()),
            );
            let mut resp = build_client_response(parts, decrypted, request_id);
            set_response_header(&mut resp, "content-length", &ftr.total_pt.to_string());
            strip_s3armor_metadata(resp.headers_mut());
            Ok(resp)
        }
        Routing::V1(meta) => {
            let alg = meta.alg;
            let chunk_size = meta.chunk_size as usize;
            let ct_len = header_u64(&resp_headers, "content-length")
                .ok_or_else(|| S3Error::bad_gateway("backend GET returned no Content-Length"))?;
            let pt_len = plaintext_len(alg, ct_len, chunk_size as u64).map_err(|_| {
                S3Error::bad_gateway("stored object length is not a valid v1 ciphertext length")
            })?;
            let key = resolve_key(state, &meta, raw_path)?;

            let (parts, incoming) = backend_resp.into_parts();
            let decrypted = body::decrypting(
                incoming,
                alg,
                key,
                chunk_size,
                0,
                Some(state.chunk_verify_failures_handle()),
            );
            let mut resp = build_client_response(parts, decrypted, request_id);
            set_response_header(&mut resp, "content-length", &pt_len.to_string());
            strip_s3armor_metadata(resp.headers_mut());
            if let Some(etag) = emd5_etag(state, &meta, raw_path) {
                set_response_header(&mut resp, "etag", &etag);
            }
            Ok(resp)
        }
        Routing::Passthrough => Ok(translate_response(backend_resp, request_id)),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one flat match over the routing cases (v1 single/multipart, passthrough); splitting would fragment a single auditable read path"
)]
#[expect(
    clippy::indexing_slicing,
    clippy::expect_used,
    reason = "plan.is_empty() is checked and returns early just above every plan[..]/plan.last() use"
)]
async fn handle_ranged(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    raw_query: &str,
    outbound_headers: Vec<(String, String)>,
    range: (Option<u64>, Option<u64>),
    request_id: &str,
) -> Result<Response<ProxyBody>, S3Error> {
    let mut head_headers = outbound_headers.clone();
    head_headers.retain(|(k, _)| !k.eq_ignore_ascii_case("range"));
    let head_resp = forward(
        state,
        backend,
        "HEAD",
        raw_path,
        raw_query,
        head_headers,
        body::empty(),
    )
    .await?;
    if !head_resp.status().is_success() {
        // Let the ranged GET itself surface the real status/error — a HEAD
        // and a GET can in principle diverge (a delete between the two),
        // and the GET's response is the one that actually matters here.
        let backend_resp = forward(
            state,
            backend,
            "GET",
            raw_path,
            raw_query,
            outbound_headers,
            body::empty(),
        )
        .await?;
        return Ok(translate_response(backend_resp, request_id));
    }
    let head_headers_pairs = to_pairs(head_resp.headers());

    match route_from_headers(&head_headers_pairs)? {
        Routing::Passthrough => {
            let backend_resp = forward(
                state,
                backend,
                "GET",
                raw_path,
                raw_query,
                outbound_headers,
                body::empty(),
            )
            .await?;
            Ok(translate_response(backend_resp, request_id))
        }
        Routing::V1(meta) if meta.multipart => {
            let alg = meta.alg;
            let chunk_size = meta.chunk_size as usize;
            let ct_len = header_u64(&head_headers_pairs, "content-length")
                .ok_or_else(|| S3Error::bad_gateway("backend HEAD returned no Content-Length"))?;
            let etag = header_value(&head_headers_pairs, "etag")
                .unwrap_or("")
                .to_string();
            let key = resolve_key(state, &meta, raw_path)?;
            let ftr = footer::load(state, backend, raw_path, alg, &key, ct_len, &etag).await?;
            let pt_len = ftr.total_pt;
            let (start, end) = resolve_range(range, pt_len);
            let spans = part_layout(alg, chunk_size as u64, &ftr.parts);
            let plan = plan_multipart_range(&spans, alg, chunk_size as u64, start, end)
                .map_err(|_| S3Error::invalid_range())?;

            if plan.is_empty() {
                let mut resp =
                    build_client_response(head_resp.into_parts().0, body::empty(), request_id);
                *resp.status_mut() = http::StatusCode::PARTIAL_CONTENT;
                set_response_header(
                    &mut resp,
                    "content-range",
                    &format!("bytes {start}-{start}/{pt_len}"),
                );
                set_response_header(&mut resp, "content-length", "0");
                strip_s3armor_metadata(resp.headers_mut());
                return Ok(resp);
            }

            // The touched parts' local ciphertext spans concatenate into
            // one contiguous global range (`plan_multipart_range`'s doc
            // comment), so a single ranged GET covers all of them.
            let global_start = plan[0].0.ct_start + plan[0].1.ct_start;
            let last = plan.last().expect("checked non-empty above");
            let global_end = last.0.ct_start + last.1.ct_end;

            let mut ranged_headers = outbound_headers;
            set_header(
                &mut ranged_headers,
                "range",
                &format!("bytes={global_start}-{}", global_end.saturating_sub(1)),
            );
            let backend_resp = forward(
                state,
                backend,
                "GET",
                raw_path,
                raw_query,
                ranged_headers,
                body::empty(),
            )
            .await?;
            if !backend_resp.status().is_success() {
                return Ok(translate_response(backend_resp, request_id));
            }
            let (parts, incoming) = backend_resp.into_parts();
            let decrypted = body::decrypting_multipart_range(
                incoming,
                alg,
                key,
                chunk_size,
                plan,
                Some(state.chunk_verify_failures_handle()),
            );
            let mut resp = build_client_response(parts, decrypted, request_id);
            *resp.status_mut() = http::StatusCode::PARTIAL_CONTENT;
            let last_byte = if end > start { end - 1 } else { start };
            set_response_header(
                &mut resp,
                "content-range",
                &format!("bytes {start}-{last_byte}/{pt_len}"),
            );
            set_response_header(&mut resp, "content-length", &(end - start).to_string());
            strip_s3armor_metadata(resp.headers_mut());
            Ok(resp)
        }
        Routing::V1(meta) => {
            let alg = meta.alg;
            let chunk_size = meta.chunk_size as usize;
            let ct_len = header_u64(&head_headers_pairs, "content-length")
                .ok_or_else(|| S3Error::bad_gateway("backend HEAD returned no Content-Length"))?;
            let pt_len = plaintext_len(alg, ct_len, chunk_size as u64).map_err(|_| {
                S3Error::bad_gateway("stored object length is not a valid v1 ciphertext length")
            })?;
            let (start, end) = resolve_range(range, pt_len);
            let plan = plan_range(alg, pt_len, chunk_size as u64, start, end)
                .map_err(|_| S3Error::invalid_range())?;
            let key = resolve_key(state, &meta, raw_path)?;

            let mut ranged_headers = outbound_headers;
            let ct_range = format!("bytes={}-{}", plan.ct_start, plan.ct_end.saturating_sub(1));
            set_header(&mut ranged_headers, "range", &ct_range);
            let backend_resp = forward(
                state,
                backend,
                "GET",
                raw_path,
                raw_query,
                ranged_headers,
                body::empty(),
            )
            .await?;
            if !backend_resp.status().is_success() {
                return Ok(translate_response(backend_resp, request_id));
            }

            let total_chunks = n_chunks(pt_len, chunk_size as u64);
            let (parts, incoming) = backend_resp.into_parts();
            let decrypted = body::decrypting_range(
                incoming,
                alg,
                key,
                chunk_size,
                &plan,
                total_chunks,
                Some(state.chunk_verify_failures_handle()),
            );
            let mut resp = build_client_response(parts, decrypted, request_id);
            *resp.status_mut() = http::StatusCode::PARTIAL_CONTENT;
            let last = if end > start { end - 1 } else { start };
            set_response_header(
                &mut resp,
                "content-range",
                &format!("bytes {start}-{last}/{pt_len}"),
            );
            set_response_header(&mut resp, "content-length", &(end - start).to_string());
            strip_s3armor_metadata(resp.headers_mut());
            Ok(resp)
        }
    }
}

/// Parses a single-range `Range: bytes=...` value: `start-end`, `start-`
/// (open end), or `-suffix`. Multi-range (`bytes=0-1,5-6`) and anything
/// else unparseable returns `None` — the caller then serves the whole
/// object with `200`, the common tolerant behavior for a Range this proxy
/// doesn't understand.
fn parse_byte_range(value: &str) -> Option<(Option<u64>, Option<u64>)> {
    let spec = value.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    match (a.is_empty(), b.is_empty()) {
        (true, true) => None,
        (true, false) => Some((None, Some(b.parse().ok()?))),
        (false, true) => Some((Some(a.parse().ok()?), None)),
        (false, false) => Some((Some(a.parse().ok()?), Some(b.parse().ok()?))),
    }
}

/// Resolves a parsed `Range` against the object's actual plaintext length
/// into a half-open `[start, end)` byte span.
fn resolve_range(range: (Option<u64>, Option<u64>), pt_len: u64) -> (u64, u64) {
    match range {
        (Some(start), Some(end_inclusive)) => {
            let start = start.min(pt_len);
            // saturating_add: `bytes=0-18446744073709551615` would otherwise
            // wrap to 0 (overflow-checks are off in release) and return an
            // empty 206 instead of the object.
            (
                start,
                end_inclusive.saturating_add(1).min(pt_len).max(start),
            )
        }
        (Some(start), None) => (start.min(pt_len), pt_len),
        (None, Some(suffix)) => (pt_len.saturating_sub(suffix), pt_len),
        (None, None) => (0, pt_len),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_header_parses_closed_open_ended_and_suffix_forms() {
        assert_eq!(parse_byte_range("bytes=0-4"), Some((Some(0), Some(4))));
        assert_eq!(parse_byte_range("bytes=10-"), Some((Some(10), None)));
        assert_eq!(parse_byte_range("bytes=-5"), Some((None, Some(5))));
    }

    #[test]
    fn rejects_multi_range_and_garbage() {
        assert_eq!(parse_byte_range("bytes=0-1,5-6"), None);
        assert_eq!(parse_byte_range("bytes=-"), None);
        assert_eq!(parse_byte_range("nonsense"), None);
    }

    #[test]
    fn resolves_against_object_length() {
        assert_eq!(resolve_range((Some(0), Some(4)), 100), (0, 5));
        assert_eq!(resolve_range((Some(10), None), 100), (10, 100));
        assert_eq!(resolve_range((None, Some(5)), 100), (95, 100));
        assert_eq!(resolve_range((None, Some(5)), 3), (0, 3));
    }
}
