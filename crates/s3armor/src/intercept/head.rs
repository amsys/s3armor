//! HeadObject interception: same routing as GET, no body to transform —
//! just the plaintext size fixup and the plaintext-ETag rewrite.
//! `docs/ARCHITECTURE.md` "Object metadata v1" and "ETag policy".

use http::Response;

use s3armor_format::v1::plaintext_len;

use crate::config::Backend;
use crate::intercept::conditional::{not_modified_response, Conditionals, Precondition};
use crate::intercept::{
    effective_etag, emd5_etag, footer, header_u64, resolve_key, route_from_headers,
    set_response_header, Routing,
};
use crate::proxy::body::{self, ProxyBody};
use crate::proxy::error::S3Error;
use crate::proxy::headers::{strip_s3armor_metadata, to_pairs};
use crate::proxy::{forward, header_value, translate_response, ProxyState};

pub async fn handle(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    raw_query: &str,
    mut outbound_headers: Vec<(String, String)>,
    request_id: &str,
) -> Result<Response<ProxyBody>, S3Error> {
    let conds = Conditionals::take(&mut outbound_headers);
    // Strip any Range header: a HEAD carrying it makes the backend report a
    // partial Content-Length, which the plaintext-size fixup below would then
    // compute from. HEAD reports the whole object's size.
    outbound_headers.retain(|(k, _)| !k.eq_ignore_ascii_case("range"));
    let backend_resp = forward(
        state,
        backend,
        "HEAD",
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
    let routing = route_from_headers(&resp_headers)?;

    if !conds.is_empty() {
        if let Some(etag) = effective_etag(state, &routing, &resp_headers, raw_path) {
            match conds.evaluate(&etag) {
                Precondition::Proceed => {}
                Precondition::NotModified => {
                    return Ok(not_modified_response(&resp_headers, &etag, request_id));
                }
                Precondition::Failed => return Err(S3Error::precondition_failed()),
            }
        }
    }

    match routing {
        Routing::V1(meta) if meta.multipart => {
            let alg = meta.alg;
            let ct_len = header_u64(&resp_headers, "content-length")
                .ok_or_else(|| S3Error::bad_gateway("backend HEAD returned no Content-Length"))?;
            let etag = header_value(&resp_headers, "etag")
                .unwrap_or("")
                .to_string();
            let key = resolve_key(state, &meta, raw_path)?;
            let footer = footer::load(state, backend, raw_path, alg, &key, ct_len, &etag).await?;

            let mut resp = translate_response(backend_resp, request_id);
            set_response_header(&mut resp, "content-length", &footer.total_pt.to_string());
            strip_s3armor_metadata(resp.headers_mut());
            // Multipart ETags are not content MD5s (`docs/ARCHITECTURE.md`
            // "ETag policy") —
            // the backend's own Complete ETag is kept as-is.
            Ok(resp)
        }
        Routing::V1(meta) => {
            let alg = meta.alg;
            let chunk_size = u64::from(meta.chunk_size);
            let ct_len = header_u64(&resp_headers, "content-length")
                .ok_or_else(|| S3Error::bad_gateway("backend HEAD returned no Content-Length"))?;
            let pt_len = plaintext_len(alg, ct_len, chunk_size).map_err(|_| {
                S3Error::bad_gateway("stored object length is not a valid v1 ciphertext length")
            })?;

            let mut resp = translate_response(backend_resp, request_id);
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
