//! PutObject interception: mint a DEK, wrap it under the active key, and
//! encrypt the body as v1 frames while streaming. `docs/ARCHITECTURE.md`
//! "Keys and wrap" and "Object metadata v1".

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use http::Response;
use rand_core::{OsRng, RngCore};

use s3armor_format::v1::{ciphertext_len, seal_emd5, ObjectMeta};

use crate::config::Backend;
use crate::intercept::{header_u64, set_response_header, write_binding};
use crate::proxy::body::{self, ProxyBody};
use crate::proxy::error::S3Error;
use crate::proxy::{forward, set_header, translate_response, ProxyState};

/// `outbound_headers` has already been through the same strip/rewrite
/// pipeline every op gets (`proxy::mod::handle_inner`); `base_body` is the
/// verified plaintext stream from `build_outbound_body` (aws-chunked
/// already decoded and chunk-signatures already checked, if applicable).
/// `content_md5_header` is the raw `Content-MD5` value, captured before
/// `strip_for_backend` removed the header itself.
#[expect(
    clippy::too_many_arguments,
    reason = "one flat PUT-encrypt-forward sequence: state, backend, path, headers, body, and the pre-strip Content-MD5 each need their own argument; splitting would fragment a single auditable path"
)]
pub async fn handle(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    raw_query: &str,
    mut outbound_headers: Vec<(String, String)>,
    base_body: ProxyBody,
    content_md5_header: Option<String>,
    request_id: &str,
) -> Result<Response<ProxyBody>, S3Error> {
    // S3 requires a length for PUT, and v1 needs the exact plaintext length
    // up front to compute the ciphertext Content-Length before the body
    // streams — this is why emd5 comes from Content-MD5 rather than a
    // buffer-then-compute step (docs/ARCHITECTURE.md "ETag policy").
    let pt_len = header_u64(&outbound_headers, "content-length")
        .ok_or_else(S3Error::missing_content_length)?;

    let alg = state.config.alg;
    let chunk_size = state.config.chunk_size as usize;

    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);
    let binding = write_binding(state, raw_path)?;
    let (kek, kid, wrapped_dek) = state.config.keyring.wrap_active(&dek, &binding)?;

    // No Content-MD5, or one that isn't 16 raw bytes: no emd5. HEAD/GET
    // then return the backend's ciphertext ETag — consistent with each
    // other, just not with the plaintext.
    let expected_md5 = content_md5_header
        .as_deref()
        .and_then(|h| B64.decode(h).ok())
        .and_then(|b| <[u8; 16]>::try_from(b).ok());
    let emd5 = expected_md5.map(|m| seal_emd5(alg, &dek, &m));

    let meta = ObjectMeta {
        alg,
        kek,
        kid,
        wrapped_dek,
        chunk_size: state.config.chunk_size,
        multipart: false,
        emd5,
    };
    for (k, v) in meta.to_map() {
        set_header(&mut outbound_headers, &format!("x-amz-meta-{k}"), &v);
    }
    let ct_len = ciphertext_len(alg, pt_len, chunk_size as u64);
    set_header(&mut outbound_headers, "content-length", &ct_len.to_string());

    let body = body::encrypting(
        base_body,
        alg,
        dek,
        chunk_size,
        expected_md5,
        pt_len,
        0,
        None,
    );

    let backend_resp = forward(
        state,
        backend,
        "PUT",
        raw_path,
        raw_query,
        outbound_headers,
        body,
    )
    .await?;
    let success = backend_resp.status().is_success();
    let mut resp = translate_response(backend_resp, request_id);
    // The client's own PUT ETag: the plaintext MD5 it sent, so PUT agrees
    // with HEAD/GET on the same object (docs/ARCHITECTURE.md "ETag policy"). Only on
    // success — an error response's headers are the backend's own.
    if success {
        if let Some(md5) = expected_md5 {
            set_response_header(&mut resp, "etag", &format!("\"{}\"", hex::encode(md5)));
        }
    }
    Ok(resp)
}
