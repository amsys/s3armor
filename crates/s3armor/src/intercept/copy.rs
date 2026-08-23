//! CopyObject interception: reject the silent-data-loss case a plain
//! passthrough server-side copy would otherwise create, then pass
//! everything else through untouched. `docs/ARCHITECTURE.md` "S3
//! operation matrix (v1)"; found while building the copy interceptor.
//!
//! A passthrough copy is correct for a v1 or plaintext source: v1
//! ciphertext isn't path-bound in default mode, so a same-content copy
//! under a new key stays decryptable.
//!
//! `x-amz-metadata-directive: REPLACE` against a v1 source is rejected
//! outright: it drops the `s3a-*` metadata keys and orphans the object —
//! a silent, undecryptable-copy defect.
//!
//! Under `S3A_BIND_PATHS` (`docs/ARCHITECTURE.md` "Path binding"), a v1
//! source becomes a second case: a plain passthrough copy would leave the
//! destination object's DEK still wrapped under the *source's*
//! `bucket ‖ key`, which `resolve_key` at the new location can never
//! unwrap (the same silent-loss class the REPLACE case above already
//! guards against) — so the copy unwraps under the source's binding and
//! re-wraps under the destination's, same metadata-only self-copy shape
//! `tools::rewrap` uses.
//!
//! `x-amz-copy-source-if-match`/`-if-none-match` name the *effective* ETag
//! this proxy handed the client (`intercept::effective_etag`) — the
//! plaintext MD5 for a v1 single-part source with `s3a-emd5` — but the
//! backend only knows its own stored (ciphertext) ETag. Left untranslated,
//! a client's `if-match` on the ETag it was given would spuriously fail,
//! and — worse — its `if-none-match` would spuriously succeed a copy the
//! client meant to skip because it believed the source unchanged. Both
//! headers are rewritten to the backend's ETag when the client's list
//! names the effective one, mirroring `intercept::conditional`'s
//! GET/HEAD translation. `-if-modified-since`/`-if-unmodified-since` are
//! left untouched: they compare `Last-Modified`, which this proxy never
//! rewrites, same as `conditional.rs`'s own note on the date headers.

use http::{Response, StatusCode};

use s3armor_format::v1::ObjectMeta;

use crate::config::{Backend, BindMode};
use crate::intercept::conditional::list_contains_etag;
use crate::intercept::{binding_for, effective_etag, resolve_key_for, route_from_headers, Routing};
use crate::proxy::body::{self, ProxyBody};
use crate::proxy::error::S3Error;
use crate::proxy::headers::{is_own_metadata_header, to_pairs};
use crate::proxy::route;
use crate::proxy::{forward, header_value, set_header, translate_response, ProxyState};

pub async fn handle(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    raw_query: &str,
    mut outbound_headers: Vec<(String, String)>,
    request_id: &str,
) -> Result<Response<ProxyBody>, S3Error> {
    let copy_source = header_value(&outbound_headers, "x-amz-copy-source")
        .ok_or_else(|| S3Error::bad_gateway("CopyObject routed with no x-amz-copy-source"))?
        .to_string();
    let source = route::parse_copy_source(&copy_source)
        .ok_or_else(|| S3Error::bad_gateway("malformed x-amz-copy-source"))?;
    let (Some(src_bucket), Some(src_key)) = (source.bucket, source.key) else {
        return Err(S3Error::bad_gateway("malformed x-amz-copy-source"));
    };
    let src_path = format!("/{src_bucket}/{src_key}");

    // A diagnostic HEAD on the source, direct to the backend — not a
    // client-visible operation. If it fails, the copy itself (issued
    // below) surfaces the real error (missing source, access denied, ...)
    // rather than this probe.
    let head_resp = forward(
        state,
        backend,
        "HEAD",
        &src_path,
        "",
        Vec::new(),
        body::empty(),
    )
    .await?;
    if !head_resp.status().is_success() {
        let backend_resp = forward(
            state,
            backend,
            "PUT",
            raw_path,
            raw_query,
            outbound_headers,
            body::empty(),
        )
        .await?;
        return Ok(translate_response(backend_resp, request_id));
    }
    let head_headers = to_pairs(head_resp.headers());
    let routing = route_from_headers(&head_headers)?;

    // The client's copy-source conditionals name the ETag this proxy handed
    // it, not what the backend stores under — translate before either copy
    // path below forwards them. A no-op for passthrough/multipart sources,
    // where the two already agree.
    if let (Some(effective), Some(backend_etag)) = (
        effective_etag(state, &routing, &head_headers, &src_path),
        header_value(&head_headers, "etag"),
    ) {
        if effective != backend_etag {
            translate_copy_source_conditionals(&mut outbound_headers, &effective, backend_etag);
        }
    }

    let is_replace = header_value(&outbound_headers, "x-amz-metadata-directive")
        .is_some_and(|v| v.eq_ignore_ascii_case("REPLACE"));

    #[expect(
        clippy::match_same_arms,
        reason = "each empty arm is a distinct routing case (untouched, or already made safe below); merging would obscure that"
    )]
    match &routing {
        Routing::Passthrough => {}
        Routing::V1(_) if is_replace => {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "metadata-directive REPLACE would drop this object's v1 encryption metadata; \
                 re-encrypt it through a PUT instead",
            ));
        }
        Routing::V1(meta) if state.config.bind_mode != BindMode::Off => {
            return rewrap_copy(
                state,
                backend,
                raw_path,
                raw_query,
                &outbound_headers,
                &head_headers,
                &src_bucket,
                &src_key,
                meta,
                request_id,
            )
            .await;
        }
        Routing::V1(_) => {}
    }

    let backend_resp = forward(
        state,
        backend,
        "PUT",
        raw_path,
        raw_query,
        outbound_headers,
        body::empty(),
    )
    .await?;
    Ok(translate_response(backend_resp, request_id))
}

/// `S3A_BIND_PATHS != off`'s copy path for a v1 source: unwrap under the
/// source's binding, re-wrap under the destination's, and issue the copy as
/// a `metadata-directive: REPLACE` carrying the rebuilt `s3a-*` metadata —
/// still one server-side copy, no data movement, same shape as
/// `tools::rewrap`'s self-copy.
#[expect(
    clippy::too_many_arguments,
    reason = "one flat rewrap-and-copy sequence: source/destination path, headers, and rewrap material each need their own argument; splitting would fragment a single auditable copy path"
)]
async fn rewrap_copy(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    raw_query: &str,
    outbound_headers: &[(String, String)],
    src_head_headers: &[(String, String)],
    src_bucket: &str,
    src_key: &str,
    meta: &ObjectMeta,
    request_id: &str,
) -> Result<Response<ProxyBody>, S3Error> {
    let dest = route::parse(raw_path);
    let (Some(dest_bucket), Some(dest_key)) = (dest.bucket, dest.key) else {
        return Err(S3Error::bad_gateway(
            "CopyObject destination has no bucket/key",
        ));
    };

    let dek = resolve_key_for(state, meta, src_bucket, &route::decode_key(src_key))?;
    let dest_binding = binding_for(state, &dest_bucket, &route::decode_key(&dest_key));
    let (new_kek, new_kid, wrapped_dek) = state.config.keyring.wrap_active(&dek, &dest_binding)?;
    let new_meta = ObjectMeta {
        alg: meta.alg,
        kek: new_kek,
        kid: new_kid,
        wrapped_dek,
        chunk_size: meta.chunk_size,
        multipart: meta.multipart,
        emd5: meta.emd5.clone(),
    };

    let mut copy_headers: Vec<(String, String)> = outbound_headers
        .iter()
        .filter(|(k, _)| {
            !k.eq_ignore_ascii_case("x-amz-metadata-directive")
                && (!k.to_ascii_lowercase().starts_with("x-amz-meta-")
                    || !is_own_metadata_header(k))
        })
        .cloned()
        .collect();
    set_header(&mut copy_headers, "x-amz-metadata-directive", "REPLACE");
    if let Some(ct) = header_value(src_head_headers, "content-type") {
        set_header(&mut copy_headers, "content-type", ct);
    }
    for (k, v) in src_head_headers {
        let kl = k.to_ascii_lowercase();
        if kl.starts_with("x-amz-meta-") && !is_own_metadata_header(k) {
            set_header(&mut copy_headers, k, v);
        }
    }
    for (k, v) in new_meta.to_map() {
        set_header(&mut copy_headers, &format!("x-amz-meta-{k}"), &v);
    }

    let backend_resp = forward(
        state,
        backend,
        "PUT",
        raw_path,
        raw_query,
        copy_headers,
        body::empty(),
    )
    .await?;
    Ok(translate_response(backend_resp, request_id))
}

/// Rewrites `x-amz-copy-source-if-match`/`-if-none-match` from the
/// effective ETag this proxy handed the client to the backend's own stored
/// ETag, when the client's list names the effective one. Leaves a header
/// untouched when it names something else — a plaintext-MD5 list already
/// evaluates "no match" correctly against the stored ciphertext ETag.
fn translate_copy_source_conditionals(
    headers: &mut [(String, String)],
    effective_etag: &str,
    backend_etag: &str,
) {
    for name in [
        "x-amz-copy-source-if-match",
        "x-amz-copy-source-if-none-match",
    ] {
        if let Some((_, value)) = headers
            .iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
        {
            if list_contains_etag(value, effective_etag) {
                value.clear();
                value.push_str(backend_etag);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_a_header_naming_the_effective_etag() {
        let mut headers = vec![(
            "x-amz-copy-source-if-match".to_string(),
            "\"plaintext-md5\"".to_string(),
        )];
        translate_copy_source_conditionals(
            &mut headers,
            "\"plaintext-md5\"",
            "\"ciphertext-etag\"",
        );
        assert_eq!(headers[0].1, "\"ciphertext-etag\"");
    }

    #[test]
    fn leaves_a_header_naming_something_else_untouched() {
        let mut headers = vec![(
            "x-amz-copy-source-if-none-match".to_string(),
            "\"some-other-etag\"".to_string(),
        )];
        translate_copy_source_conditionals(
            &mut headers,
            "\"plaintext-md5\"",
            "\"ciphertext-etag\"",
        );
        assert_eq!(headers[0].1, "\"some-other-etag\"");
    }

    #[test]
    fn missing_header_is_a_no_op() {
        let mut headers: Vec<(String, String)> = vec![];
        translate_copy_source_conditionals(&mut headers, "\"a\"", "\"b\"");
        assert!(headers.is_empty());
    }
}
