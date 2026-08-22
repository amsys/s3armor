//! Put/Get/Head/Copy interception: format v1 encrypt on write, v1
//! decrypt on read. `docs/ARCHITECTURE.md` "Architecture: re-signing
//! streaming reverse proxy" and "Cryptographic design (format v1)".
//! Everything else stays passthrough (`proxy::mod`'s `Op::Passthrough`
//! arm); multipart is handled separately by `intercept::mpu`.

pub mod conditional;
pub mod copy;
pub mod footer;
pub mod get;
pub mod head;
pub mod mpu;
pub mod put;

use std::collections::BTreeMap;

use s3armor_format::v1::{open_emd5, path_binding, ObjectMeta};

use crate::config::BindMode;
use crate::proxy::body::ProxyBody;
use crate::proxy::error::S3Error;
use crate::proxy::route;
use crate::proxy::{header_value, ProxyState};

/// What GET/HEAD's shared routing decided about an object, from its
/// backend response headers. `docs/ARCHITECTURE.md` "Object metadata v1"'s
/// routing order: a v1 key, else passthrough (a pre-existing plaintext
/// object).
pub(crate) enum Routing {
    V1(ObjectMeta),
    Passthrough,
}

/// Collects `x-amz-meta-*` response headers (the `x-amz-meta-` prefix
/// stripped) and routes on **presence of the v1 version key**, never a
/// hardcoded default.
pub(crate) fn route_from_headers(headers: &[(String, String)]) -> Routing {
    let mut meta = BTreeMap::new();
    for (k, v) in headers {
        if let Some(rest) = k.to_ascii_lowercase().strip_prefix("x-amz-meta-") {
            meta.insert(rest.to_string(), v.clone());
        }
    }
    if meta.contains_key(s3armor_format::v1::KEY_VERSION) {
        return ObjectMeta::from_map(&meta).map_or(Routing::Passthrough, Routing::V1);
    }
    Routing::Passthrough
}

/// `bucket ‖ key` for `S3A_BIND_PATHS` (`docs/ARCHITECTURE.md` "Path
/// binding"), or empty
/// when the mode is `Off`. `key` must already be the real object key bytes
/// (percent-decoded, not the URL-path form) — `write_binding` below is the
/// version for callers that only have a raw request path.
pub(crate) fn binding_for(state: &ProxyState, bucket: &str, key: &[u8]) -> Vec<u8> {
    if state.config.bind_mode == BindMode::Off {
        return Vec::new();
    }
    path_binding(bucket.as_bytes(), key)
}

/// Like [`binding_for`], for callers that only have the request path —
/// `intercept::put`/`intercept::mpu`'s `handle_create`, and `resolve_key`
/// below. `key` is percent-decoded (`route::decode_key`) so a client's
/// choice of URL encoding never changes the binding.
///
/// A request path this proxy cannot parse into `(bucket, key)` should not
/// happen here — the dispatcher only routes `PutObject`/`Mpu` create to
/// this code once it has already parsed one — but `strict`'s entire
/// promise is that every object is provably bound, so this refuses to
/// silently degrade to an empty (unbound) write if that invariant is ever
/// wrong; `off`/`on` keep the previous empty-binding fallback (`on`'s
/// point is exactly that an unbound write/read still works).
pub(crate) fn write_binding(state: &ProxyState, raw_path: &str) -> Result<Vec<u8>, S3Error> {
    if state.config.bind_mode == BindMode::Off {
        return Ok(Vec::new());
    }
    let parsed = route::parse(raw_path);
    let (Some(bucket), Some(key)) = (parsed.bucket, parsed.key) else {
        return if state.config.bind_mode == BindMode::Strict {
            Err(S3Error::access_denied(
                "S3A_BIND_PATHS=strict: cannot parse a bucket/key from this request path to bind it",
            ))
        } else {
            Ok(Vec::new())
        };
    };
    Ok(binding_for(state, &bucket, &route::decode_key(&key)))
}

/// Resolves the DEK for a v1 object's metadata. `Keyring::unwrap` covers
/// both AES kids and the RSA write-only node (`KeyNotAvailable` when only
/// the public half is configured) — `docs/ARCHITECTURE.md` "Keys and
/// wrap".
///
/// `S3A_BIND_PATHS=on`'s bound-then-unbound retry lives here rather than in
/// `Keyring` because it needs to try two different `binding` values against
/// the same key, not two different keys: a bound wrap fails AEAD
/// authentication (`Error::UnwrapFailed`) under the wrong binding exactly
/// like it would under a tampered ciphertext, so only that specific failure
/// gets a second attempt — `KeyNotAvailable` (wrong/missing key) never does,
/// since no binding would fix that.
pub(crate) fn resolve_key(
    state: &ProxyState,
    meta: &ObjectMeta,
    raw_path: &str,
) -> Result<[u8; 32], S3Error> {
    let parsed = route::parse(raw_path);
    let (Some(bucket), Some(key)) = (parsed.bucket, parsed.key) else {
        // Same invariant as `write_binding`: an unparseable path must not
        // become a silent exception to `strict`'s "every unwrap is bound"
        // guarantee — reach `resolve_key_for`'s own `Strict` arm instead of
        // skipping it with an empty-binding unwrap.
        return if state.config.bind_mode == BindMode::Strict {
            Err(S3Error::access_denied(
                "S3A_BIND_PATHS=strict: cannot parse a bucket/key from this request path to verify its binding",
            ))
        } else {
            state
                .config
                .keyring
                .unwrap(meta.kek, &meta.kid, &meta.wrapped_dek, &[])
                .map_err(S3Error::from)
        };
    };
    resolve_key_for(state, meta, &bucket, &route::decode_key(&key))
}

/// [`resolve_key`] for callers that already have `(bucket, key)` rather than
/// a raw request path — `tools::rewrap`, `intercept::copy`'s rewrap-on-copy
/// arm.
pub(crate) fn resolve_key_for(
    state: &ProxyState,
    meta: &ObjectMeta,
    bucket: &str,
    key: &[u8],
) -> Result<[u8; 32], S3Error> {
    let keyring = &state.config.keyring;
    match state.config.bind_mode {
        BindMode::Off => keyring
            .unwrap(meta.kek, &meta.kid, &meta.wrapped_dek, &[])
            .map_err(S3Error::from),
        BindMode::Strict => {
            let binding = binding_for(state, bucket, key);
            keyring
                .unwrap(meta.kek, &meta.kid, &meta.wrapped_dek, &binding)
                .map_err(S3Error::from)
        }
        BindMode::On => {
            let binding = binding_for(state, bucket, key);
            match keyring.unwrap(meta.kek, &meta.kid, &meta.wrapped_dek, &binding) {
                Err(s3armor_format::Error::UnwrapFailed) => keyring
                    .unwrap(meta.kek, &meta.kid, &meta.wrapped_dek, &[])
                    .map_err(S3Error::from),
                other => other.map_err(S3Error::from),
            }
        }
    }
}

pub(crate) fn header_u64(headers: &[(String, String)], name: &str) -> Option<u64> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.parse().ok())
}

pub(crate) fn set_response_header(resp: &mut http::Response<ProxyBody>, name: &str, value: &str) {
    let Ok(hn) = http::HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    let Ok(hv) = http::HeaderValue::from_str(value) else {
        return;
    };
    resp.headers_mut().insert(hn, hv);
}

/// Strips surrounding `"` (an ETag's normal HTTP-header quoting) — shared
/// by multipart part-ETag comparison (`intercept::mpu::handle_complete`)
/// and conditional-request evaluation (`intercept::conditional`).
pub(crate) fn normalize_etag(s: &str) -> &str {
    s.trim_matches('"')
}

/// The plaintext-MD5 ETag for a v1 single-part object carrying `s3a-emd5`
/// (`docs/ARCHITECTURE.md` "ETag policy") — `None` for a multipart object
/// (its ETag is the backend's own Complete ETag, not a content MD5), an
/// object with no `Content-MD5` on its original PUT, or a key this node
/// cannot resolve.
pub(crate) fn emd5_etag(state: &ProxyState, meta: &ObjectMeta, raw_path: &str) -> Option<String> {
    if meta.multipart {
        return None;
    }
    let sealed = meta.emd5.as_ref()?;
    let key = resolve_key(state, meta, raw_path).ok()?;
    let md5 = open_emd5(meta.alg, &key, sealed).ok()?;
    Some(format!("\"{}\"", hex::encode(md5)))
}

/// The ETag this proxy will actually hand a client for an object, given its
/// routing and backend response headers: [`emd5_etag`] for a v1 single-part
/// object that has one, the backend's own ETag otherwise (v1 multipart,
/// passthrough). Used both to rewrite the response ETag (`intercept::get`,
/// `intercept::head`) and to evaluate conditional requests
/// (`intercept::conditional`) against it, so the two can never disagree —
/// a client would otherwise be handed an ETag this proxy then refuses to
/// honor in `If-Match`/`If-None-Match`.
pub(crate) fn effective_etag(
    state: &ProxyState,
    routing: &Routing,
    resp_headers: &[(String, String)],
    raw_path: &str,
) -> Option<String> {
    if let Routing::V1(meta) = routing {
        if let Some(etag) = emd5_etag(state, meta, raw_path) {
            return Some(etag);
        }
    }
    header_value(resp_headers, "etag").map(str::to_string)
}
