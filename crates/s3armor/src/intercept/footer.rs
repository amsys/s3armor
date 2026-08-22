//! Loads a multipart object's footer: two ranged GETs (trailer, then the
//! footer frame) the first time it is needed, cached afterward so a repeat
//! GET/HEAD costs nothing extra. `docs/ARCHITECTURE.md` "Multipart v1".

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use http_body_util::BodyExt;
use lru::LruCache;

use s3armor_format::v1::{Alg, Footer, TRAILER_LEN};

use crate::config::Backend;
use crate::proxy::body;
use crate::proxy::error::S3Error;
use crate::proxy::{forward, set_header, ProxyState};

/// Keyed by `(backend name, raw request path, backend ETag)` — the backend
/// name keeps two backends that happen to share a bucket/key/ETag from
/// colliding, and the ETag makes a new upload to the same key a natural
/// cache miss, never a stale read of a prior version's footer.
pub type FooterCache = Mutex<LruCache<(String, String, String), Arc<Footer>>>;

#[expect(clippy::expect_used, reason = "1 is nonzero")]
pub fn new_cache(capacity: usize) -> FooterCache {
    let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1).expect("1 is nonzero"));
    Mutex::new(LruCache::new(cap))
}

/// Loads a multipart object's footer, from cache or two ranged backend
/// GETs. `ct_len`/`etag` come from the HEAD/GET response the caller already
/// has; `alg`/`dek` come from the object's `ObjectMeta`.
#[expect(
    clippy::expect_used,
    reason = "footer cache mutex is never held across an await point, so it never poisons on a cancelled future"
)]
pub async fn load(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    alg: Alg,
    dek: &[u8; 32],
    ct_len: u64,
    etag: &str,
) -> Result<Arc<Footer>, S3Error> {
    let cache_key = (backend.name.clone(), raw_path.to_string(), etag.to_string());
    // Bound the lock to this statement (not the `if let`'s scrutinee) so the
    // guard drops before record_footer_cache/the early return, not after.
    let cached = state
        .footer_cache
        .lock()
        .expect("footer cache mutex is never held across an await point")
        .get(&cache_key)
        .cloned();
    if let Some(hit) = cached {
        state.record_footer_cache(true);
        return Ok(hit);
    }
    state.record_footer_cache(false);

    if ct_len < TRAILER_LEN as u64 {
        return Err(S3Error::bad_gateway(
            "multipart object is shorter than the footer trailer",
        ));
    }
    let trailer = ranged_get(
        state,
        backend,
        raw_path,
        ct_len - TRAILER_LEN as u64,
        ct_len - 1,
        "footer trailer",
    )
    .await?;
    let footer_len = Footer::parse_trailer(&trailer)
        .map_err(|e| S3Error::bad_gateway(format!("corrupt multipart footer trailer: {e}")))?;
    let frame_end = ct_len - TRAILER_LEN as u64;
    let frame_start = frame_end.checked_sub(footer_len).ok_or_else(|| {
        S3Error::bad_gateway("multipart footer trailer names a length larger than the object")
    })?;
    let frame = ranged_get(
        state,
        backend,
        raw_path,
        frame_start,
        frame_end - 1,
        "footer frame",
    )
    .await?;
    let footer = Footer::open(alg, dek, &frame).map_err(S3Error::from)?;
    let footer = Arc::new(footer);
    state
        .footer_cache
        .lock()
        .expect("footer cache mutex is never held across an await point")
        .put(cache_key, footer.clone());
    Ok(footer)
}

async fn ranged_get(
    state: &ProxyState,
    backend: &Backend,
    raw_path: &str,
    start: u64,
    end_inclusive: u64,
    what: &str,
) -> Result<bytes::Bytes, S3Error> {
    let mut headers = Vec::new();
    set_header(
        &mut headers,
        "range",
        &format!("bytes={start}-{end_inclusive}"),
    );
    let resp = forward(state, backend, "GET", raw_path, "", headers, body::empty()).await?;
    if !resp.status().is_success() {
        return Err(S3Error::bad_gateway(format!(
            "could not fetch multipart {what}: backend returned {}",
            resp.status()
        )));
    }
    resp.into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .map_err(|e| S3Error::bad_gateway(format!("reading multipart {what}: {e}")))
}
