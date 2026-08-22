//! `s3armor rewrap`: v1 key rotation, metadata-only (`docs/ARCHITECTURE.md`
//! "Key handling"). For every v1 object whose `s3a-kid` isn't the active
//! key, unwrap its DEK under the old key, re-wrap it under the active key,
//! and land the new metadata with a self-`CopyObject` (`REPLACE`
//! directive) — the DEK itself never changes, so the ciphertext never
//! moves. Runs with parallel workers, a checkpoint, and `--dry-run`.

use std::path::PathBuf;
use std::sync::Arc;

use futures_util::{stream, StreamExt};

use s3armor_format::v1::ObjectMeta;

use crate::config::Backend;
use crate::intercept::{route_from_headers, Routing};
use crate::proxy::body;
use crate::proxy::headers::{is_own_metadata_header, to_pairs};
use crate::proxy::{forward, set_header, ProxyState};

use super::{list, resolve_backend, Checkpoint, ToolError};

pub struct RewrapArgs {
    pub bucket: String,
    pub prefix: String,
    pub workers: usize,
    pub checkpoint: Option<PathBuf>,
    pub dry_run: bool,
    /// Which configured backend to walk. `None` only works when exactly
    /// one backend is configured (`tools::resolve_backend`).
    pub backend: Option<String>,
}

impl Default for RewrapArgs {
    fn default() -> Self {
        Self {
            bucket: String::new(),
            prefix: String::new(),
            workers: 4,
            checkpoint: None,
            dry_run: false,
            backend: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct RewrapReport {
    pub rewrapped: u64,
    pub skipped_already_active: u64,
    pub skipped_not_v1: u64,
    pub failed: Vec<(String, String)>,
}

impl RewrapReport {
    pub const fn ok(&self) -> bool {
        self.failed.is_empty()
    }

    pub fn print(&self, dry_run: bool) {
        let verb = if dry_run { "would rewrap" } else { "rewrapped" };
        println!(
            "s3armor rewrap: {verb} {}, already-active {}, not-v1 {}, failed {}",
            self.rewrapped,
            self.skipped_already_active,
            self.skipped_not_v1,
            self.failed.len()
        );
        for (key, reason) in &self.failed {
            println!("  FAILED {key}: {reason}");
        }
    }
}

enum Outcome {
    Rewrapped,
    AlreadyActive,
    NotV1,
}

/// Lists every object under `prefix`, then drops the ones the checkpoint
/// already marked done — shared by `rewrap` and `rebind`, the only part of
/// their walks that's actually identical (each dispatches to a different
/// per-object function with a different signature, so that part stays
/// separate rather than forcing a generic higher-order walk over it).
async fn list_pending(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
    prefix: &str,
    checkpoint: &Checkpoint,
) -> Result<Vec<list::ListedObject>, ToolError> {
    let mut objects = Vec::new();
    let mut token = None;
    loop {
        let page = list::list_page(state, backend, bucket, prefix, token.as_deref()).await?;
        objects.extend(page.objects);
        token = page.next_token;
        if token.is_none() {
            break;
        }
    }
    objects.retain(|o| !checkpoint.is_done(&o.key));
    Ok(objects)
}

pub async fn rewrap(state: Arc<ProxyState>, args: RewrapArgs) -> Result<RewrapReport, ToolError> {
    let backend = resolve_backend(&state.config, args.backend.as_deref())?.clone();
    let checkpoint = Arc::new(tokio::sync::Mutex::new(Checkpoint::open(
        args.checkpoint.as_deref(),
    )?));

    let objects = list_pending(
        &state,
        &backend,
        &args.bucket,
        &args.prefix,
        &*checkpoint.lock().await,
    )
    .await?;
    println!(
        "s3armor rewrap: {} object(s) to consider in s3://{}/{}",
        objects.len(),
        args.bucket,
        args.prefix
    );

    let bucket = args.bucket.clone();
    let dry_run = args.dry_run;
    let workers = args.workers.max(1);

    let results: Vec<(String, Result<Outcome, String>)> = stream::iter(objects)
        .map(|o| {
            let state = state.clone();
            let backend = backend.clone();
            let bucket = bucket.clone();
            let checkpoint = checkpoint.clone();
            async move {
                let key = o.key.clone();
                let outcome = rewrap_one(&state, &backend, &bucket, &o.key, dry_run).await;
                if outcome.is_ok() && !dry_run {
                    let mut cp = checkpoint.lock().await;
                    let _ = cp.mark_done(&key);
                }
                (key, outcome.map_err(|e| e.to_string()))
            }
        })
        .buffer_unordered(workers)
        .collect()
        .await;

    let mut report = RewrapReport::default();
    for (key, r) in results {
        match r {
            Ok(Outcome::Rewrapped) => report.rewrapped += 1,
            Ok(Outcome::AlreadyActive) => report.skipped_already_active += 1,
            Ok(Outcome::NotV1) => report.skipped_not_v1 += 1,
            Err(reason) => report.failed.push((key, reason)),
        }
    }
    Ok(report)
}

fn header_owned(pairs: &[(String, String)], name: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

async fn rewrap_one(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
    key: &str,
    dry_run: bool,
) -> Result<Outcome, ToolError> {
    let path = format!(
        "/{bucket}/{}",
        crate::proxy::route::encode_key_for_path(key)
    );
    let head = forward(state, backend, "HEAD", &path, "", Vec::new(), body::empty()).await?;
    if !head.status().is_success() {
        return Err(ToolError::Backend(format!(
            "HEAD failed: {}",
            head.status()
        )));
    }
    let head_headers = to_pairs(head.headers());
    let meta = match route_from_headers(&head_headers) {
        Routing::V1(m) => m,
        Routing::Passthrough => return Ok(Outcome::NotV1),
    };
    let active_kid = state.config.keyring.active_kid();
    if meta.kid == active_kid {
        return Ok(Outcome::AlreadyActive);
    }
    if dry_run {
        return Ok(Outcome::Rewrapped);
    }

    let dek = crate::intercept::resolve_key_for(state, &meta, bucket, key.as_bytes())
        .map_err(|_| ToolError::Backend(format!("old key {} is not configured", meta.kid)))?;
    let binding = crate::intercept::binding_for(state, bucket, key.as_bytes());
    let (new_kek, new_kid, wrapped_dek) = state.config.keyring.wrap_active(&dek, &binding)?;

    let new_meta = ObjectMeta {
        alg: meta.alg,
        kek: new_kek,
        kid: new_kid,
        wrapped_dek,
        chunk_size: meta.chunk_size,
        multipart: meta.multipart,
        emd5: meta.emd5.clone(),
    };

    let content_type = header_owned(&head_headers, "content-type");
    let preserved: Vec<(String, String)> = head_headers
        .iter()
        .filter(|(k, _)| k.to_ascii_lowercase().starts_with("x-amz-meta-"))
        .filter(|(k, _)| !is_own_metadata_header(k))
        .cloned()
        .collect();

    let mut copy_headers = Vec::new();
    set_header(&mut copy_headers, "x-amz-copy-source", &path);
    set_header(&mut copy_headers, "x-amz-metadata-directive", "REPLACE");
    if let Some(ct) = &content_type {
        set_header(&mut copy_headers, "content-type", ct);
    }
    for (k, v) in &preserved {
        set_header(&mut copy_headers, k, v);
    }
    for (k, v) in new_meta.to_map() {
        set_header(&mut copy_headers, &format!("x-amz-meta-{k}"), &v);
    }

    let resp = forward(
        state,
        backend,
        "PUT",
        &path,
        "",
        copy_headers,
        body::empty(),
    )
    .await?;
    if !resp.status().is_success() {
        return Err(ToolError::Backend(format!(
            "self-copy failed: {}",
            resp.status()
        )));
    }
    Ok(Outcome::Rewrapped)
}

// --- s3armor rebind -------------------------------------------------------
//
// `s3armor rebind`: metadata-only `S3A_BIND_PATHS` migration (`docs/ARCHITECTURE.md`
// "Path binding"). `rebind` *is* `rewrap` with a different binding instead of a
// different key — same list/checkpoint/parallel-workers/`--dry-run` shape,
// so it lives in this file rather than duplicating the whole tool. It
// re-wraps under the **active** key (same as `rewrap`, since `Keyring` only
// exposes wrapping under the active key) — an object still on an old key
// gets rotated onto the active one as a side effect of gaining a binding;
// run `rewrap` first if you want key rotation and rebinding as separate,
// auditable steps.

pub struct RebindArgs {
    pub bucket: String,
    pub prefix: String,
    pub workers: usize,
    pub checkpoint: Option<PathBuf>,
    pub dry_run: bool,
    /// Which configured backend to walk. `None` only works when exactly
    /// one backend is configured (`tools::resolve_backend`).
    pub backend: Option<String>,
    /// The renamed-bucket restore case (`docs/ARCHITECTURE.md` "Path binding"): try this
    /// bucket's binding (same key) after the current bucket's and the empty
    /// binding both fail to unwrap.
    pub from_bucket: Option<String>,
}

impl Default for RebindArgs {
    fn default() -> Self {
        Self {
            bucket: String::new(),
            prefix: String::new(),
            workers: 4,
            checkpoint: None,
            dry_run: false,
            backend: None,
            from_bucket: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct RebindReport {
    pub rebound: u64,
    pub skipped_already_bound: u64,
    pub skipped_not_v1: u64,
    pub failed: Vec<(String, String)>,
}

impl RebindReport {
    pub const fn ok(&self) -> bool {
        self.failed.is_empty()
    }

    pub fn print(&self, dry_run: bool) {
        let verb = if dry_run { "would rebind" } else { "rebound" };
        println!(
            "s3armor rebind: {verb} {}, already-bound {}, not-v1 {}, failed {}",
            self.rebound,
            self.skipped_already_bound,
            self.skipped_not_v1,
            self.failed.len()
        );
        for (key, reason) in &self.failed {
            println!("  FAILED {key}: {reason}");
        }
    }
}

enum RebindOutcome {
    Rebound,
    AlreadyBound,
    NotV1,
}

pub async fn rebind(state: Arc<ProxyState>, args: RebindArgs) -> Result<RebindReport, ToolError> {
    let backend = resolve_backend(&state.config, args.backend.as_deref())?.clone();
    let checkpoint = Arc::new(tokio::sync::Mutex::new(Checkpoint::open(
        args.checkpoint.as_deref(),
    )?));

    let objects = list_pending(
        &state,
        &backend,
        &args.bucket,
        &args.prefix,
        &*checkpoint.lock().await,
    )
    .await?;
    println!(
        "s3armor rebind: {} object(s) to consider in s3://{}/{}",
        objects.len(),
        args.bucket,
        args.prefix
    );

    let bucket = args.bucket.clone();
    let from_bucket = args.from_bucket.clone();
    let dry_run = args.dry_run;
    let workers = args.workers.max(1);

    let results: Vec<(String, Result<RebindOutcome, String>)> = stream::iter(objects)
        .map(|o| {
            let state = state.clone();
            let backend = backend.clone();
            let bucket = bucket.clone();
            let from_bucket = from_bucket.clone();
            let checkpoint = checkpoint.clone();
            async move {
                let key = o.key.clone();
                let outcome = rebind_one(
                    &state,
                    &backend,
                    &bucket,
                    &o.key,
                    from_bucket.as_deref(),
                    dry_run,
                )
                .await;
                if outcome.is_ok() && !dry_run {
                    let mut cp = checkpoint.lock().await;
                    let _ = cp.mark_done(&key);
                }
                (key, outcome.map_err(|e| e.to_string()))
            }
        })
        .buffer_unordered(workers)
        .collect()
        .await;

    let mut report = RebindReport::default();
    for (key, r) in results {
        match r {
            Ok(RebindOutcome::Rebound) => report.rebound += 1,
            Ok(RebindOutcome::AlreadyBound) => report.skipped_already_bound += 1,
            Ok(RebindOutcome::NotV1) => report.skipped_not_v1 += 1,
            Err(reason) => report.failed.push((key, reason)),
        }
    }
    Ok(report)
}

async fn rebind_one(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
    key: &str,
    from_bucket: Option<&str>,
    dry_run: bool,
) -> Result<RebindOutcome, ToolError> {
    let path = format!(
        "/{bucket}/{}",
        crate::proxy::route::encode_key_for_path(key)
    );
    let head = forward(state, backend, "HEAD", &path, "", Vec::new(), body::empty()).await?;
    if !head.status().is_success() {
        return Err(ToolError::Backend(format!(
            "HEAD failed: {}",
            head.status()
        )));
    }
    let head_headers = to_pairs(head.headers());
    let meta = match route_from_headers(&head_headers) {
        Routing::V1(m) => m,
        Routing::Passthrough => return Ok(RebindOutcome::NotV1),
    };

    let keyring = &state.config.keyring;
    let current_binding = crate::intercept::binding_for(state, bucket, key.as_bytes());

    // Already wrapped under this (bucket, key)'s current binding (a no-op
    // re-run, or S3A_BIND_PATHS=off where "current" is the empty binding
    // anyway) — idempotent, nothing to do.
    if keyring
        .unwrap(meta.kek, &meta.kid, &meta.wrapped_dek, &current_binding)
        .is_ok()
    {
        return Ok(RebindOutcome::AlreadyBound);
    }

    // Not bound to (bucket, key) yet. Try the empty binding (written before
    // S3A_BIND_PATHS existed), then --from-bucket's binding (the
    // renamed-bucket restore case) — first success wins.
    let mut dek = keyring.unwrap(meta.kek, &meta.kid, &meta.wrapped_dek, &[]);
    if dek.is_err() {
        if let Some(from) = from_bucket {
            let old_binding = crate::intercept::binding_for(state, from, key.as_bytes());
            dek = keyring.unwrap(meta.kek, &meta.kid, &meta.wrapped_dek, &old_binding);
        }
    }
    let dek = dek.map_err(|_| {
        ToolError::Backend(format!(
            "no binding unwrapped key id {} (tried this bucket, empty{})",
            meta.kid,
            if from_bucket.is_some() {
                ", --from-bucket"
            } else {
                ""
            }
        ))
    })?;

    if dry_run {
        return Ok(RebindOutcome::Rebound);
    }

    let (new_kek, new_kid, wrapped_dek) = keyring.wrap_active(&dek, &current_binding)?;
    let new_meta = ObjectMeta {
        alg: meta.alg,
        kek: new_kek,
        kid: new_kid,
        wrapped_dek,
        chunk_size: meta.chunk_size,
        multipart: meta.multipart,
        emd5: meta.emd5.clone(),
    };

    let content_type = header_owned(&head_headers, "content-type");
    let preserved: Vec<(String, String)> = head_headers
        .iter()
        .filter(|(k, _)| k.to_ascii_lowercase().starts_with("x-amz-meta-"))
        .filter(|(k, _)| !is_own_metadata_header(k))
        .cloned()
        .collect();

    let mut copy_headers = Vec::new();
    set_header(&mut copy_headers, "x-amz-copy-source", &path);
    set_header(&mut copy_headers, "x-amz-metadata-directive", "REPLACE");
    if let Some(ct) = &content_type {
        set_header(&mut copy_headers, "content-type", ct);
    }
    for (k, v) in &preserved {
        set_header(&mut copy_headers, k, v);
    }
    for (k, v) in new_meta.to_map() {
        set_header(&mut copy_headers, &format!("x-amz-meta-{k}"), &v);
    }

    let resp = forward(
        state,
        backend,
        "PUT",
        &path,
        "",
        copy_headers,
        body::empty(),
    )
    .await?;
    if !resp.status().is_success() {
        return Err(ToolError::Backend(format!(
            "self-copy failed: {}",
            resp.status()
        )));
    }
    Ok(RebindOutcome::Rebound)
}
