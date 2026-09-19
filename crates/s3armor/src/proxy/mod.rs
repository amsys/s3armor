//! The re-signing streaming reverse proxy — `docs/ARCHITECTURE.md` "Architecture: re-signing streaming reverse proxy". Verify the
//! client's SigV4 signature, rewrite only what must change (payload
//! representation, a handful of headers, the credential, and — for
//! Put/Get/Head — the object body itself), re-sign with the backend's
//! credentials, stream both ways. Everything the client sent that doesn't
//! need to change reaches the backend byte-identical, and the backend's own
//! response — including its own XML for every operation this proxy does not
//! intercept — comes back unchanged.
//!
//! Put/Get/Head/Copy/multipart are all intercepted with format v1
//! (`crate::intercept`). Three operations fail with an explicit
//! `NotImplemented` instead of running: `UploadPartCopy` and
//! `GetObject?partNumber` (ciphertext cannot be re-chunked server-side,
//! `docs/ARCHITECTURE.md` "S3 operation matrix (v1)"), and `SelectObjectContent` (the backend would query
//! ciphertext, not plaintext, and return wrong or empty results instead of
//! an honest error). Everything else stays passthrough.

pub mod body;
pub mod client;
pub mod error;
pub mod headers;
pub mod metrics;
pub mod route;

use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Request, Response, StatusCode, Uri};
use http_body_util::BodyExt;
use hyper::body::Incoming;

use crate::chunked::ChunkVerifier;
use crate::config::{Backend, Config};
use crate::intercept;
use crate::intercept::footer::FooterCache;
use crate::mpu::Sessions;
use crate::ratelimit::AuthRateLimiter;
use crate::sigv4;

use body::ProxyBody;
use client::BackendClient;
use error::S3Error;

pub struct ProxyState {
    pub config: Config,
    pub client: BackendClient,
    request_counter: AtomicU64,
    /// Multipart-upload session state (`docs/ARCHITECTURE.md` "Multipart
    /// v1"). RAM only,
    /// single instance — `Arc` so `spawn_mpu_sweeper` can hold its own
    /// reference independent of `ProxyState`'s lifetime.
    pub sessions: Arc<Sessions>,
    /// Cached multipart footers, keyed by `(request path, backend ETag)` —
    /// see `intercept::footer`.
    pub footer_cache: FooterCache,
    mpu_sessions_created: AtomicU64,
    footer_cache_hits: AtomicU64,
    footer_cache_misses: AtomicU64,
    /// SigV4 verification failures — `docs/ARCHITECTURE.md` "Observability"'s
    /// "auth failures by reason" (reason itself is in the log line, not
    /// this counter; this is the alertable count). Incremented at
    /// `handle_inner`'s single `sigv4::verify::verify` call site.
    auth_failures: AtomicU64,
    /// v1 chunk AEAD verify failures — docs/ARCHITECTURE.md
    /// "Observability"'s "chunk verify failures (alert on any)". `Arc`
    /// because the decrypt body transforms (`proxy::body::decrypting` and
    /// friends) run in a spawned, 'static tokio task with no reference to
    /// `ProxyState` — this is the one piece of state handed to them
    /// directly, a side channel independent of the request lifetime.
    chunk_verify_failures: Arc<AtomicU64>,
    /// Requests rejected with `429 SlowDown` before SigV4 verification even
    /// ran, because the source IP was already over `S3A_AUTH_FAIL_LIMIT`.
    auth_rate_limited: AtomicU64,
    /// Per-source-IP token bucket on auth failures (`crate::ratelimit`).
    auth_rate_limiter: AuthRateLimiter,
    /// Set once `serve`'s shutdown sequence begins (`docs/ARCHITECTURE.md`
    /// "Observability": "`/health` ... 503 during drain"). `/health` reads
    /// this to tell a
    /// load balancer / `docker`'s own healthcheck to stop routing new
    /// traffic here while in-flight requests finish.
    draining: AtomicBool,
}

impl ProxyState {
    pub fn new(config: Config) -> Self {
        let footer_cache = intercept::footer::new_cache(config.footer_cache);
        let auth_rate_limiter = AuthRateLimiter::new(config.auth_fail_limit);
        Self {
            client: client::build(config.timeout_connect),
            request_counter: AtomicU64::new(0),
            sessions: Arc::new(Sessions::new()),
            footer_cache,
            mpu_sessions_created: AtomicU64::new(0),
            footer_cache_hits: AtomicU64::new(0),
            footer_cache_misses: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            chunk_verify_failures: Arc::new(AtomicU64::new(0)),
            auth_rate_limited: AtomicU64::new(0),
            auth_rate_limiter,
            draining: AtomicBool::new(false),
            config,
        }
    }

    /// Flips `/health` from `200` to `503` — called once, from `serve`'s
    /// shutdown sequence, before it stops accepting new connections.
    pub fn set_draining(&self) {
        self.draining.store(true, Ordering::Relaxed);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Starts the multipart-session TTL sweeper (`docs/ARCHITECTURE.md`
    /// "Multipart v1"). Call once, from `serve` — the CLI tools never
    /// create multipart sessions, so they have nothing to sweep. Ticks
    /// every 60s.
    pub fn spawn_mpu_sweeper(self: &Arc<Self>) {
        self.spawn_mpu_sweeper_with_tick(self.config.mp_ttl, Duration::from_mins(1));
    }

    /// Like [`spawn_mpu_sweeper`](Self::spawn_mpu_sweeper), with an
    /// explicit tick interval — tests use a short tick so TTL expiry is
    /// observable without a minute-long sleep.
    ///
    /// For every session `Sessions::take_expired` reaps that never reached
    /// `CompleteMultipartUpload`, this also aborts the backend's own
    /// multipart upload — otherwise the parts stay on the backend, billed,
    /// forever (docs/ARCHITECTURE.md "Multipart v1"; a sweeper that runs
    /// but leaves the backend upload dangling is a quieter version of the
    /// same leak). Best-effort: logged on
    /// failure, never retried — this is cleanup, not a correctness path, and
    /// a real S3 backend also expires abandoned multipart uploads on its
    /// own lifecycle policy.
    pub fn spawn_mpu_sweeper_with_tick(self: &Arc<Self>, ttl: Duration, tick: Duration) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tick);
            loop {
                interval.tick().await;
                for (session_key, completed) in state.sessions.take_expired(ttl) {
                    if completed {
                        continue; // finished upload, nothing to abort
                    }
                    abort_expired_upload(&state, session_key).await;
                }
            }
        });
    }

    pub(crate) fn record_mpu_session_created(&self) {
        self.mpu_sessions_created.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mpu_sessions_created(&self) -> u64 {
        self.mpu_sessions_created.load(Ordering::Relaxed)
    }

    pub fn mpu_sessions_active(&self) -> usize {
        self.sessions.len()
    }

    pub(crate) fn record_footer_cache(&self, hit: bool) {
        if hit {
            self.footer_cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.footer_cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn footer_cache_hits(&self) -> u64 {
        self.footer_cache_hits.load(Ordering::Relaxed)
    }

    pub fn footer_cache_misses(&self) -> u64 {
        self.footer_cache_misses.load(Ordering::Relaxed)
    }

    pub(crate) fn record_auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn auth_failures(&self) -> u64 {
        self.auth_failures.load(Ordering::Relaxed)
    }

    pub fn auth_rate_limited(&self) -> u64 {
        self.auth_rate_limited.load(Ordering::Relaxed)
    }

    /// A cloneable handle to the chunk-verify-failure counter, for the
    /// spawned decrypt body transforms that have no other way to reach
    /// `ProxyState` — see the field's own doc comment.
    pub(crate) fn chunk_verify_failures_handle(&self) -> Arc<AtomicU64> {
        self.chunk_verify_failures.clone()
    }

    pub fn chunk_verify_failures(&self) -> u64 {
        self.chunk_verify_failures.load(Ordering::Relaxed)
    }

    /// A per-request correlation id for logs and `RequestId` — not a
    /// security token, so a cheap counter mixed with the clock is enough;
    /// no RNG dependency needed for this.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "not a security token (see doc above) — truncating the nanosecond count is fine"
    )]
    fn next_request_id(&self) -> String {
        let n = self.request_counter.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        format!("{:016X}", nanos ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15))
    }
}

/// The hyper entry point. Never returns `Err` — every failure becomes an
/// S3-shaped XML error response, so the connection loop stays simple.
/// `peer_ip` is the TCP peer only — see `crate::ratelimit`'s module doc for
/// why `X-Forwarded-For` is never trusted here.
pub async fn handle(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
    peer_ip: IpAddr,
) -> Result<Response<ProxyBody>, Infallible> {
    let request_id = state.next_request_id();
    if req.method() == http::Method::GET {
        match req.uri().path() {
            "/health" => return Ok(health_response(state.is_draining())),
            "/ready" => return Ok(ready_response(&state).await),
            _ => {}
        }
    }
    // The scope gives this request the abort slot its verifying body
    // wrappers report into (`body::AbortSlot`).
    match body::with_abort_slot(handle_inner(&state, req, &request_id, peer_ip)).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            tracing::warn!(request_id, code = e.code, error = %e.message, "request failed");
            Ok(e.into_response(&request_id))
        }
    }
}

/// Liveness — `200 ok` normally, `503 draining` once `serve`'s shutdown
/// sequence has set `ProxyState::draining` (`docs/ARCHITECTURE.md` "Observability").
/// Unauthenticated, middleware-free: matched in `handle` before
/// `handle_inner` ever runs.
#[expect(clippy::expect_used, reason = "static health response always builds")]
fn health_response(draining: bool) -> Response<ProxyBody> {
    let (status, text): (StatusCode, &'static str) = if draining {
        (StatusCode::SERVICE_UNAVAILABLE, "draining")
    } else {
        (StatusCode::OK, "ok")
    };
    Response::builder()
        .status(status)
        .body(body::full(Bytes::from_static(text.as_bytes())))
        .expect("static health response always builds")
}

/// Readiness — are the *backends* reachable, not just this process
/// (`docs/ARCHITECTURE.md` "Observability"). Reuses `forward`'s own signing/dial machinery
/// with a signed `GET /` (ListBuckets) per configured backend rather than
/// adding a second HTTP client: any response back from a backend, of any
/// status, means it is reachable; a connect failure or `S3A_TIMEOUT_REQUEST`
/// elapsing means it is not. Ready only when every backend answers — one
/// unreachable backend is still a real outage for whichever client is
/// mapped to it. No separate timeout knob — `forward` already bounds this
/// on `S3A_TIMEOUT_CONNECT`/`S3A_TIMEOUT_REQUEST`.
///
/// ponytail: sequential, not fan-out — a homelab's backend count is small
/// enough that this doesn't matter; no caching either, same reasoning as
/// before (an orchestrator polling every few seconds costs one cheap
/// non-per-bucket request per backend).
#[expect(clippy::expect_used, reason = "static ready response always builds")]
async fn ready_response(state: &ProxyState) -> Response<ProxyBody> {
    let mut status = StatusCode::OK;
    let mut text = "ready".to_string();
    for backend in state.config.backends.values() {
        if let Err(e) = forward(state, backend, "GET", "/", "", Vec::new(), body::empty()).await {
            tracing::warn!(backend = %backend.name, error = %e, "/ready: backend unreachable");
            status = StatusCode::SERVICE_UNAVAILABLE;
            text = format!("backend unreachable: {}", backend.name);
            break;
        }
    }
    Response::builder()
        .status(status)
        .body(body::full(Bytes::from(text)))
        .expect("static ready response always builds")
}

pub(crate) fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[expect(
    clippy::too_many_lines,
    reason = "one flat dispatch over the S3 operation matrix; splitting would fragment a single auditable routing table"
)]
#[expect(
    clippy::match_same_arms,
    reason = "each arm documents a distinct S3 operation's posture, even where two currently forward identically"
)]
async fn handle_inner(
    state: &ProxyState,
    req: Request<Incoming>,
    request_id: &str,
    peer_ip: IpAddr,
) -> Result<Response<ProxyBody>, S3Error> {
    if !state.auth_rate_limiter.allow(peer_ip) {
        state.auth_rate_limited.fetch_add(1, Ordering::Relaxed);
        return Err(S3Error::slow_down(
            "Too many failed authentication attempts from this address; slow down.",
        ));
    }

    let method = req.method().as_str().to_string();
    let raw_path = req.uri().path().to_string();
    let raw_query = req.uri().query().unwrap_or("").to_string();
    // A browser CORS preflight carries no `Authorization` header by design
    // (`docs/ARCHITECTURE.md` "S3 operation matrix (v1)": "answered from the backend's bucket CORS
    // config, before auth"), so it must be forwarded ahead of the SigV4
    // verify call below, or every preflight would fail with `403` before
    // the browser ever gets to see the backend's real CORS answer.
    if method == "OPTIONS" {
        // A CORS preflight carries no Authorization header by design (it's
        // exactly what "S3 operation matrix (v1)"'s own doc comment above says), so there is no
        // client identity here to resolve a backend from. Route it to
        // `DEFAULT` when configured, else whichever backend sorts first —
        // this is a CORS capability check, not a data path, so a heuristic
        // here doesn't create a security regression.
        let backend = preflight_backend(&state.config)?;
        let outbound_headers = headers::to_pairs(req.headers());
        let backend_resp = forward(
            state,
            backend,
            &method,
            &raw_path,
            &raw_query,
            outbound_headers,
            body::empty(),
        )
        .await?;
        return Ok(translate_response(backend_resp, request_id));
    }
    let header_pairs = headers::to_pairs(req.headers());
    let payload_hash_header = header_value(&header_pairs, "x-amz-content-sha256")
        .unwrap_or("UNSIGNED-PAYLOAD")
        .to_string();
    // Captured before `strip_for_backend` removes it (the client's
    // signature covers it, so removal must wait until after verify — same
    // ordering constraint `headers.rs`'s module doc documents for
    // Content-MD5 generally). `intercept::put` needs the value itself, not
    // just its absence.
    let content_md5_header = header_value(&header_pairs, "content-md5").map(str::to_string);

    let identity = sigv4::verify::verify(
        &method,
        &raw_path,
        &raw_query,
        &header_pairs,
        &payload_hash_header,
        &state.config.clients,
        SystemTime::now(),
    )
    .inspect_err(|_| {
        state.record_auth_failure();
        state.auth_rate_limiter.record_failure(peer_ip);
    })?;
    tracing::debug!(
        request_id,
        access_key = identity.access_key,
        backend = identity.backend,
        method,
        raw_path,
        "authenticated"
    );
    // Can't fail in practice — `Config::load` already rejected any client
    // naming a backend that doesn't exist — but a 500 here is a far better
    // failure mode than a panic if that invariant is ever broken.
    let backend = state
        .config
        .backends
        .get(&identity.backend)
        .ok_or_else(|| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("resolved backend {} is not configured", identity.backend),
            )
        })?;

    let route = route::parse(&raw_path);
    let has_copy_source = header_value(&header_pairs, "x-amz-copy-source").is_some();
    let op = route::classify(&method, &route, &raw_query, has_copy_source);
    // GetPart/UploadPartCopy/Select fail before the body is even read —
    // same posture as the old blanket multipart rejection, just narrowed
    // to the operations v1 genuinely does not support.
    match op {
        route::Op::Mpu(route::MpuOp::GetPart) => return Err(intercept::mpu::get_part_unsupported()),
        route::Op::Mpu(route::MpuOp::UploadPartCopy) => {
            return Err(intercept::mpu::upload_part_copy_unsupported());
        }
        route::Op::SelectObjectContent => {
            return Err(S3Error::not_implemented(
                "SelectObjectContent (the backend would query ciphertext, not your data; download and query locally)",
            ));
        }
        _ => {}
    }

    let (_parts, incoming) = req.into_parts();
    let base_body = build_outbound_body(incoming, &payload_hash_header, &identity.chunk_seed);

    let mut outbound_headers = header_pairs;
    if let Some(decoded_len) =
        header_value(&outbound_headers, "x-amz-decoded-content-length").map(str::to_string)
    {
        set_header(&mut outbound_headers, "content-length", &decoded_len);
    }
    outbound_headers.retain(|(k, _)| {
        !k.eq_ignore_ascii_case("x-amz-decoded-content-length")
            && !k.eq_ignore_ascii_case("x-amz-trailer")
    });
    if let Some(ce) = header_value(&outbound_headers, "content-encoding").map(str::to_string) {
        match headers::strip_aws_chunked_token(&ce) {
            Some(new_ce) => set_header(&mut outbound_headers, "content-encoding", &new_ce),
            None => outbound_headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-encoding")),
        }
    }
    headers::strip_for_backend(&mut outbound_headers);

    match op {
        route::Op::PutObject => {
            intercept::put::handle(
                state,
                backend,
                &raw_path,
                &raw_query,
                outbound_headers,
                base_body,
                content_md5_header,
                request_id,
            )
            .await
        }
        route::Op::GetObject => {
            intercept::get::handle(
                state,
                backend,
                &raw_path,
                &raw_query,
                outbound_headers,
                request_id,
            )
            .await
        }
        route::Op::HeadObject => {
            intercept::head::handle(
                state,
                backend,
                &raw_path,
                &raw_query,
                outbound_headers,
                request_id,
            )
            .await
        }
        route::Op::CopyObject => {
            intercept::copy::handle(
                state,
                backend,
                &raw_path,
                &raw_query,
                outbound_headers,
                request_id,
            )
            .await
        }
        route::Op::Mpu(route::MpuOp::Create) => {
            intercept::mpu::handle_create(
                state,
                backend,
                &raw_path,
                &raw_query,
                outbound_headers,
                request_id,
            )
            .await
        }
        route::Op::Mpu(route::MpuOp::UploadPart) => {
            intercept::mpu::handle_upload_part(
                state,
                backend,
                &raw_path,
                &raw_query,
                outbound_headers,
                base_body,
                request_id,
            )
            .await
        }
        route::Op::Mpu(route::MpuOp::Complete) => {
            intercept::mpu::handle_complete(
                state,
                backend,
                &raw_path,
                &raw_query,
                outbound_headers,
                base_body,
                request_id,
            )
            .await
        }
        route::Op::Mpu(route::MpuOp::Abort) => {
            intercept::mpu::handle_abort(
                state,
                backend,
                &raw_path,
                &raw_query,
                outbound_headers,
                request_id,
            )
            .await
        }
        // ListParts: part sizes are ciphertext sizes, same posture as List
        // (`docs/ARCHITECTURE.md` "List sizes are ciphertext sizes") — the backend's own XML, unintercepted.
        route::Op::Mpu(route::MpuOp::ListParts) => {
            let backend_resp = forward(
                state,
                backend,
                &method,
                &raw_path,
                &raw_query,
                outbound_headers,
                base_body,
            )
            .await?;
            Ok(translate_response(backend_resp, request_id))
        }
        route::Op::Mpu(route::MpuOp::UploadPartCopy | route::MpuOp::GetPart)
        | route::Op::SelectObjectContent => {
            unreachable!("rejected above, before the body was even read")
        }
        route::Op::Passthrough => {
            let backend_resp = forward(
                state,
                backend,
                &method,
                &raw_path,
                &raw_query,
                outbound_headers,
                base_body,
            )
            .await?;
            Ok(translate_response(backend_resp, request_id))
        }
    }
}

/// Which backend a CORS preflight (no client identity available — see the
/// call site) is checked against: `DEFAULT` if configured, else whichever
/// backend sorts first. Errors only if `backends` is somehow empty, which
/// `Config::load` already forbids.
fn preflight_backend(config: &Config) -> Result<&Backend, S3Error> {
    config
        .backends
        .get(crate::config::DEFAULT_BACKEND_NAME)
        .or_else(|| config.backends.values().next())
        .ok_or_else(|| S3Error::bad_gateway("no backend configured"))
}

/// Best-effort `AbortMultipartUpload` for a session the TTL sweeper just
/// reaped without ever seeing a `CompleteMultipartUpload` — see
/// `spawn_mpu_sweeper_with_tick`'s doc comment.
async fn abort_expired_upload(state: &ProxyState, session_key: crate::mpu::SessionKey) {
    let (backend_name, bucket, key, upload_id) = session_key;
    // The session outlives any request context, so the backend it was
    // created against travels in the key itself (`mpu::SessionKey`'s own
    // doc comment) — there is nothing else left to read it from here.
    let Some(backend) = state.config.backends.get(&backend_name) else {
        tracing::warn!(
            backend = backend_name,
            bucket,
            key,
            upload_id,
            "mpu sweeper: backend AbortMultipartUpload skipped — backend no longer configured"
        );
        return;
    };
    let path = format!("/{bucket}/{}", route::encode_key_for_path(&key));
    let encoded_id =
        percent_encoding::utf8_percent_encode(&upload_id, percent_encoding::NON_ALPHANUMERIC);
    let query = format!("uploadId={encoded_id}");
    match forward(
        state,
        backend,
        "DELETE",
        &path,
        &query,
        Vec::new(),
        body::empty(),
    )
    .await
    {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => tracing::warn!(
            bucket, key, upload_id, status = %resp.status(),
            "mpu sweeper: backend AbortMultipartUpload of an expired session failed"
        ),
        Err(e) => tracing::warn!(
            bucket, key, upload_id, error = %e,
            "mpu sweeper: backend AbortMultipartUpload of an expired session failed"
        ),
    }
}

/// Signs `outbound_headers`/`outbound_body` with the backend's credentials
/// and sends the request, returning the backend's raw response untouched.
/// Shared by passthrough and every interceptor — this is `docs/ARCHITECTURE.md`
/// "Architecture: re-signing streaming reverse proxy"'s "re-sign with backend credentials" step, factored out so a ranged
/// GET can issue its own HEAD *and* ranged GET through the same signing
/// path (`intercept::get`).
pub(crate) async fn forward(
    state: &ProxyState,
    backend: &Backend,
    method: &str,
    raw_path: &str,
    raw_query: &str,
    mut outbound_headers: Vec<(String, String)>,
    outbound_body: ProxyBody,
) -> Result<Response<Incoming>, S3Error> {
    // Backend endpoint and name are deployment-internal. Log the detail
    // server-side (the request span carries the correlation id) and return a
    // fixed message, so a client never sees the backend topology.
    let backend_uri: Uri = backend.endpoint.parse().map_err(|e| {
        tracing::error!(backend = %backend.name, error = %e, "invalid backend endpoint");
        S3Error::bad_gateway("upstream endpoint is misconfigured".to_string())
    })?;
    let backend_authority = backend_uri.authority().ok_or_else(|| {
        tracing::error!(backend = %backend.name, "backend endpoint has no host");
        S3Error::bad_gateway("upstream endpoint is misconfigured".to_string())
    })?;
    set_header(&mut outbound_headers, "host", backend_authority.as_str());

    let amz_date = sigv4::time::format_amz_date(SystemTime::now());
    set_header(&mut outbound_headers, "x-amz-date", &amz_date);
    set_header(
        &mut outbound_headers,
        "x-amz-content-sha256",
        "UNSIGNED-PAYLOAD",
    );

    let outbound_query = headers::filter_query(raw_query, headers::PRESIGNED_QUERY_PARAMS);
    let signed_names = {
        let mut names: Vec<String> = outbound_headers
            .iter()
            .map(|(k, _)| k.to_ascii_lowercase())
            .collect();
        names.sort();
        names.dedup();
        names
    };
    let auth = sigv4::sign::authorization_header(
        method,
        raw_path,
        &outbound_query,
        &outbound_headers,
        &signed_names,
        "UNSIGNED-PAYLOAD",
        &backend.access_key,
        &backend.secret_key,
        &backend.region,
        "s3",
        &amz_date,
    );
    set_header(&mut outbound_headers, "authorization", &auth);

    let target = if outbound_query.is_empty() {
        format!(
            "{}://{}{}",
            backend_uri.scheme_str().unwrap_or("http"),
            backend_authority,
            raw_path
        )
    } else {
        format!(
            "{}://{}{}?{}",
            backend_uri.scheme_str().unwrap_or("http"),
            backend_authority,
            raw_path,
            outbound_query
        )
    };

    let mut builder = Request::builder().method(method).uri(&target);
    for (name, value) in &outbound_headers {
        let hn = HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| S3Error::bad_gateway(e.to_string()))?;
        let hv = HeaderValue::from_str(value).map_err(|e| S3Error::bad_gateway(e.to_string()))?;
        builder = builder.header(hn, hv);
    }
    let outbound_req = builder
        .body(outbound_body)
        .map_err(|e| S3Error::bad_gateway(format!("failed to build backend request: {e}")))?;

    // `S3A_TIMEOUT_REQUEST` bounds waiting for the backend to start
    // answering — connect (already bounded by `S3A_TIMEOUT_CONNECT` inside
    // `client::build`) plus however long it takes the backend to produce
    // response headers. It deliberately does NOT wrap the body stream that
    // follows (`translate_response` and friends pipe `Incoming` separately,
    // outside this function) — a large PUT/GET legitimately runs longer
    // than this timeout, and only the headers phase should be bounded.
    match tokio::time::timeout(
        state.config.timeout_request,
        state.client.request(outbound_req),
    )
    .await
    {
        Ok(Ok(resp)) => Ok(resp),
        // A verifying body wrapper that stopped this request records its own
        // reason (`body::AbortSlot`): the client's bytes failed
        // verification, not the backend, so answer with that code — an SDK
        // must not retry a request that can never succeed.
        Ok(Err(e)) => Err(body::abort_reason().unwrap_or_else(|| {
            // The transport error is a per-request internal detail; log it,
            // return a fixed message.
            tracing::error!(backend = %backend.name, error = %e, "backend request failed");
            S3Error::bad_gateway("upstream request failed".to_string())
        })),
        Err(_) => Err(S3Error::gateway_timeout(format!(
            "backend did not respond within {:?} (S3A_TIMEOUT_REQUEST)",
            state.config.timeout_request
        ))),
    }
}

/// Translates a backend response into a client response verbatim: copy
/// status and headers (minus hop-by-hop), stamp `x-amz-request-id`, box the
/// body without transforming it. The passthrough tail, and the base every
/// interceptor's own response is built from.
pub(crate) fn translate_response(
    backend_resp: Response<Incoming>,
    request_id: &str,
) -> Response<ProxyBody> {
    let (parts, incoming) = backend_resp.into_parts();
    let boxed: ProxyBody = incoming
        .map_err(|e| std::io::Error::other(e.to_string()))
        .boxed();
    build_client_response(parts, boxed, request_id)
}

/// Like [`translate_response`], but takes an already-transformed body — for
/// an interceptor that decrypts the backend's body before returning it.
#[expect(
    clippy::needless_pass_by_value,
    reason = "every caller passes an owned, single-use Parts already at its last use; by-value is the natural zero-cost signature"
)]
#[expect(
    clippy::expect_used,
    reason = "headers copied from a real backend response are always valid"
)]
pub(crate) fn build_client_response(
    parts: http::response::Parts,
    body: ProxyBody,
    request_id: &str,
) -> Response<ProxyBody> {
    let mut response_builder = Response::builder().status(parts.status);
    for (name, value) in &parts.headers {
        if is_hop_by_hop_response_header(name.as_str()) {
            continue;
        }
        response_builder = response_builder.header(name, value);
    }
    response_builder = response_builder.header("x-amz-request-id", request_id);
    response_builder
        .body(body)
        .expect("headers copied from a real backend response are always valid")
}

pub(crate) fn is_hop_by_hop_response_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "keep-alive" | "te" | "trailer" | "transfer-encoding" | "upgrade"
    )
}

pub(crate) fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    headers.push((name.to_string(), value.to_string()));
}

fn build_outbound_body(
    incoming: Incoming,
    payload_hash_header: &str,
    chunk_seed: &sigv4::verify::ChunkSeed,
) -> ProxyBody {
    if payload_hash_header == "UNSIGNED-PAYLOAD" {
        body::passthrough(incoming)
    } else if let Some(rest) = payload_hash_header.strip_prefix("STREAMING-") {
        let signed = rest.starts_with("AWS4-HMAC-SHA256-PAYLOAD");
        let verifier = signed.then(|| {
            ChunkVerifier::new(
                chunk_seed.signing_key,
                chunk_seed.amz_date.clone(),
                chunk_seed.credential_scope.clone(),
                chunk_seed.seed_signature.clone(),
            )
        });
        body::dechunking(incoming, verifier)
    } else {
        // A real hex SHA-256: hash the body while streaming and verify it
        // matches before the outbound stream is allowed to end cleanly.
        body::hashing(incoming, payload_hash_header.to_ascii_lowercase())
    }
}
