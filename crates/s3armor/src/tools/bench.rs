//! `s3armor bench`: three tiers of benchmark, human table by default,
//! `--json`. `docs/ARCHITECTURE.md` "Benchmarks (`s3armor bench`)".
//!
//! - `local` (default): AES-256-GCM vs XChaCha20-Poly1305 across chunk
//!   sizes, no network. `crates/s3armor-format/benches/crypto.rs` is the
//!   precise criterion instrument for the same grid; this is the fast
//!   picker `--write-config` reads from.
//! - `--backend`: TTFB, throughput ladder, multipart part-size sweep,
//!   concurrency discovery (ramp + bisection) against the configured
//!   backend, direct (same signing path `check`/`rewrap` use).
//! - `--proxy <url>`: proxy-vs-direct efficiency ratio per size class, with
//!   SHA-256 verification of every round-trip. Memory sampling is **not**
//!   included — docs/ARCHITECTURE.md "Benchmarks (`s3armor bench`)" specifies
//!   scraping the proxy's own metrics endpoint (`proxy::metrics`, which
//!   exists today), deliberately, rather than sampling the wrong process.

use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};

use s3armor_format::v1::{decrypt_all, encrypt_all, Alg};

use crate::config::Backend;
use crate::intercept::mpu::{build_complete_xml, parse_single_tag};
use crate::proxy::body;
use crate::proxy::route::encode_key_for_path;
use crate::proxy::{forward, set_header, ProxyState};

const ALGS: [Alg; 2] = [Alg::Aes256Gcm, Alg::XChaCha20Poly1305];
const CHUNK_SIZES: [usize; 4] = [64 * 1024, 256 * 1024, 1024 * 1024, 8 * 1024 * 1024];
const LOCAL_PAYLOAD_LEN: usize = 8 * 1024 * 1024;

const fn alg_name(alg: Alg) -> &'static str {
    match alg {
        Alg::Aes256Gcm => "aes-gcm",
        Alg::XChaCha20Poly1305 => "xchacha20-poly1305",
    }
}

pub struct LocalResult {
    pub alg: Alg,
    pub chunk_size: usize,
    pub encrypt_gib_s: f64,
    pub decrypt_gib_s: f64,
}

/// One iteration per (alg, chunk_size) pair — a picker, not a precision
/// instrument (that's criterion). `Instant`-timed single passes are enough
/// to separate "AES-NI present" from "not" and pick a sane chunk size.
#[expect(clippy::expect_used, reason = "just-encrypted data always round-trips")]
#[expect(
    clippy::cast_precision_loss,
    reason = "GiB throughput display; f64's 52-bit mantissa loses no meaningful precision at benchmark payload sizes"
)]
pub fn run_local() -> Vec<LocalResult> {
    let key = [0x42u8; 32];
    let payload = vec![0xABu8; LOCAL_PAYLOAD_LEN];
    let mut out = Vec::with_capacity(ALGS.len() * CHUNK_SIZES.len());
    for alg in ALGS {
        for chunk_size in CHUNK_SIZES {
            let t0 = Instant::now();
            let ciphertext = encrypt_all(alg, &key, 0, chunk_size, &payload);
            let enc_secs = t0.elapsed().as_secs_f64();

            let t1 = Instant::now();
            let _ = decrypt_all(alg, &key, 0, chunk_size, &ciphertext).expect("round-trips");
            let dec_secs = t1.elapsed().as_secs_f64();

            let gib = LOCAL_PAYLOAD_LEN as f64 / (1024.0 * 1024.0 * 1024.0);
            out.push(LocalResult {
                alg,
                chunk_size,
                encrypt_gib_s: gib / enc_secs.max(f64::EPSILON),
                decrypt_gib_s: gib / dec_secs.max(f64::EPSILON),
            });
        }
    }
    out
}

/// Picks the fastest `(alg, chunk_size)` by combined encrypt+decrypt
/// throughput — what `--write-config` recommends.
pub fn recommend(results: &[LocalResult]) -> (Alg, usize) {
    results
        .iter()
        .max_by(|a, b| {
            (a.encrypt_gib_s + a.decrypt_gib_s).total_cmp(&(b.encrypt_gib_s + b.decrypt_gib_s))
        })
        .map_or((Alg::Aes256Gcm, 1024 * 1024), |r| (r.alg, r.chunk_size))
}

pub fn print_local(results: &[LocalResult]) {
    println!(
        "{:<20} {:>10} {:>14} {:>14}",
        "alg", "chunk", "encrypt GiB/s", "decrypt GiB/s"
    );
    for r in results {
        println!(
            "{:<20} {:>10} {:>14.2} {:>14.2}",
            alg_name(r.alg),
            human_size(r.chunk_size),
            r.encrypt_gib_s,
            r.decrypt_gib_s
        );
    }
    let (alg, chunk_size) = recommend(results);
    println!(
        "\nrecommended: S3A_ALG={} S3A_CHUNK_SIZE={chunk_size}",
        alg_name(alg)
    );
}

pub fn local_json(results: &[LocalResult]) -> String {
    let items: Vec<String> = results
        .iter()
        .map(|r| {
            format!(
                "{{\"alg\":\"{}\",\"chunk_size\":{},\"encrypt_gib_s\":{:.4},\"decrypt_gib_s\":{:.4}}}",
                alg_name(r.alg),
                r.chunk_size,
                r.encrypt_gib_s,
                r.decrypt_gib_s
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

#[expect(
    clippy::integer_division,
    reason = "KiB/MiB display, rounded down to a whole unit by design"
)]
fn human_size(n: usize) -> String {
    if n >= 1024 * 1024 {
        format!("{}MiB", n / (1024 * 1024))
    } else {
        format!("{}KiB", n / 1024)
    }
}

/// Prints the env block `--write-config` promises, actually wired to
/// something a config file or env can consume directly.
pub fn write_config(results: &[LocalResult]) {
    let (alg, chunk_size) = recommend(results);
    println!("S3A_ALG={}", alg_name(alg));
    println!("S3A_CHUNK_SIZE={chunk_size}");
}

// --- backend tier -----------------------------------------------------

const SIZE_LADDER: [usize; 4] = [4 * 1024, 256 * 1024, 4 * 1024 * 1024, 32 * 1024 * 1024];

pub struct BackendResult {
    pub size: usize,
    pub ttfb: Duration,
    pub put_gib_s: f64,
    pub get_gib_s: f64,
}

#[expect(
    clippy::cast_precision_loss,
    reason = "GiB throughput display; f64's 52-bit mantissa loses no meaningful precision at benchmark payload sizes"
)]
async fn probe_object(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
    key: &str,
    size: usize,
) -> Result<BackendResult, String> {
    let path = format!("/{bucket}/{}", encode_key_for_path(key));
    let payload = Bytes::from(vec![0x33u8; size]);

    let mut headers = Vec::new();
    set_header(&mut headers, "content-length", &size.to_string());
    let t_put = Instant::now();
    // Check the status: a fast rejection (e.g. 403 on an unwritable bucket)
    // is not throughput. Timing it and reporting it as GiB/s would give a
    // huge, meaningless number and skew concurrency discovery too.
    let put = forward(
        state,
        backend,
        "PUT",
        &path,
        "",
        headers,
        body::full(payload),
    )
    .await
    .map_err(|e| format!("PUT probe failed: {e}"))?;
    if !put.status().is_success() {
        return Err(format!("PUT probe returned {}", put.status()));
    }
    let put_secs = t_put.elapsed().as_secs_f64();

    let t_get = Instant::now();
    let resp = forward(state, backend, "GET", &path, "", Vec::new(), body::empty()).await;
    let ttfb = t_get.elapsed();
    let get_status = match resp {
        Ok(resp) => {
            let status = resp.status();
            let _ = resp.into_body().collect().await;
            status
        }
        Err(e) => return Err(format!("GET probe failed: {e}")),
    };
    if !get_status.is_success() {
        return Err(format!("GET probe returned {get_status}"));
    }
    let get_secs = t_get.elapsed().as_secs_f64();

    let _ = forward(
        state,
        backend,
        "DELETE",
        &path,
        "",
        Vec::new(),
        body::empty(),
    )
    .await;

    let gib = size as f64 / (1024.0 * 1024.0 * 1024.0);
    Ok(BackendResult {
        size,
        ttfb,
        put_gib_s: gib / put_secs.max(f64::EPSILON),
        get_gib_s: gib / get_secs.max(f64::EPSILON),
    })
}

/// TTFB + throughput across a size ladder, direct to the configured
/// backend. Every object lives under a UUID-ish prefix and is deleted
/// immediately after its own probe.
pub async fn run_backend(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
) -> Result<Vec<BackendResult>, String> {
    let prefix = format!("s3a-bench-{:x}", std::process::id());
    let mut out = Vec::with_capacity(SIZE_LADDER.len());
    for (i, &size) in SIZE_LADDER.iter().enumerate() {
        let key = format!("{prefix}/ladder-{i}");
        out.push(probe_object(state, backend, bucket, &key, size).await?);
    }
    Ok(out)
}

pub fn print_backend(results: &[BackendResult]) {
    println!(
        "{:>10} {:>12} {:>12} {:>12}",
        "size", "ttfb", "put GiB/s", "get GiB/s"
    );
    for r in results {
        println!(
            "{:>10} {:>12?} {:>12.3} {:>12.3}",
            human_size(r.size),
            r.ttfb,
            r.put_gib_s,
            r.get_gib_s
        );
    }
}

pub fn backend_json(results: &[BackendResult]) -> String {
    let items: Vec<String> = results
        .iter()
        .map(|r| {
            format!(
                "{{\"size\":{},\"ttfb_ms\":{},\"put_gib_s\":{:.4},\"get_gib_s\":{:.4}}}",
                r.size,
                r.ttfb.as_millis(),
                r.put_gib_s,
                r.get_gib_s
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

pub struct PartSizeResult {
    pub part_size: usize,
    pub gib_s: f64,
}

/// Sweeps multipart part size for a fixed 32 MiB object — two parts at the
/// largest size in the sweep, more at the smallest — direct to the
/// backend. A part size is often chosen for a size-ceiling constraint
/// (e.g. S3's 10000-part limit for very large objects), not for
/// throughput; this is the probe that would tell an operator if a smaller
/// part size actually moves data faster against their backend.
#[expect(
    clippy::cast_possible_truncation,
    reason = "S3 caps a multipart upload at 10_000 parts, far below u32::MAX"
)]
#[expect(
    clippy::cast_precision_loss,
    reason = "GiB throughput display; f64's 52-bit mantissa loses no meaningful precision at benchmark payload sizes"
)]
pub async fn part_size_sweep(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
) -> Vec<PartSizeResult> {
    const OBJECT_SIZE: usize = 32 * 1024 * 1024;
    const PART_SIZES: [usize; 3] = [4 * 1024 * 1024, 8 * 1024 * 1024, 16 * 1024 * 1024];
    let prefix = format!("s3a-bench-partsize-{:x}", std::process::id());
    let mut out = Vec::with_capacity(PART_SIZES.len());
    for (i, &part_size) in PART_SIZES.iter().enumerate() {
        let key = format!("{prefix}/sweep-{i}");
        let path = format!("/{bucket}/{}", encode_key_for_path(&key));
        let n_parts = OBJECT_SIZE.div_ceil(part_size);

        let start = Instant::now();
        if let Ok(upload_id) = create_multipart(state, backend, &path).await {
            let encoded_id = encode_key_for_path(&upload_id);
            let mut etags = Vec::with_capacity(n_parts);
            for part in 1..=n_parts {
                let size = part_size.min(OBJECT_SIZE - (part - 1) * part_size);
                let mut headers = Vec::new();
                set_header(&mut headers, "content-length", &size.to_string());
                let query = format!("partNumber={part}&uploadId={encoded_id}");
                if let Ok(resp) = forward(
                    state,
                    backend,
                    "PUT",
                    &path,
                    &query,
                    headers,
                    body::full(Bytes::from(vec![0x66u8; size])),
                )
                .await
                {
                    if resp.status().is_success() {
                        let etag = crate::proxy::headers::to_pairs(resp.headers())
                            .into_iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("etag"))
                            .map(|(_, v)| v)
                            .unwrap_or_default();
                        etags.push((part as u32, etag));
                    }
                }
            }
            let complete_xml = build_complete_xml(&etags);
            let mut complete_headers = Vec::new();
            set_header(
                &mut complete_headers,
                "content-length",
                &complete_xml.len().to_string(),
            );
            let complete_query = format!("uploadId={encoded_id}");
            let _ = forward(
                state,
                backend,
                "POST",
                &path,
                &complete_query,
                complete_headers,
                body::full(Bytes::from(complete_xml)),
            )
            .await;
            // Abort the upload too. If Complete did not succeed, the plain
            // object DELETE below does not remove the uploaded parts; aborting
            // a completed upload is a harmless no-op.
            let _ = forward(
                state,
                backend,
                "DELETE",
                &path,
                &complete_query,
                Vec::new(),
                body::empty(),
            )
            .await;
        }
        let secs = start.elapsed().as_secs_f64();
        let gib = OBJECT_SIZE as f64 / (1024.0 * 1024.0 * 1024.0);
        out.push(PartSizeResult {
            part_size,
            gib_s: gib / secs.max(f64::EPSILON),
        });
        let _ = forward(
            state,
            backend,
            "DELETE",
            &path,
            "",
            Vec::new(),
            body::empty(),
        )
        .await;
    }
    out
}

async fn create_multipart(state: &ProxyState, backend: &Backend, path: &str) -> Result<String, ()> {
    let resp = forward(
        state,
        backend,
        "POST",
        path,
        "uploads",
        Vec::new(),
        body::empty(),
    )
    .await
    .map_err(|_| ())?;
    if !resp.status().is_success() {
        return Err(());
    }
    let xml = resp.into_body().collect().await.map_err(|_| ())?.to_bytes();
    parse_single_tag(&xml, b"UploadId").ok_or(())
}

pub fn print_part_size_sweep(results: &[PartSizeResult]) {
    println!("{:>10} {:>12}", "part size", "GiB/s");
    for r in results {
        println!("{:>10} {:>12.3}", human_size(r.part_size), r.gib_s);
    }
}

/// Concurrency discovery: ramp up concurrent PUTs of a fixed-size object
/// until per-request latency degrades past `degrade_factor` of the
/// single-request baseline, then bisect between the last-good and
/// first-bad concurrency to find the knee (docs/ARCHITECTURE.md
/// "Benchmarks (`s3armor bench`)").
#[expect(
    clippy::integer_division,
    reason = "bisecting the concurrency range; floor division is the intended midpoint"
)]
pub async fn discover_concurrency(state: &ProxyState, backend: &Backend, bucket: &str) -> usize {
    const OBJECT_SIZE: usize = 256 * 1024;
    const DEGRADE_FACTOR: f64 = 2.0;
    let prefix = format!("s3a-bench-conc-{:x}", std::process::id());

    let baseline = {
        let key = format!("{prefix}/baseline");
        let start = Instant::now();
        let _ = probe_object(state, backend, bucket, &key, OBJECT_SIZE).await;
        start.elapsed()
    };

    let mut last_good = 1usize;
    let mut first_bad = None;
    let mut concurrency = 2usize;
    while concurrency <= 64 {
        let elapsed =
            timed_concurrent_puts(state, backend, bucket, &prefix, concurrency, OBJECT_SIZE).await;
        if elapsed.as_secs_f64() > baseline.as_secs_f64() * DEGRADE_FACTOR {
            first_bad = Some(concurrency);
            break;
        }
        last_good = concurrency;
        concurrency *= 2;
    }

    let Some(mut bad) = first_bad else {
        return last_good; // never degraded within the ramp — backend keeps up
    };
    let mut good = last_good;
    while bad - good > 1 {
        let mid = good + (bad - good) / 2;
        let elapsed =
            timed_concurrent_puts(state, backend, bucket, &prefix, mid, OBJECT_SIZE).await;
        if elapsed.as_secs_f64() > baseline.as_secs_f64() * DEGRADE_FACTOR {
            bad = mid;
        } else {
            good = mid;
        }
    }
    good
}

async fn timed_concurrent_puts(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
    prefix: &str,
    concurrency: usize,
    size: usize,
) -> Duration {
    let start = Instant::now();
    let puts = (0..concurrency).map(|i| {
        let path = format!(
            "/{bucket}/{}",
            encode_key_for_path(&format!("{prefix}/c{concurrency}-{i}"))
        );
        let payload = Bytes::from(vec![0x44u8; size]);
        async move {
            let _ = forward(
                state,
                backend,
                "PUT",
                &path,
                "",
                Vec::new(),
                body::full(payload),
            )
            .await;
            let _ = forward(
                state,
                backend,
                "DELETE",
                &path,
                "",
                Vec::new(),
                body::empty(),
            )
            .await;
        }
    });
    // All `concurrency` PUTs in flight together — that's the point of the
    // probe (find where the backend stops absorbing more at once), not a
    // worker pool draining a queue.
    futures_util::future::join_all(puts).await;
    start.elapsed()
}

// --- proxy tier ---------------------------------------------------------

pub struct ProxyVsDirectResult {
    pub size: usize,
    pub direct_gib_s: f64,
    pub proxy_gib_s: f64,
    pub verified: bool,
}

/// Round-trips the same size ladder through the proxy URL and directly to
/// the backend, verifying content (SHA-256) on the proxy path. The
/// direct-vs-proxy ratio is the number that actually matters to an
/// operator sizing the proxy's overhead.
#[expect(
    clippy::cast_precision_loss,
    reason = "GiB throughput display; f64's 52-bit mantissa loses no meaningful precision at benchmark payload sizes"
)]
pub async fn run_proxy_vs_direct(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
    proxy_client: &reqwest_like::Client,
) -> Vec<ProxyVsDirectResult> {
    let prefix = format!("s3a-bench-proxy-{:x}", std::process::id());
    let mut out = Vec::with_capacity(SIZE_LADDER.len());
    for (i, &size) in SIZE_LADDER.iter().enumerate() {
        let payload = vec![0x55u8; size];
        let expected = Sha256::digest(&payload);

        let gib = size as f64 / (1024.0 * 1024.0 * 1024.0);

        // Time the direct path over the same PUT+GET+DELETE the proxy path
        // runs below, so the ratio compares like with like. A PUT-only direct
        // number against a put+get+delete proxy number understated the proxy
        // by 2-3x.
        let direct_key = format!("{prefix}/direct-{i}");
        let direct_path = format!("/{bucket}/{}", encode_key_for_path(&direct_key));
        let dstart = Instant::now();
        let mut dheaders = Vec::new();
        set_header(&mut dheaders, "content-length", &size.to_string());
        let dput = forward(
            state,
            backend,
            "PUT",
            &direct_path,
            "",
            dheaders,
            body::full(Bytes::from(payload.clone())),
        )
        .await;
        // The GET's status matters too: a failed GET transfers no body, so
        // its (fast) elapsed time would inflate the direct number.
        let dget_ok = match forward(
            state,
            backend,
            "GET",
            &direct_path,
            "",
            Vec::new(),
            body::empty(),
        )
        .await
        {
            Ok(r) => {
                let ok = r.status().is_success();
                let _ = r.into_body().collect().await;
                ok
            }
            Err(_) => false,
        };
        let _ = forward(
            state,
            backend,
            "DELETE",
            &direct_path,
            "",
            Vec::new(),
            body::empty(),
        )
        .await;
        let direct_secs = dstart.elapsed().as_secs_f64();
        let direct_ok = dput.is_ok_and(|r| r.status().is_success()) && dget_ok;
        let direct_gib_s = if direct_ok {
            gib / direct_secs.max(f64::EPSILON)
        } else {
            0.0
        };

        let proxy_key = format!("{prefix}/proxy-{i}");
        let t = Instant::now();
        let got = proxy_client
            .put_get_delete(bucket, &proxy_key, &payload)
            .await;
        let proxy_secs = t.elapsed().as_secs_f64();
        let verified = got.as_deref().map(Sha256::digest).as_deref() == Some(expected.as_slice());

        out.push(ProxyVsDirectResult {
            size,
            direct_gib_s,
            proxy_gib_s: gib / proxy_secs.max(f64::EPSILON),
            verified,
        });
    }
    out
}

pub fn print_proxy_vs_direct(results: &[ProxyVsDirectResult]) {
    println!(
        "{:>10} {:>14} {:>14} {:>10} {:>10}",
        "size", "direct GiB/s", "proxy GiB/s", "ratio", "verified"
    );
    for r in results {
        println!(
            "{:>10} {:>14.3} {:>14.3} {:>10.2} {:>10}",
            human_size(r.size),
            r.direct_gib_s,
            r.proxy_gib_s,
            r.proxy_gib_s / r.direct_gib_s.max(f64::EPSILON),
            if r.verified { "yes" } else { "NO" }
        );
    }
}

pub fn proxy_json(results: &[ProxyVsDirectResult]) -> String {
    let items: Vec<String> = results
        .iter()
        .map(|r| {
            format!(
                "{{\"size\":{},\"direct_gib_s\":{:.4},\"proxy_gib_s\":{:.4},\"verified\":{}}}",
                r.size, r.direct_gib_s, r.proxy_gib_s, r.verified
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// A minimal HTTP PUT/GET/DELETE client for the `--proxy` tier — this
/// binary already depends on `hyper`/`hyper-util` for the server side;
/// reusing it here avoids adding `reqwest` for three verbs.
pub mod reqwest_like {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::client::legacy::Client as HyperClient;
    use hyper_util::rt::TokioExecutor;

    use crate::proxy::route::encode_key_for_path;
    use crate::sigv4::{sign, time};

    /// `x-amz-date`/`Authorization`, signed against the proxy's own SigV4
    /// verifier with a registered client credential — a proxy under test
    /// authenticates exactly like any other S3 client, so this needs the
    /// same `S3A_CLIENT_<NAME>_ACCESS_KEY`/`_SECRET_KEY` pair `bench` was
    /// run with (region is unchecked by `verify_header`, so any consistent
    /// value works; `"us-east-1"` matches this workspace's other defaults).
    pub struct Client {
        base_url: String,
        access_key: String,
        secret_key: String,
        inner: HyperClient<HttpConnector, Full<Bytes>>,
    }

    impl Client {
        pub fn new(base_url: String, access_key: String, secret_key: String) -> Self {
            Self {
                base_url,
                access_key,
                secret_key,
                inner: HyperClient::builder(TokioExecutor::new()).build(HttpConnector::new()),
            }
        }

        fn signed_request(
            &self,
            method: &str,
            path: &str,
            body: Bytes,
        ) -> Option<http::Request<Full<Bytes>>> {
            let authority = self.base_url.strip_prefix("http://")?;
            let amz_date = time::format_amz_date(std::time::SystemTime::now());
            let headers = vec![
                ("host".to_string(), authority.to_string()),
                ("x-amz-date".to_string(), amz_date.clone()),
            ];
            let signed_names = vec!["host".to_string(), "x-amz-date".to_string()];
            let auth = sign::authorization_header(
                method,
                path,
                "",
                &headers,
                &signed_names,
                "UNSIGNED-PAYLOAD",
                &self.access_key,
                &self.secret_key,
                "us-east-1",
                "s3",
                &amz_date,
            );
            http::Request::builder()
                .method(method)
                .uri(format!("{}{path}", self.base_url))
                .header("host", authority)
                .header("x-amz-date", amz_date)
                .header("authorization", auth)
                .body(Full::new(body))
                .ok()
        }

        /// PUTs `payload`, GETs it back, DELETEs it, and returns the bytes
        /// actually read on GET (`None` on any request failure).
        pub async fn put_get_delete(
            &self,
            bucket: &str,
            key: &str,
            payload: &[u8],
        ) -> Option<Vec<u8>> {
            let path = format!("/{bucket}/{}", encode_key_for_path(key));
            let put = self.signed_request("PUT", &path, Bytes::copy_from_slice(payload))?;
            let put_resp = self.inner.request(put).await.ok()?;
            if !put_resp.status().is_success() {
                return None;
            }

            let get = self.signed_request("GET", &path, Bytes::new())?;
            let resp = self.inner.request(get).await.ok()?;
            if !resp.status().is_success() {
                return None;
            }
            let body = resp.into_body().collect().await.ok()?.to_bytes().to_vec();

            if let Some(del) = self.signed_request("DELETE", &path, Bytes::new()) {
                let _ = self.inner.request(del).await;
            }
            Some(body)
        }
    }
}
