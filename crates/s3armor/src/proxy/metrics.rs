//! Prometheus text-exposition endpoint (`docs/ARCHITECTURE.md`
//! "Configuration model" and "Observability"). Deliberately its own
//! listener (`Config::metrics_listen`, `main::serve`) — the S3 port is
//! authenticated and public-facing, this one is neither, same posture as
//! `/health` on the main listener.
//!
//! With the `pprof` feature (off by default, only in the `-debug` Docker
//! image, `docs/ARCHITECTURE.md` "Profiling support"), `GET
//! /debug/pprof/flamegraph` also lives here. This listener is
//! unauthenticated by design — a flamegraph is strictly more sensitive
//! than a counter (it exposes symbol names and coarse timing), which is
//! why the feature stays off in every image but `-debug`, and why
//! `-debug` should never be run with `S3A_METRICS` bound to anything but a
//! private interface.
//!
//! # ponytail
//! Hand-rolled formatting, no `metrics`/`metrics-exporter-prometheus`
//! (`docs/ARCHITECTURE.md` "Crate choices" named crates) — this is five
//! counters and a gauge, not a per-op/histogram registry. Upgrade when
//! duration percentiles or per-op labels are actually wanted; today
//! they'd be pure overhead.

use std::fmt::Write as _;

use http::{Response, StatusCode};

use super::body::{self, ProxyBody};
use super::ProxyState;

fn write_counter(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} counter");
    let _ = writeln!(out, "{name} {value}");
}

fn write_gauge(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name} {value}");
}

/// Renders every counter/gauge `ProxyState` tracks as Prometheus text
/// exposition format. No per-bucket/per-key labels (`docs/ARCHITECTURE.md`
/// "Observability").
pub fn render(state: &ProxyState) -> String {
    let mut out = String::new();
    write_counter(
        &mut out,
        "s3armor_auth_failures_total",
        "SigV4 verification failures",
        state.auth_failures(),
    );
    write_counter(
        &mut out,
        "s3armor_auth_rate_limited_total",
        "requests rejected with 429 before SigV4 verification, over S3A_AUTH_FAIL_LIMIT",
        state.auth_rate_limited(),
    );
    write_counter(
        &mut out,
        "s3armor_chunk_verify_failures_total",
        "v1 chunk AEAD verify failures — alert on any",
        state.chunk_verify_failures(),
    );
    write_counter(
        &mut out,
        "s3armor_mpu_sessions_created_total",
        "multipart sessions created",
        state.mpu_sessions_created(),
    );
    write_counter(
        &mut out,
        "s3armor_footer_cache_hits_total",
        "multipart footer cache hits",
        state.footer_cache_hits(),
    );
    write_counter(
        &mut out,
        "s3armor_footer_cache_misses_total",
        "multipart footer cache misses",
        state.footer_cache_misses(),
    );
    write_gauge(
        &mut out,
        "s3armor_mpu_sessions_active",
        "in-flight multipart sessions",
        state.mpu_sessions_active() as u64,
    );
    out
}

/// The metrics listener's whole hyper service. `GET /metrics` renders
/// [`render`]; with the `pprof` feature, `GET /debug/pprof/flamegraph`
/// samples this process for 30s and returns an SVG; anything else is a
/// plain 404 — no auth, no SigV4, no XML error shape (this is not an S3
/// endpoint). `async` only because the `pprof` arm needs to await a
/// blocking-thread sample; the `/metrics` and 404 paths do no I/O.
#[expect(
    clippy::expect_used,
    reason = "these are static, well-formed responses that always build"
)]
#[cfg_attr(
    not(feature = "pprof"),
    expect(
        clippy::unused_async,
        reason = "async without the pprof feature — the caller awaits this uniformly either way"
    )
)]
pub async fn handle(state: &ProxyState, path: &str) -> Response<ProxyBody> {
    if path == "/metrics" {
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4")
            .body(body::full(render(state).into_bytes().into()))
            .expect("static metrics response always builds");
    }
    #[cfg(feature = "pprof")]
    if path == "/debug/pprof/flamegraph" {
        return pprof_support::flamegraph_response().await;
    }
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(body::empty())
        .expect("static 404 response always builds")
}

/// Sampling lives on a blocking thread from build to render — the profiler
/// guard is dropped inside that same closure, never held across an
/// `.await`, so its `Send`-ness (it is not `Send`) never has to matter.
#[cfg(feature = "pprof")]
mod pprof_support {
    use std::time::Duration;

    use http::{Response, StatusCode};

    use super::{body, ProxyBody};

    /// Fixed, not a query parameter: an unauthenticated endpoint that took
    /// an attacker-chosen duration would be a cheap way to pin a blocking
    /// thread and a process-wide SIGPROF handler for as long as they liked
    /// (AGENTS.md: no config knob without a test exercising its effect —
    /// there is exactly one duration to test).
    const SAMPLE_SECONDS: u64 = 30;

    #[expect(
        clippy::expect_used,
        reason = "the error responses built here are static and always build"
    )]
    pub(super) async fn flamegraph_response() -> Response<ProxyBody> {
        let sampled = tokio::task::spawn_blocking(sample_flamegraph).await;
        match sampled {
            Ok(Ok(svg)) => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "image/svg+xml")
                .body(body::full(svg.into()))
                .expect("static flamegraph response always builds"),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "pprof sample failed");
                Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(body::empty())
                    .expect("static error response always builds")
            }
            Err(e) => {
                tracing::warn!(error = %e, "pprof sampling task panicked");
                Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(body::empty())
                    .expect("static error response always builds")
            }
        }
    }

    /// Runs entirely on a blocking thread: builds the profiler guard,
    /// blocks for `SAMPLE_SECONDS` with a real (non-async) sleep, then
    /// renders the collected samples as an SVG flamegraph.
    fn sample_flamegraph() -> Result<Vec<u8>, pprof::Error> {
        let guard = pprof::ProfilerGuardBuilder::default()
            .frequency(99)
            .blocklist(&["libc", "libgcc", "pthread", "vdso"])
            .build()?;
        std::thread::sleep(Duration::from_secs(SAMPLE_SECONDS));
        let report = guard.report().build()?;
        let mut svg = Vec::new();
        report.flamegraph(&mut svg)?;
        Ok(svg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Backend, ClientCredentials, Config, LogFormat, DEFAULT_BACKEND_NAME};
    use crate::keys::Keyring;
    use s3armor_format::v1::{Alg, MasterKey};
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn state_with_all_counters_at_zero() -> ProxyState {
        let mut keys = BTreeMap::new();
        keys.insert("TEST".to_string(), MasterKey::new([0x11; 32]));
        let keyring = Keyring::new("TEST", keys, None).unwrap();
        ProxyState::new(Config {
            listen: "127.0.0.1:0".to_string(),
            log_level: "error".to_string(),
            log_format: LogFormat::Text,
            backends: BTreeMap::from([(
                DEFAULT_BACKEND_NAME.to_string(),
                Backend {
                    name: DEFAULT_BACKEND_NAME.to_string(),
                    endpoint: "http://127.0.0.1:1".to_string(),
                    region: "us-east-1".to_string(),
                    access_key: "a".to_string(),
                    secret_key: "b".to_string(),
                },
            )]),
            clients: BTreeMap::from([(
                "C".to_string(),
                ClientCredentials {
                    access_key: "a".to_string(),
                    secret_key: "b".to_string(),
                    backend: DEFAULT_BACKEND_NAME.to_string(),
                },
            )]),
            timeout_connect: Duration::from_secs(1),
            timeout_request: Duration::from_secs(1),
            keyring,
            key_active_name: "TEST".to_string(),
            chunk_size: 65_536,
            alg: Alg::Aes256Gcm,
            sources: BTreeMap::default(),
            mp_ttl: Duration::from_hours(1),
            footer_cache: 16,
            rsa_public_pem: None,
            metrics_listen: None,
            tls: None,
            auth_fail_limit: 60,
            bind_mode: crate::config::BindMode::Off,
        })
    }

    #[test]
    fn render_includes_every_counter_at_zero() {
        let state = state_with_all_counters_at_zero();
        let text = render(&state);
        for name in [
            "s3armor_auth_failures_total",
            "s3armor_chunk_verify_failures_total",
            "s3armor_mpu_sessions_created_total",
            "s3armor_footer_cache_hits_total",
            "s3armor_footer_cache_misses_total",
            "s3armor_mpu_sessions_active",
        ] {
            assert!(
                text.contains(&format!("{name} 0")),
                "missing {name} in:\n{text}"
            );
        }
    }

    #[test]
    fn render_reflects_recorded_counts() {
        let state = state_with_all_counters_at_zero();
        state.record_auth_failure();
        state.record_auth_failure();
        state
            .chunk_verify_failures_handle()
            .fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        let text = render(&state);
        assert!(text.contains("s3armor_auth_failures_total 2"));
        assert!(text.contains("s3armor_chunk_verify_failures_total 3"));
    }

    #[tokio::test]
    async fn handle_serves_metrics_and_404s_everything_else() {
        let state = state_with_all_counters_at_zero();
        let resp = handle(&state, "/metrics").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = handle(&state, "/").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
