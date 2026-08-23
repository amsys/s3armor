//! s3armor — client-side S3 encryption proxy and tooling.
//!
//! All seven subcommands (`serve`, `check`, `bench`, `rewrap`, `rebind`,
//! `config`, `health-probe`) are implemented. Key material is generated
//! with `openssl`, not a dedicated subcommand — see docs/USER-GUIDE.md
//! "Quickstart".

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{signal, SignalKind};

use s3armor::config::{Backend, Config, Layered};
use s3armor::proxy::{self, ProxyState};
use s3armor::tools;

#[derive(Parser)]
#[command(name = "s3armor", version, about = "Client-side S3 encryption proxy")]
struct Cli {
    /// Path to a TOML config file. Without this flag, `./s3armor.toml` then
    /// `/etc/s3armor/config.toml` are tried; neither existing is not an error.
    /// An explicitly given path that doesn't exist is a startup error.
    /// Env vars always override the file.
    #[arg(long, global = true)]
    config: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy.
    Serve,
    /// Preflight backend compatibility check.
    Check(CheckCli),
    /// Local/backend/proxy benchmarks.
    Bench(BenchCli),
    /// Metadata-only v1 key rotation.
    Rewrap(RewrapCli),
    /// Metadata-only S3A_BIND_PATHS rewrap.
    Rebind(RebindCli),
    /// Print effective config with each value's source.
    Config,
    /// Liveness probe for containers without a shell.
    HealthProbe,
}

#[derive(Args)]
struct CheckCli {
    /// Bucket to probe. Must already exist; every probe object this
    /// creates is deleted before `check` exits.
    #[arg(long)]
    bucket: String,
    /// Which configured backend to probe. Required if more than one
    /// backend is configured; optional (and implied) with exactly one.
    #[arg(long)]
    backend: Option<String>,
}

#[derive(Args)]
struct BenchCli {
    /// Also run the backend tier: TTFB, throughput ladder, and concurrency
    /// discovery against the configured backend, direct.
    #[arg(long)]
    backend: bool,
    /// Which configured backend the --backend/--proxy tiers run against.
    /// Required if more than one backend is configured; optional (and
    /// implied) with exactly one. Named `--backend-name`, not `--backend`
    /// — that flag already means "run the backend tier" (bool).
    #[arg(long)]
    backend_name: Option<String>,
    /// Also run the proxy tier: proxy-vs-direct efficiency ratio against a
    /// running proxy instance at this URL, with SHA-256 verification.
    #[arg(long)]
    proxy: Option<String>,
    /// Bucket to use for --backend/--proxy (ignored for the local tier).
    #[arg(long)]
    bucket: Option<String>,
    /// Emit machine-readable JSON instead of a human table.
    #[arg(long)]
    json: bool,
    /// Print the recommended env block (S3A_ALG, S3A_CHUNK_SIZE) from the
    /// local tier and exit.
    #[arg(long)]
    write_config: bool,
}

#[derive(Args)]
struct RewrapCli {
    /// Bucket to rewrap.
    #[arg(long)]
    bucket: String,
    /// Only objects under this key prefix.
    #[arg(long, default_value = "")]
    prefix: String,
    /// Parallel workers.
    #[arg(long, default_value_t = 4)]
    workers: usize,
    /// Resumable checkpoint file (append-only list of rewrapped keys).
    #[arg(long)]
    checkpoint: Option<PathBuf>,
    /// Report what would happen; write nothing.
    #[arg(long)]
    dry_run: bool,
    /// Which configured backend to rewrap. Required if more than one
    /// backend is configured; optional (and implied) with exactly one.
    #[arg(long)]
    backend: Option<String>,
}

#[derive(Args)]
struct RebindCli {
    /// Bucket to rebind.
    #[arg(long)]
    bucket: String,
    /// Only objects under this key prefix.
    #[arg(long, default_value = "")]
    prefix: String,
    /// Parallel workers.
    #[arg(long, default_value_t = 4)]
    workers: usize,
    /// Resumable checkpoint file (append-only list of rebound keys).
    #[arg(long)]
    checkpoint: Option<PathBuf>,
    /// Report what would happen; write nothing.
    #[arg(long)]
    dry_run: bool,
    /// Try this bucket's binding (same key) for objects that don't unwrap
    /// under the current bucket or an empty binding — the renamed-bucket
    /// restore case (docs/ARCHITECTURE.md "Path binding").
    #[arg(long)]
    from_bucket: Option<String>,
    /// Which configured backend to rebind. Required if more than one
    /// backend is configured; optional (and implied) with exactly one.
    #[arg(long)]
    backend: Option<String>,
}

fn load_config_or_exit(config_path: Option<&str>) -> Config {
    let env = match Layered::new(config_path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("s3armor: config error: {e}");
            std::process::exit(1);
        }
    };
    let config = match Config::load(&env) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("s3armor: config error: {e}");
            std::process::exit(1);
        }
    };
    init_tracing(&config);
    config
}

/// Installs the `tracing` subscriber from `S3A_LOG`/`S3A_LOG_FORMAT`. Every
/// subcommand routes through `load_config_or_exit`, so this runs once no
/// matter which one is invoked — previously only `serve` called this,
/// which meant `check`/`bench`/`rewrap`/`rebind` ran with `S3A_LOG=debug`
/// having no effect and any `tracing::warn!` from the shared `forward`
/// machinery they reuse going nowhere. `try_init` rather than `init`: a
/// second call (there is none today, but a future one) should not panic.
fn init_tracing(config: &Config) {
    let filter = tracing_subscriber::EnvFilter::try_new(&config.log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);
    let _ = match config.log_format {
        s3armor::config::LogFormat::Json => subscriber.json().try_init(),
        s3armor::config::LogFormat::Text => subscriber.try_init(),
    };
}

/// Resolves a tool's `--backend` flag the same way, for the same reason, on
/// every subcommand that talks to exactly one backend per run — see
/// `tools::resolve_backend`'s own doc comment for the two failure cases.
fn resolve_backend_or_exit<'a>(state: &'a ProxyState, name: Option<&str>) -> &'a Backend {
    match tools::resolve_backend(&state.config, name) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("s3armor: {e}");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let config_path = cli.config;
    match cli.command {
        None | Some(Command::Serve) => serve(config_path.as_deref()).await,
        Some(Command::Config) => {
            load_config_or_exit(config_path.as_deref()).print_effective();
        }
        Some(Command::HealthProbe) => health_probe(config_path.as_deref()).await,
        Some(Command::Rewrap(args)) => run_rewrap(args, config_path.as_deref()).await,
        Some(Command::Check(args)) => run_check(args, config_path.as_deref()).await,
        Some(Command::Bench(args)) => run_bench(args, config_path.as_deref()).await,
        Some(Command::Rebind(args)) => run_rebind(args, config_path.as_deref()).await,
    }
}

async fn run_check(args: CheckCli, config_path: Option<&str>) {
    let config = load_config_or_exit(config_path);
    let state = Arc::new(ProxyState::new(config));
    let backend = resolve_backend_or_exit(&state, args.backend.as_deref());
    let report = tools::check::check(&state, backend, &args.bucket).await;
    report.print();
    if !report.ok() {
        std::process::exit(1);
    }
}

async fn run_bench(args: BenchCli, config_path: Option<&str>) {
    let local = tools::bench::run_local();
    if args.write_config {
        tools::bench::write_config(&local);
        return;
    }
    if args.json {
        println!("{}", tools::bench::local_json(&local));
    } else {
        tools::bench::print_local(&local);
    }

    if !args.backend && args.proxy.is_none() {
        return;
    }
    let Some(bucket) = args.bucket else {
        eprintln!("s3armor: bench: --bucket is required with --backend/--proxy");
        std::process::exit(1);
    };
    let config = load_config_or_exit(config_path);
    let state = Arc::new(ProxyState::new(config));
    let backend = resolve_backend_or_exit(&state, args.backend_name.as_deref());

    if args.backend {
        let results = tools::bench::run_backend(&state, backend, &bucket).await;
        if args.json {
            println!("{}", tools::bench::backend_json(&results));
        } else {
            tools::bench::print_backend(&results);
        }
        let sweep = tools::bench::part_size_sweep(&state, backend, &bucket).await;
        tools::bench::print_part_size_sweep(&sweep);
        let concurrency = tools::bench::discover_concurrency(&state, backend, &bucket).await;
        println!("max sustained concurrency (2x-latency knee): {concurrency}");
    }

    if let Some(proxy_url) = args.proxy {
        // The proxy under test authenticates like any other S3 client —
        // reuse the first registered `S3A_CLIENT_<NAME>` credential this
        // `bench` process was configured with (the same env a real
        // operator runs `bench` alongside the proxy with).
        let Some(cred) = state.config.clients.values().next() else {
            eprintln!(
                "s3armor: bench --proxy: no S3A_CLIENT_<NAME>_ACCESS_KEY/_SECRET_KEY configured to \
                 authenticate against the proxy with"
            );
            std::process::exit(1);
        };
        let client = tools::bench::reqwest_like::Client::new(
            proxy_url,
            cred.access_key.clone(),
            cred.secret_key.clone(),
        );
        let results = tools::bench::run_proxy_vs_direct(&state, backend, &bucket, &client).await;
        if args.json {
            println!("{}", tools::bench::proxy_json(&results));
        } else {
            tools::bench::print_proxy_vs_direct(&results);
        }
    }
}

async fn run_rewrap(args: RewrapCli, config_path: Option<&str>) {
    let config = load_config_or_exit(config_path);
    let dry_run = args.dry_run;
    let state = Arc::new(ProxyState::new(config));
    let report = match tools::rewrap(
        state,
        tools::RewrapArgs {
            bucket: args.bucket,
            prefix: args.prefix,
            workers: args.workers,
            checkpoint: args.checkpoint,
            dry_run,
            backend: args.backend,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("s3armor: rewrap: {e}");
            std::process::exit(1);
        }
    };
    report.print(dry_run);
    if !report.ok() {
        std::process::exit(1);
    }
}

async fn run_rebind(args: RebindCli, config_path: Option<&str>) {
    let config = load_config_or_exit(config_path);
    let dry_run = args.dry_run;
    let state = Arc::new(ProxyState::new(config));
    let report = match tools::rebind(
        state,
        tools::RebindArgs {
            bucket: args.bucket,
            prefix: args.prefix,
            workers: args.workers,
            checkpoint: args.checkpoint,
            dry_run,
            from_bucket: args.from_bucket,
            backend: args.backend,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("s3armor: rebind: {e}");
            std::process::exit(1);
        }
    };
    report.print(dry_run);
    if !report.ok() {
        std::process::exit(1);
    }
}

/// Unix-only signals for the shutdown trigger below: this proxy's only
/// shipping target is Linux (musl Docker image, Proxmox LXC,
/// `docs/ARCHITECTURE.md` "Deployment").
#[expect(
    clippy::expect_used,
    reason = "a failure to install a signal handler is a startup-time environment fault \
              (e.g. no signal support at all) with no recovery — fail loudly, not silently \
              run un-drainable"
)]
async fn serve(config_path: Option<&str>) {
    let config = load_config_or_exit(config_path);

    let listen = config.listen.clone();
    let tls_acceptor = config.tls.as_ref().map(|t| {
        let server_config = match s3armor::tls::load_server_config(&t.cert_path, &t.key_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("s3armor: cannot load S3A_TLS_CERT/S3A_TLS_KEY: {e}");
                std::process::exit(1);
            }
        };
        tokio_rustls::TlsAcceptor::from(server_config)
    });
    let listener = match TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("s3armor: cannot bind {listen}: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!(
        listen,
        backends = config.backends.len(),
        clients = config.clients.len(),
        tls = tls_acceptor.is_some(),
        "s3armor listening"
    );
    if config.clients.is_empty() {
        // Not fatal — a zero-client proxy is a legitimate transient state
        // while an operator is still setting up — but every request 403s
        // (`sigv4::verify::resolve_client`) until at least one
        // S3A_CLIENT_<NAME>_ACCESS_KEY is configured, and that is easy to
        // miss silently.
        tracing::warn!(
            "no S3A_CLIENT_<NAME>_ACCESS_KEY configured — every request will be rejected"
        );
    }

    let state = Arc::new(ProxyState::new(config));
    state.spawn_mpu_sweeper();
    spawn_metrics_listener(&state).await;

    // `shutdown_tx` fires once, on SIGTERM/SIGINT; every live connection
    // task holds a receiver and reacts by graceful-shutting-down its own
    // `hyper::server::conn::http1::Connection` — finish the in-flight
    // request, refuse a new one on the same keep-alive connection — rather
    // than the old bare `loop { accept }` that let `docker stop` sever
    // every upload mid-stream (`docs/ARCHITECTURE.md` "Observability"'s "503 during drain").
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    // Held by `serve` for `Arc::strong_count` after the accept loop exits;
    // each `handle_connection` task holds its own clone (`conn_guard`) so
    // the count reflects exactly the connections still live.
    let in_flight = Arc::new(());

    // Registered once, outside the loop: `Signal` is reused across
    // iterations rather than re-installing a handler on every accepted
    // connection.
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    // `None` until a signal arrives, then the hard cap on the whole drain
    // (`/health`/`/ready` must stay *reachable* while draining, not just
    // internally correct — an accept loop that stops the instant the
    // signal fires makes `/health`'s promised 503 unobservable, since every
    // new probe connection gets refused instead of answered — so this loop
    // keeps accepting even after draining starts). Bounded by
    // `S3A_TIMEOUT_REQUEST` — no new config knob — but exits as soon as
    // `in_flight` reaches zero rather than always burning the full budget:
    // `drained` below is a fresh `wait_for_drain` call each iteration,
    // racing the *remaining* time against `listener.accept()`, so an
    // otherwise-idle shutdown completes as soon as the one connection that
    // was in flight closes, while a straggler or continuous new traffic
    // still gets cut off at the deadline.
    let mut draining_deadline: Option<tokio::time::Instant> = None;
    loop {
        let drained = async {
            match draining_deadline {
                Some(deadline) => {
                    wait_for_drain(
                        &in_flight,
                        deadline.saturating_duration_since(tokio::time::Instant::now()),
                    )
                    .await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = sigterm.recv(), if draining_deadline.is_none() => {
                tracing::info!("SIGTERM received, draining");
                state.set_draining();
                let _ = shutdown_tx.send(true);
                draining_deadline = Some(tokio::time::Instant::now() + state.config.timeout_request);
            }
            _ = sigint.recv(), if draining_deadline.is_none() => {
                tracing::info!("SIGINT received, draining");
                state.set_draining();
                let _ = shutdown_tx.send(true);
                draining_deadline = Some(tokio::time::Instant::now() + state.config.timeout_request);
            }
            () = drained => break,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        continue;
                    }
                };
                // Small-request-heavy traffic (HeadObject, Nextcloud sync,
                // presign checks) feels Nagle + delayed-ACK directly as
                // fixed per-request latency; a socket option failure here
                // is not a reason to drop an otherwise-good connection.
                let _ = stream.set_nodelay(true);
                // Held for the task's whole lifetime so `Arc::strong_count(&in_flight)`
                // reflects exactly the connections still live — its `Drop`
                // at task end is the side effect `drained` above polls for,
                // not an unused binding.
                let conn_guard = in_flight.clone();
                tokio::spawn(handle_connection(
                    stream,
                    peer,
                    tls_acceptor.clone(),
                    state.clone(),
                    shutdown_rx.clone(),
                    conn_guard,
                ));
            }
        }
    }
    // ponytail: a connection accepted after draining started never observes
    // `shutdown_rx.changed()` (the watch channel's value already flipped
    // before that connection's receiver was cloned, so there is no edge
    // left to fire) and so is served with ordinary keep-alive semantics
    // rather than closing itself promptly — it is still bounded by the
    // deadline above before the process exits regardless, just not
    // proactively told to wrap up early. Thread an explicit "already
    // draining" flag into `handle_connection` if a real deployment's logs
    // show late connections outliving a drain.
}

/// One accepted connection's whole lifetime: TLS handshake (if configured),
/// then serve requests until either the peer closes it or `shutdown_rx`
/// fires — in which case it finishes whatever request is in flight and
/// then closes, rather than waiting for a new request on the same
/// keep-alive connection. `_conn_guard`'s only job is staying alive until
/// this function returns; `serve`'s drain wait watches its `Arc`'s
/// `strong_count` drop when it does.
async fn handle_connection(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    state: Arc<ProxyState>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    _conn_guard: Arc<()>,
) {
    let conn = match tls_acceptor {
        Some(acceptor) => match acceptor.accept(stream).await {
            Ok(tls) => s3armor::tls::Conn::Tls(Box::new(tls)),
            Err(e) => {
                tracing::debug!(error = %e, "TLS handshake failed");
                return;
            }
        },
        None => s3armor::tls::Conn::Plain(stream),
    };
    let io = TokioIo::new(conn);
    let service = hyper::service::service_fn(move |req| {
        let state = state.clone();
        async move { proxy::handle(state, req, peer.ip()).await }
    });
    let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, service);
    tokio::pin!(conn);
    loop {
        tokio::select! {
            res = conn.as_mut() => {
                if let Err(e) = res {
                    tracing::debug!(error = %e, "connection error");
                }
                break;
            }
            _ = shutdown_rx.changed() => {
                // Finish the in-flight request, then close instead of
                // waiting for the next one on this keep-alive connection.
                // Polled again next loop iteration until it resolves.
                conn.as_mut().graceful_shutdown();
            }
        }
    }
}

/// Waits for every `handle_connection` task to finish its own graceful
/// shutdown — observed as `in_flight`'s `Arc::strong_count` dropping back
/// to 1 (`serve`'s own handle) — bounded by `deadline` so one stuck
/// connection can't hang the process forever.
async fn wait_for_drain(in_flight: &Arc<()>, deadline: Duration) {
    let until = tokio::time::Instant::now() + deadline;
    while Arc::strong_count(in_flight) > 1 && tokio::time::Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if Arc::strong_count(in_flight) > 1 {
        tracing::warn!("shutdown deadline reached with connections still open");
    }
}

/// Binds and spawns the Prometheus metrics listener when `S3A_METRICS` is
/// set — its own port, unauthenticated, separate from the S3 traffic
/// (`Config::metrics_listen`'s doc comment). A no-op when unset (the
/// default). A bind failure here is loud but not fatal to the proxy
/// itself: metrics are observability, not the product.
async fn spawn_metrics_listener(state: &Arc<ProxyState>) {
    let Some(addr) = state.config.metrics_listen.clone() else {
        return;
    };
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            // `tracing::error!`, not `eprintln!` — this needs to reach the
            // same log pipeline as everything else here, or it breaks
            // `S3A_LOG_FORMAT=json` output with a stray unstructured line.
            tracing::error!(addr, error = %e, "cannot bind S3A_METRICS");
            return;
        }
    };
    tracing::info!(addr, "s3armor metrics listening");
    let state = state.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "metrics listener accept failed");
                    continue;
                }
            };
            let io = TokioIo::new(stream);
            let state = state.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req: hyper::Request<_>| {
                    let state = state.clone();
                    let path = req.uri().path().to_string();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            proxy::metrics::handle(&state, &path).await,
                        )
                    }
                });
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await
                {
                    tracing::debug!(error = %e, "metrics connection error");
                }
            });
        }
    });
}

async fn health_probe(config_path: Option<&str>) {
    let config = load_config_or_exit(config_path);
    // `S3A_LISTEN` is a bind address (often `0.0.0.0:PORT` or `[::]:PORT`);
    // the probe needs somewhere to actually connect to, not the unspecified
    // address itself. Parse rather than a literal-string substitution, so
    // both the IPv4 and IPv6 unspecified forms are handled the same way;
    // fall back to the original string if it isn't a plain `ip:port` (a
    // hostname, which needs no rewriting).
    let target = match config.listen.parse::<std::net::SocketAddr>() {
        Ok(addr) if addr.ip().is_unspecified() => {
            let loopback = if addr.is_ipv6() {
                std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            } else {
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            };
            std::net::SocketAddr::new(loopback, addr.port()).to_string()
        }
        _ => config.listen.clone(),
    };
    let req_result = if config.tls.is_some() {
        let url = format!("https://{target}/health");
        let _ = rustls::crypto::ring::default_provider().install_default();
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
        // `target` is `127.0.0.1`, which will never match the configured
        // certificate's hostname — this probe authenticates nothing and
        // carries no secret, it only asks whether the process still
        // answers `/health` (see `tls::AcceptAnyServerCert`'s doc comment).
        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(s3armor::tls::AcceptAnyServerCert(provider)))
            .with_no_client_auth();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_only()
            .enable_http1()
            .build();
        let client: hyper_util::client::legacy::Client<_, http_body_util::Empty<bytes::Bytes>> =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(https);
        let req = match http::Request::get(&url).body(http_body_util::Empty::new()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("s3armor: health-probe: bad url {url}: {e}");
                std::process::exit(1);
            }
        };
        client.request(req).await.map_err(|e| (url, e.to_string()))
    } else {
        let url = format!("http://{target}/health");
        let client: hyper_util::client::legacy::Client<_, http_body_util::Empty<bytes::Bytes>> =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(hyper_util::client::legacy::connect::HttpConnector::new());
        let req = match http::Request::get(&url).body(http_body_util::Empty::new()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("s3armor: health-probe: bad url {url}: {e}");
                std::process::exit(1);
            }
        };
        client.request(req).await.map_err(|e| (url, e.to_string()))
    };
    match req_result {
        Ok(resp) if resp.status().is_success() => std::process::exit(0),
        Ok(resp) => {
            eprintln!("s3armor: health-probe: returned {}", resp.status());
            std::process::exit(1);
        }
        Err((url, e)) => {
            eprintln!("s3armor: health-probe: {url} unreachable: {e}");
            std::process::exit(1);
        }
    }
}
