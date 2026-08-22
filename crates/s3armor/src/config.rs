//! Flat env config loader. See `docs/ARCHITECTURE.md` "Configuration
//! model" and `AGENTS.md`.
//!
//! Every knob has one exact env name. No `__` nesting, no generic config
//! crate. `_FILE` reads a file (Docker/Podman secret); the plain var is the
//! fallback. Both set is a startup error, not a silent precedence choice.
//! Missing or contradictory config is fatal at startup, and the message
//! names the offending variable.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use s3armor_format::v1::{Alg, MasterKey, RsaKek};

use crate::keys::{Keyring, RSA_ACTIVE_NAME};

mod file;
pub use file::Layered;

/// Where a config value came from. Printed by `s3armor config` so "why is my
/// env var ignored" is a one-command diagnosis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Default,
    Env,
    EnvFile(String),
    /// Came from the optional `config.toml` file layer (`config::file`),
    /// not the process environment. `String` is the file's path.
    File(String),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => write!(f, "default"),
            Self::Env => write!(f, "env"),
            Self::EnvFile(path) => write!(f, "env-file:{path}"),
            Self::File(path) => write!(f, "file:{path}"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required env var {0}")]
    Missing(&'static str),
    #[error("both {0} and {0}_FILE are set — set only one")]
    BothSet(String),
    #[error("cannot read {0}_FILE at {1}: {2}")]
    FileRead(String, String, std::io::Error),
    #[error("invalid value for {0}: {1}")]
    Invalid(&'static str, String),
    #[error("cannot read config file {0}: {1}")]
    ConfigFileRead(String, std::io::Error),
    #[error("cannot parse config file {0}: {1}")]
    ConfigFileParse(String, toml::de::Error),
    #[error("secret {0} must not be set in a config file — use the environment or {0}_FILE")]
    SecretInFile(String),
    #[error("client {0} names unknown backend {1} — known backends: {2}")]
    UnknownBackend(String, String, String),
}

/// One resolved value plus where it came from, for `s3armor config` reporting.
struct Resolved {
    source: Source,
    value: String,
}

/// Reads `NAME` directly or `NAME_FILE` (file contents, trailing
/// `\r`/`\n` stripped). Both set is an error. Neither set returns `None`.
fn read_var(env: &dyn EnvSource, name: &str) -> Result<Option<Resolved>, ConfigError> {
    let plain = env.get(name);
    let file_var = format!("{name}_FILE");
    let file = env.get(&file_var);
    match (plain, file) {
        (Some(_), Some(_)) => Err(ConfigError::BothSet(name.to_string())),
        (Some(v), None) => Ok(Some(Resolved {
            source: env.origin(name),
            value: v,
        })),
        (None, Some(path)) => {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| ConfigError::FileRead(name.to_string(), path.clone(), e))?;
            let trimmed = raw.trim_end_matches(['\r', '\n']).to_string();
            Ok(Some(Resolved {
                source: Source::EnvFile(path),
                value: trimmed,
            }))
        }
        (None, None) => Ok(None),
    }
}

/// Abstraction over `std::env::var` so tests can inject a fake environment
/// without mutating the real process env (which is not test-safe under
/// parallel `cargo test`).
pub trait EnvSource {
    fn get(&self, name: &str) -> Option<String>;
    /// Every var name this source knows about — used to discover
    /// `S3A_CLIENT_<NAME>_*` entries without a fixed name list.
    fn names(&self) -> Vec<String>;
    /// Where `name`'s plain (non-`_FILE`) value came from, for `s3armor
    /// config` reporting. Only called once `get(name)` is known to return
    /// `Some`. Default `Source::Env` is correct for every source with no
    /// file layer (`ProcessEnv`, tests' `FakeEnv`) — only `config::Layered`
    /// needs to override it.
    fn origin(&self, _name: &str) -> Source {
        Source::Env
    }
}

#[derive(Debug)]
pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
    fn names(&self) -> Vec<String> {
        std::env::vars().map(|(k, _)| k).collect()
    }
}

#[derive(Clone)]
pub struct ClientCredentials {
    pub access_key: String,
    pub secret_key: String,
    /// Which `backends` entry this client's requests are re-signed and
    /// forwarded to. Always a key present in `Config::backends` —
    /// `Config::load` validates that before returning.
    pub backend: String,
}

impl fmt::Debug for ClientCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCredentials")
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .field("backend", &self.backend)
            .finish()
    }
}

/// The name every request needs but only this and `ClientCredentials` (via
/// `S3A_CLIENT_<NAME>_BACKEND`) ever set: which upstream a client's
/// requests go to. `DEFAULT` is implicit — a deployment with exactly one
/// backend never has to name it.
pub const DEFAULT_BACKEND_NAME: &str = "DEFAULT";

/// One upstream S3-compatible endpoint. `Config::backends` holds one or
/// more of these, keyed by name; `ClientCredentials::backend` selects
/// which one a client's requests are re-signed and forwarded to.
#[derive(Clone)]
pub struct Backend {
    pub name: String,
    pub endpoint: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
}

impl fmt::Debug for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Backend")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct Config {
    pub listen: String,
    pub log_level: String,
    pub log_format: LogFormat,
    /// Every configured upstream, keyed by name (`DEFAULT_BACKEND_NAME`
    /// when unnamed). Never empty once `load` returns `Ok`.
    pub backends: BTreeMap<String, Backend>,
    /// Access key -> credentials. The proxy re-signs upstream with the
    /// credentials of the client's own resolved `backend` — never a fixed
    /// backend — this map is only for verifying the client's own signature.
    pub clients: BTreeMap<String, ClientCredentials>,
    pub timeout_connect: Duration,
    pub timeout_request: Duration,
    /// v1 master keys, indexed by key id. Debug-safe: prints ids only,
    /// never key material (docs/ARCHITECTURE.md "Zeroization").
    pub keyring: Keyring,
    /// The `S3A_KEY_ACTIVE` env name, kept only for `s3armor config` reporting
    /// — decrypt routing uses `keyring`'s key ids, never this name.
    pub key_active_name: String,
    /// Plaintext chunk size for v1 framing, in bytes.
    pub chunk_size: u32,
    /// v1 data algorithm, resolved at load time (CPU feature detection when
    /// `S3A_ALG=auto`).
    pub alg: Alg,
    /// Value -> source, for `s3armor config`. Secrets are redacted at print
    /// time, not here, so tests can still assert on sources.
    pub sources: BTreeMap<String, Source>,
    /// `S3A_MP_TTL` — multipart session TTL, measured from last activity,
    /// not creation (a TTL from creation killed slow uploads mid-flight)
    /// (`docs/ARCHITECTURE.md` "Multipart v1" and "Configuration model").
    pub mp_ttl: Duration,
    /// `S3A_FOOTER_CACHE` — max entries in the multipart footer LRU cache
    /// (`docs/ARCHITECTURE.md` "Multipart v1" and "Configuration model").
    pub footer_cache: usize,
    /// The v1 RSA public key, SPKI PEM — kept only so `s3armor config` has
    /// something non-secret to print for `S3A_RSA_PUBLIC`; `keyring` is the
    /// source of truth for everything the proxy actually does with it.
    pub rsa_public_pem: Option<String>,
    /// `S3A_METRICS` — address for the Prometheus text-exposition endpoint
    /// (`docs/ARCHITECTURE.md` "Configuration model" and "Observability").
    /// Unset (`None`) means off. Never the S3
    /// listen address: that port is authenticated and public-facing, this
    /// one is neither, so it always gets its own listener (`main::serve`).
    pub metrics_listen: Option<String>,
    /// `S3A_TLS_CERT`/`S3A_TLS_KEY` — filesystem paths to PEM files, not
    /// `_FILE`-suffixed values: a certificate isn't a secret, and a private
    /// key already arrives as a file from both Docker secrets and systemd
    /// `LoadCredential`, so a path is the natural shape here (unlike
    /// `S3A_KEY_<NAME>`, whose *value* is the key material itself). `None`
    /// means plain HTTP — most deployments sit behind a TLS-terminating
    /// reverse proxy or a private network, so plain HTTP is a reasonable
    /// default here.
    pub tls: Option<TlsConfig>,
    /// `S3A_AUTH_FAIL_LIMIT` — failed SigV4 verifications per source IP per
    /// minute before further attempts get `429 SlowDown` without even being
    /// checked. `0` disables the limiter. Source IP is the TCP peer only;
    /// `X-Forwarded-For` is never trusted (client-settable, would make the
    /// limiter both bypassable and a DoS vector) — behind a reverse proxy
    /// every client collapses to one IP, so set this to `0` there.
    pub auth_fail_limit: u32,
    /// `S3A_BIND_PATHS` — binds each object's DEK wrap to its
    /// `bucket ‖ key` (`docs/ARCHITECTURE.md` "Path binding"). Default `Off`.
    pub bind_mode: BindMode,
}

/// Redacts `backend_secret_key` — `derive(Debug)` would otherwise print it
/// verbatim from a single `{config:?}` in a log field or panic message
/// (`clients`' own secrets are already safe: `ClientCredentials` has its
/// own redacting `Debug`; `keyring` likewise prints ids/presence only,
/// `docs/ARCHITECTURE.md` "Zeroization").
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("listen", &self.listen)
            .field("log_level", &self.log_level)
            .field("log_format", &self.log_format)
            .field("backends", &self.backends)
            .field("clients", &self.clients)
            .field("timeout_connect", &self.timeout_connect)
            .field("timeout_request", &self.timeout_request)
            .field("keyring", &self.keyring)
            .field("key_active_name", &self.key_active_name)
            .field("chunk_size", &self.chunk_size)
            .field("alg", &self.alg)
            .field("sources", &self.sources)
            .field("mp_ttl", &self.mp_ttl)
            .field("footer_cache", &self.footer_cache)
            .field("rsa_public_pem", &self.rsa_public_pem)
            .field("metrics_listen", &self.metrics_listen)
            .field("tls", &self.tls)
            .field("auth_fail_limit", &self.auth_fail_limit)
            .field("bind_mode", &self.bind_mode)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// `S3A_BIND_PATHS`'s three states — see `docs/ARCHITECTURE.md` "Path
/// binding" for why a plain on/off would be unsafe to flip on an existing
/// bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindMode {
    /// Wrap and unwrap with an empty binding — today's behavior, and the
    /// only mode that can read objects written before this feature existed.
    Off,
    /// Wrap bound; unwrap tries the bound AAD first, then falls back to the
    /// empty one. Safe to enable on an existing bucket without running
    /// `s3armor rebind` first — nothing becomes unreadable.
    On,
    /// Wrap and unwrap bound only, no fallback — the retirement switch, once
    /// `s3armor rebind` has run over every object.
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

const SECRET_KEYS: &[&str] = &["S3A_RSA_KEY"];

/// `S3A_CHUNK_SIZE` bounds, docs/ARCHITECTURE.md "Data: chunked AEAD": 64
/// KiB .. 8 MiB.
const MIN_CHUNK_SIZE: u32 = 65_536;
const MAX_CHUNK_SIZE: u32 = 8_388_608;
const DEFAULT_CHUNK_SIZE: u32 = 1_048_576;

fn is_secret(name: &str) -> bool {
    SECRET_KEYS.contains(&name)
        || (name.starts_with("S3A_CLIENT_") && name.ends_with("_SECRET_KEY"))
        // Covers both the unprefixed DEFAULT var (S3A_BACKEND_SECRET_KEY)
        // and every named backend's (S3A_BACKEND_<NAME>_SECRET_KEY).
        || (name.starts_with("S3A_BACKEND_") && name.ends_with("_SECRET_KEY"))
        // S3A_KEY_ACTIVE just names which key is active, not key material.
        // A _FILE-suffixed name holds a path, never material itself — see
        // every other prefix's `_SECRET_KEY`/exact-name rule above, which
        // already excludes its own _FILE variant by construction.
        || (name.starts_with("S3A_KEY_")
            && name != "S3A_KEY_ACTIVE"
            && !name.ends_with("_FILE"))
}

/// Picks the data algorithm for `S3A_ALG=auto`: AES-256-GCM when the CPU
/// reports hardware AES, else XChaCha20-Poly1305 (fast everywhere).
/// docs/ARCHITECTURE.md "Data: chunked AEAD".
#[cfg(target_arch = "x86_64")]
fn has_aes_hw() -> bool {
    std::is_x86_feature_detected!("aes")
}
#[cfg(target_arch = "aarch64")]
fn has_aes_hw() -> bool {
    std::arch::is_aarch64_feature_detected!("aes")
}
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn has_aes_hw() -> bool {
    false
}

impl Config {
    #[expect(
        clippy::too_many_lines,
        reason = "a flat, linear list of independent field-parsing steps; splitting it would fragment a single audit-friendly sequence"
    )]
    pub fn load(env: &dyn EnvSource) -> Result<Self, ConfigError> {
        fn required(
            env: &dyn EnvSource,
            sources: &mut BTreeMap<String, Source>,
            name: &'static str,
        ) -> Result<String, ConfigError> {
            match read_var(env, name)? {
                Some(r) => {
                    sources.insert(name.to_string(), r.source);
                    Ok(r.value)
                }
                None => Err(ConfigError::Missing(name)),
            }
        }
        fn optional(
            env: &dyn EnvSource,
            sources: &mut BTreeMap<String, Source>,
            name: &'static str,
            default: &str,
        ) -> Result<String, ConfigError> {
            if let Some(r) = read_var(env, name)? {
                sources.insert(name.to_string(), r.source);
                Ok(r.value)
            } else {
                sources.insert(name.to_string(), Source::Default);
                Ok(default.to_string())
            }
        }

        let mut sources = BTreeMap::new();

        let listen = optional(env, &mut sources, "S3A_LISTEN", "0.0.0.0:8080")?;
        let log_level = optional(env, &mut sources, "S3A_LOG", "info")?;
        let log_format_raw = optional(env, &mut sources, "S3A_LOG_FORMAT", "text")?;
        let log_format = match log_format_raw.as_str() {
            "text" => LogFormat::Text,
            "json" => LogFormat::Json,
            other => return Err(ConfigError::Invalid("S3A_LOG_FORMAT", other.to_string())),
        };

        let backends = load_backends(env, &mut sources)?;
        if backends.is_empty() {
            return Err(ConfigError::Missing("S3A_BACKEND_ENDPOINT"));
        }

        let timeout_connect = parse_duration_secs(
            &optional(env, &mut sources, "S3A_TIMEOUT_CONNECT", "10")?,
            "S3A_TIMEOUT_CONNECT",
        )?;
        let timeout_request = parse_duration_secs(
            &optional(env, &mut sources, "S3A_TIMEOUT_REQUEST", "300")?,
            "S3A_TIMEOUT_REQUEST",
        )?;

        let clients = load_clients(env, &mut sources)?;
        if let Some((client_name, bad_backend)) = clients.iter().find_map(|(n, c)| {
            (!backends.contains_key(&c.backend)).then(|| (n.clone(), c.backend.clone()))
        }) {
            let known = backends.keys().cloned().collect::<Vec<_>>().join(", ");
            return Err(ConfigError::UnknownBackend(client_name, bad_backend, known));
        }

        let chunk_size_raw = optional(
            env,
            &mut sources,
            "S3A_CHUNK_SIZE",
            &DEFAULT_CHUNK_SIZE.to_string(),
        )?;
        let chunk_size: u32 = chunk_size_raw
            .parse()
            .ok()
            .filter(|n| (MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(n))
            .ok_or_else(|| ConfigError::Invalid("S3A_CHUNK_SIZE", chunk_size_raw.clone()))?;

        let alg_raw = optional(env, &mut sources, "S3A_ALG", "auto")?;
        let alg = match alg_raw.as_str() {
            "auto" if has_aes_hw() => Alg::Aes256Gcm,
            "aes-gcm" => Alg::Aes256Gcm,
            "auto" | "xchacha20-poly1305" => Alg::XChaCha20Poly1305,
            other => return Err(ConfigError::Invalid("S3A_ALG", other.to_string())),
        };

        let key_active_name = required(env, &mut sources, "S3A_KEY_ACTIVE")?;
        let named_keys = load_keys(env, &mut sources)?;
        let rsa = load_rsa_kek(env, &mut sources)?;
        let rsa_public_pem = rsa
            .as_ref()
            .map(RsaKek::public_pem)
            .transpose()
            .map_err(|e| ConfigError::Invalid("S3A_RSA_PUBLIC", e.to_string()))?;
        let keyring = Keyring::new(&key_active_name, named_keys, rsa).ok_or_else(|| {
            if key_active_name == RSA_ACTIVE_NAME {
                ConfigError::Invalid(
                    "S3A_KEY_ACTIVE",
                    "'RSA' needs S3A_RSA_KEY[_FILE] or S3A_RSA_PUBLIC[_FILE] configured"
                        .to_string(),
                )
            } else {
                ConfigError::Invalid(
                    "S3A_KEY_ACTIVE",
                    format!("'{key_active_name}' has no matching S3A_KEY_{key_active_name}[_FILE]"),
                )
            }
        })?;

        // Default 24h. A `24h`/`1h`/`90m`-style suffix reads more like
        // the docs than a bare seconds count for a knob operators tune
        // directly; `parse_duration_secs` still accepts a bare number too.
        let mp_ttl_raw = optional(env, &mut sources, "S3A_MP_TTL", "24h")?;
        let mp_ttl = parse_duration(&mp_ttl_raw, "S3A_MP_TTL")?;

        let footer_cache_raw = optional(env, &mut sources, "S3A_FOOTER_CACHE", "1024")?;
        let footer_cache: usize = footer_cache_raw
            .parse()
            .ok()
            .filter(|n| *n >= 1)
            .ok_or_else(|| ConfigError::Invalid("S3A_FOOTER_CACHE", footer_cache_raw.clone()))?;

        let metrics_listen = if let Some(r) = read_var(env, "S3A_METRICS")? {
            sources.insert("S3A_METRICS".to_string(), r.source);
            Some(r.value)
        } else {
            sources.insert("S3A_METRICS".to_string(), Source::Default);
            None
        };

        // Plain paths, not `read_var`'s NAME/NAME_FILE convention — see the
        // field doc comment on `Config::tls`. Both set or neither: a lone
        // cert or key is a startup config error, not a guess.
        let tls_cert = env.get("S3A_TLS_CERT");
        let tls_key = env.get("S3A_TLS_KEY");
        let tls = match (tls_cert, tls_key) {
            (Some(cert_path), Some(key_path)) => {
                sources.insert("S3A_TLS_CERT".to_string(), Source::Env);
                sources.insert("S3A_TLS_KEY".to_string(), Source::Env);
                Some(TlsConfig {
                    cert_path,
                    key_path,
                })
            }
            (None, None) => {
                sources.insert("S3A_TLS_CERT".to_string(), Source::Default);
                sources.insert("S3A_TLS_KEY".to_string(), Source::Default);
                None
            }
            (Some(_), None) => {
                return Err(ConfigError::Missing("S3A_TLS_KEY"));
            }
            (None, Some(_)) => {
                return Err(ConfigError::Missing("S3A_TLS_CERT"));
            }
        };

        let auth_fail_limit_raw = optional(env, &mut sources, "S3A_AUTH_FAIL_LIMIT", "60")?;
        let auth_fail_limit: u32 = auth_fail_limit_raw.parse().map_err(|_| {
            ConfigError::Invalid("S3A_AUTH_FAIL_LIMIT", auth_fail_limit_raw.clone())
        })?;

        let bind_mode_raw = optional(env, &mut sources, "S3A_BIND_PATHS", "off")?;
        let bind_mode = match bind_mode_raw.as_str() {
            "off" => BindMode::Off,
            "on" => BindMode::On,
            "strict" => BindMode::Strict,
            other => return Err(ConfigError::Invalid("S3A_BIND_PATHS", other.to_string())),
        };

        Ok(Self {
            listen,
            log_level,
            log_format,
            backends,
            clients,
            timeout_connect,
            timeout_request,
            keyring,
            key_active_name,
            chunk_size,
            alg,
            sources,
            mp_ttl,
            footer_cache,
            rsa_public_pem,
            metrics_listen,
            tls,
            auth_fail_limit,
            bind_mode,
        })
    }

    /// Prints the effective config, one line per var, source, and (for
    /// secrets) a redacted value.
    pub fn print_effective(&self) {
        for (name, source) in &self.sources {
            let display = if is_secret(name) {
                "<redacted>".to_string()
            } else {
                self.raw_value(name)
            };
            println!("{name}={display}  ({source})");
        }
        // Node capability (docs/ARCHITECTURE.md "Write-only (RSA) nodes
        // cannot serve GETs"): a write-only RSA node returns
        // `KeyNotAvailable` on every GET of an encrypted object — printing
        // this at startup is the one-line diagnosis for a misrouted
        // cluster.
        let capability = match self.keyring.capability() {
            crate::keys::Capability::ReadWrite => "read+write",
            crate::keys::Capability::WriteOnly => {
                "write-only (GET of encrypted objects returns KeyNotAvailable)"
            }
        };
        println!("# node capability: {capability}");
        // Routing: with more than one client and/or backend, "who
        // talks to what" no longer falls out of the alphabetical var list
        // above at a glance — this trailer makes it a one-command answer.
        for (client_name, creds) in &self.clients {
            if let Some(b) = self.backends.get(&creds.backend) {
                println!(
                    "# routing: client {client_name} -> backend {} ({})",
                    creds.backend, b.endpoint
                );
            }
        }
    }

    #[expect(
        clippy::integer_division,
        reason = "S3A_MP_TTL is displayed rounded down to whole hours by design"
    )]
    fn raw_value(&self, name: &str) -> String {
        match name {
            "S3A_LISTEN" => self.listen.clone(),
            "S3A_LOG" => self.log_level.clone(),
            "S3A_LOG_FORMAT" => match self.log_format {
                LogFormat::Text => "text".to_string(),
                LogFormat::Json => "json".to_string(),
            },
            "S3A_TIMEOUT_CONNECT" => self.timeout_connect.as_secs().to_string(),
            "S3A_TIMEOUT_REQUEST" => self.timeout_request.as_secs().to_string(),
            "S3A_CHUNK_SIZE" => self.chunk_size.to_string(),
            "S3A_ALG" => match self.alg {
                Alg::Aes256Gcm => "aes-gcm".to_string(),
                Alg::XChaCha20Poly1305 => "xchacha20-poly1305".to_string(),
            },
            "S3A_KEY_ACTIVE" => self.key_active_name.clone(),
            "S3A_MP_TTL" => format!("{}h", self.mp_ttl.as_secs() / 3600),
            "S3A_FOOTER_CACHE" => self.footer_cache.to_string(),
            "S3A_RSA_PUBLIC" => self.rsa_public_pem.clone().unwrap_or_default(),
            "S3A_METRICS" => self.metrics_listen.clone().unwrap_or_default(),
            "S3A_TLS_CERT" => self
                .tls
                .as_ref()
                .map(|t| t.cert_path.clone())
                .unwrap_or_default(),
            "S3A_TLS_KEY" => self
                .tls
                .as_ref()
                .map(|t| t.key_path.clone())
                .unwrap_or_default(),
            "S3A_AUTH_FAIL_LIMIT" => self.auth_fail_limit.to_string(),
            "S3A_BIND_PATHS" => match self.bind_mode {
                BindMode::Off => "off".to_string(),
                BindMode::On => "on".to_string(),
                BindMode::Strict => "strict".to_string(),
            },
            other => {
                if let Some(client_name) = other
                    .strip_prefix("S3A_CLIENT_")
                    .and_then(|s| s.strip_suffix("_ACCESS_KEY"))
                {
                    if let Some(c) = self.clients.get(client_name) {
                        return c.access_key.clone();
                    }
                }
                if let Some(client_name) = other
                    .strip_prefix("S3A_CLIENT_")
                    .and_then(|s| s.strip_suffix("_BACKEND"))
                {
                    if let Some(c) = self.clients.get(client_name) {
                        return c.backend.clone();
                    }
                }
                if let Some(rest) = other.strip_prefix("S3A_BACKEND_") {
                    for field in ["ENDPOINT", "REGION", "ACCESS_KEY"] {
                        let backend_name = if rest == field {
                            Some(DEFAULT_BACKEND_NAME)
                        } else {
                            rest.strip_suffix(&format!("_{field}"))
                        };
                        if let Some(b) = backend_name.and_then(|n| self.backends.get(n)) {
                            return match field {
                                "ENDPOINT" => b.endpoint.clone(),
                                "REGION" => b.region.clone(),
                                _ => b.access_key.clone(),
                            };
                        }
                    }
                }
                String::new()
            }
        }
    }
}

fn parse_duration_secs(raw: &str, name: &'static str) -> Result<Duration, ConfigError> {
    raw.parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|_| ConfigError::Invalid(name, raw.to_string()))
}

/// Parses a duration as a bare seconds count or a single `<n><unit>` suffix
/// (`s`/`m`/`h`/`d`) — `S3A_MP_TTL`'s `24h` reads better in `docker-compose`
/// than `86400`, and a bare number still works for scripts.
fn parse_duration(raw: &str, name: &'static str) -> Result<Duration, ConfigError> {
    let invalid = || ConfigError::Invalid(name, raw.to_string());
    if let Ok(secs) = raw.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }
    let (digits, unit) = raw.split_at(raw.len().saturating_sub(1));
    let n: u64 = digits.parse().map_err(|_| invalid())?;
    let mul = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(invalid()),
    };
    Ok(Duration::from_secs(n * mul))
}

/// Discovers `S3A_CLIENT_<NAME>_ACCESS_KEY(_FILE)` /
/// `S3A_CLIENT_<NAME>_SECRET_KEY(_FILE)` pairs. `<NAME>` is `[A-Z0-9]+` —
/// no underscores in names, so the flat form parses unambiguously (see "Configuration model").
fn load_clients(
    env: &dyn EnvSource,
    sources: &mut BTreeMap<String, Source>,
) -> Result<BTreeMap<String, ClientCredentials>, ConfigError> {
    let mut names = std::collections::BTreeSet::new();
    for var in env.names() {
        if let Some(rest) = var.strip_prefix("S3A_CLIENT_") {
            for suffix in [
                "_ACCESS_KEY",
                "_ACCESS_KEY_FILE",
                "_SECRET_KEY",
                "_SECRET_KEY_FILE",
            ] {
                if let Some(name) = rest.strip_suffix(suffix) {
                    if !name.is_empty()
                        && name
                            .chars()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    {
                        names.insert(name.to_string());
                    }
                }
            }
        }
    }

    let mut clients = BTreeMap::new();
    for name in names {
        let access_var = format!("S3A_CLIENT_{name}_ACCESS_KEY");
        let secret_var = format!("S3A_CLIENT_{name}_SECRET_KEY");
        let access = read_var(env, &access_var)?
            .ok_or(ConfigError::Missing("S3A_CLIENT_<NAME>_ACCESS_KEY"))?;
        let secret = read_var(env, &secret_var)?
            .ok_or(ConfigError::Missing("S3A_CLIENT_<NAME>_SECRET_KEY"))?;
        sources.insert(access_var, access.source);
        sources.insert(secret_var, secret.source);

        let backend_var = format!("S3A_CLIENT_{name}_BACKEND");
        let backend = if let Some(r) = read_var(env, &backend_var)? {
            sources.insert(backend_var, r.source);
            r.value.to_uppercase()
        } else {
            sources.insert(backend_var, Source::Default);
            DEFAULT_BACKEND_NAME.to_string()
        };

        clients.insert(
            name,
            ClientCredentials {
                access_key: access.value,
                secret_key: secret.value,
                backend,
            },
        );
    }
    Ok(clients)
}

/// Discovers backends: the implicit `DEFAULT` backend from
/// `S3A_BACKEND_{ENDPOINT,REGION,ACCESS_KEY,SECRET_KEY}(_FILE)`, and any
/// number of named backends from `S3A_BACKEND_<NAME>_{...}(_FILE)`.
/// Exact-match-first: the four `DEFAULT` suffixes are excluded from the
/// `<NAME>_SUFFIX` split, so `S3A_BACKEND_ACCESS_KEY` names `DEFAULT`'s
/// access key, never a backend named `ACCESS`. `<NAME>` is `[A-Z0-9]+`,
/// matching the client/key-name rule (see "Configuration model"). Returns an empty map if no
/// backend vars are set at all — `Config::load` turns that into the same
/// `Missing("S3A_BACKEND_ENDPOINT")` a single-backend deployment always saw.
fn load_backends(
    env: &dyn EnvSource,
    sources: &mut BTreeMap<String, Source>,
) -> Result<BTreeMap<String, Backend>, ConfigError> {
    const DEFAULT_SUFFIXES: [&str; 4] = ["ENDPOINT", "REGION", "ACCESS_KEY", "SECRET_KEY"];

    let mut named = std::collections::BTreeSet::new();
    for var in env.names() {
        let Some(rest) = var.strip_prefix("S3A_BACKEND_") else {
            continue;
        };
        let rest = rest.strip_suffix("_FILE").unwrap_or(rest);
        if DEFAULT_SUFFIXES.contains(&rest) {
            continue;
        }
        for suffix in ["_ENDPOINT", "_REGION", "_ACCESS_KEY", "_SECRET_KEY"] {
            if let Some(name) = rest.strip_suffix(suffix) {
                if !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                {
                    named.insert(name.to_string());
                }
            }
        }
    }

    let mut backends = BTreeMap::new();

    let default_present = DEFAULT_SUFFIXES.iter().any(|s| {
        env.get(&format!("S3A_BACKEND_{s}")).is_some()
            || env.get(&format!("S3A_BACKEND_{s}_FILE")).is_some()
    });
    if default_present {
        backends.insert(
            DEFAULT_BACKEND_NAME.to_string(),
            load_one_backend(
                env,
                sources,
                DEFAULT_BACKEND_NAME,
                "S3A_BACKEND_ENDPOINT".to_string(),
                "S3A_BACKEND_REGION".to_string(),
                "S3A_BACKEND_ACCESS_KEY".to_string(),
                "S3A_BACKEND_SECRET_KEY".to_string(),
                "S3A_BACKEND_ENDPOINT",
                "S3A_BACKEND_ACCESS_KEY",
                "S3A_BACKEND_SECRET_KEY",
            )?,
        );
    }

    for name in named {
        backends.insert(
            name.clone(),
            load_one_backend(
                env,
                sources,
                &name,
                format!("S3A_BACKEND_{name}_ENDPOINT"),
                format!("S3A_BACKEND_{name}_REGION"),
                format!("S3A_BACKEND_{name}_ACCESS_KEY"),
                format!("S3A_BACKEND_{name}_SECRET_KEY"),
                "S3A_BACKEND_<NAME>_ENDPOINT",
                "S3A_BACKEND_<NAME>_ACCESS_KEY",
                "S3A_BACKEND_<NAME>_SECRET_KEY",
            )?,
        );
    }

    Ok(backends)
}

/// Loads one backend's four vars, given the exact var names to read
/// (`DEFAULT`'s are unprefixed, a named backend's carry `_<NAME>_`) and the
/// placeholder names `ConfigError::Missing` should report when required
/// ones are absent.
#[expect(
    clippy::too_many_arguments,
    reason = "internal helper, called from exactly two call sites that differ only in these strings"
)]
fn load_one_backend(
    env: &dyn EnvSource,
    sources: &mut BTreeMap<String, Source>,
    name: &str,
    endpoint_var: String,
    region_var: String,
    access_var: String,
    secret_var: String,
    missing_endpoint: &'static str,
    missing_access: &'static str,
    missing_secret: &'static str,
) -> Result<Backend, ConfigError> {
    let endpoint = read_var(env, &endpoint_var)?.ok_or(ConfigError::Missing(missing_endpoint))?;
    sources.insert(endpoint_var, endpoint.source);

    let region = if let Some(r) = read_var(env, &region_var)? {
        sources.insert(region_var, r.source);
        r.value
    } else {
        sources.insert(region_var, Source::Default);
        "us-east-1".to_string()
    };

    let access = read_var(env, &access_var)?.ok_or(ConfigError::Missing(missing_access))?;
    sources.insert(access_var, access.source);

    let secret = read_var(env, &secret_var)?.ok_or(ConfigError::Missing(missing_secret))?;
    sources.insert(secret_var, secret.source);

    Ok(Backend {
        name: name.to_string(),
        endpoint: endpoint.value,
        region,
        access_key: access.value,
        secret_key: secret.value,
    })
}

/// Discovers `S3A_KEY_<NAME>(_FILE)` pairs (base64 of a 32-byte master
/// key). `S3A_KEY_ACTIVE(_FILE)` is excluded — that var names which key is
/// active, read separately by `Config::load` via `required`. `<NAME>` is
/// `[A-Z0-9]+`, matching the client-name rule (see "Configuration model").
fn load_keys(
    env: &dyn EnvSource,
    sources: &mut BTreeMap<String, Source>,
) -> Result<BTreeMap<String, MasterKey>, ConfigError> {
    let mut names = std::collections::BTreeSet::new();
    for var in env.names() {
        if let Some(rest) = var.strip_prefix("S3A_KEY_") {
            let name = rest.strip_suffix("_FILE").unwrap_or(rest);
            if name == "ACTIVE" {
                continue;
            }
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            {
                names.insert(name.to_string());
            }
        }
    }

    let mut keys = BTreeMap::new();
    for name in names {
        let var = format!("S3A_KEY_{name}");
        let resolved = read_var(env, &var)?.ok_or(ConfigError::Missing("S3A_KEY_<NAME>"))?;
        let raw = resolved.value.clone();
        let bytes = B64
            .decode(raw.trim())
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or_else(|| {
                ConfigError::Invalid(
                    "S3A_KEY_<NAME>",
                    format!("{name}: not base64 of exactly 32 bytes"),
                )
            })?;
        sources.insert(var, resolved.source);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        keys.insert(name, MasterKey::new(arr));
    }
    Ok(keys)
}

/// Loads the v1 RSA keypair from `S3A_RSA_KEY[_FILE]` (private, PKCS#8 PEM
/// — a read/full node) or `S3A_RSA_PUBLIC[_FILE]` (public, SPKI PEM — a
/// write-only node). Both set is an error, same posture as `_FILE` pairs.
/// Neither set returns `Ok(None)` — a deployment with no RSA-wrapped
/// objects needs none of this.
fn load_rsa_kek(
    env: &dyn EnvSource,
    sources: &mut BTreeMap<String, Source>,
) -> Result<Option<RsaKek>, ConfigError> {
    let private = read_var(env, "S3A_RSA_KEY")?;
    let public = read_var(env, "S3A_RSA_PUBLIC")?;
    sources
        .entry("S3A_RSA_KEY".to_string())
        .or_insert(Source::Default);
    sources
        .entry("S3A_RSA_PUBLIC".to_string())
        .or_insert(Source::Default);
    match (private, public) {
        (Some(_), Some(_)) => Err(ConfigError::BothSet(
            "S3A_RSA_KEY and S3A_RSA_PUBLIC".to_string(),
        )),
        (Some(r), None) => {
            sources.insert("S3A_RSA_KEY".to_string(), r.source);
            RsaKek::from_private_pem(&r.value)
                .map(Some)
                .map_err(|e| ConfigError::Invalid("S3A_RSA_KEY", e.to_string()))
        }
        (None, Some(r)) => {
            sources.insert("S3A_RSA_PUBLIC".to_string(), r.source);
            RsaKek::from_public_pem(&r.value)
                .map(Some)
                .map_err(|e| ConfigError::Invalid("S3A_RSA_PUBLIC", e.to_string()))
        }
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeEnv(HashMap<String, String>);

    impl FakeEnv {
        fn new(pairs: &[(&str, &str)]) -> Self {
            Self(
                pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )
        }
    }

    impl EnvSource for FakeEnv {
        fn get(&self, name: &str) -> Option<String> {
            self.0.get(name).cloned()
        }
        fn names(&self) -> Vec<String> {
            self.0.keys().cloned().collect()
        }
    }

    /// Base64 of 32 zero bytes — a validly-shaped (if not secret) master
    /// key for tests that don't care about the key's actual value.
    const TEST_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn minimal() -> Vec<(&'static str, &'static str)> {
        vec![
            ("S3A_BACKEND_ENDPOINT", "http://127.0.0.1:9000"),
            ("S3A_BACKEND_ACCESS_KEY", "minioadmin"),
            ("S3A_BACKEND_SECRET_KEY", "minioadmin"),
            ("S3A_KEY_ACTIVE", "K1"),
            ("S3A_KEY_K1", TEST_KEY_B64),
        ]
    }

    #[test]
    fn defaults_apply_when_unset() {
        let env = FakeEnv::new(&minimal());
        let cfg = Config::load(&env).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:8080");
        assert_eq!(cfg.sources["S3A_LISTEN"], Source::Default);
        assert_eq!(cfg.timeout_connect, Duration::from_secs(10));
        assert_eq!(cfg.chunk_size, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn missing_required_var_error_names_the_variable() {
        let env = FakeEnv::new(&[]);
        let err = Config::load(&env).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("S3A_BACKEND_ENDPOINT")));
    }

    #[test]
    fn file_variant_reads_file_and_strips_newline() {
        let dir = std::env::temp_dir().join(format!("s3a-cfg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        std::fs::write(&path, "minioadmin\n").unwrap();

        let mut pairs = minimal();
        pairs.retain(|(k, _)| *k != "S3A_BACKEND_SECRET_KEY");
        let path_str = path.to_str().unwrap().to_string();
        let env = FakeEnv::new(&pairs);
        let mut map = env.0;
        map.insert("S3A_BACKEND_SECRET_KEY_FILE".to_string(), path_str.clone());
        let env = FakeEnv(map);

        let cfg = Config::load(&env).unwrap();
        assert_eq!(cfg.backends[DEFAULT_BACKEND_NAME].secret_key, "minioadmin");
        assert_eq!(
            cfg.sources["S3A_BACKEND_SECRET_KEY"],
            Source::EnvFile(path_str)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn both_plain_and_file_is_an_error() {
        let mut pairs = minimal();
        pairs.push(("S3A_BACKEND_SECRET_KEY_FILE", "/nonexistent"));
        let env = FakeEnv::new(&pairs);
        let err = Config::load(&env).unwrap_err();
        assert!(matches!(err, ConfigError::BothSet(name) if name == "S3A_BACKEND_SECRET_KEY"));
    }

    #[test]
    fn client_credentials_discovered_from_flat_names() {
        let mut pairs = minimal();
        pairs.push(("S3A_CLIENT_NEXTCLOUD_ACCESS_KEY", "nc"));
        pairs.push(("S3A_CLIENT_NEXTCLOUD_SECRET_KEY", "ncsecret"));
        let env = FakeEnv::new(&pairs);
        let cfg = Config::load(&env).unwrap();
        assert_eq!(cfg.clients["NEXTCLOUD"].access_key, "nc");
        assert_eq!(cfg.clients["NEXTCLOUD"].secret_key, "ncsecret");
    }

    #[test]
    fn client_missing_secret_is_an_error() {
        let mut pairs = minimal();
        pairs.push(("S3A_CLIENT_NEXTCLOUD_ACCESS_KEY", "nc"));
        let env = FakeEnv::new(&pairs);
        let err = Config::load(&env).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Missing("S3A_CLIENT_<NAME>_SECRET_KEY")
        ));
    }

    #[test]
    fn client_with_no_backend_var_resolves_to_default() {
        let mut pairs = minimal();
        pairs.push(("S3A_CLIENT_NEXTCLOUD_ACCESS_KEY", "nc"));
        pairs.push(("S3A_CLIENT_NEXTCLOUD_SECRET_KEY", "ncsecret"));
        let env = FakeEnv::new(&pairs);
        let cfg = Config::load(&env).unwrap();
        assert_eq!(cfg.clients["NEXTCLOUD"].backend, DEFAULT_BACKEND_NAME);
    }

    #[test]
    fn plain_backend_access_key_names_default_not_a_backend_called_access() {
        let env = FakeEnv::new(&minimal());
        let cfg = Config::load(&env).unwrap();
        assert_eq!(cfg.backends.len(), 1);
        assert!(cfg.backends.contains_key(DEFAULT_BACKEND_NAME));
        assert!(!cfg.backends.contains_key("ACCESS"));
    }

    #[test]
    fn named_backend_is_discovered_from_its_four_vars() {
        let mut pairs = minimal();
        pairs.push(("S3A_BACKEND_WASABI_ENDPOINT", "https://s3.wasabisys.com"));
        pairs.push(("S3A_BACKEND_WASABI_REGION", "eu-central-2"));
        pairs.push(("S3A_BACKEND_WASABI_ACCESS_KEY", "wa"));
        pairs.push(("S3A_BACKEND_WASABI_SECRET_KEY", "wasecret"));
        let env = FakeEnv::new(&pairs);
        let cfg = Config::load(&env).unwrap();
        let b = &cfg.backends["WASABI"];
        assert_eq!(b.endpoint, "https://s3.wasabisys.com");
        assert_eq!(b.region, "eu-central-2");
        assert_eq!(b.access_key, "wa");
        assert_eq!(b.secret_key, "wasecret");
        // DEFAULT is untouched — `minimal()` still configures it.
        assert!(cfg.backends.contains_key(DEFAULT_BACKEND_NAME));
    }

    #[test]
    fn client_naming_an_unknown_backend_is_an_error_listing_known_names() {
        let mut pairs = minimal();
        pairs.push(("S3A_CLIENT_NEXTCLOUD_ACCESS_KEY", "nc"));
        pairs.push(("S3A_CLIENT_NEXTCLOUD_SECRET_KEY", "ncsecret"));
        pairs.push(("S3A_CLIENT_NEXTCLOUD_BACKEND", "WASABI"));
        let env = FakeEnv::new(&pairs);
        let err = Config::load(&env).unwrap_err();
        let ConfigError::UnknownBackend(client, backend, known) = err else {
            panic!("expected UnknownBackend, got {err:?}");
        };
        assert_eq!(client, "NEXTCLOUD");
        assert_eq!(backend, "WASABI");
        assert_eq!(known, DEFAULT_BACKEND_NAME);
    }

    #[test]
    fn invalid_log_format_is_rejected() {
        let mut pairs = minimal();
        pairs.push(("S3A_LOG_FORMAT", "yaml"));
        let env = FakeEnv::new(&pairs);
        let err = Config::load(&env).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid("S3A_LOG_FORMAT", _)));
    }

    #[test]
    fn print_effective_does_not_panic_on_a_minimal_config() {
        // Smoke test only: exercises the print path without asserting on
        // stdout capture (not test-friendly across threads). The real
        // assertion is `is_secret` below.
        let env = FakeEnv::new(&minimal());
        let cfg = Config::load(&env).unwrap();
        cfg.print_effective();
    }

    /// `{config:?}` — a `tracing` field, a panic message, any future
    /// debug line — must not print `backend_secret_key` or a client's
    /// `secret_key` verbatim. `Config`/`ClientCredentials` originally had a
    /// plain `derive(Debug)`.
    #[test]
    fn debug_format_redacts_backend_and_client_secrets() {
        // Distinct from the access keys below — `minimal()` sets both
        // backend access and secret to "minioadmin", which would make a
        // "the secret string is absent" assertion pass trivially (the
        // access key would still print it) or fail spuriously.
        let mut pairs = minimal();
        pairs.retain(|(k, _)| *k != "S3A_BACKEND_SECRET_KEY");
        pairs.push(("S3A_BACKEND_SECRET_KEY", "super-secret-backend-value"));
        pairs.push(("S3A_CLIENT_NEXTCLOUD_ACCESS_KEY", "nextcloud"));
        pairs.push((
            "S3A_CLIENT_NEXTCLOUD_SECRET_KEY",
            "super-secret-client-value",
        ));
        let env = FakeEnv::new(&pairs);
        let cfg = Config::load(&env).unwrap();

        let debug = format!("{cfg:?}");
        assert!(
            !debug.contains("super-secret-backend-value"),
            "backend secret key leaked into Debug output: {debug}"
        );
        assert!(
            !debug.contains("super-secret-client-value"),
            "client secret key leaked into Debug output: {debug}"
        );
        assert!(
            debug.contains("<redacted>"),
            "expected a redaction marker in Debug output: {debug}"
        );
        // The corresponding access keys are not secret and should still be
        // visible — proof this is redaction, not a blanket field omission.
        assert!(debug.contains("minioadmin"));
        assert!(debug.contains("nextcloud"));
    }

    #[test]
    fn secret_classification_covers_backend_and_client_secrets() {
        assert!(is_secret("S3A_BACKEND_SECRET_KEY"));
        assert!(is_secret("S3A_CLIENT_NEXTCLOUD_SECRET_KEY"));
        assert!(!is_secret("S3A_BACKEND_ACCESS_KEY"));
        assert!(!is_secret("S3A_CLIENT_NEXTCLOUD_ACCESS_KEY"));
    }

    #[test]
    fn key_material_is_secret_but_active_name_is_not() {
        assert!(is_secret("S3A_KEY_K1"));
        assert!(!is_secret("S3A_KEY_ACTIVE"));
    }

    #[test]
    fn active_key_name_resolves_to_the_kid_wrap_active_uses() {
        let env = FakeEnv::new(&minimal());
        let cfg = Config::load(&env).unwrap();
        assert_eq!(cfg.key_active_name, "K1");
        let (_, kid, _) = cfg.keyring.wrap_active(&[0u8; 32], &[]).unwrap();
        assert_eq!(cfg.keyring.active_kid(), kid);
    }

    #[test]
    fn active_key_naming_a_missing_key_is_an_error() {
        let mut pairs = minimal();
        for p in &mut pairs {
            if p.0 == "S3A_KEY_ACTIVE" {
                p.1 = "NOPE";
            }
        }
        let env = FakeEnv::new(&pairs);
        let err = Config::load(&env).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid("S3A_KEY_ACTIVE", _)));
    }

    #[test]
    fn key_that_is_not_32_bytes_is_rejected() {
        let mut pairs = minimal();
        pairs.push(("S3A_KEY_K1", "AAAA"));
        // Duplicate key in the same Vec: FakeEnv's HashMap keeps the last
        // one inserted, which is exactly what we want to override.
        let env = FakeEnv::new(&pairs);
        let err = Config::load(&env).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid("S3A_KEY_<NAME>", _)));
    }

    #[test]
    fn chunk_size_out_of_bounds_is_rejected() {
        let mut pairs = minimal();
        pairs.push(("S3A_CHUNK_SIZE", "100"));
        let env = FakeEnv::new(&pairs);
        let err = Config::load(&env).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid("S3A_CHUNK_SIZE", _)));
    }

    #[test]
    fn mp_ttl_defaults_to_24h_and_accepts_suffixed_values() {
        let env = FakeEnv::new(&minimal());
        let cfg = Config::load(&env).unwrap();
        assert_eq!(cfg.mp_ttl, Duration::from_hours(24));

        let mut pairs = minimal();
        pairs.push(("S3A_MP_TTL", "90m"));
        let env = FakeEnv::new(&pairs);
        let cfg = Config::load(&env).unwrap();
        assert_eq!(cfg.mp_ttl, Duration::from_mins(90));
    }

    #[test]
    fn footer_cache_defaults_and_rejects_zero() {
        let env = FakeEnv::new(&minimal());
        let cfg = Config::load(&env).unwrap();
        assert_eq!(cfg.footer_cache, 1024);

        let mut pairs = minimal();
        pairs.push(("S3A_FOOTER_CACHE", "0"));
        let env = FakeEnv::new(&pairs);
        let err = Config::load(&env).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid("S3A_FOOTER_CACHE", _)));
    }

    #[test]
    fn metrics_listen_is_off_by_default_and_settable() {
        let env = FakeEnv::new(&minimal());
        let cfg = Config::load(&env).unwrap();
        assert_eq!(cfg.metrics_listen, None);

        let mut pairs = minimal();
        pairs.push(("S3A_METRICS", "0.0.0.0:9090"));
        let env = FakeEnv::new(&pairs);
        let cfg = Config::load(&env).unwrap();
        assert_eq!(cfg.metrics_listen.as_deref(), Some("0.0.0.0:9090"));
    }

    #[test]
    fn alg_pinning_overrides_auto_detection() {
        let mut pairs = minimal();
        pairs.push(("S3A_ALG", "xchacha20-poly1305"));
        let env = FakeEnv::new(&pairs);
        let cfg = Config::load(&env).unwrap();
        assert_eq!(cfg.alg, Alg::XChaCha20Poly1305);
    }

    /// `Layered` (`config::file`) wraps the *real* `ProcessEnv`, unlike
    /// every test above (which uses `FakeEnv` precisely to avoid touching
    /// the real process environment under parallel `cargo test`). These
    /// tests are the deliberate exception, so they serialize on a lock and
    /// clean up every var they set — see `EnvGuard` below.
    mod file_tests {
        use super::*;

        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

        /// Sets real process env vars for the duration of one test, then
        /// removes them on drop — including on an early panic/assert
        /// failure, so a failing test doesn't poison the ones after it.
        struct EnvGuard(Vec<&'static str>);
        impl EnvGuard {
            fn new(pairs: &[(&'static str, &str)]) -> Self {
                for (k, v) in pairs {
                    std::env::set_var(k, v);
                }
                Self(pairs.iter().map(|(k, _)| *k).collect())
            }
        }
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                for name in &self.0 {
                    std::env::remove_var(name);
                }
            }
        }

        /// The same shape as `minimal()` above, but as real env vars —
        /// `Layered` always checks the real environment first.
        fn minimal_real_env() -> Vec<(&'static str, &'static str)> {
            vec![
                ("S3A_BACKEND_ENDPOINT", "http://127.0.0.1:9000"),
                ("S3A_BACKEND_ACCESS_KEY", "minioadmin"),
                ("S3A_BACKEND_SECRET_KEY", "minioadmin"),
                ("S3A_KEY_ACTIVE", "K1"),
                ("S3A_KEY_K1", TEST_KEY_B64),
            ]
        }

        /// Writes `contents` to a fresh temp file unique to `unique` (so
        /// parallel tests in this module never share a path) and returns
        /// its path.
        fn write_temp_toml(unique: &str, contents: &str) -> std::path::PathBuf {
            let dir = std::env::temp_dir()
                .join(format!("s3a-cfgfile-test-{}-{unique}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("config.toml");
            std::fs::write(&path, contents).unwrap();
            path
        }

        #[test]
        fn file_value_loads_when_env_absent() {
            let _lock = ENV_LOCK.lock().unwrap();
            let _env = EnvGuard::new(&minimal_real_env());
            let path = write_temp_toml("loads-from-file", "[backend]\nregion = \"eu-central-1\"\n");
            let layered = Layered::new(Some(path.to_str().unwrap())).unwrap();
            let cfg = Config::load(&layered).unwrap();
            assert_eq!(cfg.backends[DEFAULT_BACKEND_NAME].region, "eu-central-1");
            assert_eq!(
                cfg.sources["S3A_BACKEND_REGION"],
                Source::File(path.to_str().unwrap().to_string())
            );
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[test]
        fn env_overrides_file_for_the_same_key() {
            let _lock = ENV_LOCK.lock().unwrap();
            let mut pairs = minimal_real_env();
            pairs.push(("S3A_BACKEND_REGION", "us-west-2"));
            let _env = EnvGuard::new(&pairs);
            let path = write_temp_toml(
                "env-overrides-file",
                "[backend]\nregion = \"eu-central-1\"\n",
            );
            let layered = Layered::new(Some(path.to_str().unwrap())).unwrap();
            let cfg = Config::load(&layered).unwrap();
            assert_eq!(cfg.backends[DEFAULT_BACKEND_NAME].region, "us-west-2");
            assert_eq!(cfg.sources["S3A_BACKEND_REGION"], Source::Env);
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[test]
        fn secret_in_file_is_a_startup_error_naming_the_key() {
            let _lock = ENV_LOCK.lock().unwrap();
            let _env = EnvGuard::new(&minimal_real_env());
            let path = write_temp_toml("secret-in-file", "[backend]\nsecret_key = \"leaked\"\n");
            let err = Layered::new(Some(path.to_str().unwrap())).unwrap_err();
            assert!(
                matches!(&err, ConfigError::SecretInFile(name) if name == "S3A_BACKEND_SECRET_KEY"),
                "expected SecretInFile(S3A_BACKEND_SECRET_KEY), got {err:?}"
            );
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[test]
        fn named_backend_declared_in_file_is_discovered_with_a_file_secret() {
            let _lock = ENV_LOCK.lock().unwrap();
            let _env = EnvGuard::new(&minimal_real_env());
            // The secret half can't live inline in the file (see the test
            // above) — it arrives as a `secret_key_file` path instead,
            // exactly the shape a Docker/Podman secret mount has.
            let dir = std::env::temp_dir().join(format!(
                "s3a-cfgfile-test-{}-named-backend",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let secret_path = dir.join("wasabi-secret");
            std::fs::write(&secret_path, "wasabi-secret-value\n").unwrap();
            let path = write_temp_toml(
                "named-backend",
                &format!(
                    "[backends.wasabi]\nendpoint = \"https://s3.wasabisys.com\"\n\
                     region = \"eu-central-2\"\naccess_key = \"wa\"\nsecret_key_file = \"{}\"\n",
                    secret_path.to_str().unwrap()
                ),
            );
            let layered = Layered::new(Some(path.to_str().unwrap())).unwrap();
            let cfg = Config::load(&layered).unwrap();
            let b = &cfg.backends["WASABI"];
            assert_eq!(b.endpoint, "https://s3.wasabisys.com");
            assert_eq!(b.region, "eu-central-2");
            assert_eq!(b.access_key, "wa");
            assert_eq!(b.secret_key, "wasabi-secret-value");
            // DEFAULT (from minimal_real_env) is untouched alongside it.
            assert!(cfg.backends.contains_key(DEFAULT_BACKEND_NAME));
            std::fs::remove_dir_all(&dir).ok();
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[test]
        fn key_file_declared_in_toml_is_accepted_not_rejected_as_secret() {
            let _lock = ENV_LOCK.lock().unwrap();
            let _env = EnvGuard::new(&minimal_real_env());
            // Regression test for the bug the `_FILE` exemption in
            // `is_secret` fixes: `[keys]`'s loop uppercases every bare key
            // into `S3A_KEY_<NAME>`, so `K2_file` becomes
            // `S3A_KEY_K2_FILE` — a *path*, which must not trip the
            // inline-secret guard the way `K2 = "..."` correctly does
            // (`file_declared_key_entry_is_discovered_and_rejected_as_secret`
            // above).
            let dir = std::env::temp_dir()
                .join(format!("s3a-cfgfile-test-{}-key-file", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let key_path = dir.join("k2");
            std::fs::write(&key_path, format!("{TEST_KEY_B64}\n")).unwrap();
            let path = write_temp_toml(
                "key-file-entry",
                &format!(
                    "[keys]\nactive = \"K1\"\nK2_file = \"{}\"\n",
                    key_path.to_str().unwrap()
                ),
            );
            let layered = Layered::new(Some(path.to_str().unwrap())).unwrap();
            let cfg = Config::load(&layered).unwrap();
            assert!(matches!(
                cfg.sources.get("S3A_KEY_K2"),
                Some(Source::EnvFile(p)) if p == key_path.to_str().unwrap()
            ));
            std::fs::remove_dir_all(&dir).ok();
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[test]
        fn file_declared_client_block_is_discovered_via_names_union() {
            let _lock = ENV_LOCK.lock().unwrap();
            let _env = EnvGuard::new(&minimal_real_env());
            // `S3A_CLIENT_NEXTCLOUD_SECRET_KEY` is a secret — it can't live
            // in the file (see the test above), so it comes from the real
            // environment here, same as any deployment would supply it.
            let _secret = EnvGuard::new(&[("S3A_CLIENT_NEXTCLOUD_SECRET_KEY", "nc-secret")]);
            let path = write_temp_toml(
                "client-block",
                "[clients.nextcloud]\naccess_key = \"nc-access\"\n",
            );
            let layered = Layered::new(Some(path.to_str().unwrap())).unwrap();
            // Proves `load_clients`'s `env.names()` scan sees the
            // file-declared `S3A_CLIENT_NEXTCLOUD_ACCESS_KEY` with zero
            // changes to `load_clients` itself.
            let cfg = Config::load(&layered).unwrap();
            assert_eq!(cfg.clients["NEXTCLOUD"].access_key, "nc-access");
            assert_eq!(cfg.clients["NEXTCLOUD"].secret_key, "nc-secret");
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[test]
        fn file_declared_key_entry_is_discovered_and_rejected_as_secret() {
            let _lock = ENV_LOCK.lock().unwrap();
            let _env = EnvGuard::new(&minimal_real_env());
            // `[keys.K2]` names `S3A_KEY_K2` once flattened — key material,
            // always a secret (`is_secret`), so this must be a hard error,
            // never a silent skip. Getting `SecretInFile("S3A_KEY_K2")`
            // (not "file parsed fine, K2 just isn't there") is proof the
            // nested `[keys.<name>]` table was actually discovered.
            let path = write_temp_toml(
                "key-entry",
                &format!("[keys]\nactive = \"K1\"\nK2 = \"{TEST_KEY_B64}\"\n"),
            );
            let err = Layered::new(Some(path.to_str().unwrap())).unwrap_err();
            assert!(
                matches!(&err, ConfigError::SecretInFile(name) if name == "S3A_KEY_K2"),
                "expected SecretInFile(S3A_KEY_K2), got {err:?}"
            );
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[test]
        fn malformed_toml_fails_naming_the_file() {
            let _lock = ENV_LOCK.lock().unwrap();
            let path = write_temp_toml("malformed", "this is not [valid toml");
            let err = Layered::new(Some(path.to_str().unwrap())).unwrap_err();
            match err {
                ConfigError::ConfigFileParse(p, _) => {
                    assert_eq!(p, path.to_str().unwrap());
                }
                other => panic!("expected ConfigFileParse naming the path, got {other:?}"),
            }
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[test]
        fn explicit_config_path_that_does_not_exist_is_an_error() {
            let _lock = ENV_LOCK.lock().unwrap();
            let path = "/nonexistent/s3a-config-file-test-path.toml";
            let err = Layered::new(Some(path)).unwrap_err();
            match err {
                ConfigError::ConfigFileRead(p, _) => assert_eq!(p, path),
                other => panic!("expected ConfigFileRead naming the path, got {other:?}"),
            }
        }

        #[test]
        fn no_config_flag_and_no_default_file_is_not_an_error() {
            let _lock = ENV_LOCK.lock().unwrap();
            // True for both local dev and this repo's CI containers — the
            // default search paths are simply absent, which must not be an
            // error (only an *explicit* missing `--config` path is fatal).
            assert!(!std::path::Path::new("s3armor.toml").exists());
            assert!(!std::path::Path::new("/etc/s3armor/config.toml").exists());
            let layered = Layered::new(None).unwrap();
            assert!(layered.get("S3A_DOES_NOT_EXIST_XYZ").is_none());
        }
    }
}
