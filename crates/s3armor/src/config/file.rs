//! Optional `config.toml` file layer, plugged into `Config::load` at the
//! `EnvSource` seam (`config.rs`'s doc comment) — env still wins over the
//! file, and the file's mere presence changes nothing about parsing or
//! validation in `Config::load` itself.
//!
//! No `${VAR}` interpolation, by design — out of scope for this stage.

use std::collections::BTreeMap;

use super::{ConfigError, EnvSource, ProcessEnv, Source};

/// Search order when no `--config` flag is given. The first that exists
/// wins; if neither exists, the file layer is simply empty (not an error —
/// only an explicit path that doesn't exist is fatal).
const DEFAULT_PATHS: [&str; 2] = ["s3armor.toml", "/etc/s3armor/config.toml"];

/// `EnvSource` that layers a flattened `config.toml` under the real process
/// environment: `get` checks env first, file second, so `env > file >
/// default` falls out of the existing `read_var` logic with no changes to
/// it beyond the `origin` override below.
#[derive(Debug)]
pub struct Layered {
    env: ProcessEnv,
    file: BTreeMap<String, String>,
    /// The one file this instance loaded from, if any — used by `origin`
    /// to report `Source::File(path)`. A single `Layered` only ever loads
    /// one file, so one path is enough to attribute every file-sourced key.
    file_path: Option<String>,
}

impl Layered {
    /// `path = Some(p)`: `p` must exist and parse, or this is a startup
    /// error naming `p`. `path = None`: tries `./s3armor.toml`, then
    /// `/etc/s3armor/config.toml`; if neither exists, the file layer is empty.
    pub fn new(path: Option<&str>) -> Result<Self, ConfigError> {
        let (file, file_path) = match path {
            Some(p) => (load(p)?, Some(p.to_string())),
            None => match DEFAULT_PATHS
                .iter()
                .find(|p| std::path::Path::new(p).is_file())
            {
                Some(p) => (load(p)?, Some((*p).to_string())),
                None => (BTreeMap::new(), None),
            },
        };
        Ok(Self {
            env: ProcessEnv,
            file,
            file_path,
        })
    }
}

impl EnvSource for Layered {
    fn get(&self, name: &str) -> Option<String> {
        self.env.get(name).or_else(|| self.file.get(name).cloned())
    }

    fn names(&self) -> Vec<String> {
        let mut names: std::collections::BTreeSet<String> = self.env.names().into_iter().collect();
        names.extend(self.file.keys().cloned());
        names.into_iter().collect()
    }

    fn origin(&self, name: &str) -> Source {
        if self.env.get(name).is_some() {
            return Source::Env;
        }
        match &self.file_path {
            Some(path) if self.file.contains_key(name) => Source::File(path.clone()),
            _ => Source::Env,
        }
    }
}

/// Reads and flattens one config file, rejecting any secret found inline.
fn load(path: &str) -> Result<BTreeMap<String, String>, ConfigError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::ConfigFileRead(path.to_string(), e))?;
    let table: toml::Table = raw
        .parse()
        .map_err(|e| ConfigError::ConfigFileParse(path.to_string(), e))?;
    flatten(&table)
}

/// Converts a scalar TOML value to the string form `Config::load` expects
/// (it parses every value, including numbers and durations, from `String`).
fn scalar(v: &toml::Value) -> Result<String, ConfigError> {
    match v {
        toml::Value::String(s) => Ok(s.clone()),
        toml::Value::Integer(i) => Ok(i.to_string()),
        toml::Value::Float(f) => Ok(f.to_string()),
        toml::Value::Boolean(b) => Ok(b.to_string()),
        other => Err(ConfigError::Invalid(
            "config file value",
            format!("{other:?}: expected a string, integer, float, or boolean"),
        )),
    }
}

/// Flattens the nested TOML shape into the flat `S3A_*` names
/// `Config::load` already expects. Written out explicitly rather than as a
/// mechanical dotted-path rule: several existing env names don't mirror
/// their table name (`[multipart].ttl` -> `S3A_MP_TTL`, `[metrics].listen`
/// -> `S3A_METRICS`, `[crypto].*` -> `S3A_*` with no `CRYPTO_` prefix at
/// all), so a generic transform would need its own exception list — this
/// table *is* that list, just direct instead of two layers deep.
fn flatten(root: &toml::Table) -> Result<BTreeMap<String, String>, ConfigError> {
    let mut out = BTreeMap::new();

    macro_rules! leaf {
        ($table:expr, $key:literal, $env_name:expr) => {
            if let Some(v) = $table.get($key) {
                out.insert($env_name.to_string(), scalar(v)?);
            }
        };
    }

    leaf!(root, "listen", "S3A_LISTEN");
    leaf!(root, "log", "S3A_LOG");
    leaf!(root, "log_format", "S3A_LOG_FORMAT");
    leaf!(root, "bind_paths", "S3A_BIND_PATHS");

    if let Some(toml::Value::Table(t)) = root.get("backend") {
        leaf!(t, "endpoint", "S3A_BACKEND_ENDPOINT");
        leaf!(t, "region", "S3A_BACKEND_REGION");
        leaf!(t, "access_key", "S3A_BACKEND_ACCESS_KEY");
        leaf!(t, "secret_key", "S3A_BACKEND_SECRET_KEY");
        leaf!(t, "secret_key_file", "S3A_BACKEND_SECRET_KEY_FILE");
    }

    // Named backends beyond the implicit `[backend]` (`DEFAULT`) — same
    // per-entry shape, `S3A_BACKEND_<NAME>_*` instead of `S3A_BACKEND_*`.
    // Its own function (mirroring `[clients.<name>]` below) rather than
    // another `leaf!` block inline here, so `flatten` itself stays under
    // clippy's line-count lint.
    if let Some(toml::Value::Table(backends)) = root.get("backends") {
        flatten_named_backends(backends, &mut out)?;
    }

    if let Some(toml::Value::Table(t)) = root.get("timeouts") {
        leaf!(t, "connect", "S3A_TIMEOUT_CONNECT");
        leaf!(t, "request", "S3A_TIMEOUT_REQUEST");
    }

    if let Some(toml::Value::Table(clients)) = root.get("clients") {
        for (name, v) in clients {
            let toml::Value::Table(t) = v else { continue };
            let upper = name.to_uppercase();
            if let Some(v) = t.get("access_key") {
                out.insert(format!("S3A_CLIENT_{upper}_ACCESS_KEY"), scalar(v)?);
            }
            if let Some(v) = t.get("secret_key") {
                out.insert(format!("S3A_CLIENT_{upper}_SECRET_KEY"), scalar(v)?);
            }
            if let Some(v) = t.get("secret_key_file") {
                out.insert(format!("S3A_CLIENT_{upper}_SECRET_KEY_FILE"), scalar(v)?);
            }
            if let Some(v) = t.get("backend") {
                out.insert(format!("S3A_CLIENT_{upper}_BACKEND"), scalar(v)?);
            }
        }
    }

    if let Some(toml::Value::Table(t)) = root.get("crypto") {
        leaf!(t, "chunk_size", "S3A_CHUNK_SIZE");
        leaf!(t, "alg", "S3A_ALG");
    }

    if let Some(toml::Value::Table(t)) = root.get("keys") {
        leaf!(t, "active", "S3A_KEY_ACTIVE");
        for (name, v) in t {
            if name == "active" || matches!(v, toml::Value::Table(_)) {
                continue;
            }
            out.insert(format!("S3A_KEY_{}", name.to_uppercase()), scalar(v)?);
        }
    }

    if let Some(toml::Value::Table(t)) = root.get("rsa") {
        leaf!(t, "key", "S3A_RSA_KEY");
        leaf!(t, "key_file", "S3A_RSA_KEY_FILE");
        leaf!(t, "public", "S3A_RSA_PUBLIC");
        leaf!(t, "public_file", "S3A_RSA_PUBLIC_FILE");
    }

    if let Some(toml::Value::Table(t)) = root.get("multipart") {
        leaf!(t, "ttl", "S3A_MP_TTL");
        leaf!(t, "footer_cache", "S3A_FOOTER_CACHE");
    }

    if let Some(toml::Value::Table(t)) = root.get("metrics") {
        leaf!(t, "listen", "S3A_METRICS");
    }

    if let Some(toml::Value::Table(t)) = root.get("tls") {
        leaf!(t, "cert", "S3A_TLS_CERT");
        leaf!(t, "key", "S3A_TLS_KEY");
    }

    if let Some(toml::Value::Table(t)) = root.get("auth") {
        leaf!(t, "fail_limit", "S3A_AUTH_FAIL_LIMIT");
    }

    // Secrets are rejected inline, no exceptions — the environment or a
    // `_FILE`-suffixed secret-manager mount is the only sanctioned path.
    if let Some(name) = out.keys().find(|k| super::is_secret(k)) {
        return Err(ConfigError::SecretInFile(name.clone()));
    }

    Ok(out)
}

/// One `[backends.<name>]` table per named backend, flattened to
/// `S3A_BACKEND_<NAME>_*` — split out of `flatten` itself only to keep that
/// function's line count down; there is nothing reusable here beyond it.
fn flatten_named_backends(
    backends: &toml::Table,
    out: &mut BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    for (name, v) in backends {
        let toml::Value::Table(t) = v else { continue };
        let upper = name.to_uppercase();
        if let Some(v) = t.get("endpoint") {
            out.insert(format!("S3A_BACKEND_{upper}_ENDPOINT"), scalar(v)?);
        }
        if let Some(v) = t.get("region") {
            out.insert(format!("S3A_BACKEND_{upper}_REGION"), scalar(v)?);
        }
        if let Some(v) = t.get("access_key") {
            out.insert(format!("S3A_BACKEND_{upper}_ACCESS_KEY"), scalar(v)?);
        }
        if let Some(v) = t.get("secret_key") {
            out.insert(format!("S3A_BACKEND_{upper}_SECRET_KEY"), scalar(v)?);
        }
        if let Some(v) = t.get("secret_key_file") {
            out.insert(format!("S3A_BACKEND_{upper}_SECRET_KEY_FILE"), scalar(v)?);
        }
    }
    Ok(())
}
