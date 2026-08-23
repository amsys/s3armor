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
/// Top-level scalar keys, beyond the tables in [`TABLES`] and the
/// operator-named tables below — everything reachable via `root.get(...)`
/// in this file, spelled out once so an unrecognized top-level key is a
/// startup error instead of a silently-ignored typo (misconfiguration is
/// fatal at startup everywhere else in this crate; a `config.toml` typo
/// was the one gap).
const TOP_LEVEL_SCALARS: &[&str] = &["listen", "log", "log_format", "bind_paths"];
/// Tables named by the operator (`[backends.mine]`, `[clients.nextcloud]`,
/// `[keys]`'s per-key entries) rather than a fixed set of legal names —
/// excluded from the unknown-key check below by design, not an oversight.
const TOP_LEVEL_DYNAMIC_TABLES: &[&str] = &["backends", "clients", "keys"];

fn flatten(root: &toml::Table) -> Result<BTreeMap<String, String>, ConfigError> {
    for key in root.keys() {
        let known = TOP_LEVEL_SCALARS.contains(&key.as_str())
            || TOP_LEVEL_DYNAMIC_TABLES.contains(&key.as_str())
            || TABLES.iter().any(|(name, _)| name == key);
        if !known {
            return Err(ConfigError::UnknownKey(key.clone()));
        }
    }

    let mut out = BTreeMap::new();

    if let Some(v) = root.get("listen") {
        out.insert("S3A_LISTEN".to_string(), scalar(v)?);
    }
    if let Some(v) = root.get("log") {
        out.insert("S3A_LOG".to_string(), scalar(v)?);
    }
    if let Some(v) = root.get("log_format") {
        out.insert("S3A_LOG_FORMAT".to_string(), scalar(v)?);
    }
    if let Some(v) = root.get("bind_paths") {
        out.insert("S3A_BIND_PATHS".to_string(), scalar(v)?);
    }

    flatten_simple_tables(root, &mut out)?;

    // Named backends beyond the implicit `[backend]` (`DEFAULT`) — same
    // per-entry shape, `S3A_BACKEND_<NAME>_*` instead of `S3A_BACKEND_*`.
    if let Some(toml::Value::Table(backends)) = root.get("backends") {
        flatten_named_backends(backends, &mut out)?;
    }

    if let Some(toml::Value::Table(clients)) = root.get("clients") {
        flatten_clients(clients, &mut out)?;
    }

    if let Some(toml::Value::Table(t)) = root.get("keys") {
        flatten_keys(t, &mut out)?;
    }

    // Secrets are rejected inline, no exceptions — the environment or a
    // `_FILE`-suffixed secret-manager mount is the only sanctioned path.
    if let Some(name) = out.keys().find(|k| super::is_secret(k)) {
        return Err(ConfigError::SecretInFile(name.clone()));
    }

    Ok(out)
}

/// `(toml table name, [(toml key, env var name), ...])` — every settings
/// group whose keys need no name transform beyond a fixed env name (see
/// `flatten`'s doc comment for why this is a literal table, not a
/// mechanical dotted-path rule). `[clients]`, `[backends]`, and `[keys]`
/// aren't here: their env names are keyed by a table-name the operator
/// picks, not fixed per table.
const TABLES: &[(&str, &[(&str, &str)])] = &[
    (
        "backend",
        &[
            ("endpoint", "S3A_BACKEND_ENDPOINT"),
            ("region", "S3A_BACKEND_REGION"),
            ("access_key", "S3A_BACKEND_ACCESS_KEY"),
            ("secret_key", "S3A_BACKEND_SECRET_KEY"),
            ("secret_key_file", "S3A_BACKEND_SECRET_KEY_FILE"),
        ],
    ),
    (
        "timeouts",
        &[
            ("connect", "S3A_TIMEOUT_CONNECT"),
            ("request", "S3A_TIMEOUT_REQUEST"),
        ],
    ),
    (
        "crypto",
        &[("chunk_size", "S3A_CHUNK_SIZE"), ("alg", "S3A_ALG")],
    ),
    (
        "rsa",
        &[
            ("key", "S3A_RSA_KEY"),
            ("key_file", "S3A_RSA_KEY_FILE"),
            ("public", "S3A_RSA_PUBLIC"),
            ("public_file", "S3A_RSA_PUBLIC_FILE"),
        ],
    ),
    (
        "multipart",
        &[("ttl", "S3A_MP_TTL"), ("footer_cache", "S3A_FOOTER_CACHE")],
    ),
    ("metrics", &[("listen", "S3A_METRICS")]),
    ("tls", &[("cert", "S3A_TLS_CERT"), ("key", "S3A_TLS_KEY")]),
    ("auth", &[("fail_limit", "S3A_AUTH_FAIL_LIMIT")]),
];

fn flatten_simple_tables(
    root: &toml::Table,
    out: &mut BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    for (table_name, keys) in TABLES {
        let Some(toml::Value::Table(t)) = root.get(*table_name) else {
            continue;
        };
        for key in t.keys() {
            if !keys.iter().any(|(k, _)| k == key) {
                return Err(ConfigError::UnknownKey(format!("{table_name}.{key}")));
            }
        }
        for (key, env_name) in *keys {
            if let Some(v) = t.get(*key) {
                out.insert((*env_name).to_string(), scalar(v)?);
            }
        }
    }
    Ok(())
}

/// One `[clients.<name>]` table per client, flattened to
/// `S3A_CLIENT_<NAME>_*` — mirrors `flatten_named_backends` below.
fn flatten_clients(
    clients: &toml::Table,
    out: &mut BTreeMap<String, String>,
) -> Result<(), ConfigError> {
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
    Ok(())
}

/// `[keys]`: `active` is a plain leaf, every other scalar entry names a
/// key (`S3A_KEY_<NAME>`); a nested table under `[keys]` is skipped rather
/// than misread as a key value.
fn flatten_keys(t: &toml::Table, out: &mut BTreeMap<String, String>) -> Result<(), ConfigError> {
    if let Some(v) = t.get("active") {
        out.insert("S3A_KEY_ACTIVE".to_string(), scalar(v)?);
    }
    for (name, v) in t {
        if name == "active" || matches!(v, toml::Value::Table(_)) {
            continue;
        }
        out.insert(format!("S3A_KEY_{}", name.to_uppercase()), scalar(v)?);
    }
    Ok(())
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
