//! CLI-only tooling: `s3armor rewrap` (v1 key rotation, metadata-only). Walks
//! a bucket direct-to-backend through the same `proxy::forward` signing
//! path `serve` uses — no separate through-proxy mode needed.
//! `docs/ARCHITECTURE.md` "Key handling".

mod list;
pub mod rewrap;

pub mod bench;
pub mod check;

pub use rewrap::{rebind, rewrap, RebindArgs, RebindReport, RewrapArgs, RewrapReport};

/// Everything that can go wrong in a walk/rewrap run. Not an S3
/// error — these tools talk to the backend directly and report to a
/// terminal, not to an S3 client, so there is no XML mapping to do.
#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("{0}")]
    Backend(String),
    #[error("xml: {0}")]
    Xml(String),
    #[error(transparent)]
    Format(#[from] s3armor_format::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<crate::proxy::error::S3Error> for ToolError {
    fn from(e: crate::proxy::error::S3Error) -> Self {
        Self::Backend(format!("{} ({})", e.message, e.code))
    }
}

/// Resolves a tool's `--backend` flag against the configured set: `name`
/// given picks it by name (case-insensitive — matches how `config.rs`
/// upper-cases every backend name at load); `name` absent works only when
/// exactly one backend is configured, since there is nothing else to guess
/// from on a CLI invocation with no client identity. Both failure messages
/// list every configured name, so a misconfigured `--backend` or a missing
/// one on a multi-backend deployment is a one-line fix, not a guess.
pub fn resolve_backend<'a>(
    config: &'a crate::config::Config,
    name: Option<&str>,
) -> Result<&'a crate::config::Backend, ToolError> {
    let known = || {
        config
            .backends
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    };
    let Some(n) = name else {
        // No --backend given: only unambiguous with exactly one backend
        // configured — checked via a two-element peek instead of `.len()`
        // + `.values().next().expect(...)`, so there is no panic path here
        // even in principle.
        let mut backends = config.backends.values();
        return match (backends.next(), backends.next()) {
            (Some(only), None) => Ok(only),
            _ => Err(ToolError::Backend(format!(
                "no --backend given and more than one is configured ({}) — pass --backend to choose one",
                known()
            ))),
        };
    };
    let upper = n.to_uppercase();
    config.backends.get(&upper).ok_or_else(|| {
        ToolError::Backend(format!(
            "unknown backend {upper} — known backends: {}",
            known()
        ))
    })
}

/// Append-only, one key per line — resumable: a killed run's already-done
/// keys are loaded back with [`load`](Checkpoint::load) so the next run
/// skips them instead of redoing the work.
pub struct Checkpoint {
    path: Option<std::path::PathBuf>,
    file: Option<std::fs::File>,
    done: std::collections::HashSet<String>,
}

impl Checkpoint {
    /// `None` path: an in-memory, non-persistent checkpoint (nothing to
    /// resume — every key runs).
    pub fn open(path: Option<&std::path::Path>) -> std::io::Result<Self> {
        let done = match path {
            Some(p) if p.exists() => std::fs::read_to_string(p)?
                .lines()
                .map(str::to_string)
                .collect(),
            _ => std::collections::HashSet::new(),
        };
        let file = match path {
            Some(p) => Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)?,
            ),
            None => None,
        };
        Ok(Self {
            path: path.map(std::path::Path::to_path_buf),
            file,
            done,
        })
    }

    pub fn is_done(&self, key: &str) -> bool {
        self.done.contains(key)
    }

    pub fn mark_done(&mut self, key: &str) -> std::io::Result<()> {
        use std::io::Write;
        self.done.insert(key.to_string());
        if let Some(f) = self.file.as_mut() {
            writeln!(f, "{key}")?;
            f.flush()?;
        }
        Ok(())
    }

    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }
}
