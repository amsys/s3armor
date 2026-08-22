//! Pure v1 framing codec for s3armor.
//!
//! No tokio, no http. This crate is the fuzzable, benchable, auditable
//! crypto surface — see AGENTS.md and docs/ARCHITECTURE.md "Cryptographic
//! design (format v1)".

pub mod v1;

/// All errors this crate can produce.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("truncated input: need at least {need} bytes, got {got}")]
    Truncated { need: usize, got: usize },

    #[error("authentication failed")]
    AuthFailed,

    #[error("invalid frame or ciphertext length")]
    InvalidLength,

    #[error("unknown format version: {0}")]
    UnknownVersion(u8),

    #[error("unknown algorithm id: {0}")]
    UnknownAlg(u8),

    #[error("missing metadata key: {0}")]
    MissingMetadata(&'static str),

    #[error("invalid metadata value for {key}: {value}")]
    InvalidMetadata { key: &'static str, value: String },

    #[error("footer trailer not found or corrupt")]
    InvalidFooter,

    #[error("key unwrap failed")]
    UnwrapFailed,

    #[error("key not available for this operation")]
    KeyNotAvailable,
}

pub type Result<T> = core::result::Result<T, Error>;
