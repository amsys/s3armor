//! s3armor — client-side S3 encryption proxy and tooling.
//!
//! Library target so integration tests (`tests/`) can exercise internal
//! modules (`sigv4`, `config`, …) directly; `main.rs` is a thin CLI shell
//! around this crate.

pub mod chunked;
pub mod config;
pub mod intercept;
pub mod keys;
pub mod mpu;
pub mod proxy;
pub mod ratelimit;
pub mod sigv4;
pub mod tls;
pub mod tools;
