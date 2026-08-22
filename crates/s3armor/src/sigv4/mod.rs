//! SigV4: one canonicalizer (`canonical`), inbound verification (`verify`),
//! outbound re-signing (`sign`). See `canonical.rs` for why this module
//! exists as one implementation instead of two.

pub mod canonical;
pub mod sign;
pub mod time;
pub mod verify;
