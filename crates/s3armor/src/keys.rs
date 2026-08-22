//! Keyring: key id -> master key, and which one new writes use. See
//! `docs/ARCHITECTURE.md` "Key handling". AES keys are indexed by kid, plus one optional
//! RSA keypair (the write-only ingestion node, docs/ARCHITECTURE.md "Keys and wrap") —
//! `S3A_KEY_ACTIVE=RSA` is the reserved name that selects it for writes.

use std::collections::BTreeMap;

use s3armor_format::v1::{Kek, MasterKey, RsaKek};
use s3armor_format::{Error, Result};

/// The reserved `S3A_KEY_ACTIVE` name that selects the RSA keypair for
/// writes, instead of one of the `S3A_KEY_<NAME>` AES entries.
pub const RSA_ACTIVE_NAME: &str = "RSA";

/// A node's read/write posture, printed by `s3armor config` (docs/ARCHITECTURE.md
/// "Write-only (RSA) nodes cannot serve GETs") so a misrouted cluster is diagnosable in one line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Can decrypt every key it holds (every AES key is always both; the
    /// active key, AES or RSA, can also encrypt).
    ReadWrite,
    /// Active key is RSA and only the public half is configured — can wrap
    /// DEKs but never unwrap them.
    WriteOnly,
}

/// Indexed by key id (`MasterKey::key_id()` / `RsaKek::key_id()`, derived
/// from the key material itself), not by the operator's `S3A_KEY_<NAME>`
/// env name — decrypt routing looks objects up by the `s3a-kid` they were
/// written with. `Debug` prints key ids only, never key material
/// (docs/ARCHITECTURE.md "Zeroization").
#[derive(Clone)]
pub struct Keyring {
    active_kid: String,
    active_is_rsa: bool,
    by_kid: BTreeMap<String, MasterKey>,
    rsa: Option<RsaKek>,
}

impl Keyring {
    /// Builds the keyring from `{env name -> master key}`, an optional RSA
    /// keypair, and the name `S3A_KEY_ACTIVE` pointed at
    /// ([`RSA_ACTIVE_NAME`] selects `rsa`). Returns `None` when
    /// `active_name` names neither a loaded AES key nor a configured RSA
    /// keypair — the caller turns that into a startup config error.
    pub fn new(
        active_name: &str,
        named: BTreeMap<String, MasterKey>,
        rsa: Option<RsaKek>,
    ) -> Option<Self> {
        let (active_kid, active_is_rsa) = if active_name == RSA_ACTIVE_NAME {
            let kid = rsa.as_ref()?.key_id().ok()?;
            (kid, true)
        } else {
            (named.get(active_name).map(MasterKey::key_id)?, false)
        };
        let by_kid = named.into_values().map(|k| (k.key_id(), k)).collect();
        Some(Self {
            active_kid,
            active_is_rsa,
            by_kid,
            rsa,
        })
    }

    pub fn active_kid(&self) -> &str {
        &self.active_kid
    }

    /// This node's read/write posture (docs/ARCHITECTURE.md "Write-only (RSA) nodes cannot serve GETs").
    pub fn capability(&self) -> Capability {
        if self.active_is_rsa && self.rsa.as_ref().is_some_and(|r| !r.can_read()) {
            Capability::WriteOnly
        } else {
            Capability::ReadWrite
        }
    }

    /// Wraps a fresh DEK under the active key for a new write. Returns the
    /// `(kek kind, key id, wrapped bytes)` triple that goes straight into
    /// `ObjectMeta`. Every PUT/multipart-create/rewrap call site
    /// uses this instead of matching on `Kek` itself. `binding` is
    /// `S3A_BIND_PATHS`'s `path_binding(bucket, key)`, or empty when the
    /// feature is off (`docs/ARCHITECTURE.md` "Path binding") — the caller decides which,
    /// this method just carries it through to the format layer.
    #[expect(
        clippy::expect_used,
        reason = "both invariants are enforced by new() and active_is_rsa's own definition, see messages"
    )]
    pub fn wrap_active(&self, dek: &[u8; 32], binding: &[u8]) -> Result<(Kek, String, Vec<u8>)> {
        if self.active_is_rsa {
            let rsa = self
                .rsa
                .as_ref()
                .expect("active_is_rsa implies rsa is Some");
            let wrapped = rsa.wrap(dek, binding)?;
            Ok((Kek::Rsa, self.active_kid.clone(), wrapped))
        } else {
            let key = self
                .by_kid
                .get(&self.active_kid)
                .expect("active_kid is always inserted into by_kid in new()");
            Ok((Kek::Aes, self.active_kid.clone(), key.wrap(dek, binding)))
        }
    }

    /// Unwraps a DEK previously wrapped by `wrap_active` with the same
    /// `binding` (this node's or another rotated-in-or-out key sharing the
    /// same kek kind + kid). `KeyNotAvailable` covers both "no such kid"
    /// and "RSA public-only node, no private key to unwrap with"; a wrong
    /// `binding` fails the same way `unwrap_active`'s caller treats a wrong
    /// key — see `intercept::resolve_key` for `S3A_BIND_PATHS=on`'s
    /// bound-then-unbound retry, which lives one level up because it needs
    /// to try two different `binding` values, not two different keys.
    pub fn unwrap(&self, kek: Kek, kid: &str, wrapped: &[u8], binding: &[u8]) -> Result<[u8; 32]> {
        match kek {
            Kek::Aes => {
                let key = self.by_kid.get(kid).ok_or(Error::KeyNotAvailable)?;
                key.unwrap(wrapped, binding)
            }
            Kek::Rsa => {
                let rsa = self.rsa.as_ref().ok_or(Error::KeyNotAvailable)?;
                if rsa.key_id()?.as_str() != kid {
                    return Err(Error::KeyNotAvailable);
                }
                rsa.unwrap(wrapped, binding)
            }
        }
    }
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("active_kid", &self.active_kid)
            .field("active_is_rsa", &self.active_is_rsa)
            .field("kids", &self.by_kid.keys().collect::<Vec<_>>())
            .field("rsa_configured", &self.rsa.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> MasterKey {
        MasterKey::new([byte; 32])
    }

    #[test]
    fn active_resolves_by_name_then_indexes_by_kid() {
        let mut named = BTreeMap::new();
        named.insert("K1".to_string(), key(1));
        named.insert("K2".to_string(), key(2));
        let ring = Keyring::new("K1", named, None).unwrap();
        assert_eq!(ring.active_kid(), key(1).key_id());
        assert_eq!(ring.capability(), Capability::ReadWrite);
    }

    #[test]
    fn unknown_active_name_is_none() {
        let mut named = BTreeMap::new();
        named.insert("K1".to_string(), key(1));
        assert!(Keyring::new("NOPE", named, None).is_none());
    }

    #[test]
    fn wrap_and_unwrap_round_trip_through_active_aes_key() {
        let mut named = BTreeMap::new();
        named.insert("K1".to_string(), key(1));
        let ring = Keyring::new("K1", named, None).unwrap();
        let dek = [7u8; 32];
        let (kek, kid, wrapped) = ring.wrap_active(&dek, &[]).unwrap();
        assert_eq!(kek, Kek::Aes);
        assert_eq!(ring.unwrap(kek, &kid, &wrapped, &[]).unwrap(), dek);
    }

    #[test]
    fn rsa_active_name_selects_rsa_keypair() {
        let rsa = RsaKek::generate(1024).unwrap(); // small bits: unit-test speed only
        let ring = Keyring::new(RSA_ACTIVE_NAME, BTreeMap::new(), Some(rsa)).unwrap();
        assert_eq!(ring.capability(), Capability::ReadWrite);
        let dek = [9u8; 32];
        let (kek, kid, wrapped) = ring.wrap_active(&dek, &[]).unwrap();
        assert_eq!(kek, Kek::Rsa);
        assert_eq!(ring.unwrap(kek, &kid, &wrapped, &[]).unwrap(), dek);
    }

    #[test]
    fn rsa_public_only_node_is_write_only() {
        let rsa = RsaKek::generate(1024).unwrap();
        let public_pem = rsa.public_pem().unwrap();
        let public_only = RsaKek::from_public_pem(&public_pem).unwrap();
        let ring = Keyring::new(RSA_ACTIVE_NAME, BTreeMap::new(), Some(public_only)).unwrap();
        assert_eq!(ring.capability(), Capability::WriteOnly);
        let dek = [1u8; 32];
        let (kek, kid, wrapped) = ring.wrap_active(&dek, &[]).unwrap();
        assert!(ring.unwrap(kek, &kid, &wrapped, &[]).is_err());
    }

    #[test]
    fn rsa_active_name_with_no_rsa_configured_is_none() {
        assert!(Keyring::new(RSA_ACTIVE_NAME, BTreeMap::new(), None).is_none());
    }
}
