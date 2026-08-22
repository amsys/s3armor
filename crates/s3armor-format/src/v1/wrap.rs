//! DEK wrap/unwrap and key ids for v1. See docs/ARCHITECTURE.md "Keys and wrap".

use crate::{Error, Result};
use aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 32-byte master key. The KEK and key id are both derived from it via
/// HKDF, never published directly — a raw `SHA-256(key)` fingerprint would
/// give an offline attacker something to guess against; this gives them
/// nothing.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[expect(
        clippy::expect_used,
        reason = "32 bytes is a valid HKDF-SHA256 output length; HKDF only fails above 255*32 bytes"
    )]
    fn kek(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut out = [0u8; 32];
        hk.expand(b"s3a/v1/kek", &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        out
    }

    /// 16 hex chars: `hex(HKDF-SHA256(master, info="s3a/v1/kid")[..8])`.
    #[expect(
        clippy::expect_used,
        reason = "32 bytes is a valid HKDF-SHA256 output length; HKDF only fails above 255*32 bytes"
    )]
    pub fn key_id(&self) -> String {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut out = [0u8; 32];
        hk.expand(b"s3a/v1/kid", &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        hex::encode(&out[..8])
    }

    /// Wrap a DEK: AES-256-GCM, random 12-byte nonce, `aad = "s3a1-kek" ‖
    /// key_id [‖ 0x00 ‖ binding]`. Returns `nonce ‖ ciphertext ‖ tag`.
    /// `binding` is `path_binding(bucket, key)` under `S3A_BIND_PATHS`, or
    /// empty to reproduce the pre-binding AAD byte-for-byte
    /// (`docs/ARCHITECTURE.md` "Path binding") — every object wrapped
    /// before this feature existed still unwraps under an empty binding.
    #[expect(
        clippy::expect_used,
        reason = "AEAD encrypt cannot fail for a valid key and nonce, only for an over-length plaintext far beyond a 32-byte DEK"
    )]
    pub fn wrap(&self, dek: &[u8; 32], binding: &[u8]) -> Vec<u8> {
        let mut kek = self.kek();
        let cipher = Aes256Gcm::new((&kek).into());
        kek.zeroize();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let aad = wrap_aad(&self.key_id(), binding);
        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: dek,
                    aad: &aad,
                },
            )
            .expect("AEAD encrypt cannot fail for a valid key and nonce");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        out
    }

    /// Unwrap a DEK sealed by [`wrap`](Self::wrap) with the same `binding`.
    /// A tampered wrap, or the wrong binding, fails loudly here instead of
    /// unwrapping to garbage.
    pub fn unwrap(&self, wrapped: &[u8], binding: &[u8]) -> Result<[u8; 32]> {
        const NONCE_LEN: usize = 12;
        if wrapped.len() < NONCE_LEN + super::frame::TAG_LEN {
            return Err(Error::UnwrapFailed);
        }
        let (nonce, ct) = wrapped.split_at(NONCE_LEN);
        let mut kek = self.kek();
        let cipher = Aes256Gcm::new((&kek).into());
        kek.zeroize();
        let aad = wrap_aad(&self.key_id(), binding);
        let pt = cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(nonce),
                Payload { msg: ct, aad: &aad },
            )
            .map_err(|_| Error::UnwrapFailed)?;
        pt.try_into().map_err(|_| Error::UnwrapFailed)
    }
}

/// `bucket ‖ 0x00 ‖ key` — the DEK-wrap (and RSA OAEP label) binding for
/// `S3A_BIND_PATHS` (`docs/ARCHITECTURE.md` "Path binding"). Byte slices, not `&str`: the
/// object key is whatever S3 actually stores it as, not necessarily valid
/// UTF-8. `key` must be the **percent-decoded** key — what the object is
/// actually named — so a client's choice of URL encoding can never change
/// the binding.
pub fn path_binding(bucket: &[u8], key: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(bucket.len() + 1 + key.len());
    b.extend_from_slice(bucket);
    b.push(0);
    b.extend_from_slice(key);
    b
}

fn wrap_aad(kid: &str, binding: &[u8]) -> Vec<u8> {
    let mut a = b"s3a1-kek".to_vec();
    a.extend_from_slice(kid.as_bytes());
    if !binding.is_empty() {
        a.push(0);
        a.extend_from_slice(binding);
    }
    a
}

/// A v1 RSA key-encryption-key. A write-only node holds only the public
/// half: it can wrap DEKs but [`unwrap`](Self::unwrap) always fails with
/// [`Error::KeyNotAvailable`] — a compromised ingestion node leaks nothing
/// at rest. See docs/ARCHITECTURE.md "Keys and wrap".
#[derive(Clone)]
pub struct RsaKek {
    private: Option<RsaPrivateKey>,
    public: RsaPublicKey,
}

impl RsaKek {
    pub fn from_private(key: RsaPrivateKey) -> Self {
        let public = RsaPublicKey::from(&key);
        Self {
            private: Some(key),
            public,
        }
    }

    pub const fn from_public(key: RsaPublicKey) -> Self {
        Self {
            private: None,
            public: key,
        }
    }

    /// Generates a fresh keypair — `openssl genpkey -algorithm RSA
    /// -pkeyopt rsa_keygen_bits:4096` is the operator-facing equivalent.
    /// 4096 bits, per docs/ARCHITECTURE.md "Keys and wrap" (a 512-byte
    /// wrapped DEK, ~684 base64 chars, comfortably inside the 2 KB
    /// user-metadata limit).
    pub fn generate(bits: usize) -> Result<Self> {
        let private = RsaPrivateKey::new(&mut OsRng, bits).map_err(|_| Error::UnwrapFailed)?;
        Ok(Self::from_private(private))
    }

    /// Parses a read/full node's private key: PKCS#8 PEM, the
    /// format `openssl genpkey` writes.
    pub fn from_private_pem(pem: &str) -> Result<Self> {
        let private = RsaPrivateKey::from_pkcs8_pem(pem.trim()).map_err(|_| Error::UnwrapFailed)?;
        Ok(Self::from_private(private))
    }

    /// Parses a write-only node's public key: SPKI PEM
    /// (`-----BEGIN PUBLIC KEY-----`).
    pub fn from_public_pem(pem: &str) -> Result<Self> {
        let public =
            RsaPublicKey::from_public_key_pem(pem.trim()).map_err(|_| Error::UnwrapFailed)?;
        Ok(Self::from_public(public))
    }

    /// PKCS#8 PEM of the private key — `None` on a write-only (public-only)
    /// node. Carries the same "the key is the data" weight as
    /// `MasterKey`'s base64 line; callers print the wallet warning
    /// alongside it.
    pub fn private_pem(&self) -> Result<Option<String>> {
        let Some(private) = &self.private else {
            return Ok(None);
        };
        let doc = private
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|_| Error::UnwrapFailed)?;
        Ok(Some(doc.to_string()))
    }

    /// SPKI PEM of the public key — always available, the snippet a
    /// write-only ingestion node is configured with.
    pub fn public_pem(&self) -> Result<String> {
        self.public
            .to_public_key_pem(LineEnding::LF)
            .map_err(|_| Error::UnwrapFailed)
    }

    /// `true` for a read/full node (holds the private key).
    pub const fn can_read(&self) -> bool {
        self.private.is_some()
    }

    /// `hex(SHA-256(SPKI DER)[..8])` — public material, so a hash is fine
    /// here (unlike the AES master key).
    #[expect(
        clippy::indexing_slicing,
        reason = "digest is a fixed 32-byte SHA-256 output; [..8] is always in bounds"
    )]
    pub fn key_id(&self) -> Result<String> {
        let der = self
            .public
            .to_public_key_der()
            .map_err(|_| Error::UnwrapFailed)?;
        let digest = Sha256::digest(der.as_bytes());
        Ok(hex::encode(&digest[..8]))
    }

    /// RSA-OAEP-SHA256. Nil label when `binding` is empty (today's
    /// default) — otherwise `hex(SHA-256(binding))` as the OAEP label,
    /// since a label must be valid text and the object key may not be
    /// (`docs/ARCHITECTURE.md` "Path binding"). A mismatched label fails
    /// OAEP decrypt cleanly, the same "wrong binding, wrong error" property
    /// the AES path gets from its AAD.
    pub fn wrap(&self, dek: &[u8; 32], binding: &[u8]) -> Result<Vec<u8>> {
        self.public
            .encrypt(&mut OsRng, oaep(binding), dek)
            .map_err(|_| Error::UnwrapFailed)
    }

    pub fn unwrap(&self, wrapped: &[u8], binding: &[u8]) -> Result<[u8; 32]> {
        let private = self.private.as_ref().ok_or(Error::KeyNotAvailable)?;
        let pt = private
            .decrypt(oaep(binding), wrapped)
            .map_err(|_| Error::UnwrapFailed)?;
        pt.try_into().map_err(|_| Error::UnwrapFailed)
    }
}

fn oaep(binding: &[u8]) -> Oaep {
    if binding.is_empty() {
        Oaep::new::<Sha256>()
    } else {
        let label = hex::encode(Sha256::digest(binding));
        Oaep::new_with_label::<Sha256, _>(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_empty_binding_round_trips() {
        let key = MasterKey::new([3u8; 32]);
        let dek = [9u8; 32];
        let wrapped = key.wrap(&dek, &[]);
        assert_eq!(key.unwrap(&wrapped, &[]).unwrap(), dek);
    }

    #[test]
    fn aes_bound_wrap_requires_the_same_binding_to_unwrap() {
        let key = MasterKey::new([3u8; 32]);
        let dek = [9u8; 32];
        let binding = path_binding(b"my-bucket", b"my/key.txt");
        let wrapped = key.wrap(&dek, &binding);
        assert_eq!(key.unwrap(&wrapped, &binding).unwrap(), dek);
        // Wrong binding, no binding at all, and a binding for a different
        // object all fail the same way a wrong key would (AEAD tag fails).
        assert!(key.unwrap(&wrapped, &[]).is_err());
        assert!(key
            .unwrap(&wrapped, &path_binding(b"my-bucket", b"other.txt"))
            .is_err());
    }

    #[test]
    fn path_binding_separates_bucket_from_key() {
        // Without the 0x00 separator, ("ab", "c") and ("a", "bc") would
        // collide — this is the property that separator exists to prevent.
        assert_ne!(path_binding(b"ab", b"c"), path_binding(b"a", b"bc"),);
    }

    #[test]
    fn rsa_empty_binding_round_trips() {
        let kek = RsaKek::generate(1024).unwrap(); // small bits: unit-test speed only
        let dek = [5u8; 32];
        let wrapped = kek.wrap(&dek, &[]).unwrap();
        assert_eq!(kek.unwrap(&wrapped, &[]).unwrap(), dek);
    }

    #[test]
    fn rsa_bound_wrap_requires_the_same_binding_to_unwrap() {
        let kek = RsaKek::generate(1024).unwrap();
        let dek = [5u8; 32];
        let binding = path_binding(b"my-bucket", b"my/key.txt");
        let wrapped = kek.wrap(&dek, &binding).unwrap();
        assert_eq!(kek.unwrap(&wrapped, &binding).unwrap(), dek);
        assert!(kek.unwrap(&wrapped, &[]).is_err());
    }
}
