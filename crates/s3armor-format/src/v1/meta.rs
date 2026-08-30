//! v1 object metadata: the `x-amz-meta-s3a-*` keys. See docs/ARCHITECTURE.md "Object metadata v1".

use super::frame::{open_frame, seal_frame, Alg};
use crate::{Error, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::collections::BTreeMap;

pub const KEY_VERSION: &str = "s3a-v";
pub const KEY_ALG: &str = "s3a-alg";
pub const KEY_KEK: &str = "s3a-kek";
pub const KEY_KID: &str = "s3a-kid";
pub const KEY_DEK: &str = "s3a-dek";
pub const KEY_CHUNK: &str = "s3a-chunk";
pub const KEY_MP: &str = "s3a-mp";
pub const KEY_EMD5: &str = "s3a-emd5";

/// `s3a-chunk` / `S3A_CHUNK_SIZE` bounds, docs/ARCHITECTURE.md "Data:
/// chunked AEAD": 64 KiB .. 8 MiB. Shared by `from_map` (an object's stored
/// chunk size must fall in this range, same as a freshly configured one) and
/// `s3armor::config` (the write-side check on `S3A_CHUNK_SIZE`).
pub const MIN_CHUNK_SIZE: u32 = 65_536;
pub const MAX_CHUNK_SIZE: u32 = 8_388_608;

/// v1 key-encryption-key kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kek {
    Aes,
    Rsa,
}

impl Kek {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Aes => "aes",
            Self::Rsa => "rsa",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "aes" => Ok(Self::Aes),
            "rsa" => Ok(Self::Rsa),
            other => Err(Error::InvalidMetadata {
                key: KEY_KEK,
                value: other.to_string(),
            }),
        }
    }
}

/// The full set of v1 object metadata. Round-trips through
/// [`to_map`](Self::to_map) / [`from_map`](Self::from_map) — the map is
/// what actually sits on the S3 object as user metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    pub alg: Alg,
    pub kek: Kek,
    /// 16 hex chars.
    pub kid: String,
    /// Opaque wrapped-DEK bytes; see `wrap.rs` for the encoding per `kek`.
    pub wrapped_dek: Vec<u8>,
    pub chunk_size: u32,
    /// `true` only for multipart objects (a footer part exists).
    pub multipart: bool,
    /// AEAD(DEK, MD5(plaintext)), when present. See docs/ARCHITECTURE.md "ETag policy".
    pub emd5: Option<Vec<u8>>,
}

// The `s3a-emd5` payload (AEAD(DEK, MD5(plaintext)), docs/ARCHITECTURE.md "ETag policy") is
// sealed as its own reserved frame, not a data chunk: `part_number =
// u32::MAX` matches the footer's reserved part (`footer.rs`'s
// `FOOTER_PART_NUMBER`), but `chunk_index = 1` keeps it from colliding with
// the footer frame itself (`chunk_index = 0`) if both ever sit under the
// same DEK.
const EMD5_PART_NUMBER: u32 = u32::MAX;
const EMD5_CHUNK_INDEX: u64 = 1;

/// Seal the plaintext MD5 for `s3a-emd5`: `AEAD(DEK, MD5(plaintext))`.
pub fn seal_emd5(alg: Alg, key: &[u8; 32], md5: &[u8; 16]) -> Vec<u8> {
    seal_frame(alg, key, EMD5_PART_NUMBER, EMD5_CHUNK_INDEX, true, md5)
}

/// Verify and open a value sealed by [`seal_emd5`]. Fails closed like every
/// other frame in this format: a tampered `s3a-emd5` never yields bytes.
pub fn open_emd5(alg: Alg, key: &[u8; 32], sealed: &[u8]) -> Result<[u8; 16]> {
    let pt = open_frame(alg, key, EMD5_PART_NUMBER, EMD5_CHUNK_INDEX, true, sealed)?;
    pt.try_into().map_err(|_| Error::InvalidMetadata {
        key: KEY_EMD5,
        value: "wrong length after decrypt".to_string(),
    })
}

fn get<'a>(m: &'a BTreeMap<String, String>, key: &'static str) -> Result<&'a str> {
    m.get(key)
        .map(String::as_str)
        .ok_or(Error::MissingMetadata(key))
}

fn invalid(key: &'static str, value: &str) -> Error {
    Error::InvalidMetadata {
        key,
        value: value.to_string(),
    }
}

impl ObjectMeta {
    pub fn to_map(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(KEY_VERSION.into(), "1".into());
        m.insert(KEY_ALG.into(), self.alg.id().to_string());
        m.insert(KEY_KEK.into(), self.kek.as_str().into());
        m.insert(KEY_KID.into(), self.kid.clone());
        m.insert(KEY_DEK.into(), B64.encode(&self.wrapped_dek));
        m.insert(KEY_CHUNK.into(), self.chunk_size.to_string());
        if self.multipart {
            m.insert(KEY_MP.into(), "1".into());
        }
        if let Some(e) = &self.emd5 {
            m.insert(KEY_EMD5.into(), B64.encode(e));
        }
        m
    }

    pub fn from_map(m: &BTreeMap<String, String>) -> Result<Self> {
        let version = get(m, KEY_VERSION)?;
        if version != "1" {
            let v: u8 = version.parse().unwrap_or(0);
            return Err(Error::UnknownVersion(v));
        }
        let alg_str = get(m, KEY_ALG)?;
        let alg_id: u8 = alg_str.parse().map_err(|_| invalid(KEY_ALG, alg_str))?;
        let alg = Alg::from_id(alg_id)?;
        let kek = Kek::parse(get(m, KEY_KEK)?)?;
        let kid = get(m, KEY_KID)?.to_string();
        let dek_str = get(m, KEY_DEK)?;
        // Do not echo the value: the wrapped DEK reaches the client XML
        // error body through Error's Display. A fixed description is enough.
        let wrapped_dek = B64
            .decode(dek_str)
            .map_err(|_| invalid(KEY_DEK, "not valid base64"))?;
        let chunk_str = get(m, KEY_CHUNK)?;
        let chunk_size: u32 = chunk_str
            .parse()
            .ok()
            .filter(|n| (MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(n))
            .ok_or_else(|| invalid(KEY_CHUNK, chunk_str))?;
        let multipart = m.get(KEY_MP).is_some_and(|s| s == "1");
        let emd5 = match m.get(KEY_EMD5) {
            Some(s) => Some(
                B64.decode(s)
                    .map_err(|_| invalid(KEY_EMD5, "not valid base64"))?,
            ),
            None => None,
        };
        Ok(Self {
            alg,
            kek,
            kid,
            wrapped_dek,
            chunk_size,
            multipart,
            emd5,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ObjectMeta {
        ObjectMeta {
            alg: Alg::Aes256Gcm,
            kek: Kek::Aes,
            kid: "0123456789abcdef".to_string(),
            wrapped_dek: vec![1, 2, 3, 4],
            chunk_size: 1_048_576,
            multipart: false,
            emd5: None,
        }
    }

    #[test]
    fn meta_round_trips() {
        let meta = sample();
        assert_eq!(ObjectMeta::from_map(&meta.to_map()).unwrap(), meta);
    }

    #[test]
    fn meta_round_trips_with_multipart_and_emd5() {
        let meta = ObjectMeta {
            multipart: true,
            emd5: Some(vec![9; 16]),
            ..sample()
        };
        assert_eq!(ObjectMeta::from_map(&meta.to_map()).unwrap(), meta);
    }

    #[test]
    fn chunk_size_zero_is_rejected() {
        let mut m = sample().to_map();
        m.insert(KEY_CHUNK.into(), "0".into());
        let err = ObjectMeta::from_map(&m).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidMetadata {
                key: KEY_CHUNK,
                value: "0".to_string()
            }
        );
    }

    #[test]
    fn chunk_size_below_min_is_rejected() {
        let mut m = sample().to_map();
        m.insert(KEY_CHUNK.into(), (MIN_CHUNK_SIZE - 1).to_string());
        assert!(ObjectMeta::from_map(&m).is_err());
    }

    #[test]
    fn chunk_size_above_max_is_rejected() {
        let mut m = sample().to_map();
        m.insert(KEY_CHUNK.into(), u32::MAX.to_string());
        let err = ObjectMeta::from_map(&m).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidMetadata {
                key: KEY_CHUNK,
                value: u32::MAX.to_string()
            }
        );
    }

    #[test]
    fn chunk_size_at_bounds_is_accepted() {
        let mut m = sample().to_map();
        m.insert(KEY_CHUNK.into(), MIN_CHUNK_SIZE.to_string());
        assert!(ObjectMeta::from_map(&m).is_ok());
        m.insert(KEY_CHUNK.into(), MAX_CHUNK_SIZE.to_string());
        assert!(ObjectMeta::from_map(&m).is_ok());
    }
}
