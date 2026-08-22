//! Multipart footer: one extra final part carrying part sizes and the
//! total plaintext size, so HEAD and ranged GET never need a self-copy or
//! a size guess. See docs/ARCHITECTURE.md "Multipart v1".

use super::frame::{open_frame, seal_frame, Alg};
use crate::{Error, Result};

/// Reserved part number for the footer frame. Client multipart part
/// numbers are 1..=10000, so this never collides.
const FOOTER_PART_NUMBER: u32 = u32::MAX;

/// Fixed trailer appended after the footer frame: `magic(8) ‖ len(8)`.
pub const TRAILER_LEN: usize = 16;
const FOOTER_MAGIC: [u8; 8] = *b"S3A1FOOT";

/// The footer record: sizes needed to serve HEAD and ranged GET on a
/// multipart object without touching the client's parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Footer {
    pub alg: Alg,
    /// `(client part number, plaintext size)`, ascending by part number —
    /// the order the parts occupy in the completed object. Client part
    /// numbers need not be contiguous (1, 5, 9 is legal S3), so position
    /// alone cannot stand in for the number.
    pub parts: Vec<(u32, u64)>,
    pub total_pt: u64,
    /// AEAD(DEK, MD5(plaintext)), when the client sent a checksum. See
    /// docs/ARCHITECTURE.md "ETag policy".
    pub md5: Option<[u8; 16]>,
}

const RECORD_VERSION: u8 = 1;

impl Footer {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "S3 multipart caps a client to 10_000 parts, far below u32::MAX"
    )]
    fn encode_record(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(RECORD_VERSION);
        b.push(self.alg.id());
        b.extend_from_slice(&(self.parts.len() as u32).to_le_bytes());
        for (number, size) in &self.parts {
            b.extend_from_slice(&number.to_le_bytes());
            b.extend_from_slice(&size.to_le_bytes());
        }
        b.extend_from_slice(&self.total_pt.to_le_bytes());
        match self.md5 {
            Some(m) => {
                b.push(1);
                b.extend_from_slice(&m);
            }
            None => b.push(0),
        }
        b
    }

    fn decode_record(b: &[u8]) -> Result<Self> {
        let mut r = Cursor::new(b);
        let version = r.u8()?;
        if version != RECORD_VERSION {
            return Err(Error::UnknownVersion(version));
        }
        let alg = Alg::from_id(r.u8()?)?;
        let count = r.u32_le()? as usize;
        let mut parts = Vec::with_capacity(count.min(1 << 20));
        for _ in 0..count {
            let number = r.u32_le()?;
            let size = r.u64_le()?;
            parts.push((number, size));
        }
        let total_pt = r.u64_le()?;
        let md5 = match r.u8()? {
            0 => None,
            1 => Some(r.bytes16()?),
            _ => return Err(Error::InvalidFooter),
        };
        r.expect_empty()?;
        // Ascending, non-decreasing part numbers and a total that matches
        // the sum are both format invariants — an authenticated frame that
        // violates them is still corrupt, just not by a bit flip.
        #[expect(
            clippy::indexing_slicing,
            reason = "windows(2) guarantees w.len() == 2, so w[0]/w[1] are always in range"
        )]
        if parts.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err(Error::InvalidFooter);
        }
        let sum: u64 = parts.iter().map(|(_, size)| *size).sum();
        if sum != total_pt {
            return Err(Error::InvalidFooter);
        }
        Ok(Self {
            alg,
            parts,
            total_pt,
            md5,
        })
    }

    /// Seal the footer under `key` and append the 16-byte trailer. The
    /// result is the complete footer part body, ready to upload as the
    /// final multipart part.
    pub fn seal(&self, key: &[u8; 32]) -> Vec<u8> {
        let record = self.encode_record();
        let frame = seal_frame(self.alg, key, FOOTER_PART_NUMBER, 0, true, &record);
        let mut out = frame;
        let footer_len = out.len() as u64;
        out.extend_from_slice(&FOOTER_MAGIC);
        out.extend_from_slice(&footer_len.to_le_bytes());
        out
    }

    /// Parse the 16-byte trailer (the last 16 bytes of the footer part) and
    /// return the length of the sealed frame that precedes it.
    #[expect(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::unwrap_in_result,
        reason = "trailer.len() == TRAILER_LEN (16) was just checked, so both ranges and the try_into are always in bounds"
    )]
    pub fn parse_trailer(trailer: &[u8]) -> Result<u64> {
        if trailer.len() != TRAILER_LEN {
            return Err(Error::InvalidFooter);
        }
        if trailer[0..8] != FOOTER_MAGIC {
            return Err(Error::InvalidFooter);
        }
        Ok(u64::from_le_bytes(trailer[8..16].try_into().unwrap()))
    }

    /// Verify and decode a footer from its sealed frame bytes (everything
    /// before the trailer — see [`parse_trailer`](Self::parse_trailer)).
    pub fn open(alg: Alg, key: &[u8; 32], frame: &[u8]) -> Result<Self> {
        let record = open_frame(alg, key, FOOTER_PART_NUMBER, 0, true, frame)?;
        Self::decode_record(&record)
    }
}

// Tiny cursor so the footer's fixed-layout decode reads top-to-bottom
// without repeating bounds checks at every field.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "the length check above guarantees pos..pos+n is in bounds"
    )]
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < self.pos + n {
            return Err(Error::InvalidFooter);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "take(1) always returns exactly 1 byte"
    )]
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    #[expect(
        clippy::unwrap_used,
        clippy::unwrap_in_result,
        reason = "take(4) always returns exactly 4 bytes, so try_into::<[u8; 4]> cannot fail"
    )]
    fn u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    #[expect(
        clippy::unwrap_used,
        clippy::unwrap_in_result,
        reason = "take(8) always returns exactly 8 bytes, so try_into::<[u8; 8]> cannot fail"
    )]
    fn u64_le(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    #[expect(
        clippy::unwrap_used,
        clippy::unwrap_in_result,
        reason = "take(16) always returns exactly 16 bytes, so try_into::<[u8; 16]> cannot fail"
    )]
    fn bytes16(&mut self) -> Result<[u8; 16]> {
        Ok(self.take(16)?.try_into().unwrap())
    }

    const fn expect_empty(&self) -> Result<()> {
        if self.pos != self.buf.len() {
            return Err(Error::InvalidFooter);
        }
        Ok(())
    }
}
