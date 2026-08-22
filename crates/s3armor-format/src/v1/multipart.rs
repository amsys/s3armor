//! Multipart object layout: mapping a footer's `(part number, plaintext
//! size)` list to byte offsets, and slicing a plaintext range across part
//! boundaries. See docs/ARCHITECTURE.md "Multipart v1".
//!
//! Pure layout math — no key material touches this module. The footer
//! itself is authenticated (`footer.rs`); this module only turns its
//! contents into offsets.

use super::frame::{ciphertext_len, plan_range, Alg, RangePlan};
use crate::{Error, Result};

/// One part's position inside the completed multipart object, in both the
/// plaintext and ciphertext coordinate spaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartSpan {
    /// The client's part number (may be non-contiguous).
    pub number: u32,
    pub pt_start: u64,
    pub pt_len: u64,
    pub ct_start: u64,
    pub ct_len: u64,
}

/// Lay out a multipart object's parts, in the order the footer lists them
/// (ascending part number), as cumulative plaintext/ciphertext spans.
pub fn part_layout(alg: Alg, chunk_size: u64, parts: &[(u32, u64)]) -> Vec<PartSpan> {
    let mut pt_off = 0u64;
    let mut ct_off = 0u64;
    parts
        .iter()
        .map(|&(number, pt_len)| {
            let ct_len = ciphertext_len(alg, pt_len, chunk_size);
            let span = PartSpan {
                number,
                pt_start: pt_off,
                pt_len,
                ct_start: ct_off,
                ct_len,
            };
            pt_off += pt_len;
            ct_off += ct_len;
            span
        })
        .collect()
}

/// Map a plaintext range `[start, end)` over the whole multipart object to
/// the parts it touches, each with its own [`RangePlan`] in that part's
/// local ciphertext coordinates. Mirrors [`plan_range`]'s own edge-case
/// rule: `start == end == total_pt` on a non-empty object names no chunk
/// and is an error (the HTTP layer should reject it as unsatisfiable
/// before calling this), but `start == end` anywhere else is a valid,
/// empty result — no parts touched, an empty `Vec`.
pub fn plan_multipart_range(
    spans: &[PartSpan],
    alg: Alg,
    chunk_size: u64,
    start: u64,
    end: u64,
) -> Result<Vec<(PartSpan, RangePlan)>> {
    let total_pt: u64 = spans.iter().map(|s| s.pt_len).sum();
    if start > end || end > total_pt || (start == total_pt && total_pt > 0) {
        return Err(Error::InvalidLength);
    }
    if start == end {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for &span in spans {
        let span_end = span.pt_start + span.pt_len;
        // Does [start, end) overlap this part's plaintext span?
        if end <= span.pt_start || start >= span_end {
            continue;
        }
        let local_start = start.saturating_sub(span.pt_start).min(span.pt_len);
        let local_end = (end - span.pt_start).min(span.pt_len);
        let plan = plan_range(alg, span.pt_len, chunk_size, local_start, local_end)?;
        out.push((span, plan));
    }
    Ok(out)
}
