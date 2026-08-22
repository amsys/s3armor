//! `X-Amz-Date` (`YYYYMMDDTHHMMSSZ`) parsing and formatting, without a date
//! crate. SigV4 dates are a fixed-width ASCII format; the only non-trivial
//! part is civil calendar <-> days-since-epoch, which is Howard Hinnant's
//! well-known 15-line algorithm (`https://howardhinnant.github.io/date_algorithms.html`).
//! Ponytail: a date crate buys nothing here that ~30 tested lines don't.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Days since 1970-01-01 for a valid proleptic-Gregorian civil date.
///
/// Every division below is the algorithm's own arithmetic, not a truncated
/// approximation — see the module doc's reference for the derivation.
#[expect(
    clippy::integer_division,
    reason = "exact calendar arithmetic from Hinnant's algorithm, not truncation"
)]
fn days_from_civil(y: i64, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (i64::from(m) + 9) % 12; // [0, 11], Mar=0..Feb=11
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146_096]
    Some(era * 146_097 + doe - 719_468)
}

/// Inverse of [`days_from_civil`].
///
/// `d` and `m` cast to `u32` are bounded to `[1, 31]` and `[1, 12]` by the
/// algorithm's own invariants (see the range comments below), so the casts
/// never truncate, wrap, or lose sign.
#[expect(
    clippy::integer_division,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "exact calendar arithmetic from Hinnant's algorithm; d/m are proven in [1, 31]/[1, 12]"
)]
const fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146_096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Parses `YYYYMMDDTHHMMSSZ`. Returns `None` on any malformed input —
/// callers treat that the same as a missing timestamp.
#[expect(
    clippy::indexing_slicing,
    reason = "`b.len() != 16` short-circuits `||` before b[8]/b[15], proving both in range"
)]
pub fn parse_amz_date(s: &str) -> Option<SystemTime> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' || !b.iter().all(u8::is_ascii) {
        return None;
    }
    let digit_run = |r: std::ops::Range<usize>| -> Option<u32> { s.get(r)?.parse().ok() };
    let year = i64::from(digit_run(0..4)?);
    let month = digit_run(4..6)?;
    let day = digit_run(6..8)?;
    let hour = u64::from(digit_run(9..11)?);
    let min = u64::from(digit_run(11..13)?);
    let sec = u64::from(digit_run(13..15)?);
    if hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    if days < 0 {
        return None;
    }
    // `days >= 0` was just checked, so the sign-loss cast below is exact.
    #[expect(clippy::cast_sign_loss, reason = "days >= 0 was just checked above")]
    let secs = days as u64 * 86400 + hour * 3600 + min * 60 + sec;
    Some(UNIX_EPOCH + Duration::from_secs(secs))
}

/// The 8-digit date prefix of an `X-Amz-Date` value (`s[0..8]`), used to
/// compare against the credential scope's date without reparsing.
pub fn date8(amz_date: &str) -> &str {
    amz_date.get(0..8).unwrap_or("")
}

/// Formats `now` as `YYYYMMDDTHHMMSSZ` for outbound re-signing.
#[expect(
    clippy::integer_division,
    clippy::cast_possible_wrap,
    reason = "days-since-epoch fits i64 for any representable SystemTime; rem/3600 etc. are the intended clock-field split"
)]
pub fn format_amz_date(now: SystemTime) -> String {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Absolute skew between two `X-Amz-Date` timestamps, in seconds. Used for
/// the ±15 minute clock-skew check.
pub fn skew_seconds(now: SystemTime, then: SystemTime) -> u64 {
    now.duration_since(then)
        .unwrap_or_else(|_| then.duration_since(now).unwrap_or(Duration::ZERO))
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground truth: `date -u -d '2015-08-30T12:36:00Z' +%s` = 1440938160.
    #[test]
    fn parses_the_aws_worked_example_timestamp() {
        let t = parse_amz_date("20150830T123600Z").unwrap();
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            1_440_938_160
        );
    }

    #[test]
    fn date8_is_the_first_eight_chars() {
        assert_eq!(date8("20150830T123600Z"), "20150830");
    }

    #[test]
    fn format_and_parse_round_trip() {
        let t = UNIX_EPOCH + Duration::from_mins(24_015_636);
        let s = format_amz_date(t);
        assert_eq!(s, "20150830T123600Z");
        assert_eq!(parse_amz_date(&s).unwrap(), t);
    }

    #[test]
    fn epoch_round_trips() {
        let s = format_amz_date(UNIX_EPOCH);
        assert_eq!(s, "19700101T000000Z");
        assert_eq!(parse_amz_date(&s).unwrap(), UNIX_EPOCH);
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(parse_amz_date("not-a-date").is_none());
        assert!(parse_amz_date("20150830T123600").is_none()); // missing Z
        assert!(parse_amz_date("20150932T123600Z").is_none()); // bad day, caught by civil math bounds check via hour/min/sec only currently
    }
}
