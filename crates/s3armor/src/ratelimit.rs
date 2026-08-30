//! Auth-failure rate limiting: a token bucket per source IP, checked before
//! SigV4 verification runs. `docs/ARCHITECTURE.md` "S3 operation matrix (v1)" promised this
//! "implemented, or absent from config" — it was originally absent; this
//! makes it real.
//!
//! Deliberately **not** `X-Forwarded-For`-aware: there is no trusted-proxy
//! config, and honoring a client-settable header would make the limiter
//! both bypassable (spoof a fresh IP every request) and a self-inflicted
//! DoS vector (spoof a victim's IP to lock them out). Behind a reverse
//! proxy every client collapses to one IP — set `S3A_AUTH_FAIL_LIMIT=0`
//! there (`config.rs`'s field doc comment says the same).

use std::net::IpAddr;
use std::time::Instant;

use dashmap::DashMap;

/// Ceiling on tracked IPs. The check-then-insert is not atomic across
/// DashMap shards, so concurrent failures from new IPs can overshoot the cap
/// by at most the number of in-flight requests; the next arrival evicts back
/// down. That keeps memory and the per-call eviction scan bounded — the failure
/// the old "prune only full-and-idle buckets" logic had under a spray from
/// an IPv6 /64, where every bucket stays fresh and non-full and the prune
/// frees nothing while the map keeps growing.
///
/// ponytail: eviction is an O(MAX_TRACKED_IPS) scan on the triggering call
/// only (a new IP arriving at the cap). That is bounded, not unbounded; a
/// real LRU would make it O(1). Upgrade only if a benchmark shows the scan
/// matters under sustained abuse.
const MAX_TRACKED_IPS: usize = 100_000;
const IDLE_PRUNE_AFTER_SECS: u64 = 3600;

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// One token bucket per source IP. `capacity` = `S3A_AUTH_FAIL_LIMIT`;
/// refill rate = `capacity` per 60 seconds. `capacity == 0` disables the
/// limiter entirely (`allow` always returns `true`, `record_failure` is a
/// no-op) — the "absent from config" mode docs/ARCHITECTURE.md "S3 operation matrix (v1)" describes.
pub struct AuthRateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: DashMap<IpAddr, Bucket>,
}

impl AuthRateLimiter {
    pub fn new(limit_per_minute: u32) -> Self {
        Self {
            capacity: f64::from(limit_per_minute),
            refill_per_sec: f64::from(limit_per_minute) / 60.0,
            buckets: DashMap::new(),
        }
    }

    fn is_disabled(&self) -> bool {
        self.capacity <= 0.0
    }

    /// `true` if this IP has budget left to even *attempt* auth right now.
    /// Does not consume a token — only `record_failure` does, so a stream
    /// of successful requests from a busy client never gets throttled.
    pub fn allow(&self, ip: IpAddr) -> bool {
        if self.is_disabled() {
            return true;
        }
        // A whole token, not just a nonzero fraction: a bucket at exactly 0
        // refills by an infinitesimal amount the instant any time at all
        // elapses, which would let the very next request through
        // immediately after hitting the limit.
        self.buckets
            .get(&ip)
            .is_none_or(|b| self.refilled_tokens(&b) >= 1.0)
    }

    /// Charges one token for a failed SigV4 verification. Call only on the
    /// failure path — successful auth never touches the bucket.
    pub fn record_failure(&self, ip: IpAddr) {
        if self.is_disabled() {
            return;
        }
        let now = Instant::now();
        // Bound the map before adding a new source. Try the cheap idle prune
        // first; if it frees nothing (an attacker keeps every bucket fresh
        // and non-full), evict the least-recently-used entry so the size
        // stays at or below the hard cap.
        if !self.buckets.contains_key(&ip) && self.buckets.len() >= MAX_TRACKED_IPS {
            self.prune(now);
            if self.buckets.len() >= MAX_TRACKED_IPS {
                self.evict_oldest();
            }
        }
        {
            let mut entry = self.buckets.entry(ip).or_insert_with(|| Bucket {
                tokens: self.capacity,
                last: now,
            });
            let refilled = self.refilled_tokens(&entry);
            entry.tokens = (refilled - 1.0).max(0.0);
            entry.last = now;
        }
    }

    /// Removes the entry with the oldest `last` timestamp. Called only when a
    /// new IP arrives with the map already at the hard cap.
    fn evict_oldest(&self) {
        let oldest_key = self
            .buckets
            .iter()
            .min_by_key(|e| e.value().last)
            .map(|e| *e.key());
        if let Some(key) = oldest_key {
            self.buckets.remove(&key);
        }
    }

    fn refilled_tokens(&self, bucket: &Bucket) -> f64 {
        let elapsed = bucket.last.elapsed().as_secs_f64();
        elapsed
            .mul_add(self.refill_per_sec, bucket.tokens)
            .min(self.capacity)
    }

    #[expect(
        clippy::suspicious_operation_groupings,
        reason = "two independent conditions (fully refilled AND idle past threshold), not a copy-paste operand swap"
    )]
    fn prune(&self, now: Instant) {
        self.buckets.retain(|_, b| {
            let idle = now.duration_since(b.last).as_secs();
            !(b.tokens >= self.capacity && idle > IDLE_PRUNE_AFTER_SECS)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread::sleep;
    use std::time::Duration;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    #[test]
    fn allows_up_to_the_limit_then_blocks() {
        let rl = AuthRateLimiter::new(3);
        let addr = ip(1);
        for _ in 0..3 {
            assert!(rl.allow(addr));
            rl.record_failure(addr);
        }
        assert!(!rl.allow(addr));
    }

    #[test]
    fn disabled_when_limit_is_zero() {
        let rl = AuthRateLimiter::new(0);
        let addr = ip(2);
        for _ in 0..1000 {
            rl.record_failure(addr);
        }
        assert!(rl.allow(addr));
    }

    #[test]
    fn different_ips_are_independent() {
        let rl = AuthRateLimiter::new(1);
        rl.record_failure(ip(3));
        assert!(!rl.allow(ip(3)));
        assert!(rl.allow(ip(4)));
    }

    #[test]
    fn an_exhausted_bucket_allows_again_after_a_second_of_refill() {
        let rl = AuthRateLimiter::new(60); // 1 token/sec
        let addr = ip(5);
        rl.record_failure(addr);
        rl.record_failure(addr);
        // Two failures consumed most of the 60-token bucket; it did not
        // block yet (limit is 60, only 2 spent). Drive it to empty first.
        for _ in 0..58 {
            rl.record_failure(addr);
        }
        assert!(!rl.allow(addr));
        sleep(Duration::from_millis(1100));
        assert!(rl.allow(addr));
    }

    #[test]
    fn tracked_ip_count_stays_bounded_under_many_sources() {
        let rl = AuthRateLimiter::new(1);
        // More distinct source IPs than the hard cap: the map must not grow
        // past it (the IPv6-/64-spray failure mode).
        let count = u32::try_from(MAX_TRACKED_IPS + 20).unwrap();
        for n in 0..count {
            rl.record_failure(IpAddr::V4(Ipv4Addr::from(n)));
        }
        assert!(rl.buckets.len() <= MAX_TRACKED_IPS);
    }

    #[test]
    fn success_never_consumes_a_token() {
        let rl = AuthRateLimiter::new(1);
        let addr = ip(6);
        for _ in 0..1000 {
            assert!(rl.allow(addr));
        }
    }
}
