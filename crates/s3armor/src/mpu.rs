//! Multipart-upload session state: one entry per `(bucket, key, upload id)`,
//! RAM only, single instance (`docs/ARCHITECTURE.md` "Multipart v1",
//! "Multipart sessions are RAM, single instance"). TTL is measured from
//! last activity, not creation — a TTL from creation would kill a slow
//! upload mid-flight. An actually-spawned sweeper reaps expired sessions,
//! and also aborts the corresponding upload on the backend — a sweeper
//! that never runs, or that reaps local state without telling the
//! backend, leaves parts billed forever.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use http::StatusCode;
use zeroize::Zeroize;

use s3armor_format::v1::Alg;

/// A part this node has recorded: the plaintext size it encrypted (needed
/// for the footer) and the backend ETag it returned — checked against the
/// client's part list at Complete, not just recorded and trusted
/// (`docs/ARCHITECTURE.md` "Multipart v1").
#[derive(Debug, Clone)]
pub struct PartRecord {
    pub pt_len: u64,
    pub etag: String,
}

/// The response `Complete` returned, cached so a retried Complete (real
/// SDKs retry it on a timeout) returns the same answer instead of
/// `NoSuchUpload` — deleting the session at Complete would break exactly
/// this retry (`docs/ARCHITECTURE.md` "Multipart v1").
#[derive(Debug, Clone)]
pub struct CachedComplete {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// Total buffered ciphertext a session's `tails` may hold before the lowest
/// part number gets evicted — three sub-5-MiB parts' worth. Bounds the RAM a
/// client can force this node to hold for one upload; a Complete whose last
/// part fell out of the cap fails loudly (`S3Error::invalid_part`) rather
/// than silently mis-merging.
pub const MAX_TAIL_BYTES: usize = 3 * 5 * 1024 * 1024;

pub struct Session {
    pub dek: [u8; 32],
    pub alg: Alg,
    pub chunk_size: u32,
    pub parts: BTreeMap<u32, PartRecord>,
    /// Every currently-uploaded part's ciphertext that is still under S3's 5
    /// MiB non-final-part minimum, keyed by part number — any of these could
    /// turn out to be the client's real last part at Complete, so each is
    /// merged with the footer instead of costing an extra, otherwise-too-small
    /// part. A part number leaving this map (re-uploaded at >= 5 MiB) is
    /// removed; the total stays under `MAX_TAIL_BYTES` by evicting the lowest
    /// part number first — the part a Complete finishes with is almost always
    /// the highest.
    pub tails: BTreeMap<u32, Bytes>,
    pub last_activity: Instant,
    pub completed: Option<CachedComplete>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.dek.zeroize();
    }
}

impl Session {
    pub fn new(dek: [u8; 32], alg: Alg, chunk_size: u32) -> Self {
        Self {
            dek,
            alg,
            chunk_size,
            parts: BTreeMap::new(),
            tails: BTreeMap::new(),
            last_activity: Instant::now(),
            completed: None,
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Buffers `ct` under `part_number`, then evicts the lowest-numbered
    /// buffered part while the total exceeds `MAX_TAIL_BYTES`.
    pub fn buffer_tail(&mut self, part_number: u32, ct: Bytes) {
        self.tails.insert(part_number, ct);
        while self.tails.values().map(Bytes::len).sum::<usize>() > MAX_TAIL_BYTES {
            let Some(&lowest) = self.tails.keys().next() else {
                break;
            };
            self.tails.remove(&lowest);
        }
    }

    fn expired(&self, ttl: Duration) -> bool {
        self.last_activity.elapsed() > ttl
    }
}

/// `(backend name, bucket, key, upload id)` — a session is scoped to all
/// four, so two different objects, or two overlapping uploads to the same
/// key, never share state. The backend name travels in the key itself
/// (not just as a call parameter) because `spawn_mpu_sweeper_with_tick`
/// aborts an expired session's backend upload minutes after the request
/// that created it is gone — there is no other context left to read it
/// from at that point (`proxy::abort_expired_upload`).
pub type SessionKey = (String, String, String, String);

#[derive(Default)]
pub struct Sessions(DashMap<SessionKey, Session>);

impl Sessions {
    pub fn new() -> Self {
        Self(DashMap::new())
    }

    pub fn create(&self, key: SessionKey, dek: [u8; 32], alg: Alg, chunk_size: u32) {
        self.0.insert(key, Session::new(dek, alg, chunk_size));
    }

    pub fn get(
        &self,
        key: &SessionKey,
    ) -> Option<dashmap::mapref::one::Ref<'_, SessionKey, Session>> {
        self.0.get(key)
    }

    pub fn get_mut(
        &self,
        key: &SessionKey,
    ) -> Option<dashmap::mapref::one::RefMut<'_, SessionKey, Session>> {
        self.0.get_mut(key)
    }

    pub fn remove(&self, key: &SessionKey) {
        self.0.remove(key);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Removes every session whose `last_activity` is older than `ttl`,
    /// returning each removed session's key and whether it had already
    /// completed. `ProxyState::spawn_mpu_sweeper` (`proxy/mod.rs`) is the
    /// actual sweeper loop — it calls this on a tick and, for every
    /// returned session that is *not* completed, aborts the corresponding
    /// backend multipart upload. `Sessions` itself stays networking-free
    /// (it has no way to reach the backend), so that abort step lives one
    /// layer up; this method's only job is the RAM bookkeeping.
    pub fn take_expired(&self, ttl: Duration) -> Vec<(SessionKey, bool)> {
        let expired: Vec<SessionKey> = self
            .0
            .iter()
            .filter(|entry| entry.value().expired(ttl))
            .map(|entry| entry.key().clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|key| {
                self.0
                    .remove(&key)
                    .map(|(_, session)| (key, session.completed.is_some()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ct(len: usize) -> Bytes {
        Bytes::from(vec![0u8; len])
    }

    #[test]
    fn buffer_tail_keeps_every_part_under_the_cap() {
        let mut s = Session::new([0u8; 32], Alg::Aes256Gcm, 1024);
        s.buffer_tail(2, ct(1024));
        s.buffer_tail(3, ct(1024));
        assert_eq!(s.tails.keys().copied().collect::<Vec<_>>(), vec![2, 3]);
    }

    #[test]
    fn buffer_tail_evicts_the_lowest_part_number_over_the_cap() {
        let mut s = Session::new([0u8; 32], Alg::Aes256Gcm, 1024);
        s.buffer_tail(1, ct(MAX_TAIL_BYTES));
        s.buffer_tail(2, ct(1));
        // Part 1 alone already fills the cap; adding part 2 must evict the
        // lowest (part 1), not the one just inserted.
        assert_eq!(s.tails.keys().copied().collect::<Vec<_>>(), vec![2]);
    }

    #[test]
    fn a_removed_session_is_no_longer_retrievable() {
        let sessions = Sessions::new();
        let key = (
            "DEFAULT".to_string(),
            "b".to_string(),
            "k".to_string(),
            "u1".to_string(),
        );
        sessions.create(key.clone(), [0x11; 32], Alg::Aes256Gcm, 1024);
        assert_eq!(sessions.len(), 1);
        assert!(sessions.get(&key).is_some());
        sessions.remove(&key);
        assert!(sessions.get(&key).is_none());
        assert_eq!(sessions.len(), 0);
    }

    #[test]
    fn expiry_is_from_last_activity_not_creation() {
        let mut s = Session::new([0x22; 32], Alg::Aes256Gcm, 1024);
        assert!(!s.expired(Duration::from_hours(1)));
        s.last_activity = Instant::now().checked_sub(Duration::from_hours(2)).unwrap();
        assert!(s.expired(Duration::from_hours(1)));
        s.touch();
        assert!(!s.expired(Duration::from_hours(1)));
    }

    /// `take_expired` reports whether each reaped session had completed —
    /// `ProxyState::spawn_mpu_sweeper_with_tick` uses that to skip aborting
    /// the backend upload for sessions that finished normally.
    #[test]
    fn take_expired_reports_completion_and_removes_only_expired_sessions() {
        let sessions = Sessions::new();
        let fresh = (
            "DEFAULT".to_string(),
            "b".to_string(),
            "fresh".to_string(),
            "u1".to_string(),
        );
        let stale_incomplete = (
            "DEFAULT".to_string(),
            "b".to_string(),
            "stale-open".to_string(),
            "u2".to_string(),
        );
        let stale_completed = (
            "DEFAULT".to_string(),
            "b".to_string(),
            "stale-done".to_string(),
            "u3".to_string(),
        );

        sessions.create(fresh.clone(), [0x01; 32], Alg::Aes256Gcm, 1024);
        sessions.create(stale_incomplete.clone(), [0x02; 32], Alg::Aes256Gcm, 1024);
        sessions.create(stale_completed.clone(), [0x03; 32], Alg::Aes256Gcm, 1024);

        let old = Instant::now().checked_sub(Duration::from_hours(2)).unwrap();
        sessions.get_mut(&stale_incomplete).unwrap().last_activity = old;
        {
            let mut entry = sessions.get_mut(&stale_completed).unwrap();
            entry.last_activity = old;
            entry.completed = Some(CachedComplete {
                status: StatusCode::OK,
                headers: Vec::new(),
                body: Bytes::new(),
            });
        }

        let ttl = Duration::from_hours(1);
        let mut expired = sessions.take_expired(ttl);
        expired.sort_by(|a, b| a.0 .2.cmp(&b.0 .2));

        assert_eq!(
            expired,
            vec![(stale_completed, true), (stale_incomplete, false)]
        );
        assert_eq!(sessions.len(), 1, "only the fresh session survives");
        assert!(sessions.get(&fresh).is_some());
    }
}
