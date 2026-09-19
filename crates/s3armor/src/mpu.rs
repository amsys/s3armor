//! Multipart-upload session state: one entry per `(bucket, key, upload id)`,
//! RAM only, single instance (`docs/ARCHITECTURE.md` "Multipart v1",
//! "Multipart sessions are RAM, single instance"). TTL is measured from
//! last activity, not creation — a TTL from creation would kill a slow
//! upload mid-flight. An actually-spawned sweeper reaps expired sessions,
//! and also aborts the corresponding upload on the backend — a sweeper
//! that never runs, or that reaps local state without telling the
//! backend, leaves parts billed forever.
//!
//! `Session::finish` runs at a successful Complete, ahead of the sweeper
//! and any TTL. It zeroizes the DEK and clears the parts and tails, so a
//! finished session holds only its cached response. `Sessions::make_room`
//! evicts the oldest such finished session when a new upload arrives at
//! `MAX_SESSIONS`, so a burst of completions does not block new uploads
//! for the rest of the TTL.

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
/// this retry (`docs/ARCHITECTURE.md` "Multipart v1"). `Session::finish`
/// keeps this value and clears everything else the session held.
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

/// Largest number of concurrent multipart sessions this node holds. Each is
/// a few hundred bytes plus up to `MAX_TAIL_BYTES` of buffered tails, so an
/// unbounded count is a memory DoS. `create` calls `Sessions::make_room`
/// first, which evicts the oldest finished session to free a slot; it
/// rejects with `SlowDown` only when the node is at the cap and every
/// session is still open. The check-then-insert is not atomic, so
/// concurrent creates can overshoot the cap by at most the number of
/// in-flight requests — a soft bound, which is enough for a DoS ceiling.
///
/// ponytail: a flat count cap, not a global tail-byte budget. It bounds the
/// session count directly; per-session tail RAM is already bounded by
/// `MAX_TAIL_BYTES`. Add a shared tail-byte budget only if concurrent
/// sub-5-MiB uploads are shown to pressure the memory target.
pub const MAX_SESSIONS: usize = 1024;

pub struct Session {
    /// `None` once `finish` has run — the earliest safe moment to release
    /// the key, rather than waiting for TTL. Every reader must handle the
    /// finished case; there is no default key to fall back to.
    pub dek: Option<[u8; 32]>,
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
    /// A `CompleteMultipartUpload` is uploading the footer and completing on
    /// the backend right now. Set under the session guard so a second,
    /// concurrent Complete for the same upload gets `SlowDown` instead of
    /// racing a duplicate footer upload. Cleared if that attempt fails.
    pub completing: bool,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.dek.zeroize();
    }
}

impl Session {
    pub fn new(dek: [u8; 32], alg: Alg, chunk_size: u32) -> Self {
        Self {
            dek: Some(dek),
            alg,
            chunk_size,
            parts: BTreeMap::new(),
            tails: BTreeMap::new(),
            last_activity: Instant::now(),
            completed: None,
            completing: false,
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Runs at a successful Complete: releases what a finished session no
    /// longer needs. Zeroizes the DEK (leaving `None`), clears `parts` and
    /// `tails`, stores `cached` so a retried Complete still gets its
    /// answer, and touches `last_activity` so `Sessions::make_room` evicts
    /// the oldest finished session first.
    pub fn finish(&mut self, cached: CachedComplete) {
        self.dek.zeroize();
        self.parts.clear();
        self.tails.clear();
        self.completed = Some(cached);
        self.touch();
    }

    /// Records a completed part and applies the tail-buffer rule: every
    /// sub-5-MiB part's ciphertext is buffered (capped, `buffer_tail`) so
    /// Complete can find whichever part it actually finishes with; a part
    /// re-uploaded at >= 5 MiB clears its own stale buffer entry. Does
    /// nothing once `finish` has run — a late, concurrent UploadPart must
    /// not repopulate state a Complete already cleared.
    pub fn record_part(&mut self, part_number: u32, pt_len: u64, etag: String, ct: Option<Bytes>) {
        if self.completed.is_some() {
            return;
        }
        self.parts.insert(part_number, PartRecord { pt_len, etag });
        match ct {
            Some(c) => self.buffer_tail(part_number, c),
            None => {
                self.tails.remove(&part_number);
            }
        }
        self.touch();
    }

    /// Buffers `ct` under `part_number`, then evicts the lowest-numbered
    /// buffered part while the total exceeds `MAX_TAIL_BYTES`.
    fn buffer_tail(&mut self, part_number: u32, ct: Bytes) {
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

    /// Creates a session, unless the node is already at `MAX_SESSIONS` (and
    /// this key is new). Returns `false` when the cap rejects it, so the
    /// caller can answer `SlowDown` rather than growing memory without bound.
    #[must_use]
    pub fn create(&self, key: SessionKey, dek: [u8; 32], alg: Alg, chunk_size: u32) -> bool {
        if !self.0.contains_key(&key) && !self.make_room() {
            return false;
        }
        self.0.insert(key, Session::new(dek, alg, chunk_size));
        true
    }

    /// Frees a slot for a new session when the node is at `MAX_SESSIONS`,
    /// by evicting the finished session with the oldest `last_activity`.
    /// Returns `true` when a slot is available (whether or not anything
    /// was evicted), and `false` only when the node is at the cap and
    /// every session is still open — the caller then answers `SlowDown`
    /// rather than growing memory without bound.
    ///
    /// ponytail: an O(`MAX_SESSIONS`) scan, run only at the cap. An
    /// ordered index by `last_activity` is the upgrade path if the cap
    /// ever grows past about 10000.
    #[must_use]
    pub fn make_room(&self) -> bool {
        if self.0.len() < MAX_SESSIONS {
            return true;
        }
        let victim: Option<SessionKey> = self
            .0
            .iter()
            .filter(|entry| entry.value().completed.is_some())
            .min_by_key(|entry| entry.value().last_activity)
            .map(|entry| entry.key().clone());
        victim.is_some_and(|key| {
            self.0.remove(&key);
            true
        })
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
        assert!(sessions.create(key.clone(), [0x11; 32], Alg::Aes256Gcm, 1024));
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

        assert!(sessions.create(fresh.clone(), [0x01; 32], Alg::Aes256Gcm, 1024));
        assert!(sessions.create(stale_incomplete.clone(), [0x02; 32], Alg::Aes256Gcm, 1024));
        assert!(sessions.create(stale_completed.clone(), [0x03; 32], Alg::Aes256Gcm, 1024));

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

    fn cached() -> CachedComplete {
        CachedComplete {
            status: StatusCode::OK,
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }

    #[test]
    fn finish_releases_the_dek_parts_and_tails() {
        let mut s = Session::new([0x55; 32], Alg::Aes256Gcm, 1024);
        s.parts.insert(
            1,
            PartRecord {
                pt_len: 10,
                etag: "e1".to_string(),
            },
        );
        s.buffer_tail(1, ct(10));

        s.finish(cached());

        assert!(s.dek.is_none());
        assert!(s.parts.is_empty());
        assert!(s.tails.is_empty());
        assert!(s.completed.is_some());
    }

    #[test]
    fn record_part_on_a_finished_session_changes_nothing() {
        let mut s = Session::new([0x66; 32], Alg::Aes256Gcm, 1024);
        s.finish(cached());

        s.record_part(1, 10, "e1".to_string(), Some(ct(10)));

        assert!(s.parts.is_empty());
        assert!(s.tails.is_empty());
    }

    fn open_key(i: usize) -> SessionKey {
        (
            "DEFAULT".to_string(),
            "b".to_string(),
            format!("open-{i}"),
            format!("u-open-{i}"),
        )
    }

    #[test]
    fn make_room_at_the_cap_evicts_the_oldest_finished_session() {
        let sessions = Sessions::new();
        for i in 0..MAX_SESSIONS - 2 {
            assert!(sessions.create(open_key(i), [0u8; 32], Alg::Aes256Gcm, 1024));
        }
        let older = (
            "DEFAULT".to_string(),
            "b".to_string(),
            "older".to_string(),
            "u-older".to_string(),
        );
        let newer = (
            "DEFAULT".to_string(),
            "b".to_string(),
            "newer".to_string(),
            "u-newer".to_string(),
        );
        assert!(sessions.create(older.clone(), [0x01; 32], Alg::Aes256Gcm, 1024));
        assert!(sessions.create(newer.clone(), [0x02; 32], Alg::Aes256Gcm, 1024));
        assert_eq!(sessions.len(), MAX_SESSIONS);

        // Finish both, then push the older one's activity further back —
        // `finish` itself touches `last_activity`, so this must happen
        // after, not before.
        sessions.get_mut(&older).unwrap().finish(cached());
        sessions.get_mut(&newer).unwrap().finish(cached());
        sessions.get_mut(&older).unwrap().last_activity =
            Instant::now().checked_sub(Duration::from_hours(2)).unwrap();

        assert!(sessions.make_room());

        assert!(
            sessions.get(&older).is_none(),
            "the older finished session must be evicted"
        );
        assert!(
            sessions.get(&newer).is_some(),
            "the newer finished session must stay"
        );
        for i in 0..MAX_SESSIONS - 2 {
            assert!(
                sessions.get(&open_key(i)).is_some(),
                "open session {i} must stay"
            );
        }
        assert_eq!(sessions.len(), MAX_SESSIONS - 1);
    }

    #[test]
    fn make_room_at_the_cap_with_no_finished_session_rejects() {
        let sessions = Sessions::new();
        for i in 0..MAX_SESSIONS {
            assert!(sessions.create(open_key(i), [0u8; 32], Alg::Aes256Gcm, 1024));
        }
        assert_eq!(sessions.len(), MAX_SESSIONS);

        assert!(!sessions.make_room());

        assert_eq!(sessions.len(), MAX_SESSIONS);
    }

    fn two_hours_ago() -> Instant {
        Instant::now().checked_sub(Duration::from_hours(2)).unwrap()
    }

    fn named_key(name: &str) -> SessionKey {
        (
            "DEFAULT".to_string(),
            "b".to_string(),
            name.to_string(),
            format!("u-{name}"),
        )
    }

    #[test]
    fn finish_restarts_the_ttl_clock() {
        let mut s = Session::new([0x01; 32], Alg::Aes256Gcm, 1024);
        s.last_activity = two_hours_ago();

        s.finish(cached());

        // Guards: `finish` calls `touch`.
        assert!(!s.expired(Duration::from_hours(1)));
    }

    #[test]
    fn record_part_on_a_finished_session_does_not_extend_its_life() {
        let mut s = Session::new([0x02; 32], Alg::Aes256Gcm, 1024);
        s.finish(cached());
        s.last_activity = two_hours_ago();

        s.record_part(1, 10, "e1".to_string(), Some(ct(10)));

        // Guards: the early return in `record_part` comes before `touch`.
        assert!(s.expired(Duration::from_hours(1)));
        assert!(s.parts.is_empty());
        assert!(s.tails.is_empty());
    }

    #[test]
    fn record_part_on_an_open_session_records_the_part_and_buffers_the_tail() {
        let mut s = Session::new([0x03; 32], Alg::Aes256Gcm, 1024);
        s.last_activity = two_hours_ago();

        s.record_part(3, 10, "e3".to_string(), Some(ct(10)));

        // Guards: `record_part` inserts the part, buffers `Some` and touches.
        assert_eq!(s.parts[&3].pt_len, 10);
        assert_eq!(s.parts[&3].etag, "e3");
        assert!(s.tails.contains_key(&3));
        assert!(!s.expired(Duration::from_hours(1)));
    }

    #[test]
    fn record_part_with_no_tail_clears_only_that_parts_tail() {
        let mut s = Session::new([0x04; 32], Alg::Aes256Gcm, 1024);
        s.record_part(3, 10, "e3".to_string(), Some(ct(10)));
        s.record_part(4, 10, "e4".to_string(), Some(ct(10)));

        s.record_part(3, 6_000_000, "e3b".to_string(), None);

        // Guards: the `None => tails.remove(&part_number)` arm.
        assert_eq!(s.parts[&3].etag, "e3b");
        assert_eq!(s.parts[&3].pt_len, 6_000_000);
        assert!(!s.tails.contains_key(&3));
        assert!(s.tails.contains_key(&4));
    }

    #[test]
    fn make_room_below_the_cap_evicts_nothing() {
        let sessions = Sessions::new();
        let done = named_key("done");
        assert!(sessions.create(open_key(0), [0u8; 32], Alg::Aes256Gcm, 1024));
        assert!(sessions.create(open_key(1), [0u8; 32], Alg::Aes256Gcm, 1024));
        assert!(sessions.create(done.clone(), [0u8; 32], Alg::Aes256Gcm, 1024));
        sessions.get_mut(&done).unwrap().finish(cached());
        sessions.get_mut(&done).unwrap().last_activity = two_hours_ago();

        let room = sessions.make_room();

        // Guards: the `len() < MAX_SESSIONS` early return in `make_room`.
        assert!(room);
        assert_eq!(sessions.len(), 3);
        assert!(sessions.get(&done).is_some());
    }

    /// Fills a node to `MAX_SESSIONS`: open sessions first, then one
    /// finished session for each name in `finished`.
    fn at_the_cap_with_finished(finished: &[&str]) -> Sessions {
        let sessions = Sessions::new();
        for i in 0..MAX_SESSIONS - finished.len() {
            assert!(sessions.create(open_key(i), [0u8; 32], Alg::Aes256Gcm, 1024));
        }
        for name in finished {
            let key = named_key(name);
            assert!(sessions.create(key.clone(), [0u8; 32], Alg::Aes256Gcm, 1024));
            sessions.get_mut(&key).unwrap().finish(cached());
        }
        sessions
    }

    #[test]
    fn make_room_a_second_time_evicts_nothing_more() {
        let sessions = at_the_cap_with_finished(&["older", "newer"]);
        let older = named_key("older");
        let newer = named_key("newer");
        sessions.get_mut(&older).unwrap().last_activity = two_hours_ago();

        assert!(sessions.make_room());
        assert_eq!(sessions.len(), MAX_SESSIONS - 1);

        let again = sessions.make_room();

        // Guards: below the cap, `make_room` returns before it looks for a victim.
        assert!(again);
        assert_eq!(sessions.len(), MAX_SESSIONS - 1);
        assert!(sessions.get(&newer).is_some());
    }

    #[test]
    fn make_room_with_equal_activity_evicts_exactly_one() {
        let sessions = at_the_cap_with_finished(&["first", "second"]);
        let first = named_key("first");
        let second = named_key("second");
        let same = two_hours_ago();
        sessions.get_mut(&first).unwrap().last_activity = same;
        sessions.get_mut(&second).unwrap().last_activity = same;

        let room = sessions.make_room();

        // Guards: `min_by_key` selects one victim on a tie, not zero or two.
        assert!(room);
        assert_eq!(sessions.len(), MAX_SESSIONS - 1);
        let left = [&first, &second]
            .into_iter()
            .filter(|k| sessions.get(k).is_some())
            .count();
        assert_eq!(left, 1);
    }

    #[test]
    fn create_at_the_cap_evicts_the_oldest_finished_session_and_inserts() {
        let sessions = at_the_cap_with_finished(&["done"]);
        let done = named_key("done");
        let fresh = named_key("fresh");

        let created = sessions.create(fresh.clone(), [0u8; 32], Alg::Aes256Gcm, 1024);

        // Guards: `create` calls `make_room` for a new key at the cap.
        assert!(created);
        assert!(sessions.get(&done).is_none());
        assert!(sessions.get(&fresh).is_some());
        assert_eq!(sessions.len(), MAX_SESSIONS);
    }

    #[test]
    fn create_at_the_cap_over_an_existing_key_evicts_nothing() {
        let sessions = at_the_cap_with_finished(&["done"]);
        let done = named_key("done");

        let created = sessions.create(open_key(0), [0u8; 32], Alg::Aes256Gcm, 1024);

        // Guards: the `!contains_key(&key) &&` short circuit in `create`.
        assert!(created);
        assert!(sessions.get(&done).is_some());
        assert_eq!(sessions.len(), MAX_SESSIONS);
    }

    #[test]
    fn concurrent_create_and_finish_never_lose_an_open_session() {
        use std::sync::{mpsc, Arc};

        let sessions = Arc::new(Sessions::new());
        let (tx, rx) = mpsc::channel();
        for t in 0..4 {
            let sessions = Arc::clone(&sessions);
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut open = Vec::new();
                for i in 0..600 {
                    let key = (
                        "DEFAULT".to_string(),
                        "b".to_string(),
                        format!("t{t}-{i}"),
                        format!("u{t}-{i}"),
                    );
                    // A full node rejects the key. That is not an error here.
                    if !sessions.create(key.clone(), [0u8; 32], Alg::Aes256Gcm, 1024) {
                        continue;
                    }
                    if i % 2 == 0 {
                        sessions.get_mut(&key).unwrap().finish(cached());
                    } else {
                        open.push(key);
                    }
                }
                tx.send(open).unwrap();
            });
        }
        drop(tx);

        let mut open = Vec::new();
        for _ in 0..4 {
            match rx.recv_timeout(Duration::from_secs(60)) {
                Ok(keys) => open.extend(keys),
                Err(mpsc::RecvTimeoutError::Timeout) => panic!("deadlock suspected in Sessions"),
                Err(mpsc::RecvTimeoutError::Disconnected) => panic!("a worker thread panicked"),
            }
        }

        // Guards: `make_room` evicts only sessions with `completed.is_some()`.
        for key in &open {
            assert!(sessions.get(key).is_some(), "open session {key:?} was lost");
        }
    }
}
