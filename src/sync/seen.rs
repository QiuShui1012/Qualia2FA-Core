// Copyright (C) 2026 Qualia2FA contributors
//
// This library is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option) any
// later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, see <https://www.gnu.org/licenses/>.

//! Log of already-processed sync payload identifiers.
//!
//! # What it stops is not "data being corrupted"
//!
//! Merging is **idempotent**: merging the same payload twice gives the same result as merging it
//! once. Replaying an old payload therefore **does not break correctness**. What this log stops is
//! two other things:
//!
//! 1. **A full decryption and merge done for nothing.** A payload has to pass the outer AEAD, be
//!    decompressed, have every record decrypted and then be merged. A device on the LAN that keeps
//!    broadcasting the same payload makes the receiver repeat all of that — a denial-of-service
//!    surface that needs no cryptographic break.
//! 2. **"Last synced at" in the UI becoming a value an attacker can push around.** The user sees
//!    "synced just now" while nothing happened at all.
//!
//! A duplicate payload returns [`crate::Error::SyncAlreadyApplied`]: the caller does **not**
//! update the sync time, and can still report that this data was already synced.
//!
//! # Bounded, and failing explicitly when full
//!
//! The log must not grow without bound. At the limit it returns [`crate::Error::SyncIdLogFull`]
//! rather than silently dropping the oldest entry: dropping would make a very old payload
//! acceptable again, which is precisely what this module guards against. The limit is
//! [`MAX_SEEN_SYNC_IDS`]; what to do once it is full is the caller's decision (warn the user, or
//! give up replay protection and clear — that is a higher-level policy, not a decision this module
//! can make for the user).

use std::collections::VecDeque;

use crate::sync::SyncId;
use crate::{Error, Result};

/// Maximum number of entries in the log.
///
/// Each identifier is 32 bytes, so 4096 entries take about 128 KiB. That is negligible on desktop
/// and mobile, and 4096 syncs take a long time to accumulate in real use (syncing is a
/// user-triggered action).
///
/// Unlike a limit such as [`crate::vault::MAX_RECORDS`], which defends against malicious input,
/// this limit is **not** a security boundary: payload identifiers are random, so an attacker cannot
/// push useful old identifiers out of the log by deliberately sending new ones — the entries pushed
/// out would only be its own.
pub const MAX_SEEN_SYNC_IDS: usize = 4096;

/// Remembers which payload identifiers have been processed.
///
/// # Behaviour when full is explicit
///
/// [`SeenSyncIds::record`] returns [`Error::SyncIdLogFull`] when the log is full and does **not**
/// evict automatically. To keep going, the caller explicitly calls [`SeenSyncIds::clear`] — a
/// decision to give up replay protection, which the library must not make for the user.
///
/// # Container
///
/// Identifiers are held in a `VecDeque` in processing order, oldest first, and lookups scan it
/// linearly (32 bytes per comparison). There is no hash collision path, so a new payload can never
/// be misjudged as already seen because of one.
#[derive(Debug, Clone, Default)]
pub struct SeenSyncIds {
    /// Payload identifiers in processing order, oldest first.
    seen: VecDeque<SyncId>,
}

impl SeenSyncIds {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many identifiers are remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether nothing has been remembered yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Whether this payload has already been processed.
    #[must_use]
    pub fn contains(&self, sync_id: &SyncId) -> bool {
        self.seen.contains(sync_id)
    }

    /// Remembers a payload identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SyncIdLogFull`] when the log is full. **This call does not fail on a
    /// duplicate identifier** — duplicates are detected by the caller through
    /// [`SeenSyncIds::contains`] first, because "duplicate" and "full" call for completely
    /// different UI actions.
    pub fn record(&mut self, sync_id: SyncId) -> Result<()> {
        if self.seen.len() >= MAX_SEEN_SYNC_IDS {
            return Err(Error::SyncIdLogFull {
                limit: MAX_SEEN_SYNC_IDS,
            });
        }
        self.seen.push_back(sync_id);
        Ok(())
    }

    /// Checks and records in one step.
    ///
    /// # Errors
    ///
    /// - [`Error::SyncAlreadyApplied`]: this payload has been processed. **Nothing is recorded
    ///   again in that case.**
    /// - [`Error::SyncIdLogFull`]: the log is full and this payload is new.
    ///
    /// The two steps are one call because callers almost always need them together — splitting
    /// them invites the "checked but forgot to record" mistake, which drops replay protection and
    /// is invisible in normal operation.
    pub fn check_and_record(&mut self, sync_id: SyncId) -> Result<()> {
        if self.contains(&sync_id) {
            return Err(Error::SyncAlreadyApplied);
        }
        self.record(sync_id)
    }

    /// Clears the log.
    ///
    /// **This gives up replay protection for old payloads**: after clearing, a payload that was
    /// once processed becomes acceptable again. Call it only when the log is full and the user
    /// chose to keep syncing.
    pub fn clear(&mut self) {
        self.seen.clear();
    }

    /// Iterates the remembered identifiers in chronological order (oldest first).
    pub fn iter(&self) -> impl Iterator<Item = &SyncId> {
        self.seen.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> SyncId {
        [seed; crate::sync::SYNC_ID_LEN]
    }

    #[test]
    fn a_new_id_is_accepted_and_then_recognized() {
        let mut log = SeenSyncIds::new();
        assert!(log.is_empty());
        assert!(!log.contains(&id(1)));

        log.check_and_record(id(1))
            .expect("the first call must be accepted");
        assert_eq!(log.len(), 1);
        assert!(log.contains(&id(1)));
    }

    #[test]
    fn a_repeated_id_is_rejected() {
        let mut log = SeenSyncIds::new();
        log.check_and_record(id(1))
            .expect("the first call must be accepted");
        let err = log.check_and_record(id(1));
        assert!(
            matches!(err, Err(Error::SyncAlreadyApplied)),
            "actual {err:?}"
        );
        assert_eq!(
            log.len(),
            1,
            "a repeated identifier must not be recorded twice"
        );
    }

    #[test]
    fn many_distinct_ids_are_all_remembered() {
        let mut log = SeenSyncIds::new();
        for seed in 0..200_u8 {
            log.check_and_record(id(seed))
                .expect("a new identifier must be accepted");
        }
        assert_eq!(log.len(), 200);
        for seed in 0..200_u8 {
            assert!(
                log.contains(&id(seed)),
                "identifier {seed} was not remembered"
            );
        }
    }

    /// A full log must **fail explicitly**, never silently drop the oldest entry.
    ///
    /// A silent drop would make a very old payload acceptable again, which is exactly what replay
    /// protection must prevent. What this test pins down is a security property, not a capacity
    /// behaviour.
    #[test]
    fn a_full_log_fails_instead_of_evicting() {
        let mut log = SeenSyncIds::new();
        for i in 0..MAX_SEEN_SYNC_IDS {
            let mut sync_id = [0_u8; crate::sync::SYNC_ID_LEN];
            sync_id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            log.record(sync_id)
                .expect("must be accepted while not full");
        }
        assert_eq!(log.len(), MAX_SEEN_SYNC_IDS);

        let mut fresh = [9_u8; crate::sync::SYNC_ID_LEN];
        fresh[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        let err = log.record(fresh);
        assert!(
            matches!(err, Err(Error::SyncIdLogFull { .. })),
            "actual {err:?}"
        );

        let mut oldest = [0_u8; crate::sync::SYNC_ID_LEN];
        oldest[..8].copy_from_slice(&0_u64.to_be_bytes());
        assert!(log.contains(&oldest), "the oldest identifier was evicted");
    }

    #[test]
    fn clear_gives_up_protection_explicitly() {
        let mut log = SeenSyncIds::new();
        log.check_and_record(id(1))
            .expect("the first call must be accepted");
        log.clear();
        assert!(log.is_empty());
        log.check_and_record(id(1))
            .expect("must be accepted again after a reset");
    }

    #[test]
    fn iteration_is_oldest_first() {
        let mut log = SeenSyncIds::new();
        for seed in 1..=5_u8 {
            log.record(id(seed)).expect("must be accepted");
        }
        let order: Vec<u8> = log.iter().map(|s| s[0]).collect();
        assert_eq!(order, vec![1, 2, 3, 4, 5]);
    }
}
