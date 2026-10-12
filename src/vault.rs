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

//! Encrypted vault: on-disk format, entry encryption and decryption, atomic writes.
//!
//! # Threat model
//!
//! The vault file is assumed to be **fully readable and writable by an attacker**.
//! It travels through a cloud drive the user picked, QR codes and another device,
//! none of which this application controls. Therefore:
//!
//! - Apart from [`EntryId`], the file holds **no plaintext semantics**. Not even
//!   "TOTP or HOTP" is visible, because that lives inside the ciphertext.
//! - Flipping any byte must make decryption fail instead of quietly yielding
//!   tampered data.
//! - All an attacker can observe is how many entries exist and how long each
//!   ciphertext is.
//!
//! **Length itself still leaks information** (how long a note or an account name
//! is). Hiding it would take padding to fixed-size blocks at several times the file
//! size. That is not done today: a known, deliberate trade-off.
//!
//! # File format v2
//!
//! All integers are **big-endian**. Layout:
//!
//! ```text
//! Offset    Length  Content
//! 0         8       magic "Q2FAVLT\0"
//! 8         1       format version (currently 2)
//! 9         1       reserved byte (must be 0; a non-zero value is rejected so a
//!                   future extension cannot be misread as an old file)
//! 10        4       record count (big-endian u32)
//! 14        ...     records, packed back to back
//! end       32      master key check value
//! ```
//!
//! Each record:
//!
//! ```text
//! Offset    Length  Content
//! 0         1       record kind (1 = live entry, 2 = tombstone)
//! 1         16      entry ID
//! 17        24      XChaCha20-Poly1305 nonce
//! 41        4       ciphertext length (big-endian u32)
//! 45        N       ciphertext (including the 16-byte authentication tag)
//! ```
//!
//! **Records are not padded**, and no checksum sits between them: the AEAD tag
//! already covers whether a record is complete, whether it belongs at this position
//! and whether it belongs to this version, so another checksum would only add
//! failure modes. The final 32 bytes are not a checksum either: they are the master
//! key check value, answering "was this file written with this key", while a record
//! tag answers "was this record modified".
//!
//! The additional authenticated data (AAD) of a record is 18 bytes: the record kind
//! (1 byte), the entry ID (16 bytes) and the format version (1 byte). The tag covers
//! those bytes together with the ciphertext.
//!
//! ## Version 1 files remain readable
//!
//! Version 1 has no trailing 32 bytes; parsing simply skips the check-value step,
//! everything else is identical. This is deliberate: after upgrading the
//! application, an existing file must still open.
//!
//! **The converse does not hold.** A version 1 parser rejects a version 2 file,
//! because it carries a "reject any trailing bytes" check and those 32 bytes look
//! like trailing content to it. Repairing that would mean relaxing the check, which
//! would also make "the file had content appended" disappear silently - a higher
//! price than "an old version cannot open a new file". Users on the old version see
//! a clear error, not garbled data.
//!
//! # Where the key comes from
//!
//! The file **does not contain** the master key, but it **does contain a value
//! derived from it** (format version 2 onward, see [`crypto::key_check`]). That
//! value answers only "is this the key you guessed"; it cannot be inverted to the
//! master key. What it blocks is a real failure mode: a mis-stored master key going
//! unnoticed because the vault happened to be empty.
//!
//! The master key is held in the platform hardware keystore (Windows TPM).
//! **Losing the master key means the data can never be decrypted** - the unavoidable
//! price of having no server and no account password.

mod codec;
pub(crate) mod crypto;
mod entry;

pub use crypto::{
    KEY_CHECK_LEN, MASTER_KEY_LEN, MasterKey, NONCE_LEN, TAG_LEN, key_check, master_key_to_bytes,
    verify_key_check,
};
pub use entry::{Entry, EntryId, Timestamp, entry_from_parsed_uri};

pub(crate) use crypto::RecordKind;

use std::collections::BTreeMap;
use std::path::Path;

use crate::{Error, Result, otp};
use codec::{Reader, put_bytes, put_u32};
use entry::Entry as VaultEntry;

/// File magic. 8 bytes; the trailing NUL makes it recognizable in a hex editor.
pub const MAGIC: &[u8; 8] = b"Q2FAVLT\0";

/// Format version currently written: 2.
///
/// Version 2 differs from version 1 in exactly one place: the master key check value
/// at the end of the file, which lets "which master key wrote this file" be decided
/// **before the first record is read**. In version 1 the master key only took part in
/// each record AEAD, so **a file with no entries parsed successfully under any 32-byte
/// key** - a mis-stored key surfaced only once the first entry was added, long after
/// the UI had shown "opened successfully".
///
/// # This constant is **also** the version number in the record AAD
///
/// It therefore cannot merely describe a layout: change the number in the AAD and
/// every old record tag stops verifying. Parsing must use **the version declared by
/// the file being parsed**, never this constant; otherwise reading a version 1 file
/// fails authentication on every record. See `version` in [`VaultFile::parse`].
///
/// # Version 1 is still readable
///
/// A version 1 file has no check value, so `parse` skips that step and behaves as
/// before (including the known limitation). The converse **does not hold**: a version
/// 1 parser rejects a version 2 file over the extra trailing bytes (it carries a
/// "reject any trailing bytes" check) and reports [`Error::VaultTrailingBytes`]
/// rather than an unsupported version. That follows directly from version 1 having no
/// skip path for richer future versions, and it cannot be repaired without relaxing
/// that check - which would make "the file had content appended" disappear silently.
pub const FORMAT_VERSION: u8 = 2;

/// Format versions that can be parsed: 1 and the current [`FORMAT_VERSION`].
///
/// Only added to, never removed: dropping a version would suddenly make an old file
/// unopenable, and the error message ("unsupported version") would suggest the file
/// is broken.
///
/// Public so that the "old versions stay readable" promise is pinned by tests
/// directly, instead of a test restating the version number - where both sides would
/// change together and never fail.
pub const READABLE_VERSIONS: &[u8] = &[1, FORMAT_VERSION];

/// Upper bound on the ciphertext length of a single record: 1 MiB.
///
/// The length comes from the file, which is attacker-controlled. Unbounded, a
/// 100-byte malicious file could claim the next record is 4 GiB and the parser would
/// try to allocate it.
///
/// 1 MiB far exceeds any real entry: even with every variable-length field at
/// [`Entry::MAX_FIELD_LEN`] (64 KiB), an entry is a few hundred KiB.
pub const MAX_RECORD_LEN: usize = 1024 * 1024;

/// Upper bound on the record count: 1,000,000.
///
/// Blocks a malicious file claiming four billion records. A million 2FA entries is
/// far beyond any real user.
pub const MAX_RECORDS: usize = 1_000_000;

/// Field tags of the plaintext entry.
///
/// Every node carries a tag and a length, so an unknown tag can be **skipped by its
/// length**. That is what lets a newer version add fields while an older version
/// still reads the fields it knows, instead of failing to parse the whole file - a
/// user does not lose access to a vault just because it was written once by a newer
/// version.
///
/// The parser must therefore handle "skip an unknown node" correctly, and a wrong
/// skip is an out-of-range read; the `vault_parse` fuzz target exercises that path.
mod tag {
    /// Display name.
    pub(super) const NAME: u8 = 0x01;
    /// Issuer.
    pub(super) const ISSUER: u8 = 0x02;
    /// Account name.
    pub(super) const ACCOUNT: u8 = 0x03;
    /// OTP secret (raw bytes, not Base32).
    pub(super) const SECRET: u8 = 0x04;
    /// HMAC algorithm.
    pub(super) const ALGORITHM: u8 = 0x05;
    /// Number of digits in a code.
    pub(super) const DIGITS: u8 = 0x06;
    /// TOTP period (seconds).
    pub(super) const PERIOD: u8 = 0x07;
    /// HOTP counter.
    pub(super) const COUNTER: u8 = 0x08;
    /// Note.
    pub(super) const NOTE: u8 = 0x09;
    /// Creation time.
    pub(super) const CREATED_AT: u8 = 0x0A;
    /// Last modification time.
    pub(super) const UPDATED_AT: u8 = 0x0B;
    /// Deletion time of a tombstone.
    pub(super) const DELETED_AT: u8 = 0x0C;
    /// Deleting device of a tombstone.
    ///
    /// Reserved for originator-side conflict adjudication; not written yet.
    pub(super) const DELETED_BY: u8 = 0x0D;

    /// Value of the algorithm field.
    pub(super) const ALG_SHA1: u8 = 1;
    /// Value of the algorithm field.
    pub(super) const ALG_SHA256: u8 = 2;
    /// Value of the algorithm field.
    pub(super) const ALG_SHA512: u8 = 3;

    /// Digit count: 6.
    pub(super) const DIGITS_SIX: u8 = 6;
    /// Digit count: 7.
    pub(super) const DIGITS_SEVEN: u8 = 7;
    /// Digit count: 8.
    pub(super) const DIGITS_EIGHT: u8 = 8;
}

/// A deletion record.
///
/// A deleted entry leaves a tombstone behind so that "I deleted it" becomes a fact
/// that can be synced: without one, a peer device still holding the entry looks like
/// it has a new entry and the deletion is silently undone.
///
/// # A tombstone holds no plaintext
///
/// It contains **none** of the name, account or secret of the deleted entry - only
/// the ID and timestamps, and the whole record is AEAD-encrypted like any other. An
/// attacker holding the file learns nothing about which service the user deleted.
///
/// # Retention
///
/// Tombstones **never expire**, matching the union semantics of sync: as long as one
/// device has never seen this deletion, the tombstone is useful. The cost is that the
/// file grows slowly with the number of deletions - 45 bytes of ciphertext per
/// tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tombstone {
    /// ID of the deleted entry.
    pub entry_id: EntryId,
    /// Deletion time (Unix seconds).
    pub deleted_at: Timestamp,
    /// ID of the device that performed the deletion.
    ///
    /// Currently always `None`. Reserved, so that a tombstone can record which device
    /// deleted the entry.
    pub deleted_by: Option<EntryId>,
}

/// A decrypted vault.
///
/// # Ordering is deterministic
///
/// Entries and tombstones live in [`BTreeMap`]s rather than `HashMap`s, so
/// serialization is **byte-for-byte reproducible**: otherwise the same content would
/// produce different files on two devices, defeating the most obvious consistency
/// check ("are the files the same") and making round-trip comparisons in tests
/// unreliable.
#[derive(Debug, Default)]
pub struct Vault {
    /// Live entries, ordered by ID.
    entries: BTreeMap<EntryId, VaultEntry>,
    /// Tombstones, ordered by ID.
    tombstones: BTreeMap<EntryId, Tombstone>,
}

impl Vault {
    /// Creates an empty vault.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no live entries (tombstones are not counted).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of tombstones.
    #[must_use]
    pub fn tombstone_count(&self) -> usize {
        self.tombstones.len()
    }

    /// Iterates the live entries by ID, in a deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&EntryId, &VaultEntry)> {
        self.entries.iter()
    }

    /// Returns an entry by ID.
    #[must_use]
    pub fn get(&self, id: &EntryId) -> Option<&VaultEntry> {
        self.entries.get(id)
    }

    /// Returns a tombstone by ID.
    #[must_use]
    pub fn get_tombstone(&self, id: &EntryId) -> Option<&Tombstone> {
        self.tombstones.get(id)
    }

    /// Inserts an entry and returns its ID.
    ///
    /// The ID comes from a CSPRNG. Callers only display and diagnose it, they never
    /// construct one. An existing tombstone with the same ID is dropped, so "the entry
    /// exists and is marked deleted" cannot occur.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`] when the OS random source is
    /// unavailable.
    pub fn insert(&mut self, entry: VaultEntry) -> Result<EntryId> {
        let id = EntryId::generate()?;
        self.tombstones.remove(&id);
        self.entries.insert(id, entry);
        Ok(id)
    }

    /// Inserts an entry under a given ID.
    ///
    /// **For parsing an existing vault file only.** New entries go through
    /// [`Vault::insert`]; otherwise two devices generate the same ID independently and
    /// sync silently merges them into one, dropping the other.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultDuplicateEntryId`] when the ID already has a live entry.
    /// The call is refused rather than turned into an overwrite: a duplicate ID inside
    /// a file means it was constructed or corrupted, and silently keeping one of the
    /// two would lose an entry.
    pub fn insert_with_id(&mut self, id: EntryId, entry: VaultEntry) -> Result<()> {
        if self.entries.contains_key(&id) {
            return Err(Error::VaultDuplicateEntryId);
        }
        self.entries.insert(id, entry);
        Ok(())
    }

    /// Replaces an **existing** entry with new content, keeping the ID and leaving
    /// **no tombstone**.
    ///
    /// The ID is the only thing two devices have to talk about "the same entry".
    /// Renaming through "delete, then insert under a new ID" would read on the peer as
    /// "one entry deleted, another added", leaving the history and the tombstones of
    /// the entry out of step: the user sees a rename turn into two entries, or the
    /// original disappear.
    ///
    /// Going through [`Vault::remove`] and then [`Vault::insert_with_id`] does not work
    /// either: `remove` leaves a tombstone **by design**, and a rename is not a
    /// deletion. A stray tombstone gets synced out and the other side may delete the
    /// entry for real because of it.
    ///
    /// # What the caller decides
    ///
    /// Whether `created_at` is preserved is up to the caller. Keeping it is the usual
    /// choice: it records when the user added the entry, and changing it on a rename
    /// makes the UI reorder.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultEntryNotFound`] when no live entry has this ID. The call is
    /// refused rather than degraded into an insert: the caller believes it is editing an
    /// existing entry (the user pressed save in the editor) while the entry is already
    /// gone (deleted on the other side), and the useful response is to ask the user to
    /// refresh, not to add it back out of nowhere.
    pub fn replace(&mut self, id: EntryId, entry: VaultEntry) -> Result<()> {
        if !self.entries.contains_key(&id) {
            return Err(Error::VaultEntryNotFound);
        }
        self.entries.insert(id, entry);
        Ok(())
    }

    /// Deletes an entry and leaves a tombstone.
    ///
    /// Returns the removed entry when it existed, so the caller can offer undo. `now`
    /// comes from the caller (this library reads no clock).
    ///
    /// An existing tombstone for the ID keeps its original timestamp: a repeated
    /// deletion must not refresh the deletion time, or one device deleting over and over
    /// would look newer than the choice of the other device.
    ///
    /// The removed entry is handed back rather than dropped because handling the
    /// plaintext of its `OtpSecret` belongs to the caller - usually the undo prompt in
    /// the UI. This library neither decides for it nor keeps it in memory any longer.
    pub fn remove(&mut self, id: &EntryId, now: Timestamp) -> Option<VaultEntry> {
        let removed = self.entries.remove(id)?;
        self.tombstones.entry(*id).or_insert_with(|| Tombstone {
            entry_id: *id,
            deleted_at: now,
            deleted_by: None,
        });
        Some(removed)
    }

    /// Records a tombstone without checking for a matching live entry.
    ///
    /// Used by sync: when the peer sends a tombstone, this device may never have had
    /// that entry.
    ///
    /// # Semantics
    ///
    /// A live entry with the same ID is **not** deleted; the caller decides which side
    /// wins. This function only records the tombstone.
    pub fn record_tombstone(&mut self, tombstone: Tombstone) {
        self.tombstones.insert(tombstone.entry_id, tombstone);
    }

    /// Iterates over every tombstone.
    pub fn iter_tombstones(&self) -> impl Iterator<Item = (&EntryId, &Tombstone)> {
        self.tombstones.iter()
    }

    /// Drops a tombstone, so this ID is no longer marked as deleted.
    ///
    /// Returns the tombstone that was dropped, or `None` when this ID had none.
    ///
    /// # What it is for
    ///
    /// A tombstone records a deletion that **has happened**. Dropping it overrules that
    /// deletion: the ID becomes unknown again, and an entry arriving under it later is
    /// taken as content this device does not have rather than as something a device failed
    /// to delete.
    ///
    /// Only a user may overrule a deletion. The case it exists for is an entry this device
    /// deleted while a peer still held a copy: the peer's record arrives, the user is asked,
    /// and "the entry should not have been deleted" is answered by putting the entry back.
    /// A library deciding this on its own would be undoing an explicit user action.
    ///
    /// # A live entry with the same ID is not touched
    ///
    /// The two states mean different things: a tombstone on its own is "deleted", while a
    /// tombstone next to a live entry is "the deletion has not been adjudicated yet" (see
    /// [`crate::sync`]). Deleting the live entry is [`Vault::remove`], and neither is a side
    /// effect of the other.
    pub fn forget_tombstone(&mut self, id: &EntryId) -> Option<Tombstone> {
        self.tombstones.remove(id)
    }
}

/// A vault file together with the master key that opens it.
///
/// Keeping the ciphertext and the key in separate stores (the key in the hardware
/// keystore) is deliberate, but passing them around separately invites "decrypted file
/// B with the key of file A" mistakes whose symptom is "nothing decrypts", which is
/// hard to pin down. This type makes the file and the key that opens it a single value.
///
/// # Lifetime
///
/// Opening a file decrypts every entry: a real vault holds tens to hundreds of entries,
/// and decrypting them at once costs far less than maintaining a state machine of
/// "which entries are decrypted". Consequently **all plaintext is in memory while the
/// vault is unlocked** - consistent with the convention that secret material exists
/// only as `secrecy` types, though paging and memory dumps remain known residual risks.
#[derive(Debug)]
pub struct VaultFile {
    /// Master key.
    master: MasterKey,
    /// Decrypted contents.
    vault: Vault,
}

impl VaultFile {
    /// Creates an empty vault with a fresh random master key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`] when the OS random source is
    /// unavailable.
    pub fn create() -> Result<Self> {
        Ok(Self {
            master: MasterKey::generate()?,
            vault: Vault::new(),
        })
    }

    /// Opens an empty vault under the given master key.
    ///
    /// Used when the master key is already in the hardware keystore but there is no
    /// local file yet.
    #[must_use]
    pub fn with_master_key(master: MasterKey) -> Self {
        Self {
            master,
            vault: Vault::new(),
        }
    }

    /// Read-only reference to the master key.
    #[must_use]
    pub const fn master_key(&self) -> &MasterKey {
        &self.master
    }

    /// Takes ownership of the master key and splits the `VaultFile` apart.
    ///
    /// Used by the layer above to store the master key in the hardware keystore.
    #[must_use]
    pub fn into_parts(self) -> (MasterKey, Vault) {
        (self.master, self.vault)
    }

    /// Read-only reference to the contents.
    #[must_use]
    pub const fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Mutable reference to the contents.
    pub const fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }

    /// The master key and the contents together.
    ///
    /// # Why this entry point exists
    ///
    /// An operation that needs both at once cannot be written with [`VaultFile::master_key`]
    /// and [`VaultFile::vault_mut`]: the first borrows the whole value, so the second is
    /// refused even though the two fields are disjoint. Synchronization is exactly such an
    /// operation — the key seals and opens payloads while the contents are what gets merged —
    /// and the alternative would be copying the master key, which a caller that only wants
    /// to borrow has no reason to do.
    #[must_use]
    pub fn split_mut(&mut self) -> (&MasterKey, &mut Vault) {
        (&self.master, &mut self.vault)
    }

    /// Serializes to the file bytes.
    ///
    /// # Errors
    ///
    /// Returns the corresponding error when an entry field exceeds what the format can
    /// represent, and [`Error::RandomnessUnavailable`] when the random source is
    /// unavailable (every record needs a fresh nonce).
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let total = self
            .vault
            .entries
            .len()
            .checked_add(self.vault.tombstones.len())
            .ok_or(Error::VaultTooManyRecords)?;
        if total > MAX_RECORDS {
            return Err(Error::VaultTooManyRecords);
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "total was already compared against MAX_RECORDS (far below u32::MAX)"
        )]
        let count = total as u32;

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.push(0);
        put_u32(&mut out, count);

        for (id, entry) in &self.vault.entries {
            let plaintext = encode_entry(entry)?;
            write_record(
                &mut out,
                &self.master,
                FORMAT_VERSION,
                RecordKind::Entry,
                id,
                &plaintext,
            )?;
        }
        for (id, tombstone) in &self.vault.tombstones {
            let plaintext = encode_tombstone(tombstone);
            write_record(
                &mut out,
                &self.master,
                FORMAT_VERSION,
                RecordKind::Tombstone,
                id,
                &plaintext,
            )?;
        }

        out.extend_from_slice(&crypto::key_check(&self.master));
        Ok(out)
    }

    /// Parses from the file bytes.
    ///
    /// Each record is authenticated with the version **declared by this file**, not with
    /// [`FORMAT_VERSION`]; using the constant would fail authentication on every record
    /// of an older file and report it as a wrong key.
    ///
    /// # Errors
    ///
    /// Any structural problem (bad magic, unsupported version, a record running past the
    /// end, an over-long length) returns a structural error; **any authentication failure
    /// returns [`Error::VaultDecryptionFailed`]** without distinguishing the cause. A
    /// mismatching master key check value in a version 2 file returns it too: that is an
    /// earlier detection point for the same thing as "the first record does not decrypt".
    ///
    /// # Version 1 files remain readable
    ///
    /// Version 1 has no check value, so that step is skipped and behaviour is exactly as
    /// before. A file that exists must still open after an application upgrade.
    ///
    /// # A version 1 file still cannot tell a wrong key
    ///
    /// Not a regression: the file simply holds nothing to decide from. For authoritative
    /// confirmation of a key, use the challenge-response in the `auth` module, which does
    /// not depend on file contents.
    ///
    /// # This function must never panic
    ///
    /// Its input is a wholly attacker-controlled file. Every out-of-range access is
    /// blocked by the internal read cursor, and every length is compared against its
    /// limit before allocating. The `vault_parse` fuzz target checks this.
    pub fn parse(master: MasterKey, data: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(data);

        let magic = reader.take(MAGIC.len()).ok_or(Error::VaultTruncated)?;
        if magic != MAGIC {
            return Err(Error::VaultBadMagic);
        }

        let version = reader.u8().ok_or(Error::VaultTruncated)?;
        if !READABLE_VERSIONS.contains(&version) {
            return Err(Error::VaultUnsupportedVersion { version });
        }

        let reserved = reader.u8().ok_or(Error::VaultTruncated)?;
        if reserved != 0 {
            return Err(Error::VaultReservedByteNotZero { value: reserved });
        }

        let count = reader.u32().ok_or(Error::VaultTruncated)? as usize;
        if count > MAX_RECORDS {
            return Err(Error::VaultTooManyRecords);
        }

        let mut vault = Vault::new();
        for _ in 0..count {
            let kind_byte = reader.u8().ok_or(Error::VaultTruncated)?;
            let kind = RecordKind::from_byte(kind_byte)
                .ok_or(Error::VaultUnknownRecordKind { value: kind_byte })?;
            let id = reader.entry_id().ok_or(Error::VaultTruncated)?;
            let nonce = reader.nonce().ok_or(Error::VaultTruncated)?;
            let len = reader.u32().ok_or(Error::VaultTruncated)? as usize;
            if len > MAX_RECORD_LEN {
                return Err(Error::VaultRecordTooLong {
                    limit: MAX_RECORD_LEN,
                    actual: len,
                });
            }
            let ciphertext = reader.take(len).ok_or(Error::VaultTruncated)?;

            let plaintext = crypto::open(&master, kind, &id, version, &nonce, ciphertext)?;
            match kind {
                RecordKind::Entry => {
                    let entry = decode_entry(&plaintext)?;
                    vault.insert_with_id(id, entry)?;
                }
                RecordKind::Tombstone => {
                    let tombstone = decode_tombstone(id, &plaintext)?;
                    vault.record_tombstone(tombstone);
                }
                RecordKind::SyncEntry | RecordKind::SyncTombstone => {
                    return Err(Error::VaultUnknownRecordKind { value: kind_byte });
                }
            }
        }

        if version >= 2 {
            let stored = reader
                .take(crypto::KEY_CHECK_LEN)
                .ok_or(Error::VaultTruncated)?;
            crypto::verify_key_check(&master, stored)?;
        }

        if !reader.is_empty() {
            return Err(Error::VaultTrailingBytes {
                count: reader.remaining(),
            });
        }

        Ok(Self { master, vault })
    }
}

/// Appends one record to the output buffer.
///
/// `format_version` is passed in explicitly rather than read from [`FORMAT_VERSION`]: it
/// also goes into the AAD, and parsing must be able to match the version the file
/// declares.
fn write_record(
    out: &mut Vec<u8>,
    master: &MasterKey,
    format_version: u8,
    kind: RecordKind,
    id: &EntryId,
    plaintext: &[u8],
) -> Result<()> {
    let (nonce, ciphertext) = crypto::seal(master, kind, id, format_version, plaintext)?;
    out.push(kind.as_byte());
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&nonce);
    put_bytes(out, &ciphertext);
    Ok(())
}

/// Serializes the plaintext of an entry.
///
/// # Encoding rule: **every** node is "tag + u32 length + content"
///
/// No exceptions, not even one-byte enum values or eight-byte timestamps. Letting
/// fixed-width fields omit the length prefix would save a few bytes but force the parser
/// to keep a table of which tags carry a length - exactly where the "skip unknown nodes"
/// forward-compatibility mechanism is easiest to get wrong (where does the length of an
/// unknown tag come from?).
///
/// With the uniform format, skipping an unknown node has one path: read the tag, read the
/// u32 length, skip that many bytes.
pub(crate) fn encode_entry(entry: &VaultEntry) -> Result<Vec<u8>> {
    let mut out = Vec::new();

    put_node(&mut out, tag::NAME, entry.name.as_bytes());
    put_node(
        &mut out,
        tag::ISSUER,
        entry.issuer.as_deref().unwrap_or_default().as_bytes(),
    );
    put_node(&mut out, tag::ACCOUNT, entry.account.as_bytes());
    put_node(&mut out, tag::SECRET, entry.secret.expose());
    put_node(
        &mut out,
        tag::ALGORITHM,
        &[algorithm_to_byte(entry.algorithm)],
    );
    put_node(&mut out, tag::DIGITS, &[digits_to_byte(entry.digits)]);
    put_node(&mut out, tag::PERIOD, &entry.period.to_be_bytes());
    if let Some(counter) = entry.counter {
        put_node(&mut out, tag::COUNTER, &counter.to_be_bytes());
    }
    put_node(&mut out, tag::NOTE, entry.note.as_bytes());
    put_node(&mut out, tag::CREATED_AT, &entry.created_at.to_be_bytes());
    put_node(&mut out, tag::UPDATED_AT, &entry.updated_at.to_be_bytes());

    Ok(out)
}

/// Appends one "tag + length + content" node.
fn put_node(out: &mut Vec<u8>, tag: u8, payload: &[u8]) {
    out.push(tag);
    put_bytes(out, payload);
}

/// Serializes the plaintext of a tombstone.
///
/// Same node encoding as an entry, so unknown nodes are skipped here too.
pub(crate) fn encode_tombstone(tombstone: &Tombstone) -> Vec<u8> {
    let mut out = Vec::new();
    put_node(
        &mut out,
        tag::DELETED_AT,
        &tombstone.deleted_at.to_be_bytes(),
    );
    if let Some(by) = &tombstone.deleted_by {
        put_node(&mut out, tag::DELETED_BY, by.as_bytes());
    }
    out
}

/// Parses the plaintext of an entry.
///
/// A known tag (up to `DELETED_BY`, 0x0D) that appears twice is rejected as
/// [`Error::VaultDuplicateField`]; unknown tags are skipped by their length, and several
/// nodes sharing an unknown tag are tolerated, since a newer version may write them
/// legitimately.
///
/// The node loop is bounded by the input length, so a file of pure garbage cannot spin
/// it.
pub(crate) fn decode_entry(data: &[u8]) -> Result<VaultEntry> {
    /// Fields accumulated during parsing: each is filled in through an `Option`, and the
    /// required ones are checked at the end.
    #[derive(Default)]
    struct Fields {
        /// Display name.
        name: Option<String>,
        /// Issuer; an empty node is normalized to `None`.
        issuer: Option<String>,
        /// Account name.
        account: Option<String>,
        /// Secret.
        secret: Option<Vec<u8>>,
        /// Algorithm.
        algorithm: Option<otp::Algorithm>,
        /// Digits.
        digits: Option<otp::Digits>,
        /// Period.
        period: Option<u64>,
        /// Counter.
        counter: Option<u64>,
        /// Note.
        note: String,
        /// Creation time.
        created_at: Option<u64>,
        /// Modification time.
        updated_at: Option<u64>,
    }

    let mut reader = Reader::new(data);
    let mut f = Fields::default();
    let mut seen: u16 = 0;

    let mut guard = data.len() + 1;
    while !reader.is_empty() {
        guard = guard.checked_sub(1).ok_or(Error::VaultCorrupt)?;
        let node_tag = reader.u8().ok_or(Error::VaultTruncated)?;
        let len = reader.u32().ok_or(Error::VaultTruncated)? as usize;
        if len > Entry::MAX_FIELD_LEN {
            return Err(Error::FieldTooLong {
                field: "vault node",
                limit: Entry::MAX_FIELD_LEN,
                actual: len,
            });
        }
        let payload = reader.take(len).ok_or(Error::VaultTruncated)?;

        if node_tag <= tag::DELETED_BY {
            let bit = 1_u16 << node_tag;
            if seen & bit != 0 {
                return Err(Error::VaultDuplicateField { tag: node_tag });
            }
            seen |= bit;
        }

        match node_tag {
            tag::NAME => f.name = Some(utf8(payload)?),
            tag::ISSUER => {
                let text = utf8(payload)?;
                f.issuer = if text.is_empty() { None } else { Some(text) };
            }
            tag::ACCOUNT => f.account = Some(utf8(payload)?),
            tag::SECRET => {
                f.secret = Some(payload.to_vec());
            }
            tag::ALGORITHM => {
                f.algorithm =
                    Some(algorithm_from_byte(single_byte(payload)?).ok_or(Error::VaultCorrupt)?);
            }
            tag::DIGITS => {
                f.digits =
                    Some(digits_from_byte(single_byte(payload)?).ok_or(Error::VaultCorrupt)?);
            }
            tag::PERIOD => f.period = Some(u64_from(payload)?),
            tag::COUNTER => f.counter = Some(u64_from(payload)?),
            tag::NOTE => f.note = utf8(payload)?,
            tag::CREATED_AT => f.created_at = Some(u64_from(payload)?),
            tag::UPDATED_AT => f.updated_at = Some(u64_from(payload)?),
            _ => {}
        }
    }

    let created_at = f.created_at.ok_or(Error::VaultCorrupt)?;
    Entry::new(
        f.name.ok_or(Error::VaultCorrupt)?,
        f.issuer,
        f.account.ok_or(Error::VaultCorrupt)?,
        otp::OtpSecret::from_bytes(f.secret.ok_or(Error::VaultCorrupt)?)?,
        f.algorithm.ok_or(Error::VaultCorrupt)?,
        f.digits.ok_or(Error::VaultCorrupt)?,
        f.period.ok_or(Error::VaultCorrupt)?,
        f.counter,
        f.note,
        created_at,
        f.updated_at.unwrap_or(created_at),
    )
}

/// Parses the plaintext of a tombstone.
pub(crate) fn decode_tombstone(id: EntryId, data: &[u8]) -> Result<Tombstone> {
    let mut reader = Reader::new(data);
    let mut deleted_at = None;
    let mut deleted_by = None;
    let mut guard = data.len() + 1;

    while !reader.is_empty() {
        guard = guard.checked_sub(1).ok_or(Error::VaultCorrupt)?;
        let node_tag = reader.u8().ok_or(Error::VaultTruncated)?;
        let len = reader.u32().ok_or(Error::VaultTruncated)? as usize;
        if len > Entry::MAX_FIELD_LEN {
            return Err(Error::VaultCorrupt);
        }
        let payload = reader.take(len).ok_or(Error::VaultTruncated)?;
        match node_tag {
            tag::DELETED_AT => deleted_at = Some(u64_from(payload)?),
            tag::DELETED_BY => {
                let bytes: [u8; EntryId::LEN] =
                    payload.try_into().map_err(|_| Error::VaultCorrupt)?;
                deleted_by = Some(EntryId::from_bytes(bytes));
            }
            _ => {}
        }
    }

    Ok(Tombstone {
        entry_id: id,
        deleted_at: deleted_at.ok_or(Error::VaultCorrupt)?,
        deleted_by,
    })
}

/// Interprets bytes as UTF-8.
fn utf8(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::VaultInvalidUtf8)
}

/// Reads the single byte of a node that is exactly one byte long.
///
/// Any other length is rejected: extra bytes have no meaning, and ignoring them would let
/// an attacker smuggle data behind a known field.
fn single_byte(payload: &[u8]) -> Result<u8> {
    let bytes: [u8; 1] = payload.try_into().map_err(|_| Error::VaultCorrupt)?;
    Ok(bytes[0])
}

/// Reads a `u64` from an eight-byte node.
fn u64_from(payload: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = payload.try_into().map_err(|_| Error::VaultCorrupt)?;
    Ok(u64::from_be_bytes(bytes))
}

/// Algorithm to storage byte.
const fn algorithm_to_byte(algorithm: otp::Algorithm) -> u8 {
    match algorithm {
        otp::Algorithm::Sha1 => tag::ALG_SHA1,
        otp::Algorithm::Sha256 => tag::ALG_SHA256,
        otp::Algorithm::Sha512 => tag::ALG_SHA512,
    }
}

/// Storage byte to algorithm. An unknown value returns `None`.
///
/// There is **no** fallback to SHA-1: a silent fallback would give the user permanently
/// wrong codes with nothing to diagnose.
const fn algorithm_from_byte(byte: u8) -> Option<otp::Algorithm> {
    match byte {
        tag::ALG_SHA1 => Some(otp::Algorithm::Sha1),
        tag::ALG_SHA256 => Some(otp::Algorithm::Sha256),
        tag::ALG_SHA512 => Some(otp::Algorithm::Sha512),
        _ => None,
    }
}

/// Digit count to storage byte.
const fn digits_to_byte(digits: otp::Digits) -> u8 {
    match digits {
        otp::Digits::Six => tag::DIGITS_SIX,
        otp::Digits::Seven => tag::DIGITS_SEVEN,
        otp::Digits::Eight => tag::DIGITS_EIGHT,
    }
}

/// Storage byte to digit count. An unknown value returns `None`.
const fn digits_from_byte(byte: u8) -> Option<otp::Digits> {
    match byte {
        tag::DIGITS_SIX => Some(otp::Digits::Six),
        tag::DIGITS_SEVEN => Some(otp::Digits::Seven),
        tag::DIGITS_EIGHT => Some(otp::Digits::Eight),
        _ => None,
    }
}

/// Writes bytes to a file atomically.
///
/// "Write a file" is not one operation at the OS level: the target is truncated and then
/// written. Losing power or crashing between the two leaves a **truncated vault**, every
/// entry damaged, with no backup at all. The sequence here writes a temporary file in the
/// same directory, `sync_all`s it, then renames it over the target; `rename` is atomic on
/// POSIX and on Windows within one volume, so the target holds either the old content or
/// the new content, never something in between.
///
/// The temporary name carries the process ID, so two processes in the same directory
/// cannot overwrite the temporary file of each other.
///
/// `sync_all` rather than `flush`: `flush` only hands data from userspace buffers to the
/// kernel, and a crash can still lose the kernel page cache, leaving the renamed target
/// **empty or incomplete** - worse than a torn write, because it looks like it succeeded.
///
/// # Errors
///
/// Any I/O failure returns [`Error::VaultIo`]. A failing call deletes the temporary file
/// on a best-effort basis (a cleanup failure must not mask the real error) and leaves the
/// existing target file **untouched**: a temporary file may remain, which is cleanable
/// garbage rather than data corruption.
pub fn write_file_atomically(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".tmp{}", std::process::id()));
    let tmp_path = parent.join(tmp_name);

    let cleanup = |err| {
        let _ = std::fs::remove_file(&tmp_path);
        err
    };

    let mut file = std::fs::File::create(&tmp_path).map_err(|e| Error::VaultIo {
        reason: e.to_string(),
    })?;
    file.write_all(data).map_err(|e| {
        cleanup(Error::VaultIo {
            reason: e.to_string(),
        })
    })?;
    file.sync_all().map_err(|e| {
        cleanup(Error::VaultIo {
            reason: e.to_string(),
        })
    })?;
    drop(file);

    std::fs::rename(&tmp_path, path).map_err(|e| {
        cleanup(Error::VaultIo {
            reason: e.to_string(),
        })
    })?;
    Ok(())
}

/// Reads and parses a vault from a file.
///
/// # Errors
///
/// A read failure returns [`Error::VaultIo`]; everything else as in
/// [`VaultFile::parse`].
pub fn read_file(master: MasterKey, path: &Path) -> Result<VaultFile> {
    let data = std::fs::read(path).map_err(|e| Error::VaultIo {
        reason: e.to_string(),
    })?;
    VaultFile::parse(master, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> otp::OtpSecret {
        otp::OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("valid secret")
    }

    fn sample_entry(name: &str) -> VaultEntry {
        Entry::new(
            name.into(),
            Some("Example".into()),
            "alice".into(),
            secret(),
            otp::Algorithm::Sha256,
            otp::Digits::Eight,
            30,
            None,
            "note".into(),
            1_700_000_000,
            1_700_000_123,
        )
        .expect("valid entry")
    }

    fn sample_hotp_entry() -> VaultEntry {
        Entry::new(
            "HOTP".into(),
            None,
            "bob".into(),
            secret(),
            otp::Algorithm::Sha1,
            otp::Digits::Six,
            30,
            Some(42),
            String::new(),
            1_700_000_000,
            1_700_000_000,
        )
        .expect("valid entry")
    }

    /// Asserts that two entries are equal in **every** field.
    ///
    /// `OtpSecret` does not implement `PartialEq`, so the secret is compared through its
    /// Base32 representation.
    fn assert_entry_eq(a: &VaultEntry, b: &VaultEntry) {
        assert_eq!(a.name, b.name, "name");
        assert_eq!(a.issuer, b.issuer, "issuer");
        assert_eq!(a.account, b.account, "account");
        assert_eq!(a.secret.to_base32(), b.secret.to_base32(), "secret");
        assert_eq!(a.algorithm, b.algorithm, "algorithm");
        assert_eq!(a.digits, b.digits, "digits");
        assert_eq!(a.period, b.period, "period");
        assert_eq!(a.counter, b.counter, "counter");
        assert_eq!(a.note, b.note, "note");
        assert_eq!(a.created_at, b.created_at, "created_at");
        assert_eq!(a.updated_at, b.updated_at, "updated_at");
    }

    #[test]
    fn create_starts_empty() {
        let file = VaultFile::create().expect("OS randomness available");
        assert!(file.vault().is_empty());
        assert_eq!(file.vault().len(), 0);
        assert_eq!(file.vault().tombstone_count(), 0);
    }

    /// Serialize, parse and decrypt preserve every field.
    #[test]
    fn roundtrip_preserves_every_field() {
        let mut file = VaultFile::create().expect("OS randomness available");
        let id = file
            .vault_mut()
            .insert(sample_entry("GitHub"))
            .expect("insertion succeeds");

        let bytes = file.serialize().expect("serialization succeeds");
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        )
        .expect("parsing succeeds");

        assert_eq!(reopened.vault().len(), 1);
        let restored = reopened.vault().get(&id).expect("the entry must exist");
        assert_entry_eq(&sample_entry("GitHub"), restored);
    }

    /// An HOTP entry keeps its counter.
    #[test]
    fn roundtrip_preserves_hotp_counter() {
        let mut file = VaultFile::create().expect("OS randomness available");
        let id = file
            .vault_mut()
            .insert(sample_hotp_entry())
            .expect("insertion succeeds");
        let bytes = file.serialize().expect("serialization succeeds");
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        )
        .expect("parsing succeeds");
        let restored = reopened.vault().get(&id).expect("the entry must exist");
        assert_eq!(restored.counter, Some(42));
        assert_eq!(restored.uri_type(), crate::uri::UriType::Hotp);
    }

    /// Tombstones survive a round trip and do **not** turn into live entries.
    #[test]
    fn roundtrip_preserves_tombstones() {
        let mut file = VaultFile::create().expect("OS randomness available");
        let id = file
            .vault_mut()
            .insert(sample_entry("Doomed"))
            .expect("insertion succeeds");
        file.vault_mut().remove(&id, 1_800_000_000);

        let bytes = file.serialize().expect("serialization succeeds");
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        )
        .expect("parsing succeeds");

        assert!(
            reopened.vault().is_empty(),
            "the entry must have been deleted"
        );
        assert_eq!(reopened.vault().tombstone_count(), 1);
        let tombstone = reopened
            .vault()
            .get_tombstone(&id)
            .expect("the tombstone must exist");
        assert_eq!(tombstone.entry_id, id);
        assert_eq!(tombstone.deleted_at, 1_800_000_000);
        assert_eq!(tombstone.deleted_by, None);
    }

    /// A repeated removal does not refresh the tombstone timestamp.
    #[test]
    fn repeated_removal_keeps_original_timestamp() {
        let mut vault = Vault::new();
        let id = vault.insert(sample_entry("x")).expect("insertion succeeds");
        vault.remove(&id, 100);
        assert!(vault.remove(&id, 999).is_none());
        assert_eq!(
            vault
                .get_tombstone(&id)
                .expect("tombstone exists")
                .deleted_at,
            100
        );
    }

    /// Many entries survive a round trip, in a deterministic order.
    #[test]
    fn roundtrip_preserves_many_entries() {
        let mut file = VaultFile::create().expect("OS randomness available");
        let mut ids = Vec::new();
        for i in 0..64 {
            ids.push(
                file.vault_mut()
                    .insert(sample_entry(&format!("entry-{i}")))
                    .expect("insertion succeeds"),
            );
        }
        let bytes = file.serialize().expect("serialization succeeds");
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        )
        .expect("parsing succeeds");
        assert_eq!(reopened.vault().len(), 64);
        for id in ids {
            assert!(reopened.vault().get(&id).is_some(), "missing entry {id}");
        }
    }

    /// **Serialization is deterministic in structure**: the same content serialized twice
    /// must have the same length, the same header bytes and the same record order.
    ///
    /// The nonces are random, so the two byte strings differ; what must agree is the
    /// content after parsing back, which is what this checks.
    #[test]
    fn serialization_is_deterministic_in_structure() {
        let mut file = VaultFile::create().expect("OS randomness available");
        for i in 0..16 {
            file.vault_mut()
                .insert(sample_entry(&format!("e{i}")))
                .expect("insertion succeeds");
        }
        let a = file.serialize().expect("serialization succeeds");
        let b = file.serialize().expect("serialization succeeds");

        assert_eq!(a.len(), b.len(), "two serializations differ in length");
        assert_eq!(a[..9], b[..9], "magic and version must match");
        assert_eq!(a[9], b[9], "the reserved byte must match");

        let names = |bytes: &[u8]| -> Vec<String> {
            let f = VaultFile::parse(
                MasterKey::from_bytes(master_key_to_bytes(file.master_key()))
                    .expect("correct length"),
                bytes,
            )
            .expect("parsing succeeds");
            f.vault().iter().map(|(_, e)| e.name.clone()).collect()
        };
        assert_eq!(names(&a), names(&b), "the entry order is nondeterministic");
    }

    /// A different master key cannot open the file.
    #[test]
    fn wrong_master_key_cannot_open() {
        let mut file = VaultFile::create().expect("OS randomness available");
        file.vault_mut()
            .insert(sample_entry("x"))
            .expect("insertion succeeds");
        let bytes = file.serialize().expect("serialization succeeds");

        let other = MasterKey::generate().expect("OS randomness available");
        let err = VaultFile::parse(other, &bytes);
        assert!(matches!(err, Err(Error::VaultDecryptionFailed)));
    }

    /// **Flipping any single byte must be detected.**
    ///
    /// Structural bytes (magic, version, reserved byte, record count, record header) give
    /// a structural error; the nonce and the ciphertext give an authentication failure.
    /// Both are a refusal - no single flipped byte may still decrypt into plausible data.
    #[test]
    fn tampering_any_byte_is_rejected() {
        let mut file = VaultFile::create().expect("OS randomness available");
        file.vault_mut()
            .insert(sample_entry("x"))
            .expect("insertion succeeds");
        file.vault_mut()
            .insert(sample_hotp_entry())
            .expect("insertion succeeds");
        let bytes = file.serialize().expect("serialization succeeds");
        let key_bytes = master_key_to_bytes(file.master_key());

        for index in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[index] ^= 0x01;
            let result = VaultFile::parse(
                MasterKey::from_bytes(key_bytes.clone()).expect("correct length"),
                &tampered,
            );
            assert!(
                result.is_err(),
                "byte {index} was flipped ({:#04x} -> {:#04x}) yet still accepted",
                bytes[index],
                tampered[index]
            );
        }
    }

    /// Truncating the file at any position is rejected.
    #[test]
    fn truncation_at_any_point_is_rejected() {
        let mut file = VaultFile::create().expect("OS randomness available");
        file.vault_mut()
            .insert(sample_entry("x"))
            .expect("insertion succeeds");
        file.vault_mut()
            .insert(sample_hotp_entry())
            .expect("insertion succeeds");
        let first_id = *file.vault().iter().next().expect("has an entry").0;
        file.vault_mut().remove(&first_id, 1);
        let bytes = file.serialize().expect("serialization succeeds");
        let key_bytes = master_key_to_bytes(file.master_key());

        for cut in 1..bytes.len() {
            let result = VaultFile::parse(
                MasterKey::from_bytes(key_bytes.clone()).expect("correct length"),
                &bytes[..cut],
            );
            assert!(
                result.is_err(),
                "truncating to {cut} bytes was still accepted"
            );
        }
    }

    /// Appended bytes are rejected: ignoring them silently would make "the file was
    /// modified" disappear.
    #[test]
    fn trailing_bytes_are_rejected() {
        let mut file = VaultFile::create().expect("OS randomness available");
        file.vault_mut()
            .insert(sample_entry("x"))
            .expect("insertion succeeds");
        let mut bytes = file.serialize().expect("serialization succeeds");
        bytes.push(0x00);

        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        );
        assert!(matches!(err, Err(Error::VaultTrailingBytes { count: 1 })));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let file = VaultFile::create().expect("OS randomness available");
        let mut bytes = file.serialize().expect("serialization succeeds");
        bytes[0] = b'X';
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        );
        assert!(matches!(err, Err(Error::VaultBadMagic)));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let file = VaultFile::create().expect("OS randomness available");
        let mut bytes = file.serialize().expect("serialization succeeds");
        bytes[8] = 99;
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        );
        match err {
            Err(Error::VaultUnsupportedVersion { version }) => assert_eq!(version, 99),
            other => panic!(
                "an unknown version must be rejected, actual ok={}",
                other.is_ok()
            ),
        }
    }

    #[test]
    fn nonzero_reserved_byte_is_rejected() {
        let file = VaultFile::create().expect("OS randomness available");
        let mut bytes = file.serialize().expect("serialization succeeds");
        bytes[9] = 1;
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        );
        assert!(matches!(
            err,
            Err(Error::VaultReservedByteNotZero { value: 1 })
        ));
    }

    #[test]
    fn unknown_record_kind_is_rejected() {
        let mut file = VaultFile::create().expect("OS randomness available");
        file.vault_mut()
            .insert(sample_entry("x"))
            .expect("insertion succeeds");
        let mut bytes = file.serialize().expect("serialization succeeds");
        bytes[14] = 0x7F;
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        );
        assert!(matches!(
            err,
            Err(Error::VaultUnknownRecordKind { value: 0x7F })
        ));
    }

    #[test]
    fn duplicate_entry_id_is_rejected() {
        let mut file = VaultFile::create().expect("OS randomness available");
        let id = file
            .vault_mut()
            .insert(sample_entry("x"))
            .expect("insertion succeeds");

        let mut vault = Vault::new();
        vault
            .insert_with_id(id, sample_entry("a"))
            .expect("first insertion");
        let err = vault.insert_with_id(id, sample_entry("b"));
        assert!(matches!(err, Err(Error::VaultDuplicateEntryId)));

        assert_eq!(vault.len(), 1);
        assert_eq!(vault.get(&id).expect("entry exists").name, "a");
    }

    /// `replace` renames in place: the ID stays, no tombstone is left, and the caller can
    /// preserve the creation time.
    #[test]
    fn replace_keeps_the_id_and_leaves_no_tombstone() {
        let mut vault = Vault::new();
        let id = vault
            .insert(sample_entry("original"))
            .expect("insertion succeeds");
        let created = vault.get(&id).expect("entry exists").created_at;

        let mut renamed = sample_entry("renamed");
        renamed.created_at = created;
        vault
            .replace(id, renamed)
            .expect("replacement must succeed");

        let entry = vault
            .get(&id)
            .expect("the identifier must still point at that entry");
        assert_eq!(entry.name, "renamed");
        assert_eq!(
            entry.created_at, created,
            "the creation time must be preserved"
        );
        assert_eq!(vault.len(), 1, "a replacement must not add an entry");
        assert_eq!(
            vault.tombstone_count(),
            0,
            "a rename is not a deletion and must not leave a tombstone: the tombstone gets synced out and the other side may really delete the entry because of it"
        );
    }

    /// Replacing a missing entry is an error rather than a silent insert, and it must not
    /// add the entry back.
    #[test]
    fn replace_of_a_missing_entry_is_rejected() {
        let mut vault = Vault::new();
        let missing = EntryId::from_bytes([0x5A; EntryId::LEN]);
        let err = vault.replace(missing, sample_entry("ghost"));
        assert!(matches!(err, Err(Error::VaultEntryNotFound)));
        assert!(vault.is_empty(), "a failure must not conjure up an entry");
    }

    /// An empty vault round-trips, and its file is the 14-byte header plus the master key
    /// check value.
    #[test]
    fn empty_vault_roundtrips() {
        let file = VaultFile::create().expect("OS randomness available");
        let bytes = file.serialize().expect("serialization succeeds");
        assert_eq!(
            bytes.len(),
            14 + crypto::KEY_CHECK_LEN,
            "an empty file must be the header plus the master key check value"
        );
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        )
        .expect("parsing succeeds");
        assert!(reopened.vault().is_empty());
        assert_eq!(reopened.vault().tombstone_count(), 0);
    }

    /// An **empty** vault detects a wrong master key: the check value is decidable even
    /// when there are zero records to authenticate.
    #[test]
    fn an_empty_vault_detects_a_wrong_master_key() {
        let file = VaultFile::create().expect("OS randomness available");
        assert!(
            file.vault().is_empty(),
            "precondition: this vault really is empty"
        );
        let bytes = file.serialize().expect("serialization succeeds");

        let wrong = MasterKey::generate().expect("OS randomness available");
        assert_ne!(
            wrong.expose(),
            file.master_key().expose(),
            "the two keys must differ"
        );

        let err = VaultFile::parse(wrong, &bytes);
        assert!(
            matches!(err, Err(Error::VaultDecryptionFailed)),
            "an empty vault must be rejected with the wrong key too, actual ok={}",
            err.is_ok()
        );
    }

    /// A version 1 file is still readable: version byte 1, no trailing check value, record
    /// AAD version 1. Built by hand because serialization always writes version 2 now; the
    /// property pinned here is the byte layout itself.
    #[test]
    fn version_1_files_are_still_readable() {
        let master = MasterKey::generate().expect("OS randomness available");
        let id = EntryId::generate().expect("OS randomness available");
        let entry = sample_entry("old-format");
        let plaintext = encode_entry(&entry).expect("encoding succeeds");
        let (nonce, ciphertext) =
            crypto::seal(&master, RecordKind::Entry, &id, 1, &plaintext).expect("sealing succeeds");

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(1);
        out.push(0);
        put_u32(&mut out, 1);
        out.push(RecordKind::Entry.as_byte());
        out.extend_from_slice(id.as_bytes());
        out.extend_from_slice(&nonce);
        put_u32(
            &mut out,
            u32::try_from(ciphertext.len()).expect("the test data is far below u32::MAX"),
        );
        out.extend_from_slice(&ciphertext);

        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(&master)).expect("correct length"),
            &out,
        )
        .expect("a version 1 file must still parse");
        assert_eq!(reopened.vault().len(), 1, "the entry must be read back");
        assert_eq!(
            reopened.vault().iter().next().expect("one entry").1.name,
            "old-format"
        );

        let wrong = MasterKey::generate().expect("OS randomness available");
        assert!(
            VaultFile::parse(wrong, &out).is_err(),
            "a version 1 file with content must fail under the wrong key"
        );
    }

    /// A version 1 file with zero records parses under any key: it has no check value.
    /// Known limit of that format, pinned so it is not mistaken for fixed.
    #[test]
    fn a_version_1_empty_file_still_cannot_detect_a_wrong_key() {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(1);
        out.push(0);
        put_u32(&mut out, 0);

        let wrong = MasterKey::generate().expect("OS randomness available");
        let parsed = VaultFile::parse(wrong, &out);
        assert!(
            parsed.is_ok(),
            "an empty version 1 file has no check value, so any key parses it; that is a known limitation of that format"
        );
    }

    /// Flipping any byte of the key check value is rejected.
    #[test]
    fn a_tampered_key_check_is_rejected() {
        let file = VaultFile::create().expect("OS randomness available");
        let master =
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length");
        let bytes = file.serialize().expect("serialization succeeds");

        for index in 0..crypto::KEY_CHECK_LEN {
            let mut tampered = bytes.clone();
            let last = tampered.len() - crypto::KEY_CHECK_LEN + index;
            tampered[last] ^= 0x01;
            let err = VaultFile::parse(
                MasterKey::from_bytes(master_key_to_bytes(&master)).expect("correct length"),
                &tampered,
            );
            assert!(
                matches!(err, Err(Error::VaultDecryptionFailed)),
                "check value byte {index} was flipped yet still accepted"
            );
        }
    }

    /// A truncated key check value reports a **structural** error, not a decryption
    /// failure: the two are handled differently by the UI (unusable file versus wrong key),
    /// so merging them would send the user after the wrong problem.
    #[test]
    fn a_truncated_key_check_is_a_structural_error() {
        let file = VaultFile::create().expect("OS randomness available");
        let master =
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length");
        let bytes = file.serialize().expect("serialization succeeds");

        let mut cut = bytes.clone();
        cut.truncate(cut.len() - 3);
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(&master)).expect("correct length"),
            &cut,
        );
        assert!(
            matches!(err, Err(Error::VaultTruncated)),
            "a truncated check value must report truncation, actual ok={}",
            err.is_ok()
        );

        let err = crypto::verify_key_check(&master, &[0_u8; 8]);
        assert!(
            matches!(err, Err(Error::VaultBadKeyCheck)),
            "a length mismatch must report VaultBadKeyCheck"
        );
    }

    /// The file header layout is an external contract, pinned here.
    #[test]
    fn file_header_layout_is_stable() {
        let file = VaultFile::create().expect("OS randomness available");
        let bytes = file.serialize().expect("serialization succeeds");
        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(bytes[8], FORMAT_VERSION);
        assert_eq!(bytes[9], 0, "reserved byte");
        assert_eq!(
            u32::from_be_bytes(bytes[10..14].try_into().expect("4 bytes")),
            0
        );
    }

    /// An unknown node tag is skipped rather than rejected - the whole of forward
    /// compatibility.
    #[test]
    fn unknown_entry_node_is_skipped() {
        let entry = sample_entry("x");
        let mut plaintext = encode_entry(&entry).expect("encoding succeeds");

        plaintext.push(0xEE);
        put_bytes(&mut plaintext, b"future field");

        let decoded = decode_entry(&plaintext).expect("unknown nodes must be skipped");
        assert_entry_eq(&entry, &decoded);
    }

    /// Skipping an unknown node consumes exactly its declared length.
    #[test]
    fn skipping_unknown_node_uses_its_length() {
        let entry = sample_entry("x");
        let mut plaintext = Vec::new();
        plaintext.push(0xEE);
        put_bytes(&mut plaintext, &[0xAA; 100]);
        plaintext.extend_from_slice(&encode_entry(&entry).expect("encoding succeeds"));

        let decoded = decode_entry(&plaintext).expect("must skip 100 bytes");
        assert_entry_eq(&entry, &decoded);
    }

    /// An unknown tag whose length exceeds the remaining data is rejected rather than read
    /// out of range.
    #[test]
    fn unknown_node_with_overlong_length_is_rejected() {
        let mut plaintext = Vec::new();
        plaintext.push(0xEE);
        put_u32(&mut plaintext, 9999);
        plaintext.extend_from_slice(b"short");
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::VaultTruncated)));
    }

    /// A repeated known node is rejected.
    #[test]
    fn duplicate_known_node_is_rejected() {
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, b"first");
        put_node(&mut plaintext, tag::NAME, b"second");
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::VaultDuplicateField { .. })));
    }

    /// A missing required node is rejected.
    #[test]
    fn missing_required_node_is_rejected() {
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, b"only a name");
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::VaultCorrupt)));
    }

    /// An empty secret node is rejected.
    #[test]
    fn empty_secret_node_is_rejected() {
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, b"n");
        put_node(&mut plaintext, tag::ACCOUNT, b"a");
        put_node(&mut plaintext, tag::SECRET, b"");
        put_node(&mut plaintext, tag::ALGORITHM, &[tag::ALG_SHA1]);
        put_node(&mut plaintext, tag::DIGITS, &[tag::DIGITS_SIX]);
        put_node(&mut plaintext, tag::PERIOD, &30_u64.to_be_bytes());
        put_node(&mut plaintext, tag::CREATED_AT, &0_u64.to_be_bytes());
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::SecretEmpty)));
    }

    /// A non-UTF-8 text node is rejected rather than replaced lossily.
    #[test]
    fn invalid_utf8_is_rejected() {
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, &[0xFF, 0xFE]);
        put_node(&mut plaintext, tag::ACCOUNT, b"a");
        put_node(&mut plaintext, tag::SECRET, b"secret");
        put_node(&mut plaintext, tag::ALGORITHM, &[tag::ALG_SHA1]);
        put_node(&mut plaintext, tag::DIGITS, &[tag::DIGITS_SIX]);
        put_node(&mut plaintext, tag::PERIOD, &30_u64.to_be_bytes());
        put_node(&mut plaintext, tag::CREATED_AT, &0_u64.to_be_bytes());
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::VaultInvalidUtf8)));
    }

    /// Algorithm and digit bytes round-trip through the storage format, and unknown values
    /// are rejected rather than defaulted.
    #[test]
    fn algorithm_and_digits_bytes_roundtrip() {
        for algorithm in [
            otp::Algorithm::Sha1,
            otp::Algorithm::Sha256,
            otp::Algorithm::Sha512,
        ] {
            assert_eq!(
                algorithm_from_byte(algorithm_to_byte(algorithm)),
                Some(algorithm)
            );
        }
        for digits in [otp::Digits::Six, otp::Digits::Seven, otp::Digits::Eight] {
            assert_eq!(digits_from_byte(digits_to_byte(digits)), Some(digits));
        }
        assert_eq!(algorithm_from_byte(0), None);
        assert_eq!(algorithm_from_byte(99), None);
        assert_eq!(digits_from_byte(5), None);
        assert_eq!(digits_from_byte(9), None);
    }

    /// `None` and `Some("")` for `issuer` normalize across a round trip.
    #[test]
    fn issuer_none_and_empty_normalize() {
        let mut entry = sample_entry("x");
        entry.issuer = None;
        let decoded = decode_entry(&encode_entry(&entry).expect("encoding succeeds"))
            .expect("decoding succeeds");
        assert_eq!(decoded.issuer, None);

        entry.issuer = Some(String::new());
        let decoded = decode_entry(&encode_entry(&entry).expect("encoding succeeds"))
            .expect("decoding succeeds");
        assert_eq!(
            decoded.issuer, None,
            "an empty string must normalize to None"
        );
    }

    /// An atomic write leaves exactly the bytes passed in and leaves no temporary file
    /// behind.
    #[test]
    fn atomic_write_produces_exact_content() {
        let dir = std::env::temp_dir().join(format!("q2fa-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("directory creation succeeds");
        let path = dir.join("vault.bin");

        let data = b"hello atomic world";
        write_file_atomically(&path, data).expect("writing succeeds");
        assert_eq!(std::fs::read(&path).expect("reading succeeds"), data);

        let longer = b"a much longer replacement payload";
        write_file_atomically(&path, longer).expect("writing succeeds");
        assert_eq!(std::fs::read(&path).expect("reading succeeds"), longer);

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("listing the directory succeeds")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "leftover temporary files: {leftovers:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A full write-then-read round trip preserves the vault.
    #[test]
    fn write_then_read_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("q2fa-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("directory creation succeeds");
        let path = dir.join("vault.bin");

        let mut file = VaultFile::create().expect("OS randomness available");
        let id = file
            .vault_mut()
            .insert(sample_entry("GitHub"))
            .expect("insertion succeeds");
        let bytes = file.serialize().expect("serialization succeeds");
        write_file_atomically(&path, &bytes).expect("writing succeeds");

        let key =
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length");
        let reopened = read_file(key, &path).expect("reading back succeeds");
        assert_eq!(reopened.vault().len(), 1);
        assert_entry_eq(
            &sample_entry("GitHub"),
            reopened.vault().get(&id).expect("entry exists"),
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reading a missing file returns an I/O error rather than panicking.
    #[test]
    fn reading_missing_file_reports_io_error() {
        let key = MasterKey::generate().expect("OS randomness available");
        let err = read_file(key, Path::new("definitely/not/here/vault.bin"));
        assert!(matches!(err, Err(Error::VaultIo { .. })));
    }

    /// Empty input is rejected without panicking.
    #[test]
    fn empty_input_is_rejected() {
        let key = MasterKey::generate().expect("OS randomness available");
        assert!(matches!(
            VaultFile::parse(key, &[]),
            Err(Error::VaultTruncated)
        ));
    }

    /// A file claiming an absurd record count is rejected, and **no allocation is
    /// attempted**.
    #[test]
    fn absurd_record_count_is_rejected() {
        let key = MasterKey::generate().expect("OS randomness available");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.push(0);
        put_u32(&mut bytes, u32::MAX);
        let err = VaultFile::parse(key, &bytes);
        assert!(matches!(err, Err(Error::VaultTooManyRecords)));
    }

    /// A file claiming an over-long record is rejected, and no allocation is attempted.
    #[test]
    fn absurd_record_length_is_rejected() {
        let key = MasterKey::generate().expect("OS randomness available");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.push(0);
        put_u32(&mut bytes, 1);
        bytes.push(0x01);
        bytes.extend_from_slice(&[0_u8; EntryId::LEN]);
        bytes.extend_from_slice(&[0_u8; NONCE_LEN]);
        put_u32(&mut bytes, u32::MAX);
        let err = VaultFile::parse(key, &bytes);
        match err {
            Err(Error::VaultRecordTooLong { limit, actual }) => {
                assert_eq!(limit, MAX_RECORD_LEN);
                assert_eq!(actual, u32::MAX as usize);
            }
            other => panic!(
                "an over-long record must be rejected, actual ok={}",
                other.is_ok()
            ),
        }
    }

    /// Unencrypted garbage is rejected (by the magic or by authentication).
    #[test]
    fn garbage_with_correct_magic_is_rejected() {
        let key = MasterKey::generate().expect("OS randomness available");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.push(0);
        put_u32(&mut bytes, 1);
        bytes.push(0x01);
        bytes.extend_from_slice(&[0x11; EntryId::LEN]);
        bytes.extend_from_slice(&[0x22; NONCE_LEN]);
        put_u32(&mut bytes, 32);
        bytes.extend_from_slice(&[0x33; 32]);
        let err = VaultFile::parse(key, &bytes);
        assert!(matches!(err, Err(Error::VaultDecryptionFailed)));
    }
}
