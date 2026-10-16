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
//! # File format v3
//!
//! All integers are **big-endian**. Layout:
//!
//! ```text
//! Offset    Length  Content
//! 0         8       magic "Q2FAVLT\0"
//! 8         1       format version (currently 3)
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
//! 0         1       record kind (1 = live entry, 2 = tombstone, 3 = group)
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
//! ## Versions 1 and 2 remain readable
//!
//! Version 1 has no trailing 32 bytes; parsing simply skips the check-value step,
//! everything else is identical. Version 2 adds that check value and is otherwise the
//! same layout. Reading is driven by the version the file declares, so both keep working
//! unchanged: after upgrading the application, an existing file must still open.
//!
//! **The converse does not hold.** A version 1 parser rejects a version 2 (or 3) file,
//! because it carries a "reject any trailing bytes" check and those 32 bytes look
//! like trailing content to it. Repairing that would mean relaxing the check, which
//! would also make "the file had content appended" disappear silently - a higher
//! price than "an old version cannot open a new file". Users on the old version see
//! a clear error, not garbled data.
//!
//! ## What version 3 is for
//!
//! An entry's plaintext gained the **entry kind** node, so a version 2 parser reading a
//! version 3 file would skip it and fall back to "counter present means HOTP", turning an
//! mOTP entry into a plausible TOTP entry with codes that never work. Version 3 is therefore
//! written by every file this build produces, and a version 3 file that happens to contain
//! only TOTP/HOTP entries differs from a version 2 file in nothing but that number.
//!
//! # Groups and orderings
//!
//! A group is a **record of its own** (kind 3) holding a name, a position and the ordered list
//! of the identifiers it contains. The list *is* the order: the sequence number of an entry is
//! its index there, so reordering rewrites one record and touches no entry. The entries that
//! belong to no named group are the **top group**, which is a group like any other with the
//! reserved identifier [`GroupId::TOP`] - it is what makes "the rest" sortable, and it is why a
//! file written before groups existed still reads as a definite order (the order its entry
//! records appear in).
//!
//! **Synchronization does not transport group records yet.** Payloads carry entries and
//! tombstones, so a peer receiving a vault receives the entries and puts them in its own top
//! group: the grouping and the order stay local to the device that has them. Two devices
//! therefore converge on **content** and not on arrangement, which the interface must not
//! present as agreement.
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
mod group;

pub use crypto::{
    KEY_CHECK_LEN, MASTER_KEY_LEN, MasterKey, NONCE_LEN, TAG_LEN, key_check, master_key_to_bytes,
    verify_key_check,
};
pub use entry::{Entry, EntryId, EntryKind, Timestamp, entry_from_parsed_uri};
pub use group::{Group, GroupId};

pub(crate) use crypto::RecordKind;

use std::collections::BTreeMap;
use std::path::Path;

use crate::{Error, Result, otp};
use codec::{Reader, put_bytes, put_u32};
use entry::Entry as VaultEntry;

/// File magic. 8 bytes; the trailing NUL makes it recognizable in a hex editor.
pub const MAGIC: &[u8; 8] = b"Q2FAVLT\0";

/// Format version currently written: 3.
///
/// # Version 1 → 2: the master key check value
///
/// Version 2 differs from version 1 in exactly one place: the master key check value
/// at the end of the file, which lets "which master key wrote this file" be decided
/// **before the first record is read**. In version 1 the master key only took part in
/// each record AEAD, so **a file with no entries parsed successfully under any 32-byte
/// key** - a mis-stored key surfaced only once the first entry was added, long after
/// the UI had shown "opened successfully".
///
/// # Version 2 → 3: richer entry plaintext
///
/// Version 3 exists because an entry's plaintext can now carry node tags a version 2
/// parser does not know: the **entry kind** (TOTP / HOTP / mOTP / Yandex OTP / Steam
/// Guard) and the PIN fields of the two PIN-based schemes. A version 2 parser skips unknown
/// nodes by their length and then decides the type from whether a counter node is present,
/// which turns an mOTP entry into a plausible-looking TOTP entry whose code never works.
///
/// A version 3 file containing only TOTP/HOTP entries is byte-identical to a version 2 file
/// apart from this number, but the number is still written unconditionally: deciding the
/// version from the contents would make "which version is this?" a branch that itself needs
/// independent verification, and the two versions are not worth keeping compatible -
/// nothing was lost between them.
///
/// # This constant is **also** the version number in the record AAD
///
/// It therefore cannot merely describe a layout: change the number in the AAD and
/// every old record tag stops verifying. Parsing must use **the version declared by
/// the file being parsed**, never this constant; otherwise reading a version 1 file
/// fails authentication on every record. See `version` in [`VaultFile::parse`].
///
/// # Versions 1 and 2 are still readable
///
/// A version 1 file has no check value, so `parse` skips that step and behaves as
/// before (including the known limitation); a version 2 file is read exactly as it was
/// written, including the check value. The converse **does not hold**: a version 1 parser
/// rejects a version 2 or 3 file over the extra trailing bytes (it carries a "reject any
/// trailing bytes" check) and reports [`Error::VaultTrailingBytes`] rather than an
/// unsupported version. That follows directly from version 1 having no skip path for richer
/// future versions, and it cannot be repaired without relaxing that check - which would make
/// "the file had content appended" disappear silently.
pub const FORMAT_VERSION: u8 = 3;

/// Format versions that can be parsed: 1, 2 and the current [`FORMAT_VERSION`].
///
/// Listed explicitly rather than derived from [`FORMAT_VERSION`]: `&[1, FORMAT_VERSION]`
/// silently dropped version 2 the moment the constant moved to 3, which would have made every
/// existing user file unopenable with an error suggesting the file is broken.
///
/// Only added to, never removed: dropping a version would suddenly make an old file
/// unopenable, and the error message ("unsupported version") would suggest the file
/// is broken.
///
/// Public so that the "old versions stay readable" promise is pinned by tests
/// directly, instead of a test restating the version number - where both sides would
/// change together and never fail.
pub const READABLE_VERSIONS: &[u8] = &[1, 2, FORMAT_VERSION];

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
    /// Which scheme the entry uses (TOTP / HOTP / mOTP / Yandex OTP / Steam Guard).
    ///
    /// Added in format version 3. A version 1 or 2 file has no such node, and the parser then
    /// falls back to the older rule: a counter node means HOTP, its absence means TOTP.
    pub(super) const ENTRY_KIND: u8 = 0x0E;
    /// mOTP PIN (UTF-8 text).
    pub(super) const MOTP_PIN: u8 = 0x0F;
    /// Yandex OTP PIN (UTF-8 text).
    pub(super) const YANDEX_PIN: u8 = 0x10;
    /// Position of a group among the named groups (u32).
    ///
    /// Only meaningful inside a **group** record.
    pub(super) const GROUP_ORDER: u8 = 0x11;
    /// The ordering of a group: its entry identifiers, concatenated (16 bytes each).
    pub(super) const ENTRY_IDS: u8 = 0x12;

    /// Highest tag an **entry** may carry that this version knows.
    ///
    /// Kept separate from [`tag::GROUP_TAG_MAX`] on purpose: the two record kinds are parsed by
    /// different functions, and a tag only a group record uses must stay "unknown" to the entry
    /// parser, so that a future version may repeat it there without an older build refusing the
    /// file.
    pub(super) const ENTRY_TAG_MAX: u8 = YANDEX_PIN;

    /// Highest tag a **group** record may carry that this version knows.
    pub(super) const GROUP_TAG_MAX: u8 = ENTRY_IDS;

    /// Value of the algorithm field.
    pub(super) const ALG_SHA1: u8 = 1;
    /// Value of the algorithm field.
    pub(super) const ALG_SHA256: u8 = 2;
    /// Value of the algorithm field.
    pub(super) const ALG_SHA512: u8 = 3;

    /// Value of the entry kind field: TOTP.
    pub(super) const KIND_TOTP: u8 = 1;
    /// Value of the entry kind field: HOTP.
    pub(super) const KIND_HOTP: u8 = 2;
    /// Value of the entry kind field: mOTP.
    pub(super) const KIND_MOTP: u8 = 3;
    /// Value of the entry kind field: Yandex OTP.
    pub(super) const KIND_YANDEX: u8 = 4;
    /// Value of the entry kind field: Steam Guard.
    pub(super) const KIND_STEAM: u8 = 5;

    // The digit count has no constants of its own: a count from 1 to 9 is stored as the
    // byte holding that number, so [`otp::Digits::as_byte`] is the whole mapping.
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
    /// Groups, ordered by identifier.
    ///
    /// Their **display** order is [`Group::group_order`], not the map order; the top group
    /// ([`GroupId::TOP`]) comes first by definition.
    groups: BTreeMap<GroupId, Group>,
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
        self.top_group_mut().entry_ids.push(id);
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
        self.top_group_mut().entry_ids.push(id);
        Ok(())
    }

    /// Inserts an entry **without touching any ordering**.
    ///
    /// For the parser only: the group records may come after the entry records in the file, so
    /// the orderings are decided once everything has been read (see
    /// `reconcile_groups`); a membership built here would only be undone there.
    fn insert_parsed(&mut self, id: EntryId, entry: VaultEntry) -> Result<()> {
        if self.entries.contains_key(&id) {
            return Err(Error::VaultDuplicateEntryId);
        }
        self.entries.insert(id, entry);
        Ok(())
    }

    /// Inserts a group under a given identifier. **For parsing an existing vault file only**
    /// (the counterpart of [`Vault::insert_with_id`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultDuplicateGroupId`] when the identifier is already taken.
    pub fn insert_group_with_id(&mut self, id: GroupId, group: Group) -> Result<()> {
        if self.groups.contains_key(&id) {
            return Err(Error::VaultDuplicateGroupId);
        }
        self.groups.insert(id, group);
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
        self.detach_everywhere(id);
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

/// Groups and orderings.
///
/// # The membership invariant
///
/// **A live entry appears in at most one group's list.** Two lists naming the same entry would
/// put it in two places at once, and the interface would have to pick one anyway; this type
/// keeps the choice here, where it can be tested, instead of leaving it to each caller.
/// [`Vault::set_ordering`] and [`Vault::assign_to_group`] therefore *move* an entry rather than
/// copy it, and the parser repairs a file that violates the rule (see
/// `reconcile_groups`).
///
/// # Every entry is somewhere
///
/// An entry that belongs to no named group sits in the **top group**, which is why
/// [`Vault::insert`] appends it there. "In no group at all" is not a state: it would make the
/// interface silently omit entries that exist.
impl Vault {
    /// Iterates the groups in display order: the top group first, then the named ones by
    /// [`Group::group_order`], ties broken by identifier so that the order is deterministic.
    pub fn groups(&self) -> impl Iterator<Item = (&GroupId, &Group)> {
        let mut ordered: Vec<(&GroupId, &Group)> = self.groups.iter().collect();
        ordered.sort_by_key(|(id, group)| (u8::from(!id.is_top()), group.group_order, **id));
        ordered.into_iter()
    }

    /// Number of groups, the top group included when it exists.
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Returns a group by identifier.
    #[must_use]
    pub fn group(&self, id: &GroupId) -> Option<&Group> {
        self.groups.get(id)
    }

    /// Returns the top group, when the vault has one.
    ///
    /// An empty vault has none: the group is created by the first insertion or by parsing a
    /// file that holds entries.
    #[must_use]
    pub fn top_group(&self) -> Option<&Group> {
        self.groups.get(&GroupId::TOP)
    }

    /// Returns the ordering of a group: the entry identifiers in display order.
    #[must_use]
    pub fn ordering(&self, id: &GroupId) -> Option<&[EntryId]> {
        self.groups.get(id).map(|group| group.entry_ids.as_slice())
    }

    /// Returns the group an entry belongs to.
    #[must_use]
    pub fn group_of(&self, entry: &EntryId) -> Option<&GroupId> {
        self.groups
            .iter()
            .find(|(_, group)| group.entry_ids.contains(entry))
            .map(|(id, _)| id)
    }

    /// Iterates the entries of a group, in display order.
    ///
    /// Identifiers that name no live entry are skipped: a peer may hold an ordering that
    /// mentions an entry this device does not have (yet), and the interface must show the rest
    /// rather than nothing.
    pub fn entries_in(&self, id: &GroupId) -> impl Iterator<Item = (&EntryId, &VaultEntry)> {
        self.groups
            .get(id)
            .into_iter()
            .flat_map(|group| group.entry_ids.iter())
            .filter_map(|entry_id| self.entries.get(entry_id).map(|entry| (entry_id, entry)))
    }

    /// Creates a named group at the end of the order and returns its identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`] when the OS random source is unavailable, and
    /// [`Error::FieldTooLong`] when the name is longer than
    /// [`Entry::MAX_FIELD_LEN`].
    pub fn create_group(&mut self, name: String) -> Result<GroupId> {
        let id = GroupId::generate()?;
        let order = self.next_group_order();
        let group = Group::new(name, order, Vec::new())?;
        self.groups.insert(id, group);
        Ok(id)
    }

    /// Renames a group.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultTopGroupImmutable`] for the top group (it has no name to edit),
    /// [`Error::VaultGroupNotFound`] when there is no such group, and [`Error::FieldTooLong`]
    /// when the name is too long.
    pub fn rename_group(&mut self, id: &GroupId, name: String) -> Result<()> {
        if id.is_top() {
            return Err(Error::VaultTopGroupImmutable);
        }
        if name.len() > Entry::MAX_FIELD_LEN {
            return Err(Error::FieldTooLong {
                field: "group name",
                limit: Entry::MAX_FIELD_LEN,
                actual: name.len(),
            });
        }
        let group = self.groups.get_mut(id).ok_or(Error::VaultGroupNotFound)?;
        group.name = name;
        Ok(())
    }

    /// Moves a named group to a position among the named groups and renumbers the rest.
    ///
    /// The position is clamped to the end, so "move to the bottom" needs no special case. The
    /// orders are then reassigned as `0..n`, which keeps "the order of a group is the number it
    /// carries" true instead of merely likely.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultTopGroupImmutable`] for the top group (its position is fixed) and
    /// [`Error::VaultGroupNotFound`] when there is no such group.
    pub fn reorder_group(&mut self, id: &GroupId, position: usize) -> Result<()> {
        if id.is_top() {
            return Err(Error::VaultTopGroupImmutable);
        }
        if !self.groups.contains_key(id) {
            return Err(Error::VaultGroupNotFound);
        }

        let mut named = self.named_group_ids();
        let current = named
            .iter()
            .position(|candidate| candidate == id)
            .ok_or(Error::VaultGroupNotFound)?;
        let target = position.min(named.len().saturating_sub(1));
        let moved = named.remove(current);
        named.insert(target, moved);

        for (order, group_id) in named.iter().enumerate() {
            if let Some(group) = self.groups.get_mut(group_id) {
                group.group_order =
                    u32::try_from(order).map_err(|_| Error::VaultGroupTooManyEntries {
                        limit: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
                        actual: order,
                    })?;
            }
        }
        Ok(())
    }

    /// Removes a group. The entries it held move to the top group, keeping their relative
    /// order.
    ///
    /// They are **not** deleted: deleting entries because a grouping was removed would turn a
    /// presentation choice into data loss.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultTopGroupImmutable`] for the top group; `Ok(None)` when there is no
    /// such group.
    pub fn remove_group(&mut self, id: &GroupId) -> Result<Option<Group>> {
        if id.is_top() {
            return Err(Error::VaultTopGroupImmutable);
        }
        let Some(removed) = self.groups.remove(id) else {
            return Ok(None);
        };

        for entry_id in &removed.entry_ids {
            if self.entries.contains_key(entry_id) {
                self.top_group_mut().entry_ids.push(*entry_id);
            }
        }
        self.renumber_named_groups();
        Ok(Some(removed))
    }

    /// Replaces the ordering of a group.
    ///
    /// The list **is** the order: index 0 comes first. Identifiers that already belong to
    /// another group are **moved** out of it, and identifiers missing from that other group's
    /// list are appended to its end, so that the membership invariant survives any caller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultGroupNotFound`] when there is no such group,
    /// [`Error::VaultGroupUnknownEntry`] when the list names an entry the vault does not hold
    /// (the caller is out of step, unlike a peer's file, where such a reference is skipped),
    /// [`Error::VaultGroupDuplicateEntry`] when one entry appears twice, and
    /// [`Error::VaultGroupTooManyEntries`] when the list is longer than the format allows.
    pub fn set_ordering(&mut self, id: &GroupId, entry_ids: Vec<EntryId>) -> Result<()> {
        if !self.groups.contains_key(id) {
            return Err(Error::VaultGroupNotFound);
        }
        for entry_id in &entry_ids {
            if !self.entries.contains_key(entry_id) {
                return Err(Error::VaultGroupUnknownEntry);
            }
        }
        let replacement = Group::new(String::new(), 0, entry_ids)?.entry_ids;

        for entry_id in &replacement {
            self.detach_from_other_groups(entry_id, id);
        }
        self.groups.get_mut(id).expect("checked above").entry_ids = replacement;
        Ok(())
    }

    /// Moves an entry into a group, appending it to that group's ordering.
    ///
    /// This is the "move to group" operation: it removes the entry from wherever it was, so the
    /// membership invariant holds without the caller having to know where the entry came from.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultGroupNotFound`] when there is no such group and
    /// [`Error::VaultEntryNotFound`] when the vault holds no such entry.
    pub fn assign_to_group(&mut self, entry: &EntryId, group: &GroupId) -> Result<()> {
        if !self.entries.contains_key(entry) {
            return Err(Error::VaultEntryNotFound);
        }
        if !self.groups.contains_key(group) {
            return Err(Error::VaultGroupNotFound);
        }
        if self.group_of(entry) == Some(group) {
            return Ok(());
        }
        self.detach_from_other_groups(entry, group);
        self.groups
            .get_mut(group)
            .expect("checked above")
            .entry_ids
            .push(*entry);
        Ok(())
    }

    /// Drops every reference to an entry, so nothing points at an entry that is gone.
    fn detach_everywhere(&mut self, entry: &EntryId) {
        for group in self.groups.values_mut() {
            group.entry_ids.retain(|candidate| candidate != entry);
        }
    }

    /// Drops references to an entry from every group **except** `keep`.
    fn detach_from_other_groups(&mut self, entry: &EntryId, keep: &GroupId) {
        for (id, group) in &mut self.groups {
            if id == keep {
                continue;
            }
            group.entry_ids.retain(|candidate| candidate != entry);
        }
    }

    /// The top group, created empty when the vault has none.
    fn top_group_mut(&mut self) -> &mut Group {
        self.groups
            .entry(GroupId::TOP)
            .or_insert_with(Group::top_empty)
    }

    /// The identifier order of the named groups, top group excluded.
    fn named_group_ids(&self) -> Vec<GroupId> {
        let mut named: Vec<(&GroupId, &Group)> =
            self.groups.iter().filter(|(id, _)| !id.is_top()).collect();
        named.sort_by_key(|(id, group)| (group.group_order, **id));
        named.into_iter().map(|(id, _)| *id).collect()
    }

    /// The order number a newly created group takes: one past the last named group.
    fn next_group_order(&self) -> u32 {
        self.groups
            .iter()
            .filter(|(id, _)| !id.is_top())
            .map(|(_, group)| group.group_order)
            .max()
            .map_or(0, |order| order.saturating_add(1))
    }

    /// Renumbers the named groups as `0..n` in their current order.
    fn renumber_named_groups(&mut self) {
        for (order, id) in self.named_group_ids().into_iter().enumerate() {
            if let Some(group) = self.groups.get_mut(&id) {
                group.group_order = u32::try_from(order).unwrap_or(u32::MAX);
            }
        }
    }

    /// Repairs the group state after parsing records.
    ///
    /// Three rules, in this order:
    ///
    /// 1. **A reference to an entry the file does not contain is dropped.** A peer may hold an
    ///    ordering that mentions an entry this device never received; keeping the reference
    ///    would leave a hole in the interface that no operation can fill.
    /// 2. **An entry claimed by two lists stays in the first one** (the group order decides
    ///    which is first) and is removed from the later one. Two lists both naming an entry is
    ///    a file that says two things at once, and something has to win; fixing it here means
    ///    the rest of the code can rely on the membership invariant.
    /// 3. **Every remaining live entry is appended to the top group**, in the order the file
    ///    listed its records. This is what makes a version 1 or 2 file - which has no group
    ///    records at all - read as "everything in the top group, in file order", and it is the
    ///    only definition of order those files have.
    ///
    /// `file_entry_order` is the order in which the entry records appeared in the file, and
    /// `file_group_order` the order in which the group records did - the second decides which
    /// list "came first" when two of them name the same entry.
    fn reconcile_groups(&mut self, file_entry_order: &[EntryId], file_group_order: &[GroupId]) {
        let mut claimed: Vec<EntryId> = Vec::with_capacity(self.entries.len());

        for group_id in file_group_order {
            let group_id = *group_id;
            let Some(group) = self.groups.get(&group_id) else {
                continue;
            };
            let mut kept: Vec<EntryId> = Vec::with_capacity(group.entry_ids.len());
            for entry_id in &group.entry_ids {
                if self.entries.contains_key(entry_id) && !claimed.contains(entry_id) {
                    claimed.push(*entry_id);
                    kept.push(*entry_id);
                }
            }
            if let Some(group) = self.groups.get_mut(&group_id) {
                group.entry_ids = kept;
            }
        }

        for entry_id in file_entry_order {
            if !claimed.contains(entry_id) {
                self.top_group_mut().entry_ids.push(*entry_id);
            }
        }
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
    /// Records are written entries first, then tombstones, then groups. The order of the entry
    /// records is the order the entries are read back in, which is what defines the top group's
    /// ordering in a file that has no group records (see [`VaultFile::parse`]); with group
    /// records
    /// present the orderings come from the group records and the entry order no longer matters.
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
            .and_then(|total| total.checked_add(self.vault.groups.len()))
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
                id.as_bytes(),
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
                id.as_bytes(),
                &plaintext,
            )?;
        }

        for (id, group) in self.vault.groups() {
            let plaintext = encode_group(group)?;
            write_record(
                &mut out,
                &self.master,
                FORMAT_VERSION,
                RecordKind::Group,
                id.as_bytes(),
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
        let mut file_entry_order: Vec<EntryId> = Vec::new();
        let mut file_group_order: Vec<GroupId> = Vec::new();
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

            let plaintext =
                crypto::open(&master, kind, id.as_bytes(), version, &nonce, ciphertext)?;
            match kind {
                RecordKind::Entry => {
                    let entry = decode_entry(&plaintext)?;
                    vault.insert_parsed(id, entry)?;
                    file_entry_order.push(id);
                }
                RecordKind::Tombstone => {
                    let tombstone = decode_tombstone(id, &plaintext)?;
                    vault.record_tombstone(tombstone);
                }
                RecordKind::Group => {
                    let group = decode_group(&plaintext)?;
                    let group_id = GroupId::from_bytes(*id.as_bytes());
                    vault.insert_group_with_id(group_id, group)?;
                    file_group_order.push(group_id);
                }
                RecordKind::SyncEntry | RecordKind::SyncTombstone => {
                    return Err(Error::VaultUnknownRecordKind { value: kind_byte });
                }
            }
        }

        vault.reconcile_groups(&file_entry_order, &file_group_order);

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
    record_id: &[u8; EntryId::LEN],
    plaintext: &[u8],
) -> Result<()> {
    let (nonce, ciphertext) = crypto::seal(master, kind, record_id, format_version, plaintext)?;
    out.push(kind.as_byte());
    out.extend_from_slice(record_id);
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
///
/// # The step and the counter nodes are still written
///
/// [`tag::ENTRY_KIND`] says which scheme the entry uses, but the step (or the counter) keeps
/// travelling in the node it always travelled in. That is what lets a version 1 or 2 file be
/// read without a special case: its kind is recovered from exactly those nodes, and a version
/// 3 file is read through the same code path once the kind node has been seen.
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
    put_node(
        &mut out,
        tag::ENTRY_KIND,
        &[entry_kind_to_byte(&entry.kind)],
    );
    match &entry.kind {
        EntryKind::Totp { period }
        | EntryKind::Motp { period, .. }
        | EntryKind::Yandex { period, .. } => {
            put_node(&mut out, tag::PERIOD, &period.to_be_bytes());
        }
        EntryKind::Hotp { counter } => put_node(&mut out, tag::COUNTER, &counter.to_be_bytes()),
        EntryKind::Steam => {
            put_node(&mut out, tag::PERIOD, &otp::STEAM_PERIOD.to_be_bytes());
        }
    }
    if let Some(pin) = entry.kind.motp_pin() {
        put_node(&mut out, tag::MOTP_PIN, pin.expose().as_bytes());
    }
    if let Some(pin) = entry.kind.yandex_pin() {
        put_node(&mut out, tag::YANDEX_PIN, pin.expose().as_bytes());
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

/// Serializes the plaintext of a group.
///
/// Three nodes: the name (empty for the top group), the position among the named groups, and the
/// ordering as the concatenation of its 16-byte identifiers. The list is the order - the entry
/// at index `i` is the `i`-th identifier - so there is nothing else to write and nothing that
/// could disagree with the list.
///
/// # Errors
///
/// Returns [`Error::VaultGroupTooManyEntries`] when the ordering does not fit in one node. The
/// check is here rather than only in [`Group::new`] because the list is public and a caller may
/// have grown it in place.
pub(crate) fn encode_group(group: &Group) -> Result<Vec<u8>> {
    if group.entry_ids.len() > Group::MAX_ENTRIES {
        return Err(Error::VaultGroupTooManyEntries {
            limit: Group::MAX_ENTRIES,
            actual: group.entry_ids.len(),
        });
    }

    let mut out = Vec::new();
    put_node(&mut out, tag::NAME, group.name.as_bytes());
    put_node(&mut out, tag::GROUP_ORDER, &group.group_order.to_be_bytes());

    let mut ids = Vec::with_capacity(group.entry_ids.len() * EntryId::LEN);
    for entry_id in &group.entry_ids {
        ids.extend_from_slice(entry_id.as_bytes());
    }
    put_node(&mut out, tag::ENTRY_IDS, &ids);

    Ok(out)
}

/// Parses the plaintext of a group.
///
/// A repeated known node is rejected as [`Error::VaultDuplicateField`] (see [`tag::GROUP_TAG_MAX`]);
/// unknown nodes are skipped by their length. The name is optional and defaults to empty - that
/// is the top group - while a missing ordering or position is [`Error::VaultCorrupt`]:
/// a group without an ordering is not a group.
pub(crate) fn decode_group(data: &[u8]) -> Result<Group> {
    let mut reader = Reader::new(data);
    let mut name = String::new();
    let mut group_order = None;
    let mut entry_ids = None;
    let mut seen: u32 = 0;

    let mut guard = data.len() + 1;
    while !reader.is_empty() {
        guard = guard.checked_sub(1).ok_or(Error::VaultCorrupt)?;
        let node_tag = reader.u8().ok_or(Error::VaultTruncated)?;
        let len = reader.u32().ok_or(Error::VaultTruncated)? as usize;
        if len > Entry::MAX_FIELD_LEN {
            return Err(Error::FieldTooLong {
                field: "group node",
                limit: Entry::MAX_FIELD_LEN,
                actual: len,
            });
        }
        let payload = reader.take(len).ok_or(Error::VaultTruncated)?;

        if node_tag <= tag::GROUP_TAG_MAX {
            let bit = 1_u32 << node_tag;
            if seen & bit != 0 {
                return Err(Error::VaultDuplicateField { tag: node_tag });
            }
            seen |= bit;
        }

        match node_tag {
            tag::NAME => name = utf8(payload)?,
            tag::GROUP_ORDER => {
                let bytes: [u8; 4] = payload.try_into().map_err(|_| Error::VaultCorrupt)?;
                group_order = Some(u32::from_be_bytes(bytes));
            }
            tag::ENTRY_IDS => {
                if !payload.len().is_multiple_of(EntryId::LEN) {
                    return Err(Error::VaultCorrupt);
                }
                let mut ids = Vec::with_capacity(payload.len() / EntryId::LEN);
                for start in (0..payload.len()).step_by(EntryId::LEN) {
                    let end = start.checked_add(EntryId::LEN).ok_or(Error::VaultCorrupt)?;
                    let chunk = payload.get(start..end).ok_or(Error::VaultCorrupt)?;
                    let bytes: [u8; EntryId::LEN] =
                        chunk.try_into().map_err(|_| Error::VaultCorrupt)?;
                    ids.push(EntryId::from_bytes(bytes));
                }
                entry_ids = Some(ids);
            }
            _ => {}
        }
    }

    Group::new(
        name,
        group_order.ok_or(Error::VaultCorrupt)?,
        entry_ids.ok_or(Error::VaultCorrupt)?,
    )
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

/// Fields accumulated while parsing an entry's plaintext: each is filled in through an
/// `Option`, and the required ones are checked at the end.
///
/// A module-level type rather than one local to [`decode_entry`] because
/// [`assemble_entry_kind`], which turns the collected nodes into an [`EntryKind`], needs to see
/// them.
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
    /// Raw entry kind byte, kept as a byte until its state nodes have all been seen.
    kind: Option<u8>,
    /// Period.
    period: Option<u64>,
    /// Counter.
    counter: Option<u64>,
    /// mOTP PIN.
    motp_pin: Option<String>,
    /// Yandex OTP PIN.
    yandex_pin: Option<String>,
    /// Note.
    note: String,
    /// Creation time.
    created_at: Option<u64>,
    /// Modification time.
    updated_at: Option<u64>,
}

/// Parses the plaintext of an entry.
///
/// A node whose tag is at or below [`tag::ENTRY_TAG_MAX`] that appears twice is rejected as
/// [`Error::VaultDuplicateField`]; unknown tags are skipped by their length, and several nodes
/// sharing an unknown tag are tolerated, since a newer version may write them legitimately.
///
/// # How the entry kind is recovered
///
/// A version 3 file carries [`tag::ENTRY_KIND`] and that node decides, with the step / counter
/// and PIN nodes supplying the state it needs. A version 1 or 2 file has no such node, and the
/// older rule applies unchanged: a counter node means HOTP, its absence means TOTP. An unknown
/// kind byte is [`Error::VaultCorrupt`] rather than a guess — a guess would produce codes that
/// never work.
///
/// The node loop is bounded by the input length, so a file of pure garbage cannot spin
/// it.
pub(crate) fn decode_entry(data: &[u8]) -> Result<VaultEntry> {
    let mut reader = Reader::new(data);
    let mut f = Fields::default();
    let mut seen: u32 = 0;

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

        if node_tag <= tag::ENTRY_TAG_MAX {
            let bit = 1_u32 << node_tag;
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
            tag::ENTRY_KIND => {
                let byte = single_byte(payload)?;
                if entry_kind_byte_is_known(byte) {
                    f.kind = Some(byte);
                } else {
                    return Err(Error::VaultCorrupt);
                }
            }
            tag::PERIOD => f.period = Some(u64_from(payload)?),
            tag::COUNTER => f.counter = Some(u64_from(payload)?),
            tag::MOTP_PIN => f.motp_pin = Some(utf8(payload)?),
            tag::YANDEX_PIN => f.yandex_pin = Some(utf8(payload)?),
            tag::NOTE => f.note = utf8(payload)?,
            tag::CREATED_AT => f.created_at = Some(u64_from(payload)?),
            tag::UPDATED_AT => f.updated_at = Some(u64_from(payload)?),
            _ => {}
        }
    }

    let kind = assemble_entry_kind(&mut f)?;
    let created_at = f.created_at.ok_or(Error::VaultCorrupt)?;
    Entry::new(
        f.name.ok_or(Error::VaultCorrupt)?,
        f.issuer,
        f.account.ok_or(Error::VaultCorrupt)?,
        otp::OtpSecret::from_bytes(f.secret.ok_or(Error::VaultCorrupt)?)?,
        f.algorithm.ok_or(Error::VaultCorrupt)?,
        f.digits.ok_or(Error::VaultCorrupt)?,
        kind,
        f.note,
        created_at,
        f.updated_at.unwrap_or(created_at),
    )
}

/// Assembles the entry kind from the parsed nodes.
///
/// The three cases differ in where the scheme comes from, and all three end in the same place:
///
/// - **A kind node is present** (format version 3): it decides, and the nodes it needs must be
///   there. A PIN node on a scheme without a PIN, or a missing step, is a malformed entry.
/// - **No kind node** (format versions 1 and 2): the old rule decides — a counter node means
///   HOTP, its absence means TOTP — and a PIN node cannot appear, because those versions had
///   no such field.
fn assemble_entry_kind(f: &mut Fields) -> Result<EntryKind> {
    let pin_fields_are_empty = f.motp_pin.is_none() && f.yandex_pin.is_none();

    let Some(byte) = f.kind else {
        if !pin_fields_are_empty {
            return Err(Error::VaultCorrupt);
        }
        return match f.counter {
            Some(counter) => Ok(EntryKind::Hotp { counter }),
            None => Ok(EntryKind::Totp {
                period: f.period.ok_or(Error::VaultCorrupt)?,
            }),
        };
    };

    let pin_only_where_meaningful = |pin: &Option<String>| pin.is_some();
    match byte {
        tag::KIND_TOTP => {
            if !pin_fields_are_empty {
                return Err(Error::VaultCorrupt);
            }
            Ok(EntryKind::Totp {
                period: f.period.ok_or(Error::VaultCorrupt)?,
            })
        }
        tag::KIND_HOTP => {
            if !pin_fields_are_empty {
                return Err(Error::VaultCorrupt);
            }
            Ok(EntryKind::Hotp {
                counter: f.counter.ok_or(Error::VaultCorrupt)?,
            })
        }
        tag::KIND_MOTP => {
            if pin_only_where_meaningful(&f.yandex_pin) {
                return Err(Error::VaultCorrupt);
            }
            Ok(EntryKind::Motp {
                period: f.period.ok_or(Error::VaultCorrupt)?,
                pin: f
                    .motp_pin
                    .take()
                    .filter(|text| !text.is_empty())
                    .map(crate::motp::MotpPin::new),
            })
        }
        tag::KIND_YANDEX => {
            if pin_only_where_meaningful(&f.motp_pin) {
                return Err(Error::VaultCorrupt);
            }
            Ok(EntryKind::Yandex {
                period: f.period.ok_or(Error::VaultCorrupt)?,
                pin: f
                    .yandex_pin
                    .take()
                    .filter(|text| !text.is_empty())
                    .map(crate::yaotp::YandexPin::new),
            })
        }
        tag::KIND_STEAM => {
            if !pin_fields_are_empty {
                return Err(Error::VaultCorrupt);
            }
            Ok(EntryKind::Steam)
        }
        _ => Err(Error::VaultCorrupt),
    }
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

/// Digit count to storage byte: the count itself.
///
/// No mapping table exists, so none can drift out of step with the type; the vault format
/// stores a count from 1 to 9 as one byte holding that number.
const fn digits_to_byte(digits: otp::Digits) -> u8 {
    digits.as_byte()
}

/// Storage byte to digit count. A byte outside 1..=9 returns `None`.
///
/// There is no fallback to six digits: a silent fallback would give the user permanently
/// wrong codes with nothing to diagnose.
fn digits_from_byte(byte: u8) -> Option<otp::Digits> {
    otp::Digits::try_from(byte).ok()
}

/// Entry kind to storage byte.
///
/// Only the **scheme** is stored here; the step, the counter and the PINs travel in nodes of
/// their own, so that a version 1 or 2 file (which has no kind node) can be reconstructed from
/// the same nodes.
const fn entry_kind_to_byte(kind: &EntryKind) -> u8 {
    match kind {
        EntryKind::Totp { .. } => tag::KIND_TOTP,
        EntryKind::Hotp { .. } => tag::KIND_HOTP,
        EntryKind::Motp { .. } => tag::KIND_MOTP,
        EntryKind::Yandex { .. } => tag::KIND_YANDEX,
        EntryKind::Steam => tag::KIND_STEAM,
    }
}

/// Whether a kind byte names a scheme this build knows.
///
/// A byte from a newer version is **rejected rather than guessed**: reading an unknown scheme
/// as TOTP would produce an entry whose codes never work, and nothing in the UI would say why.
const fn entry_kind_byte_is_known(byte: u8) -> bool {
    matches!(
        byte,
        tag::KIND_TOTP | tag::KIND_HOTP | tag::KIND_MOTP | tag::KIND_YANDEX | tag::KIND_STEAM
    )
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
            otp::Digits::EIGHT,
            EntryKind::Totp { period: 30 },
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
            otp::Digits::SIX,
            EntryKind::Hotp { counter: 42 },
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
        assert_eq!(a.kind, b.kind, "kind");
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
        assert_eq!(restored.kind, EntryKind::Hotp { counter: 42 });
        assert_eq!(
            restored.uri_type(),
            crate::uri::UriType::Hotp,
            "the restored entry is still HOTP"
        );
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
    /// AAD version 1. Built by hand because serialization always writes the current version
    /// now; the property pinned here is the byte layout itself.
    #[test]
    fn version_1_files_are_still_readable() {
        let master = MasterKey::generate().expect("OS randomness available");
        let id = EntryId::generate().expect("OS randomness available");
        let entry = sample_entry("old-format");
        let plaintext = encode_entry(&entry).expect("encoding succeeds");
        let (nonce, ciphertext) =
            crypto::seal(&master, RecordKind::Entry, id.as_bytes(), 1, &plaintext)
                .expect("sealing succeeds");

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

    /// Builds a valid entry of the given kind, for codec round trips.
    fn entry_with_kind(kind: EntryKind) -> VaultEntry {
        Entry::new(
            "kind".into(),
            Some("Example".into()),
            "alice".into(),
            secret(),
            otp::Algorithm::Sha1,
            otp::Digits::SIX,
            kind,
            String::new(),
            1_700_000_000,
            1_700_000_000,
        )
        .expect("valid entry")
    }

    /// Builds an entry plaintext the way **format version 2** wrote it: no kind node.
    ///
    /// Written by hand rather than through [`encode_entry`], which always writes a kind node
    /// now. A round trip through the current encoder therefore cannot stand in for a version 2
    /// file: it would prove only that this build agrees with itself.
    fn version_2_plaintext(with_counter: bool) -> Vec<u8> {
        let mut out = Vec::new();
        put_node(&mut out, tag::NAME, b"legacy");
        put_node(&mut out, tag::ACCOUNT, b"alice");
        put_node(&mut out, tag::SECRET, b"JBSWY3DPEHPK3PXP");
        put_node(&mut out, tag::ALGORITHM, &[tag::ALG_SHA1]);
        put_node(&mut out, tag::DIGITS, &[otp::Digits::SIX.as_byte()]);
        put_node(&mut out, tag::PERIOD, &30_u64.to_be_bytes());
        if with_counter {
            put_node(&mut out, tag::COUNTER, &7_u64.to_be_bytes());
        }
        put_node(&mut out, tag::NOTE, b"");
        put_node(&mut out, tag::CREATED_AT, &0_u64.to_be_bytes());
        put_node(&mut out, tag::UPDATED_AT, &0_u64.to_be_bytes());
        out
    }

    /// A version 2 file is still readable: version byte 2, the trailing master key check
    /// value, record AAD version 2, and a plaintext without a kind node. Built by hand because
    /// serialization always writes the current version now; the property pinned here is the
    /// byte layout itself.
    #[test]
    fn version_2_files_are_still_readable() {
        let master = MasterKey::generate().expect("OS randomness available");
        let id = EntryId::generate().expect("OS randomness available");
        let plaintext = version_2_plaintext(false);
        let (nonce, ciphertext) =
            crypto::seal(&master, RecordKind::Entry, id.as_bytes(), 2, &plaintext)
                .expect("sealing succeeds");

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(2);
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
        out.extend_from_slice(&crypto::key_check(&master));

        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(&master)).expect("correct length"),
            &out,
        )
        .expect("a version 2 file must still parse");
        assert_eq!(reopened.vault().len(), 1, "the entry must be read back");
        let (restored_id, restored) = reopened.vault().iter().next().expect("one entry");
        assert_eq!(*restored_id, id, "the identifier survives");
        assert_eq!(restored.name, "legacy");
        assert_eq!(
            restored.kind,
            EntryKind::Totp { period: 30 },
            "a version 2 plaintext has no kind node, so the old rule decides"
        );

        // Unlike version 1, the check value refuses a wrong key before any record is read.
        let wrong = MasterKey::generate().expect("OS randomness available");
        assert!(
            VaultFile::parse(wrong, &out).is_err(),
            "a version 2 file must fail under the wrong key"
        );
    }

    /// A plaintext with no kind node is read by the **older rule**: a counter node means HOTP,
    /// its absence means TOTP.
    ///
    /// Asserted on the decoded plaintext rather than through a round trip; the round trip would
    /// only prove that the encoder and decoder agree with each other.
    #[test]
    fn a_plaintext_without_a_kind_node_falls_back_to_the_old_rule() {
        let totp = decode_entry(&version_2_plaintext(false)).expect("a version 2 plaintext parses");
        assert_eq!(totp.kind, EntryKind::Totp { period: 30 });

        let hotp = decode_entry(&version_2_plaintext(true)).expect("a version 2 plaintext parses");
        assert_eq!(hotp.kind, EntryKind::Hotp { counter: 7 });
    }

    /// Every kind survives the codec, PINs and steps included.
    ///
    /// The kinds are listed one by one rather than derived from a list of constants, so adding
    /// a variant without teaching the codec about it fails here.
    #[test]
    fn every_entry_kind_round_trips() {
        let kinds = [
            EntryKind::Totp { period: 45 },
            EntryKind::Hotp { counter: 9_999 },
            EntryKind::Motp {
                period: 10,
                pin: Some(crate::motp::MotpPin::new("1234".to_owned())),
            },
            EntryKind::Motp {
                period: 10,
                pin: None,
            },
            EntryKind::Yandex {
                period: 30,
                pin: Some(crate::yaotp::YandexPin::new("7586".to_owned())),
            },
            EntryKind::Yandex {
                period: 60,
                pin: None,
            },
            EntryKind::Steam,
        ];

        for kind in kinds {
            let entry = entry_with_kind(kind);
            let encoded = encode_entry(&entry).expect("encoding succeeds");
            let decoded = decode_entry(&encoded).expect("the encoded entry must decode");
            assert_entry_eq(&entry, &decoded);
        }
    }

    /// A PIN node is rejected on a scheme that has no PIN.
    #[test]
    fn a_pin_node_on_a_scheme_without_a_pin_is_rejected() {
        for kind in [tag::KIND_TOTP, tag::KIND_HOTP, tag::KIND_STEAM] {
            let mut plaintext = Vec::new();
            put_node(&mut plaintext, tag::NAME, b"n");
            put_node(&mut plaintext, tag::ACCOUNT, b"a");
            put_node(&mut plaintext, tag::SECRET, b"secret");
            put_node(&mut plaintext, tag::ALGORITHM, &[tag::ALG_SHA1]);
            put_node(&mut plaintext, tag::DIGITS, &[otp::Digits::SIX.as_byte()]);
            put_node(&mut plaintext, tag::ENTRY_KIND, &[kind]);
            put_node(&mut plaintext, tag::PERIOD, &30_u64.to_be_bytes());
            put_node(&mut plaintext, tag::MOTP_PIN, b"1234");
            put_node(&mut plaintext, tag::CREATED_AT, &0_u64.to_be_bytes());
            assert!(
                matches!(decode_entry(&plaintext), Err(Error::VaultCorrupt)),
                "a PIN on a scheme without one must be rejected"
            );
        }
    }

    /// A scheme's step must be present, and an unknown kind byte is never guessed.
    #[test]
    fn an_unknown_or_incomplete_kind_is_rejected() {
        let base = |kind: Option<u8>, period: bool| {
            let mut plaintext = Vec::new();
            put_node(&mut plaintext, tag::NAME, b"n");
            put_node(&mut plaintext, tag::ACCOUNT, b"a");
            put_node(&mut plaintext, tag::SECRET, b"secret");
            put_node(&mut plaintext, tag::ALGORITHM, &[tag::ALG_SHA1]);
            put_node(&mut plaintext, tag::DIGITS, &[otp::Digits::SIX.as_byte()]);
            if let Some(kind) = kind {
                put_node(&mut plaintext, tag::ENTRY_KIND, &[kind]);
            }
            if period {
                put_node(&mut plaintext, tag::PERIOD, &30_u64.to_be_bytes());
            }
            put_node(&mut plaintext, tag::CREATED_AT, &0_u64.to_be_bytes());
            plaintext
        };

        assert!(
            matches!(decode_entry(&base(Some(0), true)), Err(Error::VaultCorrupt)),
            "kind byte 0 is not a scheme"
        );
        assert!(
            matches!(
                decode_entry(&base(Some(tag::KIND_STEAM + 1), true)),
                Err(Error::VaultCorrupt)
            ),
            "a kind byte from a newer version must be rejected, not guessed"
        );
        assert!(
            matches!(
                decode_entry(&base(Some(tag::KIND_MOTP), false)),
                Err(Error::VaultCorrupt)
            ),
            "a kind carrying a step must have one"
        );
        assert!(
            matches!(
                decode_entry(&base(Some(tag::KIND_HOTP), true)),
                Err(Error::VaultCorrupt)
            ),
            "HOTP needs a counter, not a step"
        );
        assert!(
            decode_entry(&base(Some(tag::KIND_TOTP), true)).is_ok(),
            "a complete TOTP entry is accepted"
        );
    }

    /// A repeated node is rejected for the **new** tags too.
    ///
    /// The duplicate check keeps one bit per known tag, so it has to cover the tags added with
    /// the entry kind: a bitmap that stopped at the older tag range would let a second kind
    /// node, or a second PIN node, slip through and be decided by whichever came last.
    #[test]
    fn duplicate_nodes_are_rejected_for_the_new_tags_too() {
        for duplicated in [tag::ENTRY_KIND, tag::MOTP_PIN, tag::YANDEX_PIN] {
            let mut plaintext = Vec::new();
            put_node(&mut plaintext, tag::NAME, b"n");
            put_node(&mut plaintext, tag::ACCOUNT, b"a");
            put_node(&mut plaintext, tag::SECRET, b"secret");
            put_node(&mut plaintext, tag::ALGORITHM, &[tag::ALG_SHA1]);
            put_node(&mut plaintext, tag::DIGITS, &[otp::Digits::SIX.as_byte()]);
            put_node(&mut plaintext, tag::PERIOD, &30_u64.to_be_bytes());
            put_node(&mut plaintext, tag::CREATED_AT, &0_u64.to_be_bytes());
            for _ in 0..2 {
                let payload: &[u8] = match duplicated {
                    tag::ENTRY_KIND => &[tag::KIND_TOTP],
                    _ => b"1234",
                };
                put_node(&mut plaintext, duplicated, payload);
            }

            match decode_entry(&plaintext) {
                Err(Error::VaultDuplicateField { tag }) => assert_eq!(tag, duplicated),
                other => panic!(
                    "tag {duplicated:#04x} appearing twice must be rejected, actual {}",
                    if other.is_ok() { "ok" } else { "another error" }
                ),
            }
        }
    }

    /// The "old files stay readable" promise, pinned against the list itself.
    ///
    /// The versions are named literally: deriving them from [`FORMAT_VERSION`] is exactly the
    /// mistake this catches (`&[1, FORMAT_VERSION]` silently dropped version 2).
    #[test]
    fn every_previous_format_version_stays_readable() {
        assert!(READABLE_VERSIONS.contains(&1), "version 1 was dropped");
        assert!(READABLE_VERSIONS.contains(&2), "version 2 was dropped");
        assert!(
            READABLE_VERSIONS.contains(&FORMAT_VERSION),
            "the current version is not in the readable list"
        );
    }

    /// Every file this build writes declares the current version, whatever it contains.
    ///
    /// The version is decided unconditionally rather than derived from the contents: a
    /// content-derived version would be a branch that itself needs independent verification,
    /// and nothing was lost between versions 2 and 3, so there is no reason to keep writing
    /// the older number.
    #[test]
    fn serialization_always_writes_the_current_version() {
        let empty = VaultFile::create().expect("OS randomness available");
        let bytes = empty.serialize().expect("serialization succeeds");
        assert_eq!(bytes[8], FORMAT_VERSION, "an empty vault");
        assert_eq!(bytes[8], 3, "the format version changed");

        let mut totp_only = VaultFile::create().expect("OS randomness available");
        totp_only
            .vault_mut()
            .insert(sample_entry("totp"))
            .expect("insertion succeeds");
        let bytes = totp_only.serialize().expect("serialization succeeds");
        assert_eq!(bytes[8], 3, "a vault holding only a TOTP entry");

        let mut hotp = VaultFile::create().expect("OS randomness available");
        hotp.vault_mut()
            .insert(sample_hotp_entry())
            .expect("insertion succeeds");
        let bytes = hotp.serialize().expect("serialization succeeds");
        assert_eq!(bytes[8], 3, "a vault holding only an HOTP entry");
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
        put_node(&mut plaintext, tag::DIGITS, &[otp::Digits::SIX.as_byte()]);
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
        put_node(&mut plaintext, tag::DIGITS, &[otp::Digits::SIX.as_byte()]);
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
        for count in otp::Digits::MIN..=otp::Digits::MAX {
            let digits = otp::Digits::new(count).expect("1..=9 is the supported range");
            assert_eq!(
                digits_from_byte(digits_to_byte(digits)),
                Some(digits),
                "count {count}"
            );
        }
        assert_eq!(algorithm_from_byte(0), None);
        assert_eq!(algorithm_from_byte(99), None);
        assert_eq!(digits_from_byte(0), None);
        assert_eq!(digits_from_byte(10), None);
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

    /// Writes a file from hand-built records.
    ///
    /// The record list is written in the order given, which is what decides the top group's
    /// ordering in a file that has no group records - so a test that cares about that order
    /// passes the records in the order it means.
    fn file_from_records(
        master: &MasterKey,
        records: &[(RecordKind, [u8; EntryId::LEN], Vec<u8>)],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.push(0);
        put_u32(
            &mut out,
            u32::try_from(records.len()).expect("the test writes a handful of records"),
        );
        for (kind, id, plaintext) in records {
            write_record(&mut out, master, FORMAT_VERSION, *kind, id, plaintext)
                .expect("sealing succeeds");
        }
        out.extend_from_slice(&crypto::key_check(master));
        out
    }

    /// A copy of the master key, since `MasterKey` is deliberately not `Clone`.
    fn copy_key(master: &MasterKey) -> MasterKey {
        MasterKey::from_bytes(master_key_to_bytes(master)).expect("the length is correct")
    }

    /// Reads the record count out of a file header.
    fn record_count(filedata: &[u8]) -> u32 {
        let bytes: [u8; 4] = filedata[10..14].try_into().expect("the header is 14 bytes");
        u32::from_be_bytes(bytes)
    }

    /// An entry record for a hand-built file.
    fn entry_record(
        master: &MasterKey,
        id: EntryId,
        name: &str,
    ) -> (RecordKind, [u8; 16], Vec<u8>) {
        let plaintext = encode_entry(&sample_entry(name)).expect("encoding succeeds");
        let _ = master;
        (RecordKind::Entry, *id.as_bytes(), plaintext)
    }

    /// The plan's byte-level requirement: a version 1 or 2 file has **no** group records, and
    /// reading it puts every entry in the top group in the order the file listed them - then
    /// writing it back produces group records.
    #[test]
    fn a_file_without_group_records_reads_as_one_top_group_in_file_order() {
        let master = MasterKey::generate().expect("OS randomness available");
        let first = EntryId::generate().expect("OS randomness available");
        let second = EntryId::generate().expect("OS randomness available");
        let third = EntryId::generate().expect("OS randomness available");

        let bytes = file_from_records(
            &master,
            &[
                entry_record(&master, first, "first"),
                entry_record(&master, second, "second"),
                entry_record(&master, third, "third"),
            ],
        );
        assert_eq!(record_count(&bytes), 3, "three records, no group record");

        let parsed = VaultFile::parse(copy_key(&master), &bytes).expect("it parses");
        assert_eq!(
            parsed.vault().group_count(),
            1,
            "the top group is synthesized"
        );
        let top = parsed.vault().top_group().expect("a top group exists");
        assert_eq!(
            top.entry_ids,
            vec![first, second, third],
            "reconciliation fills the top group from the file order, since no record said otherwise"
        );
        let ordering: Vec<EntryId> = parsed
            .vault()
            .entries_in(&GroupId::TOP)
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(
            ordering,
            vec![first, second, third],
            "the file order is the only order such a file has"
        );
        assert_eq!(
            parsed.vault().group_of(&second),
            Some(&GroupId::TOP),
            "every entry is in the top group"
        );

        // Writing it back adds the group record: the file now says what was previously implied.
        let rewritten = parsed.serialize().expect("it serializes");
        assert_eq!(record_count(&rewritten), 4, "three entries and one group");

        let reparsed = VaultFile::parse(copy_key(&master), &rewritten).expect("it parses");
        let ordering: Vec<EntryId> = reparsed
            .vault()
            .entries_in(&GroupId::TOP)
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(ordering, vec![first, second, third], "the order survives");
    }

    /// A group survives the file: its name, its position and its ordering.
    #[test]
    fn a_group_round_trips_with_its_ordering() {
        let mut file = VaultFile::create().expect("OS randomness available");
        let first = file
            .vault_mut()
            .insert(sample_entry("work-1"))
            .expect("insertion succeeds");
        let second = file
            .vault_mut()
            .insert(sample_entry("work-2"))
            .expect("insertion succeeds");
        let work = file
            .vault_mut()
            .create_group("Work".to_owned())
            .expect("group creation succeeds");
        file.vault_mut()
            .create_group("Private".to_owned())
            .expect("group creation succeeds");

        // The list is the order: second before first.
        file.vault_mut()
            .set_ordering(&work, vec![second, first])
            .expect("the ordering is valid");

        let bytes = file.serialize().expect("serialization succeeds");
        let parsed = VaultFile::parse(copy_key(file.master_key()), &bytes).expect("it parses back");

        let restored = parsed.vault().group(&work).expect("the group exists");
        assert_eq!(restored.name, "Work");
        assert_eq!(restored.group_order, 0, "it is the first named group");
        assert_eq!(restored.entry_ids, vec![second, first]);

        let ordering: Vec<EntryId> = parsed
            .vault()
            .entries_in(&work)
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(
            ordering,
            vec![second, first],
            "the list is read back in its own order"
        );
        assert_eq!(
            parsed.vault().group_count(),
            3,
            "two named groups and the top group"
        );

        let groups: Vec<&str> = parsed
            .vault()
            .groups()
            .map(|(_, group)| group.name.as_str())
            .collect();
        assert_eq!(
            groups,
            vec!["", "Work", "Private"],
            "the top group comes first, then the named ones in their order"
        );
    }

    /// A reference to an entry the file does not contain is dropped instead of leaving a hole.
    #[test]
    fn a_dangling_reference_is_skipped() {
        let master = MasterKey::generate().expect("OS randomness available");
        let present = EntryId::generate().expect("OS randomness available");
        let missing = EntryId::generate().expect("OS randomness available");
        let group_id = GroupId::generate().expect("OS randomness available");

        let group = Group::new("Work".to_owned(), 0, vec![missing, present])
            .expect("a valid group; two different lists are what the vault checks");
        let bytes = file_from_records(
            &master,
            &[
                entry_record(&master, present, "present"),
                (
                    RecordKind::Group,
                    *group_id.as_bytes(),
                    encode_group(&group).expect("it encodes"),
                ),
            ],
        );

        let parsed = VaultFile::parse(copy_key(&master), &bytes).expect("it parses");
        assert_eq!(
            parsed.vault().ordering(&group_id),
            Some([present].as_slice()),
            "the reference to a missing entry is skipped, the rest is kept"
        );
    }

    /// When two lists name the same entry, the one whose record came **first** keeps it and the
    /// later one loses the reference.
    ///
    /// A file that says two things at once has to be resolved somewhere; resolving it here means
    /// every other part of the library can rely on "an entry is in at most one group".
    #[test]
    fn the_first_list_wins_a_shared_entry() {
        let master = MasterKey::generate().expect("OS randomness available");
        let shared = EntryId::generate().expect("OS randomness available");
        let first_group = GroupId::generate().expect("OS randomness available");
        let second_group = GroupId::generate().expect("OS randomness available");

        let first = Group::new("First".to_owned(), 0, vec![shared]).expect("valid group");
        let second = Group::new("Second".to_owned(), 1, vec![shared]).expect("valid group");
        let bytes = file_from_records(
            &master,
            &[
                (
                    RecordKind::Group,
                    *second_group.as_bytes(),
                    encode_group(&second).expect("encodes"),
                ),
                entry_record(&master, shared, "shared"),
                (
                    RecordKind::Group,
                    *first_group.as_bytes(),
                    encode_group(&first).expect("encodes"),
                ),
            ],
        );

        let parsed = VaultFile::parse(copy_key(&master), &bytes).expect("it parses");
        assert_eq!(
            parsed.vault().ordering(&second_group),
            Some([shared].as_slice()),
            "the second record came first, so its claim stands"
        );
        assert_eq!(
            parsed.vault().ordering(&first_group),
            Some([].as_slice()),
            "the later list loses the reference"
        );
        assert_eq!(parsed.vault().group_of(&shared), Some(&second_group));
    }

    /// An entry no list names is appended to the top group, in file order.
    #[test]
    fn an_entry_no_list_names_lands_in_the_top_group() {
        let master = MasterKey::generate().expect("OS randomness available");
        let listed = EntryId::generate().expect("OS randomness available");
        let unlisted = EntryId::generate().expect("OS randomness available");
        let group_id = GroupId::generate().expect("OS randomness available");

        let group = Group::new("Work".to_owned(), 0, vec![listed]).expect("valid group");
        let bytes = file_from_records(
            &master,
            &[
                entry_record(&master, unlisted, "unlisted"),
                entry_record(&master, listed, "listed"),
                (
                    RecordKind::Group,
                    *group_id.as_bytes(),
                    encode_group(&group).expect("encodes"),
                ),
            ],
        );

        let parsed = VaultFile::parse(copy_key(&master), &bytes).expect("it parses");
        assert_eq!(
            parsed.vault().ordering(&group_id),
            Some([listed].as_slice())
        );
        assert_eq!(
            parsed.vault().ordering(&GroupId::TOP),
            Some([unlisted].as_slice()),
            "what no list claims belongs to the top group"
        );
    }

    /// The top group cannot be renamed, removed or reordered; its contents stay editable.
    #[test]
    fn the_top_group_cannot_be_renamed_removed_or_reordered() {
        let mut vault = Vault::new();
        let id = vault.insert(sample_entry("x")).expect("insertion succeeds");

        assert!(matches!(
            vault.rename_group(&GroupId::TOP, "Home".to_owned()),
            Err(Error::VaultTopGroupImmutable)
        ));
        assert!(matches!(
            vault.remove_group(&GroupId::TOP),
            Err(Error::VaultTopGroupImmutable)
        ));
        assert!(matches!(
            vault.reorder_group(&GroupId::TOP, 3),
            Err(Error::VaultTopGroupImmutable)
        ));

        vault
            .set_ordering(&GroupId::TOP, vec![id])
            .expect("the ordering of the top group is what it is for");
        assert_eq!(vault.ordering(&GroupId::TOP), Some([id].as_slice()));
    }

    /// Insertion puts an entry in the top group, and deleting it leaves no reference behind.
    #[test]
    fn insertion_and_deletion_keep_the_top_group_consistent() {
        let mut vault = Vault::new();
        let first = vault.insert(sample_entry("a")).expect("insertion succeeds");
        let second = vault.insert(sample_entry("b")).expect("insertion succeeds");
        assert_eq!(
            vault.ordering(&GroupId::TOP),
            Some([first, second].as_slice()),
            "insertion appends"
        );

        vault.remove(&first, 1_700_000_000);
        assert_eq!(
            vault.ordering(&GroupId::TOP),
            Some([second].as_slice()),
            "a deleted entry must not stay in the ordering"
        );
        assert!(vault.group_of(&first).is_none());
    }

    /// Moving an entry between groups takes it out of the old one, and a second move out of the
    /// top group does too.
    #[test]
    fn moving_an_entry_between_groups_leaves_one_reference() {
        let mut vault = Vault::new();
        let entry = vault.insert(sample_entry("x")).expect("insertion succeeds");
        let work = vault
            .create_group("Work".to_owned())
            .expect("creation succeeds");
        let private = vault
            .create_group("Private".to_owned())
            .expect("creation succeeds");

        vault
            .assign_to_group(&entry, &work)
            .expect("the move succeeds");
        assert_eq!(vault.ordering(&work), Some([entry].as_slice()));
        assert_eq!(
            vault.ordering(&GroupId::TOP),
            Some([].as_slice()),
            "it left the top group"
        );

        vault
            .assign_to_group(&entry, &private)
            .expect("the second move succeeds");
        assert_eq!(vault.ordering(&private), Some([entry].as_slice()));
        assert_eq!(vault.ordering(&work), Some([].as_slice()));

        vault
            .assign_to_group(&entry, &work)
            .expect("moving back succeeds");
        assert_eq!(vault.ordering(&work), Some([entry].as_slice()));
        assert_eq!(vault.ordering(&private), Some([].as_slice()));
        assert_eq!(vault.group_of(&entry), Some(&work));
    }

    /// Setting an ordering refuses what the vault cannot represent: an unknown entry, a repeated
    /// entry, an unknown group.
    #[test]
    fn setting_an_ordering_validates_its_input() {
        let mut vault = Vault::new();
        let entry = vault.insert(sample_entry("x")).expect("insertion succeeds");
        let group = vault
            .create_group("Work".to_owned())
            .expect("creation succeeds");
        let missing = EntryId::generate().expect("OS randomness available");

        assert!(matches!(
            vault.set_ordering(&group, vec![missing]),
            Err(Error::VaultGroupUnknownEntry)
        ));
        assert!(matches!(
            vault.set_ordering(&group, vec![entry, entry]),
            Err(Error::VaultGroupDuplicateEntry)
        ));
        assert!(matches!(
            vault.set_ordering(&missing_group_id(), vec![]),
            Err(Error::VaultGroupNotFound)
        ));
        assert!(matches!(
            vault.assign_to_group(&missing, &group),
            Err(Error::VaultEntryNotFound)
        ));
        assert!(matches!(
            vault.assign_to_group(&entry, &missing_group_id()),
            Err(Error::VaultGroupNotFound)
        ));
        assert_eq!(
            vault.ordering(&group),
            Some([].as_slice()),
            "a refused call must not have changed anything"
        );
    }

    /// Removing a group moves its entries to the top group instead of deleting them.
    #[test]
    fn removing_a_group_keeps_its_entries() {
        let mut vault = Vault::new();
        let first = vault.insert(sample_entry("a")).expect("insertion succeeds");
        let second = vault.insert(sample_entry("b")).expect("insertion succeeds");
        let work = vault
            .create_group("Work".to_owned())
            .expect("creation succeeds");
        let private = vault
            .create_group("Private".to_owned())
            .expect("creation succeeds");
        vault
            .set_ordering(&work, vec![second, first])
            .expect("valid ordering");

        let removed = vault
            .remove_group(&work)
            .expect("removal succeeds")
            .expect("the group existed");
        assert_eq!(removed.name, "Work");
        assert_eq!(vault.len(), 2, "the entries are still there");
        assert_eq!(
            vault.ordering(&GroupId::TOP),
            Some([second, first].as_slice()),
            "they moved to the top group, keeping their order"
        );
        assert_eq!(
            vault.group(&private).map(|group| group.group_order),
            Some(0),
            "the remaining named group is renumbered"
        );
        assert!(
            vault
                .remove_group(&private)
                .expect("removal succeeds")
                .is_some()
        );
        assert!(
            vault
                .remove_group(&private)
                .expect("removal succeeds")
                .is_none()
        );
    }

    /// Reordering a named group renumbers the rest, so the numbers stay a sequence.
    #[test]
    fn reordering_groups_renumbers_them() {
        let mut vault = Vault::new();
        let first = vault
            .create_group("A".to_owned())
            .expect("creation succeeds");
        let second = vault
            .create_group("B".to_owned())
            .expect("creation succeeds");
        let third = vault
            .create_group("C".to_owned())
            .expect("creation succeeds");
        assert_eq!(vault.group(&third).map(|g| g.group_order), Some(2));

        vault.reorder_group(&third, 0).expect("reordering succeeds");
        let order: Vec<(&str, u32)> = vault
            .groups()
            .map(|(_, group)| (group.name.as_str(), group.group_order))
            .collect();
        // No entry has been inserted, so there is no top group to list yet: it appears with the
        // first entry, not with the first group.
        assert_eq!(order, vec![("C", 0), ("A", 1), ("B", 2)]);

        vault
            .reorder_group(&first, 99)
            .expect("it clamps to the end");
        let order: Vec<&str> = vault
            .groups()
            .map(|(_, group)| group.name.as_str())
            .collect();
        assert_eq!(order, vec!["C", "B", "A"]);

        assert!(
            vault.reorder_group(&second, 0).is_ok(),
            "an existing group can be moved"
        );
        assert!(matches!(
            vault.reorder_group(&missing_group_id(), 0),
            Err(Error::VaultGroupNotFound)
        ));
    }

    /// A group identifier that is not in the vault.
    fn missing_group_id() -> GroupId {
        GroupId::from_bytes([0xAB; GroupId::LEN])
    }
}
