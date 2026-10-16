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

//! Groups and the ordering of entries.
//!
//! A group is an account-level fact: a named collection of entries that the user can reorder.
//! This module holds the two types that carry it, [`GroupId`] and [`Group`]; the vault stores
//! them and the file format writes them.
//!
//! # The order is the list, not a number on each entry
//!
//! Every group holds `entry_ids` in order, and **the sequence number of an entry is its index
//! in that list**. There is deliberately no "position" field on an entry:
//!
//! - reordering rewrites one group record and touches no entry at all;
//! - adjudicating a conflict is "pick one of two whole lists", which is the granularity the
//!   synchronisation rules ask for;
//! - an entry's membership is derived from the lists, so the entry format needs neither "which
//!   group am I in" nor "which position do I hold" - two fields, and two chances for the two
//!   sides to disagree, are gone.
//!
//! The cost is that a list is a **sequence, not a set**: two devices that hold the same entries
//! in different orders hold different lists, and that difference is a conflict to show the user
//! rather than something to merge automatically.
//!
//! # The top group
//!
//! Entries that belong to no named group still form one sortable whole, and it is a group like
//! any other with the reserved identifier [`GroupId::TOP`]. The user interface pins it at the
//! top and offers no way to delete it, so [`Vault::remove_group`](crate::vault::Vault::remove_group)
//! refuses it.
//!
//! The top group's `group_order` is stored as 0 and is **not meaningful**: its position is
//! fixed by definition, not by the number. Named groups order themselves among themselves.

use crate::{Error, Result};

/// Identifier of a group: a 128-bit value, the same shape as an entry identifier.
///
/// It sits in the vault file in plaintext, exactly like an entry identifier, because the record
/// header has one 16-byte identifier field and the record kind decides what it means. It
/// carries no semantics and reveals nothing: its only purpose is to let two devices and the user
/// interface name the same group.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId([u8; Self::LEN]);

impl GroupId {
    /// Byte length of an identifier.
    pub const LEN: usize = 16;

    /// The reserved identifier of the **top group**: the entries that belong to no named group.
    ///
    /// All zeroes, which no generated identifier can be in practice: [`GroupId::generate`]
    /// draws 128 random bits, so the chance of a collision is the chance of drawing exactly
    /// this value. The reserved value is what makes the top group a group like any other -
    /// storable, orderable and syncable - instead of a special case in every match.
    pub const TOP: Self = Self([0; Self::LEN]);

    /// Generates a new random identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`] when the OS random source is unavailable. There
    /// is **no** fallback to a userspace PRNG.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0_u8; Self::LEN];
        crate::getrandom::fill(&mut bytes).map_err(|_| Error::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    /// Builds an identifier from a byte array, as read from a file.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes, used to write the file and to build the AAD.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Whether this is the reserved top group.
    #[must_use]
    pub const fn is_top(&self) -> bool {
        let mut index = 0;
        while index < Self::LEN {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }
}

impl core::fmt::Debug for GroupId {
    /// Prints the hexadecimal form, with the top group called out by name.
    ///
    /// The identifier is not a secret (it sits in the file in plaintext); the name matters
    /// because "the top group" is what a reader of a log or a failing test is looking for.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_top() {
            return f.write_str("GroupId(TOP)");
        }
        write!(f, "GroupId(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// A named group, with the ordering of the entries it holds.
///
/// The list **is** the order: the entry at index `i` comes after the entry at index `i - 1` and
/// before the one at index `i + 1`. See the module documentation for why the sequence number is
/// not stored on the entry.
#[derive(Debug, PartialEq, Eq)]
pub struct Group {
    /// User-visible name. Empty for the top group, which is not nameable.
    pub name: String,
    /// Position among the **named** groups; a smaller number comes first.
    ///
    /// Ignored for the top group, whose position is fixed (see the module documentation).
    pub group_order: u32,
    /// The entries of this group, in display order.
    ///
    /// Every identifier may appear in **at most one** list of one group; the vault keeps that
    /// true (see [`Vault::set_ordering`](crate::vault::Vault::set_ordering)), and the parser
    /// repairs a file that violates it.
    pub entry_ids: Vec<crate::vault::EntryId>,
}

impl Group {
    /// Maximum number of entries one group can hold.
    ///
    /// The identifier list travels in a single length-prefixed node, so it is bounded by
    /// [`crate::vault::Entry::MAX_FIELD_LEN`]: `65_536 / 16` (the length of one identifier).
    /// The limit is far above any real group - a thousand entries already fills a screen many
    /// times over.
    pub const MAX_ENTRIES: usize = crate::vault::Entry::MAX_FIELD_LEN / GroupId::LEN;

    /// Builds a group from its parts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FieldTooLong`] when the name exceeds
    /// [`Entry::MAX_FIELD_LEN`](crate::vault::Entry::MAX_FIELD_LEN), and
    /// [`Error::VaultGroupTooManyEntries`] when the list holds more than [`Group::MAX_ENTRIES`]
    /// identifiers.
    ///
    /// A duplicate identifier **within** the list is rejected as
    /// [`Error::VaultGroupDuplicateEntry`]: the list is an ordering, and one entry cannot occupy two
    /// positions in the same ordering. Whether an entry may appear in two *different* groups is
    /// a question for the vault, not for one group.
    pub fn new(
        name: String,
        group_order: u32,
        entry_ids: Vec<crate::vault::EntryId>,
    ) -> Result<Self> {
        if name.len() > crate::vault::Entry::MAX_FIELD_LEN {
            return Err(Error::FieldTooLong {
                field: "group name",
                limit: crate::vault::Entry::MAX_FIELD_LEN,
                actual: name.len(),
            });
        }
        if entry_ids.len() > Self::MAX_ENTRIES {
            return Err(Error::VaultGroupTooManyEntries {
                limit: Self::MAX_ENTRIES,
                actual: entry_ids.len(),
            });
        }
        if first_duplicate(&entry_ids).is_some() {
            return Err(Error::VaultGroupDuplicateEntry);
        }
        Ok(Self {
            name,
            group_order,
            entry_ids,
        })
    }

    /// The top group, holding the given entries in the given order.
    ///
    /// # Errors
    ///
    /// As [`Group::new`]; the name is empty by definition and the order is not meaningful.
    pub fn top(entry_ids: Vec<crate::vault::EntryId>) -> Result<Self> {
        Self::new(String::new(), 0, entry_ids)
    }

    /// An empty top group.
    ///
    /// Used when a vault gains its first entry, or when a file that has entries but no group
    /// records is read: the top group then holds every entry, in file order.
    pub(crate) fn top_empty() -> Self {
        Self {
            name: String::new(),
            group_order: 0,
            entry_ids: Vec::new(),
        }
    }

    /// Whether this is the top group.
    #[must_use]
    pub const fn is_top_name(&self) -> bool {
        self.name.is_empty()
    }
}

/// Returns the first identifier that appears more than once, if any.
///
/// Quadratic in the list length and deliberately so: the lists are small (a screenful or two),
/// the check runs once per construction rather than per comparison, and the alternative - a
/// sorted copy - would mean copying the list of identifiers on a path that runs for every
/// group of every parse.
fn first_duplicate(ids: &[crate::vault::EntryId]) -> Option<crate::vault::EntryId> {
    for (index, id) in ids.iter().enumerate() {
        if ids[index + 1..].contains(id) {
            return Some(*id);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::EntryId;

    fn id(seed: u8) -> EntryId {
        EntryId::from_bytes([seed; EntryId::LEN])
    }

    #[test]
    fn the_top_identifier_is_reserved_and_recognized() {
        assert!(GroupId::TOP.is_top());
        assert_eq!(GroupId::TOP.as_bytes(), &[0_u8; GroupId::LEN]);
        assert_eq!(format!("{:?}", GroupId::TOP), "GroupId(TOP)");
    }

    #[test]
    fn a_generated_identifier_is_never_the_reserved_one() {
        for _ in 0..64 {
            let generated = GroupId::generate().expect("OS randomness available");
            assert!(
                !generated.is_top(),
                "a generated identifier collided with the reserved value"
            );
            assert_eq!(
                format!("{generated:?}").len(),
                "GroupId()".len() + 2 * GroupId::LEN
            );
        }
    }

    #[test]
    fn a_group_keeps_its_name_order_and_list() {
        let group = Group::new("Work".to_owned(), 3, vec![id(1), id(2)]).expect("valid group");
        assert_eq!(group.name, "Work");
        assert_eq!(group.group_order, 3);
        assert_eq!(group.entry_ids, vec![id(1), id(2)]);
        assert!(!group.is_top_name());
        assert!(Group::top(vec![]).expect("valid group").is_top_name());
    }

    #[test]
    fn a_duplicate_identifier_in_one_list_is_rejected() {
        let err = Group::new("Work".to_owned(), 0, vec![id(1), id(2), id(1)]);
        assert!(
            matches!(err, Err(Error::VaultGroupDuplicateEntry)),
            "one entry cannot hold two positions in the same ordering"
        );

        assert!(
            Group::new("Work".to_owned(), 0, vec![id(1), id(2), id(3)]).is_ok(),
            "distinct identifiers are fine"
        );
    }

    #[test]
    fn an_over_long_name_or_list_is_rejected() {
        let long = "n".repeat(crate::vault::Entry::MAX_FIELD_LEN + 1);
        assert!(matches!(
            Group::new(long, 0, vec![]),
            Err(Error::FieldTooLong { .. })
        ));

        let too_many: Vec<EntryId> = (0..=Group::MAX_ENTRIES)
            .map(|index| {
                let mut bytes = [0_u8; EntryId::LEN];
                bytes[..8].copy_from_slice(
                    &u64::try_from(index)
                        .expect("the test range fits in u64")
                        .to_be_bytes(),
                );
                EntryId::from_bytes(bytes)
            })
            .collect();
        assert!(
            matches!(
                Group::new(String::new(), 0, too_many),
                Err(Error::VaultGroupTooManyEntries { .. })
            ),
            "the list travels in one node, so it is bounded by MAX_FIELD_LEN"
        );
    }
}
