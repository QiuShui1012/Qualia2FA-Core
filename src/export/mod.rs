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

//! Writing the vault out in a form another authenticator can read.
//!
//! # The formats are the reference implementation's, not this library's
//!
//! An export exists to be read by something else, so its spelling is decided by the reader
//! rather than by what would be convenient here: the JSON object, the table of the HTML
//! export, the one-URI-per-line text file and the `motp:` form of an mOTP URI are all the
//! shapes the reference implementation writes and reads. Nothing is added, and nothing is
//! renamed.
//!
//! **One consequence is deliberate**: the `icon` field of a JSON entry is written as `null`
//! rather than as a picture. This library does not store icons (they are dropped at import,
//! see [`crate::import`]), and inventing one - or writing a placeholder - would put a value
//! in the field that means "there was an icon" to every reader.
//!
//! # An export round trips through this library's own reader
//!
//! Every format here has a reader in [`crate::import`], and each writer's tests walk the whole
//! way: vault → file → reader → entry by entry comparison. That is the property that matters,
//! because the two halves were written against the same document and a shared misunderstanding
//! would otherwise stay invisible.
//!
//! What the round trip cannot preserve is what a format does not carry: the text and HTML
//! exports have no field for the groups or for the ordering, and neither has one for the
//! account name (a URI carries it in the label). Each writer's documentation says which
//! fields survive and which do not.
//!
//! # Nothing about an entry appears in an error
//!
//! The same rule as the reader's: an error is a position and a reason. An export that cannot
//! be written says which entry it stopped at, never what the entry held.
//!
//! # The vault is not modified
//!
//! Every entry point takes `&Vault` and returns the file's bytes; the caller writes them
//! wherever it likes. This library has no I/O (see the crate documentation), and an export is
//! not an exception.

pub mod html;
pub mod json;
pub(crate) mod png;
pub mod text;

use std::collections::HashSet;

use crate::vault::{Entry, EntryId, Group, GroupId, Vault};
use crate::{Error, Result};

/// An export format this library writes.
///
/// The four are the reference implementation's own set: three files plus the encrypted form of
/// the JSON one. Which one a caller offers is a user interface question; the difference that
/// matters to the library is [`ExportFormat::needs_password`] and whether the format can carry
/// the groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// The text export: one `otpauth://` URI per line.
    Text,
    /// The JSON export, readable as it stands.
    Json,
    /// The JSON export, encrypted with a password the caller supplies.
    EncryptedJson,
    /// The HTML export: a table with one row per entry and the code drawn beside it.
    Html,
}

impl ExportFormat {
    /// The name used in messages and diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "JSON",
            Self::EncryptedJson => "encrypted JSON",
            Self::Html => "HTML",
        }
    }

    /// The file name extension this format is normally written with.
    ///
    /// Both JSON formats share one: they are the same file with and without a password, and a
    /// reader tells them apart by the `db` field being a string rather than an object.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Text => "txt",
            Self::Json | Self::EncryptedJson => "json",
            Self::Html => "html",
        }
    }

    /// Whether this format is written with a password.
    ///
    /// A caller uses it to decide whether to ask for one **before** calling [`export`], rather
    /// than calling and handling [`Error::ExportPasswordRequired`].
    #[must_use]
    pub const fn needs_password(self) -> bool {
        matches!(self, Self::EncryptedJson)
    }

    /// Whether this format carries the groups and the order inside them.
    ///
    /// Only the JSON formats do: neither a list of URIs nor a table has anywhere to put a
    /// group. An entry exported to those formats and read back lands in the top group, which is
    /// a loss of arrangement rather than of data.
    #[must_use]
    pub const fn carries_groups(self) -> bool {
        matches!(self, Self::Json | Self::EncryptedJson)
    }
}

/// Writes the vault out in one of the formats.
///
/// `password` is the UTF-8 bytes of the password, and is looked at only by
/// [`ExportFormat::EncryptedJson`]: the derivation consumes bytes, and hashing text would mean
/// choosing a normalization the format does not specify. A password supplied for one of the
/// other three is ignored rather than refused, since the caller has already chosen the format
/// and there is nothing it could open.
///
/// # Errors
///
/// - [`Error::ExportPasswordRequired`]: an encrypted export was asked for with no password.
/// - [`Error::ExportPasswordEmpty`]: the password is empty, which would leave the file open to
///   anyone who tries nothing at all.
/// - [`Error::UriAccountContainsColon`]: one entry's account name cannot be written into a URI
///   label (see [`crate::uri::serialize`]). Reported rather than worked around: the file would
///   read back as a different entry.
/// - [`Error::ExportQrTooLong`]: one entry's URI does not fit a QR code, so the HTML export
///   cannot draw it.
/// - [`Error::FieldTooLong`]: an entry holds a field the file format cannot represent.
///   Reachable only for an entry built by hand; the vault's own parser would have refused it.
pub fn export(vault: &Vault, format: ExportFormat, password: Option<&[u8]>) -> Result<Vec<u8>> {
    let text = match format {
        ExportFormat::Text => text::write(vault)?,
        ExportFormat::Json => json::write(vault)?,
        ExportFormat::Html => html::write(vault)?,
        ExportFormat::EncryptedJson => {
            let password = password.ok_or(Error::ExportPasswordRequired)?;
            if password.is_empty() {
                return Err(Error::ExportPasswordEmpty);
            }
            json::write_encrypted(vault, password)?
        }
    };
    Ok(text.into_bytes())
}

/// One entry, with what the writers need beside it.
pub(crate) struct Item<'a> {
    /// The entry's identifier, which the JSON export writes as its UUID.
    pub(crate) id: EntryId,
    /// The entry itself.
    pub(crate) entry: &'a Entry,
    /// The named group it belongs to, or `None` for the top group.
    pub(crate) group: Option<GroupId>,
    /// Where it sits in the export, counting from 1. Used in errors, never its name.
    pub(crate) position: usize,
}

/// Walks the vault in the order an export writes it.
///
/// The order is the one the user sees: the top group first, then the named groups in their own
/// order, and inside each group the ordering the vault holds. That is the same walk the
/// interface performs, which is what makes an exported file look like the application.
///
/// # An entry no ordering mentions
///
/// Every path through this library puts an entry into a group (see
/// [`crate::vault::Vault::insert`]), so this cannot normally happen. It is handled anyway,
/// because the alternative is an export that silently leaves entries out: whatever is left
/// after the walk is appended at the end, with no group.
pub(crate) fn items(vault: &Vault) -> Vec<Item<'_>> {
    let mut out: Vec<Item<'_>> = Vec::with_capacity(vault.len());
    let mut seen: HashSet<EntryId> = HashSet::with_capacity(vault.len());

    for (group_id, _) in vault.groups() {
        let named = (!group_id.is_top()).then_some(*group_id);
        for (id, entry) in vault.entries_in(group_id) {
            if !seen.insert(*id) {
                continue;
            }
            out.push(Item {
                id: *id,
                entry,
                group: named,
                position: out.len() + 1,
            });
        }
    }

    for (id, entry) in vault.iter() {
        if !seen.insert(*id) {
            continue;
        }
        out.push(Item {
            id: *id,
            entry,
            group: None,
            position: out.len() + 1,
        });
    }

    out
}

/// The named groups, in the order the vault displays them.
///
/// The top group is left out: it is not a group a file can name, it is "everything that is in
/// no named group", and the reference implementation's format has no record for it.
pub(crate) fn named_groups(vault: &Vault) -> Vec<(GroupId, &Group)> {
    vault
        .groups()
        .filter(|(id, _)| !id.is_top())
        .map(|(id, group)| (*id, group))
        .collect()
}

/// The URI of one entry, in the spelling the reference implementation writes.
///
/// # The label is the account, and the name is the fallback
///
/// A URI has one label and the reference format has no second field, so an entry with both a
/// name and an account can carry only one of them. The account wins because it is what the
/// label means (it is where the account came from when the URI was read), and the name is used
/// when there is none - an entry created in this application has a name from the start and
/// often no account at all.
///
/// # Errors
///
/// [`crate::uri::serialize`]'s: an account name containing `:` cannot be told apart from the
/// issuer separator once the label is decoded, so the URI is refused rather than written into
/// something that reads back differently.
pub(crate) fn uri_of(entry: &Entry) -> Result<String> {
    // The copy is explicit because `OtpSecret` is deliberately neither `Clone` nor copyable by
    // accident: `Entry::duplicate` is the one sanctioned way to get a second, owned entry.
    let Entry {
        name,
        issuer,
        account,
        secret,
        algorithm,
        digits,
        kind,
        ..
    } = entry.duplicate()?;

    let label = if account.is_empty() { name } else { account };
    crate::uri::serialize(&crate::uri::OtpAuth {
        kind,
        secret,
        issuer,
        account: label,
        algorithm,
        digits,
    })
}

/// The name the formats use for a scheme.
pub(crate) const fn type_name(kind: &crate::vault::EntryKind) -> &'static str {
    use crate::vault::EntryKind;
    match kind {
        EntryKind::Totp { .. } => "totp",
        EntryKind::Hotp { .. } => "hotp",
        EntryKind::Steam => "steam",
        EntryKind::Motp { .. } => "motp",
        EntryKind::Yandex { .. } => "yandex",
    }
}

/// The hash algorithm to write for an entry.
///
/// # The scheme wins over the entry's own field
///
/// Three of the five schemes fix their own algorithm: mOTP is MD5-based, Yandex OTP is SHA-256,
/// Steam Guard is SHA-1. The entry model keeps a field there anyway (it is one type for every
/// entry), and what decides the code a user sees is the scheme - so that is what is written.
/// Writing the field instead would produce a file whose declared algorithm contradicts the
/// scheme whenever an entry was built by hand, and a reader that believes the declaration would
/// compute codes that never match.
pub(crate) const fn algorithm_name(
    kind: &crate::vault::EntryKind,
    algorithm: crate::otp::Algorithm,
) -> &'static str {
    use crate::otp::Algorithm;
    use crate::vault::EntryKind;
    match kind {
        EntryKind::Motp { .. } => "MD5",
        EntryKind::Yandex { .. } => "SHA256",
        EntryKind::Steam => "SHA1",
        EntryKind::Totp { .. } | EntryKind::Hotp { .. } => match algorithm {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        },
    }
}

/// Writes a 128-bit identifier as canonical UUID text.
///
/// The reference implementation's entries and groups are identified by UUIDs, so that is the
/// spelling its files carry. Dashes are written in the canonical places; a reader that strips
/// them (this library's own does) reads the same value either way.
pub(crate) fn uuid_text(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Writes bytes as lower-case hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Writes bytes as standard base64 (RFC 4648 §4): `+`, `/`, and `=` padding.
///
/// The alphabet is the standard one, not the URL-safe one, because that is what the format
/// writes for both the encrypted database and the image of its HTML export.
pub(crate) fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut block = [0_u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let bits = (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
        let letters = [
            ALPHABET[((bits >> 18) & 0x3F) as usize],
            ALPHABET[((bits >> 12) & 0x3F) as usize],
            ALPHABET[((bits >> 6) & 0x3F) as usize],
            ALPHABET[(bits & 0x3F) as usize],
        ];
        let keep = chunk.len() + 1;
        for (index, letter) in letters.iter().enumerate() {
            out.push(if index < keep {
                char::from(*letter)
            } else {
                '='
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identifier_is_written_as_a_canonical_uuid() {
        let mut bytes = [0_u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(index).expect("the index is small");
        }
        let text = uuid_text(&bytes);
        assert_eq!(text, "00010203-0405-0607-0809-0a0b0c0d0e0f");
        assert_eq!(text.len(), 36);
    }

    #[test]
    fn base64_is_the_standard_alphabet_with_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"A"), "QQ==");
        assert_eq!(base64(b"AB"), "QUI=");
        assert_eq!(base64(b"ABC"), "QUJD");
        assert_eq!(base64(&[0xFB, 0xFF]), "+/8=");
    }

    #[test]
    fn hexadecimal_is_lower_case_and_two_digits_per_byte() {
        assert_eq!(hex(&[0x00, 0x0F, 0xFF]), "000fff");
        assert_eq!(hex(&[]), "");
    }

    /// What each format is called, what it is written with, and what it needs.
    ///
    /// A caller builds a file name and asks for a password from these answers, so they are part
    /// of the interface rather than an internal detail.
    #[test]
    fn the_formats_describe_themselves() {
        let formats = [
            ExportFormat::Text,
            ExportFormat::Json,
            ExportFormat::EncryptedJson,
            ExportFormat::Html,
        ];
        let names: Vec<&str> = formats.iter().map(|format| format.name()).collect();
        assert_eq!(names, vec!["text", "JSON", "encrypted JSON", "HTML"]);

        let extensions: Vec<&str> = formats.iter().map(|format| format.extension()).collect();
        assert_eq!(extensions, vec!["txt", "json", "json", "html"]);
        assert_eq!(
            formats
                .iter()
                .filter(|format| format.needs_password())
                .count(),
            1,
            "exactly one format is encrypted"
        );
        assert!(ExportFormat::EncryptedJson.needs_password());
        assert!(!ExportFormat::Json.needs_password());
        assert!(
            ExportFormat::Json.carries_groups() && ExportFormat::EncryptedJson.carries_groups(),
            "the two JSON forms carry the groups"
        );
        assert!(
            !ExportFormat::Text.carries_groups() && !ExportFormat::Html.carries_groups(),
            "a list of URIs and a table have nowhere to put a group"
        );
    }

    /// An empty vault exports in every format without an error.
    ///
    /// A vault with no entries has nothing to write into a list of URIs, so the text export is
    /// an empty file - that is a legitimate export, not a failure. The other three always have a
    /// container to write.
    #[test]
    fn every_format_writes_an_empty_vault() {
        let vault = Vault::new();
        for format in [
            ExportFormat::Text,
            ExportFormat::Json,
            ExportFormat::Html,
            ExportFormat::EncryptedJson,
        ] {
            let password = format.needs_password().then_some(&b"password"[..]);
            let written = export(&vault, format, password)
                .unwrap_or_else(|error| panic!("{} must write: {error}", format.name()));
            if format == ExportFormat::Text {
                assert!(written.is_empty(), "there are no entries to write");
            } else {
                assert!(
                    !written.is_empty(),
                    "{} must still produce a container",
                    format.name()
                );
            }
        }
    }
}
