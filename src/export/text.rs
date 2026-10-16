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

//! The text export: one URI per line.
//!
//! The shape is the reader's ([`crate::import::text`]): UTF-8, one URI per line, a newline
//! after every line including the last, no header and no comments. The order of the lines is
//! the order the vault displays, which for this format is the whole of what it carries.
//!
//! # What the format does not carry
//!
//! - **The name.** A URI has one label and the reference format has no second field, so the
//!   label is the account (see [`crate::uri::serialize`]), and an entry read back takes its name
//!   from that label.
//! - **The note.** No URI parameter holds one.
//! - **The groups and the order between them.** The order *inside* a group survives as the
//!   order of the lines; which group a line belonged to does not.
//!
//! # A secret this format cannot spell
//!
//! The mOTP secret is written as **hexadecimal** here rather than Base32, because that is the
//! `motp:` form the reference implementation writes. The other four schemes keep Base32. That
//! difference belongs to the URI shape and not to the scheme, and [`crate::uri::serialize`]
//! applies it - this writer only joins the lines.

use crate::Result;
use crate::export::{items, uri_of};
use crate::vault::Vault;

/// Writes the vault as one URI per line.
///
/// # Errors
///
/// [`crate::Error::UriAccountContainsColon`] when an entry cannot be written as a URI.
pub fn write(vault: &Vault) -> Result<String> {
    let mut out = String::new();
    for item in items(vault) {
        out.push_str(&uri_of(item.entry)?);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{ImportFormat, import};
    use crate::vault::Entry;

    /// One entry, built the way a scanned code would be.
    fn entry(uri: &str, now: u64) -> Entry {
        let parsed = crate::uri::parse(uri).expect("the uri is valid");
        crate::vault::entry_from_parsed_uri(parsed, now).expect("the entry is valid")
    }

    /// The five schemes, one URI each, in the spellings the reference implementation writes.
    const URIS: [&str; 5] = [
        "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=60",
        "otpauth://hotp/Bank:bob?secret=JBSWY3DPEHPK3PXP&issuer=Bank&counter=7&digits=8",
        "otpauth://steam/alice?secret=JBSWY3DPEHPK3PXP",
        "motp:/Example:alice?secret=deadbeef&issuer=Example&pin=GEZDGNBVGY3Q",
        "otpauth://yaotp/alice?secret=LA2V6KMCGYMWWVEW64RNP3JA3I&pin=GEZDGNBVGY3Q",
    ];

    /// A vault holding every scheme, in the order they are listed.
    fn vault() -> (Vault, Vec<Entry>) {
        let mut vault = Vault::new();
        let entries: Vec<Entry> = URIS.iter().map(|uri| entry(uri, 1_600_000_000)).collect();
        for built in &entries {
            vault
                .insert(built.duplicate().expect("a copy is possible"))
                .expect("the vault accepts it");
        }
        (vault, entries)
    }

    /// One line per entry, one URI each, in the vault's order.
    ///
    /// The lines are compared **as configurations** rather than as byte strings: the parameters
    /// of a URI have no order in the format, and the writer emits them in its own (secret,
    /// issuer, algorithm, digits, period, counter, pin). A byte comparison would pin that order
    /// as if it were part of the format.
    #[test]
    fn one_uri_per_entry_in_the_vaults_order() {
        let (vault, originals) = vault();
        let text = write(&vault).expect("the export is written");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), URIS.len());
        assert!(text.ends_with('\n'), "every line ends with a newline");

        for (index, original) in originals.iter().enumerate() {
            let line = index + 1;
            let parsed = crate::uri::parse(lines[index])
                .unwrap_or_else(|error| panic!("line {line} must parse: {error}"));
            assert_eq!(parsed.kind, original.kind, "line {line}");
            assert_eq!(parsed.issuer, original.issuer, "line {line}");
            assert_eq!(parsed.account, original.account, "line {line}");
            assert_eq!(parsed.algorithm, original.algorithm, "line {line}");
            assert_eq!(parsed.digits, original.digits, "line {line}");
            assert_eq!(
                parsed.secret.to_base32(),
                original.secret.to_base32(),
                "line {line}"
            );
        }
    }

    /// The whole point: what comes out goes back in, for every field the format carries.
    #[test]
    fn an_export_round_trips_through_the_reader() {
        let (vault, originals) = vault();
        let text = write(&vault).expect("the export is written");
        let report = import(text.as_bytes(), ImportFormat::Text, 1_700_000_000, None)
            .unwrap_or_else(|error| panic!("the export must read back: {error}"));

        assert!(report.problems.is_empty(), "actual {:?}", report.problems);
        assert_eq!(report.entries.len(), originals.len());
        for (index, original) in originals.iter().enumerate() {
            let read = &report.entries[index].entry;
            assert_eq!(read.kind, original.kind, "line {}", index + 1);
            assert_eq!(read.issuer, original.issuer, "line {}", index + 1);
            assert_eq!(read.algorithm, original.algorithm, "line {}", index + 1);
            assert_eq!(read.digits, original.digits, "line {}", index + 1);
            assert_eq!(
                read.secret.to_base32(),
                original.secret.to_base32(),
                "line {}",
                index + 1
            );
        }
    }

    /// The mOTP line is the `motp:` form with a hexadecimal secret, not an `otpauth://` one.
    ///
    /// The two shapes decode the same characters differently, so a line written in the wrong one
    /// reads back as a **different secret** with nothing to say so - which is why the shape is
    /// pinned here rather than only compared through a round trip.
    #[test]
    fn an_motp_line_uses_the_hexadecimal_form() {
        let mut vault = Vault::new();
        vault.insert(entry(URIS[3], 0)).expect("the vault is empty");
        let text = write(&vault).expect("the export is written");

        assert!(text.starts_with("motp:/Example:alice?"), "actual {text}");
        assert!(text.contains("secret=deadbeef"), "actual {text}");
        assert!(
            !text.contains("otpauth"),
            "mOTP is not written in the otpauth form: {text}"
        );
    }

    /// An account name a URI cannot express is reported rather than written into something that
    /// would read back as a different entry.
    #[test]
    fn an_account_a_uri_cannot_carry_is_refused() {
        let mut vault = Vault::new();
        let mut built = entry(URIS[0], 0);
        built.account = "a:b".to_owned();
        vault.insert(built).expect("the vault is empty");

        let result = write(&vault);
        assert!(
            matches!(result, Err(crate::Error::UriAccountContainsColon { .. })),
            "actual {result:?}"
        );
    }

    /// The label is the account, and the name stands in when there is none.
    #[test]
    fn the_label_is_the_account_with_the_name_as_fallback() {
        let mut vault = Vault::new();
        let mut without_account = entry(URIS[0], 0);
        without_account.name = "GitHub".to_owned();
        without_account.account = String::new();
        without_account.issuer = Some("GitHub".to_owned());
        vault.insert(without_account).expect("the vault is empty");

        let text = write(&vault).expect("the export is written");
        assert_eq!(
            text.trim(),
            "otpauth://totp/GitHub:GitHub?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=60",
            "an entry with no account is labelled with its name"
        );
    }

    /// An empty vault produces an empty file rather than an error.
    #[test]
    fn an_empty_vault_writes_an_empty_file() {
        let vault = Vault::new();
        assert_eq!(write(&vault).expect("nothing to write"), "");
    }
}
