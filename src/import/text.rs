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
//! The format is a list of URIs, UTF-8, one per line, with a trailing newline and no comments or
//! header: the order of the lines is the order of the vault. Reading it is therefore
//! [`crate::uri::parse`] per line, which is the same entry point a scanned QR code goes through -
//! **one parser, two sources**, so a line that parses here behaves exactly like a line that
//! arrived from a camera.
//!
//! # Blank lines and the line number in a message
//!
//! Blank lines are skipped, and the **physical** line number is what a problem reports: a user
//! who opens the file in an editor and goes to line 7 must find the entry the report is about
//! there, not the fourth URI.

use crate::import::{
    ImportProblem, ImportReport, ImportedEntry, decode_utf8, drop_duplicates, mapping::safe_reason,
};
use crate::vault::{Timestamp, entry_from_parsed_uri};
use crate::{Error, Result};

/// Reads a text export.
///
/// # Errors
///
/// A file-level failure: the bytes are not UTF-8. Every line that cannot be read becomes a
/// problem instead, so one damaged line does not cost the user the rest of the file.
pub fn import(bytes: &[u8], now: Timestamp) -> Result<ImportReport> {
    let text = decode_utf8(bytes)?;
    let mut report = ImportReport::default();

    for (index, line) in text.lines().enumerate() {
        let position = index + 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if report.entries.len() >= crate::import::MAX_ENTRIES {
            return Err(Error::ImportTooManyEntries {
                limit: crate::import::MAX_ENTRIES,
                actual: report.entries.len(),
            });
        }

        let parsed = match crate::uri::parse(line) {
            Ok(parsed) => parsed,
            Err(error) => {
                report.problems.push(ImportProblem {
                    position,
                    reason: safe_reason(&error),
                });
                continue;
            }
        };
        match entry_from_parsed_uri(parsed, now) {
            Ok(entry) => report.entries.push(ImportedEntry {
                entry,
                groups: Vec::new(),
                favorite: false,
                position,
                notes: Vec::new(),
            }),
            Err(error) => report.problems.push(ImportProblem {
                position,
                reason: safe_reason(&error),
            }),
        }
    }

    drop_duplicates(&mut report);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::EntryKind;

    /// One line per supported scheme, in the spelling the reference implementation writes.
    ///
    /// The PIN is Base32-encoded by the library rather than written out by hand: a hand-written
    /// constant that decodes to something other than the intended text makes a test pass for the
    /// wrong reason.
    fn sample() -> String {
        let pin = crate::base32::encode(b"1234");
        format!(
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=60\n\
             otpauth://hotp/Bank:bob?secret=JBSWY3DPEHPK3PXP&issuer=Bank&counter=7\n\
             otpauth://steam/alice?secret=JBSWY3DPEHPK3PXP\n\
             otpauth://yaotp/alice?secret=LA2V6KMCGYMWWVEW64RNP3JA3I&pin={pin}\n\
             motp:/Example:alice?secret=deadbeef&issuer=Example&pin={pin}\n"
        )
    }

    fn import_default_sample() -> ImportReport {
        import_sample(&sample())
    }

    fn import_sample(text: &str) -> ImportReport {
        import(text.as_bytes(), 1_700_000_000).expect("the sample is valid UTF-8")
    }

    #[test]
    fn every_scheme_is_read_from_its_own_line() {
        let report = import_default_sample();
        assert!(report.problems.is_empty(), "actual {:?}", report.problems);
        assert_eq!(report.entries.len(), 5);

        let kinds: Vec<&EntryKind> = report
            .entries
            .iter()
            .map(|entry| &entry.entry.kind)
            .collect();
        assert_eq!(kinds[0], &EntryKind::Totp { period: 60 });
        assert_eq!(kinds[1], &EntryKind::Hotp { counter: 7 });
        assert_eq!(kinds[2], &EntryKind::Steam);
        assert_eq!(
            kinds[3],
            &EntryKind::Yandex {
                period: 30,
                pin: Some(crate::yaotp::YandexPin::new("1234".to_owned()))
            }
        );
        assert_eq!(
            kinds[4],
            &EntryKind::Motp {
                period: 10,
                pin: Some(crate::motp::MotpPin::new("1234".to_owned()))
            }
        );

        assert_eq!(report.entries[0].entry.name, "GitHub:alice");
        assert_eq!(report.entries[0].entry.account, "alice");
        assert_eq!(report.entries[0].position, 1);
        assert_eq!(report.entries[4].position, 5);
    }

    #[test]
    fn a_blank_line_is_skipped_but_still_counts_for_the_position() {
        let report = import_sample("\notpauth://totp/a?secret=JBSWY3DPEHPK3PXP\n\n");
        assert!(report.problems.is_empty());
        assert_eq!(report.entries.len(), 1);
        assert_eq!(
            report.entries[0].position, 2,
            "the line number must match what an editor shows"
        );
    }

    #[test]
    fn a_bad_line_does_not_end_the_import() {
        let text = "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP\nnot a uri at all\notpauth://totp/b?secret=JBSWY3DPEHPK3PXP\n";
        let report = import_sample(text);

        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.problems.len(), 1);
        assert_eq!(report.problems[0].position, 2);
        assert!(
            !report.problems[0].reason.contains("not a uri"),
            "the reason must not quote the line: {}",
            report.problems[0].reason
        );
    }

    #[test]
    fn a_ten_digit_line_is_reported_with_the_reason() {
        let report = import_sample("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=10\n");
        assert!(report.entries.is_empty());
        assert_eq!(report.problems.len(), 1);
        assert!(
            report.problems[0].reason.contains("31 bits"),
            "actual {}",
            report.problems[0].reason
        );
    }

    #[test]
    fn a_secret_never_reaches_the_problem_text() {
        let report = import_sample("otpauth://totp/a?secret=NOT-BASE32-AT-ALL\n");
        assert_eq!(report.problems.len(), 1, "that secret cannot be decoded");
        let reason = &report.problems[0].reason;
        assert!(
            !reason.contains("NOT-BASE32"),
            "the reason must not quote the secret: {reason}"
        );
    }

    #[test]
    fn invalid_utf8_is_a_file_level_failure() {
        let result = import(&[0xFF, 0xFE, 0xFD], 0);
        assert!(
            matches!(result, Err(Error::ImportMalformed { .. })),
            "actual {result:?}"
        );
    }
}
