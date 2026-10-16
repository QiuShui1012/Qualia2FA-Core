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

//! The HTML export: one table row per entry.
//!
//! # Columns are found by their heading, not by their position
//!
//! The export is assembled by the exporter's own code rather than from a template, and it has
//! changed shape before, so the reader builds a "column name to column number" map from the
//! heading row and looks fields up by name. A table with the columns in a different order, or
//! with an extra column, still reads; a table that has lost a column the reader needs reports
//! that column missing rather than reading the neighbouring one.
//!
//! # What the format does not carry
//!
//! - **No time step.** The step only exists inside the QR code that sits in one of the columns,
//!   and this reader does not decode images: for the schemes that have a step, the default is
//!   used and every such entry is marked with [`ImportNote::PeriodAssumed`]. An entry whose step
//!   is not the default would otherwise produce codes that never match, with nothing on screen to
//!   say why.
//! - **No groups.** The export has no grouping at all, so every imported entry belongs to the top
//!   group.
//! - **An mOTP secret is written as hexadecimal here**, while the JSON export writes Base32. The
//!   reader converts it, so the mapping sees one encoding.
//!
//! # The image column is skipped, and nothing else is decoded
//!
//! One column holds a QR code as a `data:` image, and this reader ignores it in the simplest
//! possible way: only the **text** of a cell is looked at, and an image contributes none. Its
//! content is the same configuration the neighbouring columns already spell out, so decoding
//! images would mean pulling in a decoder for information that is already here in plain text.
//!
//! # The document is not well-formed, and that is fine
//!
//! The exporter writes its style block **after** the closing body tag, which is not legal HTML.
//! The reader therefore scans for rows rather than building a tree, and never depends on the
//! order of tags: a document that puts its table anywhere is read the same way.

use std::collections::HashMap;

use crate::import::mapping::{RawAlgorithm, RawEntry, RawKind, safe_reason};
use crate::import::{
    ImportNote, ImportProblem, ImportReport, ImportedEntry, MAX_ENTRIES, decode_utf8,
    drop_duplicates,
};
use crate::vault::Timestamp;
use crate::{Error, Result};

/// The largest number of cells one row may hold.
///
/// A row with more cells than the exporter ever writes is a sign that the scan went wrong (a
/// missing `</td>` swallowing the rest of the document, for instance). Bounding it keeps a
/// damaged file from turning into an allocation proportional to the file.
const MAX_CELLS_PER_ROW: usize = 64;

/// Reads an HTML export.
///
/// # Errors
///
/// A file-level failure: the bytes are not UTF-8, or the document holds no table the reader
/// recognises. Per-row failures are problems in the report.
pub fn import(bytes: &[u8], now: Timestamp) -> Result<ImportReport> {
    let html = decode_utf8(bytes)?;
    let mut table = Table::parse(html)?;

    let mut report = ImportReport::default();
    let mut seen = 0_usize;
    while let Some(row) = table.next_row() {
        seen += 1;
        if seen > MAX_ENTRIES {
            return Err(Error::ImportTooManyEntries {
                limit: MAX_ENTRIES,
                actual: seen,
            });
        }
        let position = seen;
        match read_row(&table.columns, &row, now) {
            Ok(Some(read)) => report.entries.push(ImportedEntry {
                entry: read.entry,
                groups: Vec::new(),
                favorite: read.favorite,
                position,
                notes: read.notes,
            }),
            Ok(None) => {}
            Err(error) => report.problems.push(ImportProblem {
                position,
                reason: safe_reason(&error),
            }),
        }
    }

    summarize(&mut report);
    drop_duplicates(&mut report);
    Ok(report)
}

/// One row read into an entry, with what the report needs beside it.
struct Read {
    /// The model entry.
    entry: crate::vault::Entry,
    /// Whether the row was marked a favourite.
    favorite: bool,
    /// What was dropped or assumed about it.
    notes: Vec<ImportNote>,
}

/// One row of cells, with the heading names beside it.
struct Table {
    /// Column name (lower case, trimmed) to column number.
    columns: HashMap<String, usize>,
    /// The data rows, still as raw cell text.
    rows: Vec<Vec<String>>,
    /// How far the reader has got.
    next: usize,
}

impl Table {
    /// Splits the document into a heading map and rows.
    ///
    /// # Errors
    ///
    /// [`Error::ImportMalformed`] when the document holds no heading row at all: without it
    /// there is nothing to look fields up by, and guessing the layout is how a reader ends up
    /// importing the wrong column as the secret.
    fn parse(html: &str) -> Result<Self> {
        let mut columns = HashMap::new();
        let mut rows = Vec::new();
        let mut heading_seen = false;

        for row_html in split_rows(html) {
            let (cells, is_heading) = split_cells(row_html);
            if cells.is_empty() {
                continue;
            }
            if is_heading && !heading_seen {
                for (index, cell) in cells.iter().enumerate() {
                    let name = cell.trim().to_ascii_lowercase();
                    if !name.is_empty() {
                        columns.entry(name).or_insert(index);
                    }
                }
                heading_seen = true;
                continue;
            }
            if !heading_seen {
                continue;
            }
            rows.push(cells);
        }

        if !heading_seen {
            return Err(Error::ImportMalformed {
                reason: "the document has no table heading to read the columns from",
            });
        }
        Ok(Self {
            columns,
            rows,
            next: 0,
        })
    }

    /// The next data row.
    fn next_row(&mut self) -> Option<Vec<String>> {
        let row = self.rows.get(self.next)?;
        self.next += 1;
        Some(row.clone())
    }
}

/// Reads one row into an entry, or `None` when the row holds nothing to import.
fn read_row(
    columns: &HashMap<String, usize>,
    row: &[String],
    now: Timestamp,
) -> Result<Option<Read>> {
    let cell = |name: &str| -> Option<&str> {
        let index = *columns.get(name)?;
        let value = row.get(index)?.trim();
        if value.is_empty() || value == "-" {
            None
        } else {
            Some(value)
        }
    };

    let Some(type_name) = cell("type") else {
        // A row with no type is a spacer or a second heading; there is nothing to import and
        // nothing to report either.
        return Ok(None);
    };
    let Some(secret_text) = cell("secret") else {
        return Err(malformed("a row has no secret"));
    };

    let kind = match type_name.to_ascii_lowercase().as_str() {
        "totp" => RawKind::Totp { period: None },
        "hotp" => RawKind::Hotp {
            counter: cell("counter")
                .and_then(|text| text.parse::<u64>().ok())
                .ok_or(malformed("an HOTP row has no counter"))?,
        },
        "steam" => RawKind::Steam,
        "motp" => RawKind::Motp {
            period: None,
            pin: cell("pin").map(str::to_owned),
        },
        "yandex" => RawKind::Yandex {
            period: None,
            pin: cell("pin").map(str::to_owned),
        },
        _ => return Err(malformed("a row has a type this library does not know")),
    };

    let secret = secret_as_base32(kind_is_motp(&kind), secret_text)?;

    let algorithm = match cell("algo") {
        Some(name) => Some(RawAlgorithm::parse(name).ok_or(malformed(
            "a row names an algorithm this library does not know",
        ))?),
        None => None,
    };

    let digits = match cell("digits") {
        Some(text) => Some(
            text.parse::<u8>()
                .map_err(|_| malformed("a row's digit count is not a number"))?,
        ),
        None => None,
    };

    let favorite = cell("favorite").is_some_and(is_true);

    let entry = RawEntry {
        name: cell("name").unwrap_or_default().to_owned(),
        issuer: cell("issuer").map(str::to_owned),
        note: cell("note").unwrap_or_default().to_owned(),
        secret,
        algorithm,
        digits,
        kind,
        // The export has no icon column at all: the image column holds the QR code, which is
        // the same configuration the neighbouring columns already spell out. Nothing is dropped
        // here, so nothing is reported.
        icon: false,
    };
    let (entry, mut notes) = entry.into_entry(now)?;

    // The step is not in the document at all; say so rather than letting the default pass for
    // something the file declared.
    if let Some(period) = entry.kind.period() {
        let text = std::mem::take(&mut notes);
        notes = vec![ImportNote::PeriodAssumed { seconds: period }];
        notes.extend(text);
    }

    Ok(Some(Read {
        entry,
        favorite,
        notes,
    }))
}

/// Whether the row describes mOTP, whose secret this format writes in hexadecimal.
fn kind_is_motp(kind: &RawKind) -> bool {
    matches!(kind, RawKind::Motp { .. })
}

/// Converts the secret column into Base32, if it is not already.
///
/// The JSON export writes Base32 for every scheme, while this one writes **hexadecimal** for
/// mOTP. Converting here keeps the mapping's single "the secret is Base32" rule intact.
fn secret_as_base32(is_motp: bool, text: &str) -> Result<String> {
    if !is_motp {
        return Ok(text.to_owned());
    }
    let bytes = decode_hex(text).ok_or(malformed("an mOTP row's secret is not hexadecimal"))?;
    Ok(crate::base32::encode(&bytes))
}

/// Decodes hexadecimal text, upper or lower case.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for index in (0..bytes.len()).step_by(2) {
        let high = hex_value(*bytes.get(index)?)?;
        let low = hex_value(*bytes.get(index + 1)?)?;
        out.push((high << 4) | low);
    }
    Some(out)
}

/// The value of one hexadecimal digit.
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Reads a boolean cell tolerantly.
///
/// The exporter writes one of a few spellings and no specification says which, so the reader
/// accepts the usual ones and treats anything else as "no". A favourite is an arrangement, not
/// data: guessing wrong costs the user a sort order, not an entry.
fn is_true(text: &str) -> bool {
    let text = text.trim();
    text.eq_ignore_ascii_case("true")
        || text == "1"
        || text.eq_ignore_ascii_case("yes")
        || text.eq_ignore_ascii_case("ja")
        || text.eq_ignore_ascii_case("★")
}

/// Counts what was dropped, from the notes of every entry.
fn summarize(report: &mut ImportReport) {
    for entry in &report.entries {
        for note in &entry.notes {
            match note {
                ImportNote::IconDropped => report.dropped.icons += 1,
                ImportNote::PeriodAssumed { .. } => report.dropped.periods_assumed += 1,
            }
        }
    }
}

/// Yields the `<tr>…</tr>` blocks of a document.
///
/// A row that is never closed runs to the end of the document, which is what a browser does with
/// it too, and the cell scan then finds the cells it holds.
fn split_rows(html: &str) -> Vec<&str> {
    let mut rows = Vec::new();
    let mut rest = html;
    while let Some(start) = find_tag(rest, "tr") {
        rest = &rest[start..];
        let end = find_tag(rest, "/tr").unwrap_or(rest.len());
        rows.push(&rest[..end]);
        rest = &rest[end.min(rest.len())..];
        if rest.is_empty() {
            break;
        }
    }
    rows
}

/// Splits a row into cell texts, and says whether the row was a heading row.
///
/// Only the text of a cell is kept: nested markup (an image, a line break) is dropped, and the
/// five entities an exporter may write are decoded. Everything else is left as it stands, which
/// matters for a note that contains an ampersand.
fn split_cells(row: &str) -> (Vec<String>, bool) {
    let mut cells = Vec::new();
    let mut is_heading = false;
    let mut rest = row;

    while cells.len() < MAX_CELLS_PER_ROW {
        // Whichever opening tag comes first starts the next cell. A closing tag never matches
        // here: `</td` does not contain `<td`.
        let (start, heading) = match (find_tag(rest, "td"), find_tag(rest, "th")) {
            (Some(td), Some(th)) if th < td => (th, true),
            (Some(td), None | Some(_)) => (td, false),
            (None, Some(th)) => (th, true),
            (None, None) => break,
        };
        is_heading |= heading;

        let Some(open_end) = rest[start..].find('>') else {
            // An opening tag that is never closed: nothing after it belongs to a cell.
            break;
        };
        let after = &rest[start + open_end + 1..];
        let name = if heading { "/th" } else { "/td" };
        // The cell ends at its own closing tag, or at the next cell when the document forgot it;
        // either way the scan moves forward.
        let end = find_tag(after, name)
            .or_else(|| find_tag(after, "td"))
            .or_else(|| find_tag(after, "th"))
            .unwrap_or(after.len());
        cells.push(text_of(&after[..end]));
        rest = &after[end..];
    }

    (cells, is_heading)
}

/// The text of a fragment: tags removed, entities decoded.
fn text_of(fragment: &str) -> String {
    let mut out = String::with_capacity(fragment.len());
    let mut chars = fragment.char_indices().peekable();
    while let Some((_, character)) = chars.next() {
        match character {
            '<' => {
                // Skip to the end of the tag; an unterminated one swallows the rest, which is
                // what the fragment being damaged means anyway.
                for (_, inner) in chars.by_ref() {
                    if inner == '>' {
                        break;
                    }
                }
            }
            '&' => {
                let mut entity = String::new();
                while let Some((_, inner)) = chars.peek().copied() {
                    if inner == ';' || entity.len() > 8 {
                        break;
                    }
                    entity.push(inner);
                    chars.next();
                }
                // A reference ends with its semicolon, which is part of it and not text.
                if matches!(chars.peek(), Some(&(_, ';'))) {
                    chars.next();
                }
                out.push_str(&decode_entity(&entity));
            }
            other => out.push(other),
        }
    }
    out.trim().to_owned()
}

/// Decodes the entities an exporter writes.
fn decode_entity(entity: &str) -> String {
    match entity {
        "amp" => "&".to_owned(),
        "lt" => "<".to_owned(),
        "gt" => ">".to_owned(),
        "quot" => "\"".to_owned(),
        "apos" | "#39" => "'".to_owned(),
        "nbsp" => " ".to_owned(),
        // An entity this reader does not know is kept as it was written: dropping it would
        // silently change the text of a note, and the text is shown to the user.
        other => format!("&{other};"),
    }
}

/// Finds the first `<name …>` or `</name …>` tag, returning its offset.
fn find_tag(haystack: &str, name: &str) -> Option<usize> {
    let needle = format!("<{name}");
    let lower = haystack.to_ascii_lowercase();
    let mut from = 0;
    while let Some(offset) = lower[from..].find(&needle) {
        let start = from + offset;
        let after = start + needle.len();
        // `<td` must not match `<tdx`; the tag name ends at a delimiter.
        let boundary = lower[after..].chars().next();
        if matches!(boundary, Some(c) if c.is_ascii_alphanumeric() || c == '-') {
            from = after;
            continue;
        }
        return Some(start);
    }
    None
}

/// A malformed row, in one phrase.
const fn malformed(reason: &'static str) -> Error {
    Error::ImportMalformed { reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::ImportFormat;
    use crate::vault::EntryKind;

    /// A document in the shape the exporter writes: a heading row and data rows, with the QR
    /// column holding an image and the style block after the body.
    fn sample() -> String {
        // The PIN is written as it is, not encoded: this format and the JSON export both carry
        // the raw string, and only the URI spelling encodes it as Base32.
        let pin = "1234";
        format!(
            r#"<!DOCTYPE html>
<html><head><title>Vault</title></head>
<body>
<table>
<tr><th>Issuer</th><th>Name</th><th>Type</th><th>QR Code</th><th>UUID</th><th>Note</th><th>Favorite</th><th>Algo</th><th>Digits</th><th>Secret</th><th>Counter</th><th>PIN</th></tr>
<tr><td>GitHub</td><td>alice</td><td>totp</td><td class='qr'><img src="data:image/png;base64,AAAA"></td><td>1111</td><td>work &amp; play</td><td>1</td><td>SHA1</td><td>6</td><td>JBSWY3DPEHPK3PXP</td><td>-</td><td>-</td></tr>
<tr><td>Bank</td><td>bob</td><td>hotp</td><td class='qr'></td><td>2222</td><td></td><td>0</td><td>SHA256</td><td>8</td><td>JBSWY3DPEHPK3PXP</td><td>7</td><td>-</td></tr>
<tr><td></td><td>Steam</td><td>steam</td><td class='qr'></td><td>3333</td><td></td><td></td><td>SHA1</td><td>5</td><td>JBSWY3DPEHPK3PXP</td><td>-</td><td>-</td></tr>
<tr><td>Example</td><td>mOTP</td><td>motp</td><td class='qr'></td><td>4444</td><td></td><td></td><td>MD5</td><td>6</td><td>deadbeef</td><td>-</td><td>1234</td></tr>
<tr><td></td><td>Yandex</td><td>yandex</td><td class='qr'></td><td>5555</td><td></td><td></td><td>SHA256</td><td>8</td><td>LA2V6KMCGYMWWVEW64RNP3JA3I</td><td>-</td><td>{pin}</td></tr>
</table>
</body>
<style>body {{ font-family: sans-serif; }}</style>
</html>
"#
        )
    }

    fn import_sample(text: &str) -> ImportReport {
        import(text.as_bytes(), 1_700_000_000).expect("the sample is well formed")
    }

    #[test]
    fn every_scheme_in_the_table_is_read() {
        let report = import_sample(&sample());
        assert!(report.problems.is_empty(), "actual {:?}", report.problems);
        assert_eq!(report.entries.len(), 5);

        let kinds: Vec<&EntryKind> = report
            .entries
            .iter()
            .map(|entry| &entry.entry.kind)
            .collect();
        assert_eq!(kinds[0], &EntryKind::Totp { period: 30 });
        assert_eq!(kinds[1], &EntryKind::Hotp { counter: 7 });
        assert_eq!(kinds[2], &EntryKind::Steam);
        assert_eq!(
            kinds[3],
            &EntryKind::Motp {
                period: 10,
                pin: Some(crate::motp::MotpPin::new("1234".to_owned()))
            },
            "the hexadecimal secret is converted and the PIN is read"
        );
        assert_eq!(
            kinds[4],
            &EntryKind::Yandex {
                period: 30,
                pin: Some(crate::yaotp::YandexPin::new("1234".to_owned()))
            }
        );

        assert_eq!(report.entries[0].entry.issuer.as_deref(), Some("GitHub"));
        assert_eq!(
            report.entries[0].entry.note, "work & play",
            "an entity in a note is decoded"
        );
        assert_eq!(report.entries[2].entry.issuer, None);
        assert_eq!(report.entries[2].entry.name, "Steam");
        assert!(!report.entries[0].entry.note.is_empty());
    }

    #[test]
    fn a_step_that_the_format_does_not_carry_is_reported_as_assumed() {
        let report = import_sample(&sample());

        for (index, expected) in [(0_usize, 30_u64), (3, 10), (4, 30)] {
            assert!(
                report.entries[index]
                    .notes
                    .contains(&ImportNote::PeriodAssumed { seconds: expected }),
                "entry {index} must say its step was assumed"
            );
        }
        assert_eq!(
            report.dropped.periods_assumed, 3,
            "the schemes with a step are counted, and only those"
        );
        assert!(
            report.entries[1].notes.is_empty(),
            "HOTP has no step to assume"
        );
        assert!(report.entries[2].notes.is_empty(), "nor has Steam Guard");
    }

    #[test]
    fn the_columns_are_found_by_their_heading() {
        // A table whose columns are in a different order and whose set is smaller. A reader that
        // went by position would read the type as the secret and quietly produce a wrong entry;
        // one that goes by heading reads what is there and reports what is missing.
        let text = "<table>\
            <tr><th>Secret</th><th>Type</th><th>Name</th><th>Digits</th><th>Algo</th></tr>\
            <tr><td>JBSWY3DPEHPK3PXP</td><td>totp</td><td>reordered</td><td>8</td><td>SHA256</td></tr>\
            </table>";
        let report = import_sample(text);
        assert!(report.problems.is_empty(), "actual {:?}", report.problems);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].entry.name, "reordered");
        assert_eq!(report.entries[0].entry.digits, crate::otp::Digits::EIGHT);
        assert_eq!(
            report.entries[0].entry.algorithm,
            crate::otp::Algorithm::Sha256
        );
        assert_eq!(
            report.entries[0].entry.secret.to_base32(),
            "JBSWY3DPEHPK3PXP",
            "the secret is found by its heading, not by its position"
        );
        assert_eq!(
            report.entries[0].entry.kind,
            EntryKind::Totp { period: 30 },
            "a table with no step column still gets the default, and is told so"
        );
        assert_eq!(report.dropped.periods_assumed, 1);
    }

    #[test]
    fn a_document_without_a_heading_is_refused() {
        let result = import(b"<html><body>no table here</body></html>", 0);
        assert!(
            matches!(result, Err(Error::ImportMalformed { .. })),
            "actual {result:?}"
        );
    }

    #[test]
    fn one_bad_row_does_not_end_the_import() {
        let text = sample().replace(
            "<td>SHA1</td><td>6</td><td>JBSWY3DPEHPK3PXP</td>",
            "<td>SHA1</td><td>10</td><td>JBSWY3DPEHPK3PXP</td>",
        );
        let report = import_sample(&text);

        assert_eq!(report.entries.len(), 4);
        assert_eq!(report.problems.len(), 1);
        assert_eq!(report.problems[0].position, 1);
        assert!(
            report.problems[0].reason.contains("31 bits"),
            "actual {}",
            report.problems[0].reason
        );
    }

    #[test]
    fn a_row_that_is_not_an_entry_is_skipped_quietly() {
        let text = sample().replace("<table>", "<table>\n<tr><td>spacer</td><td></td></tr>");
        let report = import_sample(&text);
        assert!(report.problems.is_empty(), "actual {:?}", report.problems);
        assert_eq!(report.entries.len(), 5);
    }

    #[test]
    fn a_secret_never_reaches_the_problem_text() {
        let text = sample().replace("<td>deadbeef</td>", "<td>NOT-HEX-AT-ALL</td>");
        let report = import_sample(&text);
        assert_eq!(report.problems.len(), 1);
        let reason = &report.problems[0].reason;
        assert!(
            !reason.contains("NOT-HEX") && !reason.contains("deadbeef"),
            "the reason must not quote the row: {reason}"
        );
    }

    #[test]
    fn entity_decoding_covers_what_an_exporter_writes() {
        assert_eq!(text_of("a &amp; b"), "a & b");
        assert_eq!(text_of("&lt;b&gt;"), "<b>");
        assert_eq!(text_of("&quot;q&quot;"), "\"q\"");
        assert_eq!(text_of("it&#39;s"), "it's");
        assert_eq!(text_of("<b>bold</b>"), "bold");
        assert_eq!(
            text_of("&unknown;"),
            "&unknown;",
            "an entity this reader does not know keeps its text"
        );
        assert_eq!(text_of("unterminated <b"), "unterminated");
    }

    #[test]
    fn the_format_is_detected_from_the_document() {
        assert_eq!(
            ImportFormat::detect(sample().as_bytes()),
            Some(ImportFormat::Html)
        );
    }
}
