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

//! The HTML export: one table row per entry, with the code drawn beside it.
//!
//! # Why the code is drawn at all
//!
//! The other columns carry every field an entry has, so the picture looks redundant - and it is,
//! for a reader that understands the table. It is there for the **other** reader: a person with
//! a phone, moving one account at a time. That is also why the table carries the secret in
//! plaintext, exactly like the reference implementation's export, and why this file is a secret
//! in its own right (see the note in [`crate::export`]).
//!
//! # The step lives only in the code
//!
//! There is no period column: the reference implementation's format does not have one, and the
//! only place a time step is written down is inside the QR code, which holds the entry's whole
//! `otpauth://` URI. This writer therefore draws a code for **every** entry - an entry without
//! one would come back with the scheme's default step, which for anything but a default entry
//! means codes that never match.
//!
//! # Geometry
//!
//! `256 × 256` pixels, error correction level L, exactly as the reference implementation draws
//! it. The modules are laid out at the largest whole-pixel scale that fits, and the result is
//! centred on a white canvas: a fractional scale would blur the module edges, and a scanner
//! relies on them. The base64 of the image is wrapped every 76 characters, which is the
//! line width the format uses.
//!
//! # What the format does not carry
//!
//! - **The groups and the order between them.** Rows are written in display order; which group
//!   a row came from has nowhere to go.
//! - **The account name.** The label of the URI in the QR code carries it.
//! - **The time step as a cell**, as above.

use qualia_transport::image::GrayImage;
use qualia_transport::qr::{self, EcLevel};

use crate::Error;
use crate::Result;
use crate::export::{algorithm_name, base64, hex, items, type_name, uuid_text};
use crate::vault::{Entry, EntryKind, Vault};

/// The side of the square image one entry's QR code is drawn in, in pixels.
const QR_IMAGE_SIDE: u32 = 256;

/// The quiet zone around the code, in modules.
///
/// ISO/IEC 18004 requires at least four, and a scanner that cannot find the symbol's edges finds
/// nothing at all.
const QR_QUIET_ZONE: u16 = 4;

/// The error correction level of the drawn code.
///
/// Level L because that is what the format uses, and because a code drawn on a screen at this
/// size has nothing to recover from: the level buys redundancy at the cost of modules, and more
/// modules in the same 256 pixels means smaller ones.
const QR_EC_LEVEL: EcLevel = EcLevel::Low;

/// The highest version a drawn code may use.
///
/// Level L carries 2953 bytes at version 40, which is more than an entry's URI can hold given
/// the field limits - the bound is here so that the geometry below always has an answer.
const QR_MAX_VERSION: u8 = 40;

/// The line width the base64 image data is wrapped at.
const BASE64_LINE_WIDTH: usize = 76;

/// The table's columns, in the order the format writes them.
///
/// The reader looks cells up by their heading rather than by their position, so the order is not
/// what makes this work; it is what makes the file look like the one the reference
/// implementation writes, which is what a person comparing two exports will notice.
const COLUMNS: [&str; 12] = [
    "Issuer", "Name", "Type", "QR Code", "UUID", "Note", "Favorite", "Algo", "Digits", "Secret",
    "Counter", "PIN",
];

/// The cell written for a field the entry does not have.
///
/// A dash rather than an empty cell: the format writes one, and a reader that distinguishes "no
/// counter" from "a counter that happens to be blank" has something to read.
const EMPTY_CELL: &str = "-";

/// Writes the vault as an HTML export.
///
/// # Errors
///
/// [`crate::Error::ExportQrTooLong`] when an entry's URI does not fit a QR code, and
/// [`crate::Error::UriAccountContainsColon`] when one cannot be written as a URI at all.
pub fn write(vault: &Vault) -> Result<String> {
    let mut out = String::with_capacity(1024 + vault.len() * 2048);

    out.push_str("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<title>Qualia2FA export</title>\n");
    out.push_str("<style>\n");
    out.push_str("body { font-family: sans-serif; }\n");
    out.push_str("table { border-collapse: collapse; }\n");
    out.push_str("th, td { border: 1px solid #999; padding: 4px 8px; text-align: left; }\n");
    out.push_str("td.qr img { width: 128px; height: 128px; }\n");
    out.push_str("</style>\n</head>\n<body>\n<table>\n");

    out.push_str("<tr>");
    for column in COLUMNS {
        out.push_str("<th>");
        escape_into(&mut out, column);
        out.push_str("</th>");
    }
    out.push_str("</tr>\n");

    for item in items(vault) {
        let entry = item.entry;
        let uri = crate::export::uri_of(entry)?;

        out.push_str("<tr>");
        cell(&mut out, entry.issuer.as_deref().unwrap_or_default());
        cell(&mut out, &entry.name);
        cell(&mut out, type_name(&entry.kind));
        out.push_str("<td class='qr'><img src=\"");
        out.push_str(&qr_data_url(&uri, item.position)?);
        out.push_str("\"></td>");
        cell(&mut out, &uuid_text(item.id.as_bytes()));
        cell(&mut out, &entry.note);
        // This application has no favourites; see the JSON writer for the same note.
        cell(&mut out, "0");
        cell(&mut out, algorithm_name(&entry.kind, entry.algorithm));
        cell(&mut out, &entry.digits.count().to_string());
        cell(&mut out, &secret_text(entry));
        match &entry.kind {
            EntryKind::Hotp { counter } => cell(&mut out, &counter.to_string()),
            _ => cell(&mut out, EMPTY_CELL),
        }
        match &entry.kind {
            EntryKind::Motp { pin, .. } => {
                cell(&mut out, pin.as_ref().map_or(EMPTY_CELL, |p| p.expose()))
            }
            EntryKind::Yandex { pin, .. } => {
                cell(&mut out, pin.as_ref().map_or(EMPTY_CELL, |p| p.expose()))
            }
            _ => cell(&mut out, EMPTY_CELL),
        }
        out.push_str("</tr>\n");
    }

    out.push_str("</table>\n</body>\n</html>\n");
    Ok(out)
}

/// The secret as this format writes it: Base32, except hexadecimal for mOTP.
///
/// The difference belongs to the shape of the URI rather than to the scheme (the reference
/// implementation's `motp:` form is hexadecimal), and the reader converts back, so one encoding
/// reaches the mapping either way.
fn secret_text(entry: &Entry) -> String {
    match entry.kind {
        EntryKind::Motp { .. } => hex(entry.secret.expose()),
        _ => entry.secret.to_base32(),
    }
}

/// Writes one text cell, or the empty marker.
fn cell(out: &mut String, value: &str) {
    out.push_str("<td>");
    if value.is_empty() {
        out.push_str(EMPTY_CELL);
    } else {
        escape_into(out, value);
    }
    out.push_str("</td>");
}

/// Escapes the five characters that mean something inside HTML text.
///
/// The quote is escaped as well, which text does not require: a note that contains one is
/// cheaper to escape always than to escape only in the places this writer happens to put values
/// into attributes today.
fn escape_into(out: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
}

/// Draws one entry's URI as a `data:` URL holding a PNG.
///
/// `position` is only used to say which entry failed; the URI itself is the caller's.
fn qr_data_url(uri: &str, position: usize) -> Result<String> {
    let symbol = qr::encode_text(uri, QR_EC_LEVEL, QR_MAX_VERSION)
        .map_err(|_| Error::ExportQrTooLong { position })?;

    let modules = u32::from(symbol.size()) + 2 * u32::from(QR_QUIET_ZONE);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the side in modules is at most 185, so the quotient is at most 256"
    )]
    let scale = (QR_IMAGE_SIDE / modules).max(1) as u16;
    let drawn = symbol
        .render(scale, QR_QUIET_ZONE)
        .map_err(|_| refused("QR render geometry"))?;

    let canvas = centre(&drawn)?;
    Ok(format!(
        "data:image/png;base64,{}",
        wrap(&base64(&crate::export::png::encode(&canvas)))
    ))
}

/// Centres a square image on a white canvas of [`QR_IMAGE_SIDE`] pixels.
fn centre(drawn: &GrayImage) -> Result<GrayImage> {
    let side = drawn.width().min(drawn.height());
    let offset = (QR_IMAGE_SIDE - side.min(QR_IMAGE_SIDE)) / 2;
    let mut pixels = vec![u8::MAX; (QR_IMAGE_SIDE * QR_IMAGE_SIDE) as usize];

    for y in 0..side {
        for x in 0..side {
            let Some(value) = drawn.pixel(x, y) else {
                continue;
            };
            let target = (y + offset) * QR_IMAGE_SIDE + (x + offset);
            if let Some(pixel) = pixels.get_mut(target as usize) {
                *pixel = value;
            }
        }
    }

    GrayImage::from_luma8(QR_IMAGE_SIDE, QR_IMAGE_SIDE, pixels)
        .map_err(|_| refused("QR image size"))
}

/// Breaks base64 into lines of [`BASE64_LINE_WIDTH`] characters.
///
/// The format wraps it, and a reader of the *file* may not care; the one thing that must not
/// happen is a line break inside the middle of a `data:` URL being read as the end of the
/// attribute, which is why the wrapping goes nowhere near the quotes.
fn wrap(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / BASE64_LINE_WIDTH + 1);
    for (index, character) in text.chars().enumerate() {
        if index > 0 && index % BASE64_LINE_WIDTH == 0 {
            out.push('\n');
        }
        out.push(character);
    }
    out
}

/// A parameter of an export this library fixes and the code below refused.
const fn refused(parameter: &'static str) -> Error {
    Error::ExportParameterRefused { parameter }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{ImportFormat, import};
    use crate::vault::EntryId;

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

    /// A vault holding every scheme.
    fn vault() -> (Vault, Vec<EntryId>) {
        let mut vault = Vault::new();
        let ids = URIS
            .iter()
            .map(|uri| {
                vault
                    .insert(entry(uri, 1_600_000_000))
                    .expect("the vault accepts it")
            })
            .collect();
        (vault, ids)
    }

    /// The whole point: the table this writer produces is one the reader reads, step included.
    #[test]
    fn an_export_round_trips_through_the_reader() {
        let (vault, _) = vault();
        let text = write(&vault).expect("the export is written");
        let report = import(text.as_bytes(), ImportFormat::Html, 1_700_000_000, None)
            .unwrap_or_else(|error| panic!("the export must read back: {error}"));

        assert!(report.problems.is_empty(), "actual {:?}", report.problems);
        assert_eq!(report.entries.len(), URIS.len());
        for (index, uri) in URIS.iter().enumerate() {
            let original = entry(uri, 1_600_000_000);
            let read = &report.entries[index].entry;
            assert_eq!(
                read.kind, original.kind,
                "entry {index} (the step comes from the code)"
            );
            assert_eq!(read.name, original.name, "entry {index}");
            assert_eq!(read.issuer, original.issuer, "entry {index}");
            assert_eq!(read.digits, original.digits, "entry {index}");
            assert_eq!(
                read.secret.to_base32(),
                original.secret.to_base32(),
                "entry {index}"
            );
        }
        assert_eq!(
            report.dropped.periods_assumed, 0,
            "every step was in the code, so none had to be assumed"
        );
    }

    /// A step that is not the scheme's default survives, which is the reason the code is drawn.
    #[test]
    fn a_step_that_is_not_the_default_survives() {
        let mut vault = Vault::new();
        vault
            .insert(entry(
                "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&period=90",
                1_600_000_000,
            ))
            .expect("the vault is empty");
        let text = write(&vault).expect("the export is written");

        let report = import(text.as_bytes(), ImportFormat::Html, 0, None).expect("it reads back");
        assert_eq!(report.entries[0].entry.kind, EntryKind::Totp { period: 90 });
        assert_eq!(
            report.dropped.periods_assumed, 0,
            "the step was read, not assumed"
        );
    }

    /// The table has the columns the format specifies, in its order, and a code in the fourth.
    #[test]
    fn the_table_has_the_columns_of_the_format() {
        let (vault, ids) = vault();
        let text = write(&vault).expect("the export is written");

        let heading = text
            .lines()
            .find(|line| line.starts_with("<tr><th>"))
            .expect("there is a heading row");
        let names: Vec<&str> = heading
            .split("<th>")
            .skip(1)
            .map(|cell| cell.split("</th>").next().unwrap_or_default())
            .collect();
        assert_eq!(names, COLUMNS.to_vec());

        assert!(
            text.contains(&format!("<td>{}</td>", uuid_text(ids[0].as_bytes()))),
            "the first entry's UUID must be in the table"
        );
        assert_eq!(
            text.matches("data:image/png;base64,").count(),
            URIS.len(),
            "every entry gets a code, including the ones whose scheme has no step here"
        );
    }

    /// The image is a 256×256 PNG and its base64 is wrapped, as the format says.
    #[test]
    fn the_drawn_code_is_a_wrapped_256_pixel_png() {
        let mut vault = Vault::new();
        vault.insert(entry(URIS[0], 0)).expect("the vault is empty");
        let text = write(&vault).expect("the export is written");

        let start = text.find("base64,").expect("there is an image") + 7;
        let end = start + text[start..].find('"').expect("the attribute ends");
        let encoded = &text[start..end];

        let lines: Vec<&str> = encoded.split('\n').collect();
        assert!(
            lines.len() > 1,
            "the base64 of an image this size is wrapped"
        );
        for line in &lines[..lines.len() - 1] {
            assert_eq!(line.len(), BASE64_LINE_WIDTH);
        }
        assert!(lines[lines.len() - 1].len() <= BASE64_LINE_WIDTH);

        // The reader's own decoder accepts it: the wrapping must not be between the quotes and
        // the data must be standard base64.
        let png = decode_base64_for_test(&lines.join(""));
        assert_eq!(
            &png[..8],
            &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
            "the payload is a PNG"
        );
        assert_eq!(
            u32::from_be_bytes(png[16..20].try_into().expect("four bytes")),
            256,
            "the width the format specifies"
        );
        assert_eq!(
            u32::from_be_bytes(png[20..24].try_into().expect("four bytes")),
            256,
            "and the height"
        );
    }

    /// A note that contains HTML metacharacters is escaped rather than written as markup.
    #[test]
    fn a_note_is_escaped() {
        let mut vault = Vault::new();
        let mut built = entry(URIS[0], 0);
        built.note = "<b>not bold</b> & \"quoted\"".to_owned();
        built.name = "名字".to_owned();
        built.issuer = None;
        vault.insert(built).expect("the vault is empty");

        let text = write(&vault).expect("the export is written");
        assert!(
            text.contains("&lt;b&gt;not bold&lt;/b&gt; &amp; &quot;quoted&quot;"),
            "the note must be escaped: {text}"
        );

        let report = import(text.as_bytes(), ImportFormat::Html, 0, None).expect("it reads back");
        assert_eq!(report.entries[0].entry.note, "<b>not bold</b> & \"quoted\"");
        assert_eq!(report.entries[0].entry.name, "名字");
    }

    /// An entry without an issuer writes an empty cell as the format's dash.
    #[test]
    fn an_absent_field_is_written_as_a_dash() {
        let mut vault = Vault::new();
        let mut built = entry(URIS[1], 0);
        built.issuer = None;
        built.kind = EntryKind::Hotp { counter: 7 };
        vault.insert(built).expect("the vault is empty");

        let text = write(&vault).expect("the export is written");
        assert!(text.contains("<td>-</td>"), "actual {text}");
        assert!(text.contains("<td>7</td>"), "the counter is written");
    }

    /// Standard base64, decoded by the test rather than by the writer.
    fn decode_base64_for_test(text: &str) -> Vec<u8> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut bits = 0_u32;
        let mut held = 0_u32;
        for byte in text.bytes() {
            if byte == b'=' {
                break;
            }
            let value = ALPHABET
                .iter()
                .position(|letter| *letter == byte)
                .expect("a valid base64 character") as u32;
            bits = (bits << 6) | value;
            held += 6;
            if held >= 8 {
                held -= 8;
                out.push(((bits >> held) & 0xFF) as u8);
            }
        }
        out
    }
}
