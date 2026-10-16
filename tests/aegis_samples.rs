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

//! Exports that really came out of another authenticator — the acceptance criterion for the
//! reader.
//!
//! # Why these files exist
//!
//! Every other sample in this crate was written by hand to the shape §5.7 of the project plan
//! describes. Such a sample proves that the reader agrees with **our reading of the document**;
//! it cannot prove that it agrees with the implementation that wrote the file, because the same
//! misunderstanding would be on both sides. These four files are that implementation's own
//! output: they were exported from Aegis (Android) on 2026-10-17, one per format it offers, from
//! a vault holding two TOTP entries.
//!
//! `tests/data/aegis/README.md` records where each file came from, which accounts it holds (two
//! throwaway ones, so that the key material in this public repository is worth nothing), and the
//! password of the encrypted export.
//!
//! # What is asserted, and why it is not just "it parses"
//!
//! Four things, each of which a hand-written sample cannot establish:
//!
//! 1. **The four formats describe the same entries.** They were written from one vault, so a
//!    reader that agrees with the format documents but disagrees with itself shows up here.
//! 2. **The time step of the HTML export comes out of the drawn QR code.** That code is the only
//!    place the step is written down, and it is a real 256×256 RGBA PNG whose base64 Aegis wrapped
//!    across lines.
//! 3. **The encrypted export opens with its password, and only with it.**
//! 4. **Nothing is assumed.** A step that had to be guessed would come back as
//!    [`ImportNote::PeriodAssumed`], which is what this file checks against.

use qualia2fa_core::import::{self, ImportFormat, ImportNote, ImportReport};
use qualia2fa_core::uri;
use qualia2fa_core::vault::EntryKind;
use qualia2fa_core::{Error, Result};

/// The plaintext JSON export.
const PLAIN: &[u8] = include_bytes!("data/aegis/plain.json");

/// The same database, encrypted with [`PASSWORD`].
const ENCRYPTED: &[u8] = include_bytes!("data/aegis/encrypted.json");

/// The HTML export, with a QR code drawn for every entry.
const HTML: &[u8] = include_bytes!("data/aegis/vault.html");

/// The text export: one URI per line.
const TEXT: &[u8] = include_bytes!("data/aegis/uris.txt");

/// The password `encrypted.json` was written with.
///
/// Not a secret: it protects two throwaway accounts, and a test that could not open the sample
/// would not be testing the encrypted path. See the directory's `README.md`.
const PASSWORD: &[u8] = b"Afl43670P";

/// The time handed to the reader. The exports carry no clock, so any value does.
const NOW: u64 = 1_700_000_000;

/// Reads one of the samples.
fn read(bytes: &[u8], format: ImportFormat, password: Option<&[u8]>) -> ImportReport {
    let report = import::import(bytes, format, NOW, password)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", format.name()));
    assert!(
        report.problems.is_empty(),
        "{} came back with problems: {:?}",
        format.name(),
        report.problems
    );
    report
}

/// One entry as a comparable value: everything a format is expected to carry, and no secret as
/// it stands (the secret is compared through its Base32 spelling, which is how every format but
/// the HTML one writes it).
fn shape(report: &ImportReport) -> Vec<String> {
    let mut out: Vec<String> = report
        .entries
        .iter()
        .map(|imported| {
            let entry = &imported.entry;
            format!(
                "{}|{:?}|{}|{:?}|{:?}|{}",
                entry.name,
                entry.issuer,
                entry.digits.count(),
                entry.algorithm,
                entry.kind,
                entry.secret.to_base32()
            )
        })
        .collect();
    out.sort();
    out
}

/// The step of every entry, with what the format carried beside it.
fn steps(report: &ImportReport) -> Vec<(usize, Option<u64>, bool)> {
    report
        .entries
        .iter()
        .map(|imported| {
            (
                imported.position,
                imported.entry.kind.step_seconds(),
                imported
                    .notes
                    .iter()
                    .any(|note| matches!(note, ImportNote::PeriodAssumed { .. })),
            )
        })
        .collect()
}

/// The plaintext JSON says what the vault held, down to the fields.
#[test]
fn the_plaintext_sample_holds_the_two_entries_it_was_exported_from() {
    let report = read(PLAIN, ImportFormat::Json, None);
    assert_eq!(report.entries.len(), 2);
    assert!(report.groups.is_empty(), "the vault held no group");

    let first = &report.entries[0].entry;
    assert_eq!(first.name, "tester824@spotify.com");
    assert_eq!(first.issuer.as_deref(), Some("Spotify"));
    assert_eq!(first.digits, qualia2fa_core::otp::Digits::EIGHT);
    assert_eq!(first.algorithm, qualia2fa_core::otp::Algorithm::Sha256);
    assert_eq!(first.kind, EntryKind::Totp { period: 60 });
    assert!(
        first.account.is_empty(),
        "this format has no account field, and inventing one would show up in the interface"
    );

    let second = &report.entries[1].entry;
    assert_eq!(second.name, "tester68@logrocket.com");
    assert_eq!(second.issuer.as_deref(), Some("LogRocket"));
    assert_eq!(second.digits, qualia2fa_core::otp::Digits::SIX);
    assert_eq!(second.algorithm, qualia2fa_core::otp::Algorithm::Sha1);
    assert_eq!(second.kind, EntryKind::Totp { period: 30 });
}

/// The text export describes the same two entries, in its own spelling.
///
/// The two differ in exactly two fields, and both are the format's doing rather than the
/// reader's: a URI carries no display name (the label becomes the name) and no note, and its
/// label carries the account.
#[test]
fn the_text_sample_describes_the_same_entries() {
    let report = read(TEXT, ImportFormat::Text, None);
    assert_eq!(report.entries.len(), 2);

    let plain = read(PLAIN, ImportFormat::Json, None);
    let mut from_text = shapes_without_account(&report);
    let mut from_plain = shapes_without_account(&plain);
    from_text.sort();
    from_plain.sort();
    assert_eq!(
        from_text, from_plain,
        "the same vault exported two ways must describe the same entries"
    );

    // The label of a URI is `issuer:account`, and both parts are percent-encoded in the file.
    assert_eq!(report.entries[0].entry.account, "tester824@spotify.com");
    assert_eq!(
        report.entries[0].entry.name, "Spotify:tester824@spotify.com",
        "a URI has one label and it becomes the name"
    );
}

/// Kind, algorithm, digits and secret of every entry, with the name and account dropped.
fn shapes_without_account(report: &ImportReport) -> Vec<String> {
    report
        .entries
        .iter()
        .map(|imported| {
            let entry = &imported.entry;
            format!(
                "{:?}|{}|{:?}|{}",
                entry.issuer,
                entry.digits.count(),
                entry.algorithm,
                entry.secret.to_base32()
            )
        })
        .collect()
}

/// The HTML export carries the step **inside the drawing**, and it comes back out.
///
/// This is the one property no hand-written sample could establish: the code is a real Aegis PNG
/// (256×256, RGBA, base64 wrapped across lines), and the step is nowhere else in that format.
#[test]
fn the_html_sample_gives_up_the_step_it_draws() {
    let report = read(HTML, ImportFormat::Html, None);
    assert_eq!(report.entries.len(), 2);
    assert_eq!(
        report.dropped.periods_assumed, 0,
        "a step that is in the code must not be reported as an assumption"
    );

    let expected = [(1_usize, Some(60_u64), false), (2, Some(30), false)];
    assert_eq!(steps(&report), expected.to_vec());
}

/// The code drawn in the HTML export is the very URI the text export writes.
///
/// The reader takes only the step out of the image (the secret comes from the column), so this
/// checks the whole chain on its own: pull the base64 out of the `data:` URL, decode the PNG with
/// this crate's own decoder, scan the code, and parse what comes out.
#[test]
fn the_code_drawn_in_the_html_sample_is_the_uri_of_the_text_sample() -> Result<()> {
    let html = core::str::from_utf8(HTML).expect("the sample is text");
    let codes = data_urls(html);
    assert_eq!(codes.len(), 2, "one code per entry");

    let text = core::str::from_utf8(TEXT).expect("the sample is text");
    let lines: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(lines.len(), codes.len());

    for (index, (encoded, line)) in codes.iter().zip(lines).enumerate() {
        let png = decode_base64(encoded).expect("the data URL holds base64");
        let scanned = import::qr_text_from_png(&png)
            .unwrap_or_else(|error| panic!("code {} must scan: {}", index + 1, error.reason()));
        assert_eq!(
            scanned,
            line,
            "the code of row {} must hold that row's URI",
            index + 1
        );

        let parsed = uri::parse(&scanned)?;
        assert_eq!(parsed.secret.to_base32().len(), 32);
    }
    Ok(())
}

/// The encrypted export opens with its password, and with nothing else.
#[test]
fn the_encrypted_sample_needs_its_password() {
    let missing = import::import(ENCRYPTED, ImportFormat::Json, NOW, None);
    assert!(
        matches!(missing, Err(Error::ImportPasswordRequired)),
        "actual {missing:?}"
    );

    let wrong = import::import(
        ENCRYPTED,
        ImportFormat::Json,
        NOW,
        Some(b"not the password"),
    );
    assert!(
        matches!(wrong, Err(Error::ImportWrongPassword)),
        "actual {wrong:?}"
    );

    let opened = read(ENCRYPTED, ImportFormat::Json, Some(PASSWORD));
    let plain = read(PLAIN, ImportFormat::Json, None);
    assert_eq!(
        shape(&opened),
        shape(&plain),
        "the encrypted export holds the same database as the plaintext one"
    );
}

/// All four formats describe one vault: the four readings agree.
#[test]
fn every_format_describes_the_same_entries() {
    let plain = read(PLAIN, ImportFormat::Json, None);
    let encrypted = read(ENCRYPTED, ImportFormat::Json, Some(PASSWORD));
    let text = read(TEXT, ImportFormat::Text, None);
    let html = read(HTML, ImportFormat::Html, None);

    // The text export has no name and no account, so it is compared on what it does carry; the
    // other three are compared in full.
    assert_eq!(shape(&encrypted), shape(&plain), "encrypted JSON");
    assert_eq!(shape(&html), shape(&plain), "HTML");
    let mut from_text = shapes_without_account(&text);
    let mut from_plain = shapes_without_account(&plain);
    from_text.sort();
    from_plain.sort();
    assert_eq!(from_text, from_plain, "text");
}

/// The spellings this crate's own HTML export uses are the ones in this file.
///
/// Three of them were **wrong here before this file existed**, because they had been read out of
/// the format documentation rather than out of a file the implementation wrote: the type is
/// upper case (`TOTP`, not `totp`), the favourite column is the word (`false`, not `0`), and a
/// field with no value is an **empty cell** while a field that does not apply to the entry's type
/// is the dash. This test is what keeps the writer tied to the evidence: sanitizing or
/// re-formatting the sample makes it fail.
#[test]
fn the_html_sample_spells_what_this_crates_writer_writes() {
    let html = core::str::from_utf8(HTML).expect("the sample is text");

    assert!(
        html.contains("<td>TOTP</td>"),
        "the type column is upper case in a real export"
    );
    assert!(
        html.contains("<td>false</td>"),
        "the favourite column is the word, not a digit"
    );
    assert!(
        html.contains("<td></td>"),
        "a field nobody filled in is left empty"
    );
    assert!(
        html.contains("<td>-</td>"),
        "a field that does not apply to the type is the dash"
    );
    assert!(
        !html.contains("<!DOCTYPE"),
        "a real export carries no doctype, and this reader must not depend on one"
    );
}

/// Every `data:` URL in a document, with its wrapper removed.
fn data_urls(html: &str) -> Vec<String> {
    const PREFIX: &str = "data:image/png;base64,";
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find(PREFIX) {
        rest = &rest[start + PREFIX.len()..];
        let end = rest.find('"').unwrap_or(rest.len());
        out.push(rest[..end].to_owned());
        rest = &rest[end..];
    }
    out
}

/// Standard base64 with the line breaks the format wraps it with, decoded by the test.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = Vec::new();
    let mut bits: u32 = 0;
    let mut held = 0_u32;
    for byte in text.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            break;
        }
        let value = ALPHABET.iter().position(|letter| *letter == byte)? as u32;
        bits = (bits << 6) | value;
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push(((bits >> held) & 0xFF) as u8);
        }
    }
    Some(out)
}
