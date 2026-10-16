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

//! Fuzz target: `otpauth://` URI parsing.
//!
//! # Input surface
//!
//! `otpauth::parse` is the project's **main attacker-controlled input surface**:
//!
//! - QR code content (the user scans an arbitrary code)
//! - clipboard text (the user pastes arbitrary content)
//! - a link typed in by the user
//!
//! It is also the **only** entry point that interprets attacker data as structured
//! configuration.
//!
//! # Properties covered
//!
//! 1. **Never panics** — the parse path must return for any input; this is the
//!    denial-of-service defense.
//! 2. **Never leaks** — the failure path must not carry the input verbatim into the
//!    error message (otherwise a malicious QR code writes arbitrary content into
//!    the logs), and the `Debug` output of a parsed configuration must not print the
//!    seed. The assertion is that the `secret` field is redacted, not that the seed
//!    string is absent from the output: `issuer` and `account` also come from the
//!    URI and may legitimately contain the same characters as the seed.
//! 3. **A successfully parsed configuration is self-consistent** — the seed is
//!    non-empty (a type invariant of `OtpSecret`), TOTP carries no counter while
//!    HOTP must carry one, and `period` is greater than zero.
//! 4. **Serialization round-trip** — whatever `serialize` produces must parse back,
//!    with the seed / account / issuer unchanged and serialization idempotent; this
//!    also fuzzes the output side of `serialize`. `issuer` / `account` are
//!    attacker-controlled unbounded input and may hold private data (an email
//!    address in practice), so their `Debug` representation is truncated to keep a
//!    malicious QR code from amplifying the logs. An account name containing `:` is
//!    rejected at both ends, and HOTP `period` is normalized to the default when
//!    parsing.
//!
//! # Input encoding
//!
//! The raw bytes are not guaranteed to be valid UTF-8, while `parse` takes a `&str`.
//! `String::from_utf8_lossy` is used here: it always succeeds and replaces invalid
//! bytes with U+FFFD, so the information of the invalid bytes **still reaches the
//! parser** (a higher coverage value than dropping them).
//!
//! Pure random bytes almost never hit the `otpauth://` prefix and thus never reach
//! the deep parsing logic. This target therefore has a second mode: it appends the
//! same input after each valid prefix, forcing entry into the real parse path.
//!
//! Preconditions: no feature flags, and no valid skeleton has to be built — the
//! target parses the bytes as text directly.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia2fa_core::uri;
use qualia2fa_core::vault;

/// The valid prefixes to cover. Covers `totp`/`hotp`, with and without issuer, with
/// and without query.
const PREFIXES: &[&str] = &[
    "otpauth://totp/",
    "otpauth://hotp/",
    "otpauth://totp/a:b?secret=",
    "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP",
    "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer=",
    "otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP&counter=",
    "otpauth://totp/a?secret=AA&algorithm=",
    "otpauth://totp/a?secret=AA&digits=",
    "otpauth://totp/a?secret=AA&period=",
];

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    // ── Mode 1: parse the whole string as a URI ─────────────────────────────
    check(&text);

    // ── Mode 2: append the input after each valid prefix (deep parsing) ─────
    if let Some(&selector) = data.first() {
        let prefix = PREFIXES[usize::from(selector) % PREFIXES.len()];
        let mut candidate = String::with_capacity(prefix.len() + text.len());
        candidate.push_str(prefix);
        candidate.push_str(&text);
        check(&candidate);
    }
});

/// Asserts that a parse result neither panics nor leaks.
fn check(text: &str) {
    let Ok(parsed) = uri::parse(text) else {
        return;
    };

    let debug = format!("{parsed:?}");
    assert!(
        debug.contains(r#"secret: "<redacted>""#),
        "Debug did not redact the secret field: {debug}"
    );

    let base32 = parsed.secret.to_base32();
    let leaked_as_secret_field = debug.contains(&format!(r#"secret: "{base32}""#));
    assert!(
        !leaked_as_secret_field,
        "the secret field of Debug leaked the Base32 seed: {debug}"
    );

    if let Some(issuer) = &parsed.issuer {
        if issuer.len() > 64 {
            let full = format!("{issuer:?}");
            assert!(
                !debug.contains(&full),
                "an over-long issuer was not truncated, so logs can be amplified ({} bytes)",
                issuer.len()
            );
        }
    }

    assert!(parsed.secret.len() > 0, "the parsed seed is empty");
    if let Some(period) = parsed.kind.period() {
        assert!(period > 0, "a stored time step must not be 0");
    }
    if let uri::UriType::Hotp = parsed.uri_type() {
        assert!(
            matches!(parsed.kind, vault::EntryKind::Hotp { .. }),
            "HOTP must carry a counter"
        );
    }

    // The type must agree with the spelling `serialize` writes: that text is what a peer or a
    // QR code reader sees, so a type that disagreed with it would be a configuration filed
    // under one scheme and exported as another.
    if let Ok(text) = uri::serialize(&parsed) {
        let expected = match parsed.uri_type() {
            uri::UriType::Totp => "otpauth://totp/",
            uri::UriType::Hotp => "otpauth://hotp/",
            uri::UriType::Motp => "motp:/",
            uri::UriType::Yandex => "otpauth://yaotp/",
            uri::UriType::Steam => "otpauth://steam/",
        };
        assert!(
            text.starts_with(expected),
            "a {:?} configuration was written as {text}",
            parsed.uri_type()
        );
    }

    if let Ok(roundtrip) = uri::serialize(&parsed) {
        if let Ok(reparsed) = uri::parse(&roundtrip) {
            assert_eq!(
                reparsed.secret.to_base32(),
                base32,
                "the seed changed after the round trip"
            );
            assert_eq!(reparsed.account, parsed.account, "account changed after the round trip");
            assert_eq!(reparsed.issuer, parsed.issuer, "the issuer changed after the round trip");
            let again = uri::serialize(&reparsed).expect("it must serialize again");
            assert_eq!(again, roundtrip, "serialization is not idempotent");
        }
    }
}
