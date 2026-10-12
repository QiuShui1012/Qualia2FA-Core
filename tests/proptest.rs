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

//! Property-based tests for the secret wrappers, Base32, OTP and `otpauth://`.
//!
//! The failure mode of a secret type is not a wrong result but a **leak**: once `Debug`
//! carries the plaintext out, it can end up in logs, crash dumps or telemetry. Such a bug
//! is invisible to tests built on hand-picked inputs, so it is asserted over arbitrary
//! ones.
//!
//! Coverage and properties:
//!
//! - **Secret wrappers** — arbitrary byte strings of 0 to 2048 bytes and arbitrary UTF-8
//!   text. Construction and `expose_secret` are transparent, `Clone` is exact, and
//!   `Debug` — standalone or nested in a `#[derive(Debug)]` struct — never contains the
//!   plaintext in hexadecimal or decimal form.
//! - **Base32 and OTP** — non-empty byte strings and arbitrary text. Encoding and
//!   decoding round-trip byte for byte for every legal tail remainder and in both the
//!   padded and the unpadded form, decoding never panics, and every code keeps its exact
//!   width and alphabet.
//! - **`otpauth://`** — arbitrary label text and self-consistent TOTP/HOTP
//!   configurations. Parse and serialize round-trip semantically, serialization is
//!   idempotent, and parsing never panics on arbitrary text.
//!
//! A failure means an arbitrary input reached a state the property excludes: a leaked
//! secret, data that changed or was lost, or a panic.
//!
//! Note: `prop_assert!` stringifies its whole expression into a format string, so a
//! `matches!(..)` pattern or an inline named capture (`{name}`) must be bound to a local
//! before it is asserted; `prop_assert_eq!` consumes its arguments, so a value needed
//! afterwards has to be computed up front.

use proptest::prelude::*;
use qualia2fa_core::base32;
use qualia2fa_core::otp::{self, Algorithm, Digits, OtpSecret};
use qualia2fa_core::uri::{self, OtpAuth, UriType};
use qualia2fa_core::{ExposeSecret, SecretBytes, SecretString};

/// Generates an arbitrary byte sequence.
///
/// The upper bound is 2048 bytes: it covers the size of real seeds and keys (20–64 bytes)
/// as well as longer inputs such as hand-written Base32 strings and QR payloads, while
/// keeping very long inputs from slowing the tests down.
fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=2048)
}

/// Generates a **non-empty** byte string, for round-trip properties such as
/// "encode then decode".
///
/// Empty input is not legal Base32: `base32::decode("")` returns
/// [`Error::SecretTooShort`] (see `rejects_empty_and_padding_only` in `src/base32.rs` —
/// an empty seed would make every code identical, so it must be rejected). The round-trip
/// property therefore does not hold for the empty string, and this strategy keeps it out
/// of reach; [`arb_bytes`], which allows the empty string, must not be used here.
///
/// Rejection of empty input is covered by the unit tests in `src/base32.rs`; the
/// round-trip properties only concern non-empty input.
fn arb_nonempty_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=2048)
}

proptest! {
    /// Property: constructing from a `Vec<u8>` and exposing the result gives the input
    /// back unchanged — no truncation, no padding, no rewriting.
    #[test]
    fn expose_is_transparent(data in arb_bytes()) {
        let secret: SecretBytes = data.clone().into();
        prop_assert_eq!(secret.expose_secret(), data.as_slice());
    }

    /// Property: `Clone` is byte-for-byte identical.
    #[test]
    fn clone_is_exact(data in arb_bytes()) {
        let secret: SecretBytes = data.clone().into();
        let copy = secret.clone();
        prop_assert_eq!(copy.expose_secret(), secret.expose_secret());
    }

    /// Property: `SecretString` construction and exposure are equally transparent.
    ///
    /// The input is a Rust `String` (guaranteed UTF-8), which is the text-secret path.
    #[test]
    fn secret_string_is_transparent(text in ".*") {
        let secret = SecretString::from(text.clone());
        prop_assert_eq!(secret.expose_secret(), text.as_str());
    }

    /// **Core property**: the `Debug` output never contains the plaintext.
    ///
    /// Both the hexadecimal and the decimal representation of the plaintext are checked.
    /// Upstream `secrecy` does not even print the length, so a readable length is **not**
    /// asserted here — only the absence of a leak.
    ///
    /// The substring check runs only for lengths ≥ 4: a shorter decimal string (such as
    /// the "12" of a 2-byte input) collides by chance with type names and numbers printed
    /// by `Debug` and would cause a false positive.
    #[test]
    fn debug_never_contains_plaintext(data in arb_bytes()) {
        let secret: SecretBytes = data.clone().into();
        let debug = format!("{secret:?}");
        let lower = debug.to_lowercase();

        prop_assert!(
            lower.contains("redacted"),
            "Debug does not carry the redaction marker (length {}): {}",
            data.len(),
            debug
        );

        if data.len() >= 4 {
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            prop_assert!(!lower.contains(&hex), "hexadecimal plaintext leaked: {}", debug);

            let decimal = data
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join("");
            prop_assert!(!debug.contains(&decimal), "decimal plaintext leaked: {}", debug);
        }
    }

    /// Property: a secret nested inside a `#[derive(Debug)]` struct must not leak either.
    #[test]
    fn debug_never_leaks_when_nested(data in arb_bytes()) {
        #[expect(
            dead_code,
            reason = "the field only exists to build the Debug output"
        )]
        #[derive(Debug)]
        struct Holder {
            /// Non-secret field, used to confirm that `Debug` really prints content.
            tag: u8,
            /// Secret field.
            secret: SecretBytes,
        }

        let holder = Holder { tag: 1, secret: data.clone().into() };
        let debug = format!("{holder:?}");

        if data.len() >= 4 {
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            prop_assert!(
                !debug.to_lowercase().contains(&hex),
                "nested Debug leaked hexadecimal plaintext: {}",
                debug
            );
        }
    }
}

// ─────────────────────────── Base32 and OTP properties ───────────────────────────

proptest! {
    /// **Core property**: Base32 encoding followed by decoding restores every byte.
    ///
    /// This covers all five legal tail remainders (0/2/4/5/7 bits); random byte lengths
    /// hit them evenly, so no per-remainder test is needed.
    ///
    /// Input is restricted to non-empty strings — empty input is not legal Base32, see
    /// [`arb_nonempty_bytes`].
    #[test]
    fn base32_encode_decode_roundtrips(data in arb_nonempty_bytes()) {
        let encoded = base32::encode(&data);
        prop_assert!(
            encoded.bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b) || b == b'='),
            "the encoding contains a character outside the alphabet: {}",
            encoded
        );
        let decoded = base32::decode_strict(&encoded)
            .map_err(|e| TestCaseError::fail(format!("strict decoding of our own encoding failed: {e} (input {})", encoded)))?;
        prop_assert_eq!(decoded.expose_secret(), data.as_slice());
    }

    /// Property: the unpadded form decodes to the same secret — nearly every real-world
    /// seed is distributed without padding.
    ///
    /// Input is restricted to non-empty strings for the same reason: stripping the padding
    /// from the empty string still leaves an empty string, which stays illegal.
    #[test]
    fn base32_unpadded_encoding_also_decodes(data in arb_nonempty_bytes()) {
        let padded = base32::encode(&data);
        let unpadded = padded.trim_end_matches('=');
        let decoded = base32::decode(unpadded)
            .map_err(|e| TestCaseError::fail(format!("unpadded decoding failed: {e}")))?;
        prop_assert_eq!(decoded.expose_secret(), data.as_slice());
    }

    /// Property: no string makes the decoder panic — it returns `Ok` or `Err`, nothing
    /// else.
    ///
    /// This is the no-panic contract applied to Base32. Decoder input comes straight from
    /// QR codes and manual typing, so it must stay bounded and never crash.
    #[test]
    fn base32_never_panics_on_arbitrary_text(text in "\\PC*") {
        let _ = base32::decode(&text);
        let _ = base32::decode_strict(&text);
    }

    /// Property: an OTP code is **always** a fixed-width decimal string whose numeric value
    /// lies in `[0, 10^digits)`.
    ///
    /// Leading zeros are part of the code: a value that happens to be 0 still has to be
    /// rendered at the full width, not as an empty string or "0".
    #[test]
    fn otp_code_is_always_exact_width_digits(
        data in prop::collection::vec(any::<u8>(), 1..=64),
        counter in any::<u64>(),
        algorithm in prop_oneof![
            Just(Algorithm::Sha1),
            Just(Algorithm::Sha256),
            Just(Algorithm::Sha512)
        ],
        digits in prop_oneof![Just(Digits::Six), Just(Digits::Seven), Just(Digits::Eight)],
    ) {
        let secret = OtpSecret::from_bytes(data)
            .map_err(|e| TestCaseError::fail(format!("a non-empty seed must be accepted: {e}")))?;
        let code = otp::hotp_code(&secret, counter, algorithm, digits);
        prop_assert_eq!(code.len(), digits.count() as usize);
        prop_assert!(
            code.bytes().all(|b| b.is_ascii_digit()),
            "contains a non-digit character: {}",
            code
        );
        let numeric: u64 = code.parse().expect("it should parse as a number");
        prop_assert!(numeric < 10_u64.pow(digits.count()));
    }

    /// Property: `format_code` and `hotp` agree — formatting does not change the value.
    #[test]
    fn format_code_agrees_with_numeric_value(
        data in prop::collection::vec(any::<u8>(), 1..=64),
        counter in any::<u64>(),
        digits in prop_oneof![Just(Digits::Six), Just(Digits::Seven), Just(Digits::Eight)],
    ) {
        let secret = OtpSecret::from_bytes(data).expect("non-empty");
        let numeric = otp::hotp(&secret, counter, Algorithm::Sha1, digits);
        let formatted = otp::format_code(numeric, digits);
        let reparsed: u64 = formatted.parse().expect("it parses");
        let expected = otp::hotp_code(&secret, counter, Algorithm::Sha1, digits);
        prop_assert_eq!(formatted, expected);
        prop_assert_eq!(reparsed, u64::from(numeric));
    }

    /// Property: TOTP depends only on `unix_time / period`, so two instants inside the same
    /// time step produce the same code.
    #[test]
    fn totp_is_constant_within_a_time_step(
        data in prop::collection::vec(any::<u8>(), 1..=64),
        time in 0_u64..1_000_000_000_000,
        period in 1_u64..=86_400,
        offset in 0_u64..86_400,
    ) {
        let secret = OtpSecret::from_bytes(data).expect("non-empty");
        let base = time - (time % period);
        let same_step = base + (offset % period);
        prop_assert_eq!(base / period, same_step / period, "the setup must land in one step");

        let a = otp::totp_code(&secret, base, period, Algorithm::Sha1, Digits::Six)
            .expect("period is non-zero");
        let b = otp::totp_code(&secret, same_step, period, Algorithm::Sha1, Digits::Six)
            .expect("period is non-zero");
        prop_assert_eq!(a, b);
    }

    /// Property: `verify_code` is reflexive and always `false` for inputs of a different
    /// length. Code length is not secret, so a length mismatch may return immediately.
    #[test]
    fn verify_code_is_reflexive(
        data in prop::collection::vec(any::<u8>(), 1..=64),
        counter in any::<u64>(),
    ) {
        let secret = OtpSecret::from_bytes(data).expect("non-empty");
        let code = otp::hotp_code(&secret, counter, Algorithm::Sha1, Digits::Six);
        prop_assert!(otp::verify_code(&code, &code), "reflexivity failed: {}", code);
        let too_long = format!("{code}0");
        let one_shorter = code[1..].to_owned();
        prop_assert!(!otp::verify_code(&code, &too_long));
        prop_assert!(!otp::verify_code(&code, &one_shorter));
    }

    /// Property: a Steam code is always 5 characters long and drawn entirely from the Steam
    /// alphabet.
    #[test]
    fn steam_code_shape_is_constant(
        data in prop::collection::vec(any::<u8>(), 1..=64),
        time in 0_u64..1_000_000_000_000,
    ) {
        let secret = OtpSecret::from_bytes(data).expect("non-empty");
        let code = otp::steam_guard_code(&secret, time, 30, Algorithm::Sha1)
            .expect("period is non-zero");
        prop_assert_eq!(code.chars().count(), otp::STEAM_DIGITS);
        const ALPHABET: &str = "23456789BCDFGHJKMNPQRTVWXY";
        let all_in_alphabet = code.chars().all(|c| ALPHABET.contains(c));
        prop_assert!(all_in_alphabet, "contains a character outside the alphabet: {}", code);
    }
}

// ────────────────────────── `otpauth://` parsing properties ──────────────────────────

/// Generates text that can be placed safely into every `otpauth://` field.
///
/// The character set is restricted because some characters do not round-trip through the
/// format:
///
/// - **colon `:`** — the label uses the first `:` to separate issuer from account, so a `:`
///   inside the account name cannot be told apart from the separator. This is an ambiguity
///   of the format itself, and both ends reject it explicitly
///   (`Error::UriAccountContainsColon`). The legal value domain excludes the colon, so the
///   strategy must not generate one; doing so would test an unreachable state.
/// - **whitespace** — query decoding treats `+` as a space, and leading or trailing
///   whitespace is trimmed by most implementations.
/// - **control characters** — the format defines no meaning for them.
///
/// The generated text is therefore drawn from ASCII characters that have a defined meaning
/// in the format plus arbitrary non-ASCII: the properties then focus on **encode/decode
/// correctness** instead of corners the specification leaves undefined.
fn arb_label_text() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            0x80_u32..0x2FFFF,
            prop::sample::select(vec![
                'a', 'Z', '0', '9', ' ', '+', '-', '_', '.', '%', '&', '=', '?', '#', '@', '/',
            ])
            .prop_map(|c| c as u32),
        ],
        1..=12,
    )
    .prop_map(|codes| codes.into_iter().filter_map(char::from_u32).collect())
}

/// Generates a complete TOTP or HOTP configuration whose fields are mutually consistent.
///
/// `OtpAuth` invariants: `period` has a meaning only for TOTP and HOTP always carries
/// [`uri::DEFAULT_PERIOD`], while `counter` is present only for HOTP. Only values that
/// satisfy the invariants are generated, otherwise the properties would test unreachable
/// states.
fn arb_otp_auth() -> impl Strategy<Value = OtpAuth> {
    (
        prop::collection::vec(any::<u8>(), 1..=64),
        arb_label_text(),
        prop::option::of(arb_label_text()),
        prop_oneof![
            Just(Algorithm::Sha1),
            Just(Algorithm::Sha256),
            Just(Algorithm::Sha512)
        ],
        prop_oneof![Just(Digits::Six), Just(Digits::Seven), Just(Digits::Eight)],
        1_u64..=604_800,
        any::<bool>(),
        any::<u64>(),
    )
        .prop_map(
            |(secret_bytes, account, issuer, algorithm, digits, period, is_hotp, counter)| {
                OtpAuth {
                    uri_type: if is_hotp {
                        UriType::Hotp
                    } else {
                        UriType::Totp
                    },
                    secret: OtpSecret::from_bytes(secret_bytes).expect("non-empty"),
                    issuer,
                    account,
                    algorithm,
                    digits,
                    period: if is_hotp { uri::DEFAULT_PERIOD } else { period },
                    counter: is_hotp.then_some(counter),
                }
            },
        )
}

proptest! {
    /// **Core property**: `parse(serialize(auth)?)` restores an equivalent configuration.
    ///
    /// Serialization normalizes (defaults are omitted, the secret becomes unpadded Base32),
    /// so what is asserted is **semantic equivalence**, not byte equality. The property
    /// covers percent encoding and decoding, omission of default values, and the consistency
    /// check on the issuer in both of its positions (label prefix and query parameter). The
    /// secret itself must come back byte for byte.
    #[test]
    fn otpauth_uri_roundtrips(auth in arb_otp_auth()) {
        let text = uri::serialize(&auth)
            .map_err(|e| TestCaseError::fail(format!("serialization failed: {e}")))?;
        let parsed = uri::parse(&text)
            .map_err(|e| TestCaseError::fail(format!("parse failed: {e}\nURI: {text}")))?;

        prop_assert_eq!(parsed.uri_type, auth.uri_type, "the type differs");
        prop_assert_eq!(parsed.account.clone(), auth.account.clone(), "the account differs");
        prop_assert_eq!(parsed.issuer.clone(), auth.issuer.clone(), "the issuer differs");
        prop_assert_eq!(parsed.algorithm, auth.algorithm, "the algorithm differs");
        prop_assert_eq!(parsed.digits, auth.digits, "the digit count differs");
        prop_assert_eq!(parsed.period, auth.period, "the period differs");
        prop_assert_eq!(parsed.counter, auth.counter, "the counter differs");
        prop_assert_eq!(
            parsed.secret.to_base32(),
            auth.secret.to_base32(),
            "the secret differs"
        );
    }

    /// Property: serializing twice yields the same text — normalization is idempotent.
    #[test]
    fn otpauth_serialization_is_idempotent(auth in arb_otp_auth()) {
        let once = uri::serialize(&auth).expect("it should serialize");
        let parsed = uri::parse(&once).expect("our own output should parse");
        let twice = uri::serialize(&parsed).expect("it should serialize");
        prop_assert_eq!(once, twice);
    }

    /// Property: no string makes the URI parser panic.
    ///
    /// This is the main attacker-controlled input surface (QR content, clipboard, typed
    /// links), so staying bounded without crashing is a hard contract.
    #[test]
    fn uri_parser_never_panics(text in "\\PC*") {
        let _ = uri::parse(&text);
    }

    /// Property: arbitrary text appended to a legal URI prefix must not panic either.
    ///
    /// A purely random string almost never hits the `otpauth://` prefix and therefore never
    /// reaches the deeper parsing logic; this injects randomness into the path that actually
    /// parses.
    #[test]
    fn uri_parser_never_panics_with_valid_prefix(suffix in "\\PC*") {
        for prefix in [
            "otpauth://totp/",
            "otpauth://hotp/",
            "otpauth://totp/a:b?secret=",
            "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer=",
        ] {
            let _ = uri::parse(&format!("{prefix}{suffix}"));
        }
    }

    /// Property: when a Base32 decoding result is used as a secret, its length matches the
    /// original byte count.
    ///
    /// This joins the Base32 and OTP modules: an implementation that loses or gains a byte at
    /// a multi-byte boundary fails here immediately.
    #[test]
    fn secret_length_survives_base32_roundtrip(data in prop::collection::vec(any::<u8>(), 1..=64)) {
        let encoded = base32::encode(&data);
        let secret = OtpSecret::from_base32(&encoded)
            .map_err(|e| TestCaseError::fail(format!("cannot build the secret from Base32: {e}")))?;
        prop_assert_eq!(secret.len(), data.len());
        prop_assert_eq!(secret.to_base32(), encoded.trim_end_matches('='));
    }
}

/// A `:` inside an account name makes the round trip ambiguous.
///
/// The label uses the first `:` to separate issuer from account, so a `:` inside the account
/// name **cannot be told apart from the separator**:
///
/// ```text
/// input:        otpauth://totp/:a::a?secret=AA
/// first parse:  account = "a::a",  issuer = None
/// serialized:   otpauth://totp/a%3A%3Aa?secret=AA
/// second parse: account = ":a",    issuer = Some("a")   ← ownership changed silently
/// ```
///
/// The consequence is that a user's code for one entry can be attributed to a different
/// service — for 2FA that is a security incident, not a display problem. Percent-encoding
/// does not help: after decoding, `%3A` and a literal `:` are indistinguishable.
///
/// The invariant is therefore enforced at **both** ends: `split_label` rejects account names
/// containing `:`, and `serialize` rejects them too (it returns `Result`). The legal value
/// domain then contains no ambiguous state.
#[test]
fn regression_account_with_colon_is_rejected_on_both_ends() {
    for bad in [
        "otpauth://totp/:a::a?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/ACME:john:8080?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/:a:?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/ACME:john%3A8080?secret=JBSWY3DPEHPK3PXP",
    ] {
        assert!(
            matches!(
                uri::parse(bad),
                Err(qualia2fa_core::Error::UriAccountContainsColon { .. })
            ),
            "{bad:?} should be rejected for a colon in the account name"
        );
    }

    let auth = OtpAuth {
        uri_type: UriType::Totp,
        secret: OtpSecret::from_bytes(vec![1, 2, 3, 4]).expect("non-empty"),
        issuer: Some("ACME".to_owned()),
        account: "john:8080".to_owned(),
        algorithm: Algorithm::Sha1,
        digits: Digits::Six,
        period: uri::DEFAULT_PERIOD,
        counter: None,
    };
    assert!(
        uri::serialize(&auth).is_err(),
        "serialize should reject a colon in the account name"
    );

    let ok = OtpAuth {
        account: "john@example.com".to_owned(),
        ..auth
    };
    let text = uri::serialize(&ok).expect("a colon-free account should serialize");
    let parsed = uri::parse(&text).expect("it parses");
    assert_eq!(parsed.account, "john@example.com");
    assert_eq!(parsed.issuer.as_deref(), Some("ACME"));
}

// ─────────────────────────────── Regression tests ───────────────────────────────

/// Stripping the `otpauth://` scheme prefix must never panic on a non-character boundary.
///
/// The prefix occupies the first 10 bytes, and a `str` index must fall on a character
/// boundary: when the tenth byte of the input lands inside a multi-byte character, the cut is
/// not a valid string position.
///
/// This matters because the input is attacker-controlled (QR code, clipboard, typed text): a
/// remote attacker who gets the user to scan a QR code could otherwise crash the application.
///
/// The percent-encoded form of U+0080 is `%C2%80` — six bytes, which after
/// `otpauth://hotp/` place byte 10 on `C2`. The cases below cover several prefix lengths
/// cutting into multi-byte sequences, including Chinese (3 bytes per character), emoji
/// (4 bytes per character) and U+0080 (2 bytes per character).
#[test]
fn regression_scheme_stripping_never_panics_on_multibyte_boundary() {
    for text in [
        "otpauth:\u{4e2d}",
        "otpauth\u{1f600}",
        "otpau\u{4e2d}\u{6587}",
        "\u{4e2d}\u{6587}\u{5b57}\u{7b26}",
        "otpauth:/\u{80}",
        "\u{80}\u{80}\u{80}\u{80}\u{80}",
        "",
        "otp",
    ] {
        let _ = uri::parse(text);
        let _ = uri::parse(&format!("otpauth://totp/{text}?secret=AA"));
    }

    let parsed = uri::parse("OTPAUTH://totp/a?secret=AA").expect("scheme is case-insensitive");
    assert_eq!(parsed.account, "a");
}

/// HOTP always carries [`uri::DEFAULT_PERIOD`].
///
/// `serialize` writes no `period` for HOTP, and `parse` normalizes any `period` read from a
/// HOTP URI to [`uri::DEFAULT_PERIOD`]: HOTP advances by counter, so `period` has no meaning
/// for it. `OtpAuth` therefore has no state in which HOTP carries a non-default `period`, and
/// a serialize/parse round trip cannot produce one.
#[test]
fn regression_hotp_period_is_normalized_to_default() {
    let parsed = uri::parse("otpauth://hotp/acct?secret=JBSWY3DPEHPK3PXP&counter=0&period=1")
        .expect("it parses");
    assert_eq!(parsed.uri_type, UriType::Hotp);
    assert_eq!(
        parsed.period,
        uri::DEFAULT_PERIOD,
        "the HOTP period must be normalized to the default"
    );

    let text = uri::serialize(&parsed).expect("it should serialize");
    assert!(
        !text.contains("period="),
        "HOTP serialization must not write a period: {text}"
    );
    let reparsed = uri::parse(&text).expect("it parses");
    assert_eq!(reparsed.period, uri::DEFAULT_PERIOD);

    let totp =
        uri::parse("otpauth://totp/acct?secret=JBSWY3DPEHPK3PXP&period=60").expect("it parses");
    assert_eq!(
        totp.period, 60,
        "a non-default TOTP period must be preserved"
    );
    let totp_text = uri::serialize(&totp).expect("it should serialize");
    assert!(
        totp_text.contains("period=60"),
        "TOTP should write the period: {totp_text}"
    );
    assert_eq!(
        uri::parse(&totp_text).expect("it parses").period,
        60,
        "the TOTP period must survive the round trip"
    );
}
