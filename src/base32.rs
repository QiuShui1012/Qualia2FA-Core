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

//! Base32 encoding and decoding (RFC 4648 §6).
//!
//! This is an **attacker-controlled input surface** (QR code contents, seeds typed in by
//! hand), so the implementation is biased towards "reject rather than guess": any
//! ambiguous input returns an error and is never silently corrected.
//!
//! # Deliberate leniency
//!
//! Real-world `otpauth://` seeds are not all strictly canonical, and the leniency below
//! is required, otherwise users run into "scanning fails here but works in another app":
//!
//! - **Case-insensitive**: RFC 4648 specifies uppercase for encoding, but lowercase is
//!   accepted as well.
//! - **Missing `=` padding tolerated**: many generators omit the padding.
//! - **ASCII whitespace tolerated**: seeds copied from a web page often carry spaces or
//!   line breaks.
//!
//! # Deliberately rejected input
//!
//! - **Characters outside the alphabet** (including digits such as `0`, `1`, `8`, `9`
//!   that are easily confused with letters) — rejected rather than guessed, because a
//!   wrong guess yields a "wrong key that appears to work", and the user only notices
//!   when no code arrives.
//! - **Invalid length**: a valid Base32 length is `0, 2, 4, 5, 7` modulo 8. Other lengths
//!   (1, 3, 6) mean the input was truncated or damaged.
//! - **Non-zero padding bits** (rejected only by [`decode_strict`]; [`decode`] accepts
//!   them) — see below.
//!
//! # About padding bits: lenient mode and strict mode
//!
//! RFC 4648 allows the last character to carry **unused** padding bits. One point needs
//! to be clear: **all official RFC test vectors happen to have zero padding bits**, but
//! that is a coincidence of the chosen cases, not a guarantee. Rejecting non-zero
//! padding bits would therefore falsely reject many perfectly valid encodings.
//!
//! This module consequently has two entry points:
//!
//! | Function | Non-zero padding bits | Purpose |
//! |---|---|---|
//! | [`decode`] | **accepted** (matching authenticator apps) | import seeds from users / QR codes |
//! | [`decode_strict`] | **rejected** | verify that our own [`encode`] output is canonical |
//!
//! The leniency is not a security weakness: the decoded result is uniquely determined by
//! the **valid** bits, and padding bits cannot change it, so a non-canonical encoding
//! never decodes to "another key".
//!
//! The module is about 100 lines and is covered by the RFC 4648 §10 vectors and by
//! fuzzing.

use crate::{Error, Result, SecretBytes};

/// The Base32 alphabet (RFC 4648 §6, standard uppercase form).
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A single Base32 character carries 5 bits.
const BITS_PER_CHAR: usize = 5;

/// Maps a single ASCII character to its 5-bit value.
///
/// Uppercase and lowercase are equivalent; whitespace is stripped by the caller
/// beforehand, so whitespace returns `None` here.
const fn decode_char(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a'),
        b'2'..=b'7' => Some(byte - b'2' + 26),
        _ => None,
    }
}

/// Returns the number of output bytes needed for `count` significant characters, after
/// ASCII whitespace and `=` padding have been stripped.
///
/// Integer arithmetic is used instead of floating point to avoid precision issues.
const fn output_len_for(count: usize) -> Option<usize> {
    match count % 8 {
        0 => Some(count / 8 * 5),
        2 => Some(count / 8 * 5 + 1),
        4 => Some(count / 8 * 5 + 2),
        5 => Some(count / 8 * 5 + 3),
        7 => Some(count / 8 * 5 + 4),
        _ => None,
    }
}

/// Decodes a Base32 string into secret bytes (**lenient** mode, for accepting external
/// input).
///
/// The return value is [`SecretBytes`], because in the 2FA setting the decoded result is
/// almost always an OTP seed.
///
/// # Errors
///
/// - [`Error::Base32InvalidCharacter`]: a character outside the alphabet appears, or data
///   appears after `=` padding. `index` is its position in the character sequence
///   **after whitespace has been stripped**, which makes it easy to locate.
/// - [`Error::Base32InvalidLength`]: the number of significant characters modulo 8 is not
///   `0/2/4/5/7`.
/// - [`Error::SecretTooShort`]: the decoded result is empty.
///
/// RFC 4648 allows the last character to carry **unused** padding bits whose value does not
/// participate in the decoded result, and this function ignores them, as mature implementations
/// (including authenticator apps) do. A non-canonical encoding never decodes to "another key": the
/// result is uniquely determined by the **valid** bits. To confirm that an encoding is itself
/// canonical (for example to check our own `encode` output), use [`decode_strict`].
///
/// # Example
///
/// ```
/// use qualia2fa_core::{base32, ExposeSecret};
///
/// // RFC 4648 §10 test vector for "foobar"
/// let decoded = base32::decode("MZXW6YTBOI======").expect("the vector must decode");
/// assert_eq!(decoded.expose_secret(), b"foobar");
/// ```
pub fn decode(input: &str) -> Result<SecretBytes> {
    decode_inner(input, false)
}

/// Decodes a Base32 string and **additionally** requires the trailing padding bits to be
/// zero (canonical form).
///
/// Use it only to confirm that an encoding is in RFC 4648 canonical form, for example to
/// verify the output of this module's [`encode`] or to check recovery material we
/// generated ourselves.
///
/// Do **not** use it to validate seeds imported by users — many legitimate generators
/// produce non-canonical but perfectly valid encodings, which this function would falsely
/// reject (see [`decode`]).
///
/// # Errors
///
/// All the errors of [`decode`], plus [`Error::Base32InvalidPadding`]: the unused bits of
/// the last character are non-zero.
pub fn decode_strict(input: &str) -> Result<SecretBytes> {
    decode_inner(input, true)
}

/// Shared implementation of [`decode`] and [`decode_strict`].
///
/// When `require_canonical` is true, the trailing padding bits are checked as well.
fn decode_inner(input: &str, require_canonical: bool) -> Result<SecretBytes> {
    let mut valid = 0_usize;
    let mut seen_padding = false;
    for (index, &byte) in input.as_bytes().iter().enumerate() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            seen_padding = true;
            continue;
        }
        if seen_padding {
            return Err(Error::Base32InvalidCharacter { index });
        }
        if decode_char(byte).is_none() {
            return Err(Error::Base32InvalidCharacter { index });
        }
        valid += 1;
    }

    let Some(byte_len) = output_len_for(valid) else {
        return Err(Error::Base32InvalidLength { length: valid });
    };
    if byte_len == 0 {
        return Err(Error::SecretTooShort {
            required: 1,
            actual: 0,
        });
    }

    let mut out = Vec::with_capacity(byte_len);
    let mut buffer: u64 = 0;
    let mut buffered_bits = 0_u32;

    for &byte in input.as_bytes() {
        if byte.is_ascii_whitespace() || byte == b'=' {
            continue;
        }
        let Some(value) = decode_char(byte) else {
            return Err(Error::Base32InvalidCharacter { index: 0 });
        };
        buffer = (buffer << BITS_PER_CHAR) | u64::from(value);
        buffered_bits += BITS_PER_CHAR as u32;
        if buffered_bits >= 8 {
            buffered_bits -= 8;
            out.push((buffer >> buffered_bits) as u8);
        }
    }

    if require_canonical && buffered_bits > 0 {
        let residual_mask = (1_u64 << buffered_bits) - 1;
        if buffer & residual_mask != 0 {
            return Err(Error::Base32InvalidPadding);
        }
    }

    debug_assert_eq!(
        out.len(),
        byte_len,
        "the capacity calculation disagrees with the bytes actually written"
    );
    Ok(out.into())
}

/// Encodes secret bytes as a Base32 string (**with** `=` padding, standard form).
///
/// In this project it is mainly used to test round-trip properties and to generate
/// recovery material for users to write down; the parsing direction is the
/// attacker-controlled entry point.
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u64 = 0;
    let mut buffered_bits = 0_u32;

    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        buffered_bits += 8;
        while buffered_bits >= BITS_PER_CHAR as u32 {
            buffered_bits -= BITS_PER_CHAR as u32;
            let index = ((buffer >> buffered_bits) & 0x1f) as usize;
            out.push(char::from(ALPHABET[index]));
        }
    }

    if buffered_bits > 0 {
        let index = ((buffer << (BITS_PER_CHAR as u32 - buffered_bits)) & 0x1f) as usize;
        out.push(char::from(ALPHABET[index]));
    }

    while !out.len().is_multiple_of(8) {
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExposeSecret;

    /// The official test vectors of RFC 4648 §10.
    ///
    /// The RFC gives `""`, `"f"`, `"fo"`… growing step by step, covering all five valid
    /// remainders.
    #[test]
    fn rfc4648_test_vectors() {
        let vectors: &[(&str, &[u8])] = &[
            ("", b""),
            ("MY======", b"f"),
            ("MZXQ====", b"fo"),
            ("MZXW6===", b"foo"),
            ("MZXW6YQ=", b"foob"),
            ("MZXW6YTB", b"fooba"),
            ("MZXW6YTBOI======", b"foobar"),
        ];
        for (encoded, expected) in vectors {
            if expected.is_empty() {
                assert!(
                    matches!(decode(encoded), Err(Error::SecretTooShort { .. })),
                    "empty input must be rejected"
                );
                continue;
            }
            let decoded =
                decode(encoded).unwrap_or_else(|e| panic!("{encoded:?} failed to decode: {e}"));
            assert_eq!(
                decoded.expose_secret(),
                *expected,
                "{encoded:?} decoded to the wrong value"
            );
        }
    }

    /// The encoding direction must produce the RFC 4648 standard form (with padding).
    #[test]
    fn encode_matches_rfc4648_vectors() {
        assert_eq!(encode(b"f"), "MY======");
        assert_eq!(encode(b"fo"), "MZXQ====");
        assert_eq!(encode(b"foo"), "MZXW6===");
        assert_eq!(encode(b"foob"), "MZXW6YQ=");
        assert_eq!(encode(b"fooba"), "MZXW6YTB");
        assert_eq!(encode(b"foobar"), "MZXW6YTBOI======");
    }

    #[test]
    fn accepts_lowercase() {
        let upper = decode("MZXW6YTBOI======").expect("upper case must decode");
        let lower = decode("mzxw6ytboi======").expect("lower case must decode");
        assert_eq!(upper.expose_secret(), lower.expose_secret());
    }

    #[test]
    fn tolerates_missing_padding() {
        let padded = decode("MZXW6YTBOI======").expect("padded input must decode");
        let unpadded = decode("MZXW6YTBOI").expect("unpadded input must decode");
        assert_eq!(padded.expose_secret(), unpadded.expose_secret());
    }

    #[test]
    fn tolerates_ascii_whitespace() {
        let expected = decode("MZXW6YTBOI").expect("the baseline must decode");
        for variant in [
            " MZXW6YTBOI ",
            "MZXW 6YTBOI",
            "MZXW6YTB\nOI",
            "MZ\tXW6YTBOI",
            "MZ XW 6Y TB OI ",
        ] {
            let got = decode(variant).unwrap_or_else(|e| panic!("{variant:?} must decode: {e}"));
            assert_eq!(got.expose_secret(), expected.expose_secret(), "{variant:?}");
        }
    }

    #[test]
    fn rejects_characters_outside_alphabet() {
        for bad in [
            "MZXW6YTBO0======",
            "MZXW6YTBO1======",
            "MZXW6YTBO8======",
            "MZXW6YTBO9======",
            "MZXW6YTB-=",
            "MZXW6YTB!",
            "MZXW6YTBO\u{4e2d}",
        ] {
            let result = decode(bad);
            assert!(
                matches!(result, Err(Error::Base32InvalidCharacter { .. })),
                "{bad:?} must be rejected for an invalid character, got: {result:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_lengths() {
        for bad in ["M", "MZX", "MZXW6Y"] {
            let result = decode(bad);
            assert!(
                matches!(result, Err(Error::Base32InvalidLength { .. })),
                "{bad:?} must be rejected for an invalid length, got: {result:?}"
            );
        }
    }

    #[test]
    fn rejects_data_after_padding() {
        let result = decode("MZXW6YTB=OI");
        assert!(
            matches!(result, Err(Error::Base32InvalidCharacter { .. })),
            "data after padding must be rejected, got: {result:?}"
        );
    }

    /// Non-canonical padding bits: lenient mode accepts them, strict mode rejects them.
    ///
    /// `"MZ"` = 2 significant characters → 1 byte. Only the top 3 of `'Z'`'s 5 bits enter
    /// the result; the low 2 bits (`10`) are unused padding bits.
    ///
    /// The two assertions pin the lenient/strict split: changing either side fails
    /// immediately.
    #[test]
    fn padding_bits_are_accepted_leniently_but_rejected_strictly() {
        let lenient = decode("MZ").expect("lenient mode must accept non-canonical padding bits");
        assert_eq!(lenient.expose_secret(), &[0x66]);

        let strict = decode_strict("MZ");
        assert!(
            matches!(strict, Err(Error::Base32InvalidPadding)),
            "strict mode must reject non-zero padding bits, got: {strict:?}"
        );
    }

    /// Encodings with zero padding bits must succeed in both modes.
    ///
    /// 2 significant characters → 1 byte, leaving **2** residual bits, so the value of the
    /// last character must be congruent to 0 modulo 4 for zero padding. The alphabet
    /// members satisfying this are `A`(0), `E`(4), `I`(8), `M`(12), `Q`(16), `U`(20),
    /// `Y`(24), `4`(28).
    ///
    /// Note that `B`(1) does **not** satisfy it — its residual bits are `01`.
    #[test]
    fn zero_padding_bits_accepted_in_both_modes() {
        for input in ["MA", "ME", "MI", "MM", "MQ", "MU", "MY", "M4"] {
            assert!(
                decode(input).is_ok(),
                "{input:?} must decode in lenient mode"
            );
            assert!(
                decode_strict(input).is_ok(),
                "{input:?} must decode in strict mode (zero residual bits)"
            );
        }

        assert!(decode("ML").is_ok(), "lenient mode must still accept it");
        assert!(
            matches!(decode_strict("ML"), Err(Error::Base32InvalidPadding)),
            "strict mode must reject ML"
        );
    }

    /// The output of this module's `encode` must be canonical, that is, strict mode must
    /// accept it.
    ///
    /// This ties the encoder to the strict decoder: breaking canonical form on either side
    /// fails.
    #[test]
    fn our_own_encoding_is_canonical() {
        for len in 1_usize..=70 {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
            let encoded = encode(&data);
            let decoded = decode_strict(&encoded).unwrap_or_else(|e| {
                panic!("our own encoding of length {len} is not canonical: {e}")
            });
            assert_eq!(decoded.expose_secret(), data.as_slice(), "length {len}");
        }
    }

    #[test]
    fn rejects_empty_and_padding_only() {
        for bad in ["", "   ", "========", "="] {
            let result = decode(bad);
            assert!(
                matches!(result, Err(Error::SecretTooShort { .. })),
                "{bad:?} must be rejected as an empty secret, got: {result:?}"
            );
        }
    }

    /// Realistic case: a 32-byte (256-bit) TOTP seed.
    ///
    /// This is the most common seed length, and the round trip must be correct.
    #[test]
    fn roundtrip_realistic_seed_lengths() {
        for len in [10_usize, 16, 20, 32, 64] {
            let original: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let encoded = encode(&original);
            let decoded = decode(&encoded)
                .unwrap_or_else(|e| panic!("the round trip of length {len} failed: {e}"));
            assert_eq!(decoded.expose_secret(), original.as_slice(), "length {len}");
        }
    }

    /// Error messages must **not** leak the input, which may contain a seed.
    #[test]
    fn errors_do_not_embed_input() {
        let secret_like = "JBSWY3DPEHPK3PXP0";
        let Err(error) = decode(secret_like) else {
            panic!("decoding must fail");
        };
        let text = format!("{error}");
        assert!(
            !text.contains("JBSWY3DPEHPK3PXP"),
            "the error message leaks the seed content: {text}"
        );
    }
}
