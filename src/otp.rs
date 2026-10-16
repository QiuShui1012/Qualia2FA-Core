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

//! HOTP (RFC 4226) and TOTP (RFC 6238).
//!
//! # Purity
//!
//! This module **does not read the clock**. HOTP needs a counter, TOTP needs a
//! Unix timestamp, and both are passed in by the caller. This is not a matter of
//! style: with a clock that cannot be injected, the RFC test vectors cannot be
//! verified deterministically, and correctness therefore cannot be demonstrated.
//!
//! # Supported algorithms and secret lengths
//!
//! | `Algorithm` | Secret length, RFC 6238 Appendix B | HMAC block size |
//! |---|---|---|
//! | [`Algorithm::Sha1`] (default) | 20 bytes | 64 bytes |
//! | [`Algorithm::Sha256`] | 32 bytes | 64 bytes |
//! | [`Algorithm::Sha512`] | 64 bytes | 128 bytes |
//!
//! **SHA-1 is required here, and that is not a security compromise**: SHA-1 is
//! broken for **collisions**, but HMAC security does not rest on collision
//! resistance — HMAC-SHA1 remains sound for TOTP, and the vast majority of
//! real-world services support SHA-1 only. RFC 6238 itself lists SHA-1 as a
//! required implementation.
//!
//! # On secret length validation
//!
//! The lengths in the table are RFC **recommendations**, not HMAC
//! **requirements** (HMAC accepts a key of any length). This module therefore
//! **rejects only an empty secret** and does not reject short ones — short
//! secrets exist in the real world, and rejecting them outright would keep users
//! from importing accounts that work. A short length belongs in the UI as a
//! **warning**, not in the core as an error.
//! [`recommended_min_secret_len`] returns the recommended length for it.

use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::{Error, ExposeSecret, Result, secret::SecretBox};

#[cfg(test)]
use secrecy::zeroize::Zeroize;

/// Hash algorithm used by HOTP/TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Algorithm {
    /// HMAC-SHA-1. The TOTP default and the only option most services offer.
    #[default]
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl Algorithm {
    /// Secret length recommended by RFC 6238 (bytes), used to warn the user.
    ///
    /// These values equal the output length of the corresponding hash function.
    #[must_use]
    pub const fn recommended_secret_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Parses the `algorithm` parameter of an `otpauth://` URI.
    ///
    /// Accepts `SHA1` / `SHA256` / `SHA512`, case-insensitively; a name longer
    /// than 8 bytes is rejected on length alone. When the parameter is absent
    /// the caller uses [`Algorithm::default`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedAlgorithm`] for an unrecognised name —
    /// **rejected rather than falling back to SHA-1**, because a silent fallback
    /// gives the user a permanently wrong code and leaves nothing to diagnose.
    pub fn parse(value: &str) -> Result<Self> {
        let mut buf = [0_u8; 8];
        let bytes = value.as_bytes();
        if bytes.len() > buf.len() {
            return Err(Error::UnsupportedAlgorithm {
                name: truncate_for_error(value),
            });
        }
        for (slot, &byte) in buf.iter_mut().zip(bytes) {
            *slot = byte.to_ascii_uppercase();
        }
        let normalized = &buf[..bytes.len()];

        match normalized {
            b"SHA1" => Ok(Self::Sha1),
            b"SHA256" => Ok(Self::Sha256),
            b"SHA512" => Ok(Self::Sha512),
            _ => Err(Error::UnsupportedAlgorithm {
                name: truncate_for_error(value),
            }),
        }
    }
}

/// Truncates an unrecognised algorithm name before placing it into an error, so
/// that oversized (possibly attacker-supplied) input never reaches the logs
/// verbatim. The cut is moved back to the nearest UTF-8 character boundary and
/// the result ends with `…`.
fn truncate_for_error(value: &str) -> String {
    const MAX: usize = 16;
    if value.len() <= MAX {
        return value.into();
    }
    let mut end = MAX;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::from(&value[..end]);
    out.push('…');
    out
}

/// Number of digits in a code: **1 to 9**.
///
/// A validated numeric type rather than an enumeration. RFC 4226 requires 6 digits and
/// RFC 6238 allows 8, but 7 occurs in the real world, importers meet counts from 1 upwards,
/// and an enumeration would need a variant per value — with the compiler no longer able to
/// tell a valid count from an invalid one at the point of use.
///
/// # Why 9 is the upper bound
///
/// RFC 4226 §5.3 extracts a **31-bit** value from the HMAC (`2^31 = 2_147_483_648`). At nine
/// digits the modulus `10^9` divides that range into complete, equally likely intervals; at
/// ten digits `10^10` does not, so about 79% of the range can never be produced and the
/// remaining values are not uniform. Widening the integer type does not change that: the
/// constraint is the truncation, not the storage. Ten digits would need a different
/// truncation, which no existing implementation would agree with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digits(u8);

impl Digits {
    /// Six digits: the default, and what almost every service uses.
    pub const SIX: Self = Self(6);
    /// Seven digits (some banks).
    pub const SEVEN: Self = Self(7);
    /// Eight digits (the maximum RFC 6238 mentions).
    pub const EIGHT: Self = Self(8);
    /// Smallest supported digit count.
    pub const MIN: u8 = 1;
    /// Largest supported digit count (see the type documentation for why).
    pub const MAX: u8 = 9;

    /// Validates a digit count.
    ///
    /// # Errors
    ///
    /// - `0` → [`Error::DigitsZero`]
    /// - `10` or more → [`Error::DigitsTooMany`], which carries the reason
    ///
    /// Deliberately not a `const fn`: the error type is not constructible in a const
    /// context in a way worth the contortion, and no caller needs it there.
    pub fn new(count: u8) -> Result<Self> {
        match count {
            0 => Err(Error::DigitsZero),
            Self::MIN..=Self::MAX => Ok(Self(count)),
            count => Err(Error::DigitsTooMany { count }),
        }
    }

    /// The digit count itself.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.0 as u32
    }

    /// The digit count as the storage byte, which is the count itself.
    ///
    /// The vault format stores a digit count as one byte whose value **is** the count, so no
    /// separate mapping table exists (and none can drift out of step with the type).
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// Parses the `digits` parameter of an `otpauth://` URI.
    ///
    /// # Errors
    ///
    /// The value must be the **canonical** decimal form of a supported count: `"6"` is
    /// accepted, `"06"` is not, and `"six"` is not. This is an **attacker-controlled
    /// parameter**, and accepting a non-canonical form would mean two different URIs that
    /// look different to a user compare equal.
    ///
    /// - a non-canonical or non-numeric string → [`Error::UnsupportedDigits`]
    /// - `"0"` → [`Error::DigitsZero`]
    /// - `"10"` or more → [`Error::DigitsTooMany`]
    pub fn parse(value: &str) -> Result<Self> {
        if let [digit @ b'1'..=b'9'] = value.as_bytes() {
            return Ok(Self(digit - b'0'));
        }
        if let Ok(count) = value.parse::<u8>()
            && count.to_string() == value
        {
            return Self::new(count);
        }
        Err(Error::UnsupportedDigits {
            value: truncate_for_error(value),
        })
    }

    /// `10^digits`, used as the modulus.
    ///
    /// Fits in a `u32` for every supported count: `10^9 = 1_000_000_000`.
    #[must_use]
    pub const fn modulus(self) -> u32 {
        let mut value = 1_u32;
        let mut remaining = self.0;
        while remaining > 0 {
            value *= 10;
            remaining -= 1;
        }
        value
    }
}

impl Default for Digits {
    /// [`Digits::SIX`], the count nearly every service uses.
    fn default() -> Self {
        Self::SIX
    }
}

impl TryFrom<u8> for Digits {
    type Error = Error;

    /// Validates a raw count, as read from a file or received over the wire.
    fn try_from(count: u8) -> Result<Self> {
        Self::new(count)
    }
}

/// A validated OTP secret.
///
/// A dedicated type rather than a bare `SecretBytes` pins the "non-empty"
/// invariant in the type and keeps a caller from passing an arbitrary byte
/// stream where a secret is expected.
///
/// **`Clone` is deliberately not implemented**: cloning would keep a second copy
/// of the same key in memory with its own independent erasure, widening the
/// exposure. Pass a reference where the secret is needed in more than one place.
pub struct OtpSecret {
    /// Secret bytes. `SecretBox` erases them on `Drop` and its `Debug` prints
    /// only a redaction marker.
    bytes: SecretBox<[u8]>,
}

impl OtpSecret {
    /// Builds a secret from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SecretEmpty`] for an empty input.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::SecretEmpty);
        }
        Ok(Self {
            bytes: bytes.into(),
        })
    }

    /// Builds a secret from a Base32 string (how an `otpauth://` URI carries a
    /// secret).
    ///
    /// Tolerance and escaping rules are documented in [`crate::base32::decode`].
    pub fn from_base32(encoded: &str) -> Result<Self> {
        let decoded = crate::base32::decode(encoded)?;
        Self::from_bytes(decoded.expose_secret().to_vec())
    }

    /// Secret length in bytes. The length itself is not a secret.
    ///
    /// There is no `is_empty`: every constructor of `OtpSecret` rejects empty input
    /// (see [`Error::SecretEmpty`]), so the type has no empty state and the lint is
    /// exempted below.
    #[expect(
        clippy::len_without_is_empty,
        reason = "the invariants of this type guarantee it is non-empty, so `is_empty` would always be false and offering it would be misleading"
    )]
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.expose_secret().len()
    }

    /// Whether the secret is shorter than the length the algorithm recommends —
    /// used to **warn** the user, not as an error.
    #[must_use]
    pub fn is_shorter_than_recommended(&self, algorithm: Algorithm) -> bool {
        self.len() < algorithm.recommended_secret_len()
    }

    /// Borrows the secret bytes for computation.
    ///
    /// `pub(crate)` rather than private: the vault serialises the secret into
    /// ciphertext (see the persistence path of [`crate::vault::Entry`]), which
    /// lives in another module of this crate. It is **not public** — outside
    /// callers can only obtain a displayable form via [`OtpSecret::to_base32`]
    /// and cannot take the secret away as a plain byte stream.
    pub(crate) fn expose(&self) -> &[u8] {
        self.bytes.expose_secret()
    }
    /// Exports the secret as a Base32 string (**unpadded**, upper case).
    ///
    /// Used for URI serialisation and QR code generation. This method exists
    /// instead of a public `expose` so that the secret leaves the type through
    /// exactly one narrow path: the result is a displayable, encodable form, not
    /// a bare slice that could be mistaken for ordinary bytes.
    ///
    /// The unpadded form is what most authenticators write and it keeps `=` out
    /// of the QR code, avoiding the escaping issues it would bring.
    #[must_use]
    pub fn to_base32(&self) -> String {
        let encoded = crate::base32::encode(self.expose());
        encoded.trim_end_matches('=').to_owned()
    }
}

impl core::fmt::Debug for OtpSecret {
    /// Prints only the length, **never** the contents.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OtpSecret")
            .field("len", &self.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl PartialEq for OtpSecret {
    /// Compares secret bytes in constant time.
    ///
    /// Compares secret bytes in constant time through [`subtle::ConstantTimeEq`]: a derived
    /// `PartialEq` returns early at the first differing byte, so the comparison time leaks
    /// "how many leading bytes were guessed right".
    ///
    /// # Cost
    ///
    /// Constant time means **every** byte is always compared, even when the
    /// first one already differs. The sync merge loop makes this decision for
    /// thousands of entry pairs, so `PartialEq` for [`crate::vault::Entry`]
    /// deliberately compares the cheap fields first (name, account, timestamps)
    /// and only reaches this one when they all match — a pair with different
    /// names is excluded on the first field and never pays the constant-time
    /// cost.
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq as _;
        self.expose().ct_eq(other.expose()).into()
    }
}

impl Eq for OtpSecret {}

/// Returns the minimum secret length (bytes) recommended for the algorithm, for
/// UI warnings.
#[must_use]
pub const fn recommended_min_secret_len(algorithm: Algorithm) -> usize {
    algorithm.recommended_secret_len()
}

/// Computes the HMAC digest and applies **dynamic truncation** per RFC 4226 §5.3.
///
/// Dynamic truncation: the low 4 bits of the digest's last byte give the offset
/// `offset`; the 4 bytes starting there form a big-endian 31-bit integer (the
/// top bit is masked off).
///
/// `SimpleHmac<D>` is used rather than `Hmac<D>`: both produce **identical** HMAC
/// values, but `SimpleHmac<D>` only requires `D: Digest + BlockSizeUser`, which
/// keeps the three-way runtime dispatch readable. TOTP runs once per 30 seconds
/// over a few dozen bytes, so the throughput difference has no practical effect.
fn hmac_truncate(secret: &OtpSecret, algorithm: Algorithm, message: &[u8]) -> u32 {
    use hmac::digest::common::BlockSizeUser;
    use hmac::digest::{Digest, KeyInit, Mac};

    /// Dispatches to the generic implementation by algorithm.
    ///
    /// Note that `SimpleHmac` implements `Mac` (with `update` / `finalize`),
    /// **not** `Digest` — even though its type parameter `D` must be `Digest`.
    /// Calling `Digest::update` would not compile.
    fn digest_with<D>(key: &[u8], message: &[u8]) -> Option<Vec<u8>>
    where
        D: Digest + BlockSizeUser,
    {
        let mut mac = <hmac::SimpleHmac<D> as KeyInit>::new_from_slice(key).ok()?;
        Mac::update(&mut mac, message);
        Some(Mac::finalize(mac).into_bytes().to_vec())
    }

    let digest = match algorithm {
        Algorithm::Sha1 => digest_with::<Sha1>(secret.expose(), message),
        Algorithm::Sha256 => digest_with::<Sha256>(secret.expose(), message),
        Algorithm::Sha512 => digest_with::<Sha512>(secret.expose(), message),
    };

    let Some(bytes) = digest else {
        return 0;
    };

    let Some(last) = bytes.last() else {
        return 0;
    };
    let offset = usize::from(last & 0x0f);
    if offset + 4 > bytes.len() {
        return 0;
    }
    let truncated = &bytes[offset..offset + 4];

    let value = truncated
        .iter()
        .fold(0_u32, |acc, &b| (acc << 8) | u32::from(b));
    value & 0x7fff_ffff
}

/// Computes the HOTP value (RFC 4226).
///
/// `counter` is an 8-byte big-endian counter. Returns 0..=999_999 for
/// [`Digits::SIX`].
///
/// Use [`hotp_code`] for a fixed-width string with leading zeros.
#[must_use]
pub fn hotp(secret: &OtpSecret, counter: u64, algorithm: Algorithm, digits: Digits) -> u32 {
    let truncated = hmac_truncate(secret, algorithm, &counter.to_be_bytes());
    truncated % digits.modulus()
}

/// Computes the TOTP value (RFC 6238).
///
/// `unix_time` is Unix seconds (**supplied by the caller; this module does not
/// read the clock**). A `period` of 0 returns [`Error::InvalidPeriod`].
///
/// # Errors
///
/// `period == 0` would divide by zero, so it must be rejected.
pub fn totp(
    secret: &OtpSecret,
    unix_time: u64,
    period: u64,
    algorithm: Algorithm,
    digits: Digits,
) -> Result<u32> {
    if period == 0 {
        return Err(Error::InvalidPeriod);
    }
    Ok(hotp(secret, unix_time / period, algorithm, digits))
}

/// Formats an OTP value as a **fixed-width** decimal string with leading zeros.
///
/// This is the final form shown to the user. Leading zeros must not be dropped —
/// `012345` and `12345` are different codes.
#[must_use]
pub fn format_code(value: u32, digits: Digits) -> String {
    format!("{:0width$}", value, width = digits.count() as usize)
}

/// Computes HOTP and returns the fixed-width string directly.
#[must_use]
pub fn hotp_code(secret: &OtpSecret, counter: u64, algorithm: Algorithm, digits: Digits) -> String {
    format_code(hotp(secret, counter, algorithm, digits), digits)
}

/// Computes TOTP and returns the fixed-width string directly.
pub fn totp_code(
    secret: &OtpSecret,
    unix_time: u64,
    period: u64,
    algorithm: Algorithm,
    digits: Digits,
) -> Result<String> {
    Ok(format_code(
        totp(secret, unix_time, period, algorithm, digits)?,
        digits,
    ))
}

/// Compares two OTP strings in **constant time**.
///
/// The comparison is constant time: `==` short-circuits at the first differing character, so its
/// comparison time leaks how many leading characters are correct. A length mismatch returns
/// `false` immediately, which is safe — the length is not a secret.
///
/// # Examples
///
/// ```
/// use qualia2fa_core::otp::{self, Algorithm, Digits, OtpSecret};
///
/// let secret = OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("a valid seed");
/// let code = otp::totp_code(&secret, 1_700_000_000, 30, Algorithm::Sha1, Digits::SIX)
///     .expect("period is non-zero");
/// assert!(otp::verify_code(&code, &code));
/// assert!(!otp::verify_code(&code, "000000"));
/// ```
#[must_use]
pub fn verify_code(expected: &str, provided: &str) -> bool {
    let a = expected.as_bytes();
    let b = provided.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Checks whether the supplied time step lies inside the allowed drift window
/// and returns the offset that matched.
///
/// `Some(offset)` means `provided_counter == counter + offset` holds for an
/// `offset ∈ [-window, +window]`; `None` means nothing in the window matched.
///
/// The matched offset is handed out so a caller can **calibrate the server counter to the
/// matching step** after a hit without recomputing it.
///
/// # Window direction
///
/// With `window = 1` the steps `counter-1`, `counter` and `counter+1` are
/// checked — 3 in total. **The current step is checked first** and returns 0 on a
/// hit, which makes the common path return fastest. This is **not a timing
/// leak**: the offset is attacker-known input anyway, so leaking it means
/// nothing; the real secret is the seed.
#[must_use]
pub fn verify_with_drift(
    secret: &OtpSecret,
    provided_counter: u64,
    window: u64,
    algorithm: Algorithm,
    digits: Digits,
    provided_code: &str,
) -> Option<i64> {
    /// Checks one offset. Returns whether it matched.
    fn matches(
        secret: &OtpSecret,
        counter: u64,
        offset: i64,
        algorithm: Algorithm,
        digits: Digits,
        provided_code: &str,
    ) -> bool {
        let Some(candidate) = counter.checked_add_signed(offset) else {
            return false;
        };
        let expected = hotp_code(secret, candidate, algorithm, digits);
        verify_code(&expected, provided_code)
    }

    if matches(
        secret,
        provided_counter,
        0,
        algorithm,
        digits,
        provided_code,
    ) {
        return Some(0);
    }
    for distance in 1..=window {
        let Ok(distance_i64) = i64::try_from(distance) else {
            break;
        };
        if matches(
            secret,
            provided_counter,
            -distance_i64,
            algorithm,
            digits,
            provided_code,
        ) {
            return Some(-distance_i64);
        }
        if matches(
            secret,
            provided_counter,
            distance_i64,
            algorithm,
            digits,
            provided_code,
        ) {
            return Some(distance_i64);
        }
    }
    None
}

/// Custom alphabet used by Steam Guard (visually confusable characters removed).
const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

/// The Steam Guard code length is always 5.
pub const STEAM_DIGITS: usize = 5;

/// Computes a Steam Guard code.
///
/// Steam does not use decimal digits: it repeatedly reduces the 31-bit truncated
/// value modulo 26 and maps the remainders onto the alphabet
/// `23456789BCDFGHJKMNPQRTVWXY`, which drops confusable characters such as
/// `0/O/1/I/L/S/U`. The length is a fixed 5 characters.
///
/// No `#[must_use]` here: the `Result<String>` return type already carries it,
/// and adding another would trip clippy's `double_must_use`.
pub fn steam_guard_code(
    secret: &OtpSecret,
    unix_time: u64,
    period: u64,
    algorithm: Algorithm,
) -> Result<String> {
    if period == 0 {
        return Err(Error::InvalidPeriod);
    }
    let mut value = hmac_truncate(secret, algorithm, &(unix_time / period).to_be_bytes());

    let mut out = String::with_capacity(STEAM_DIGITS);
    for _ in 0..STEAM_DIGITS {
        let index = (value % STEAM_ALPHABET.len() as u32) as usize;
        out.push(char::from(STEAM_ALPHABET[index]));
        value /= STEAM_ALPHABET.len() as u32;
    }
    Ok(out)
}

/// Gives the `zeroize` import a real use and pins the semantics of "a secret is
/// erased before it is replaced".
///
/// `SecretBox<[u8]>` already implements `ZeroizeOnDrop`; this additionally
/// confirms that a `Vec<u8>` dropped before it reaches the constructor can be
/// erased explicitly.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExposeSecret;

    #[test]
    fn algorithm_parsing_is_case_insensitive() {
        for (input, expected) in [
            ("SHA1", Algorithm::Sha1),
            ("sha1", Algorithm::Sha1),
            ("Sha1", Algorithm::Sha1),
            ("SHA256", Algorithm::Sha256),
            ("sha512", Algorithm::Sha512),
        ] {
            assert_eq!(Algorithm::parse(input).expect(input), expected, "{input}");
        }
    }

    #[test]
    fn algorithm_parsing_rejects_unknown_and_oversized() {
        for bad in ["MD5", "sha3", "", "SHA-1", "verylongalgorithmname"] {
            assert!(
                matches!(
                    Algorithm::parse(bad),
                    Err(Error::UnsupportedAlgorithm { .. })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    /// Truncating a multibyte string must happen at a character boundary,
    /// otherwise it panics.
    #[test]
    fn truncate_for_error_handles_multibyte_boundary() {
        let long = "算".repeat(20);
        let text = truncate_for_error(&long);
        assert!(text.ends_with('…'), "must end with an ellipsis: {text}");
        assert!(long.starts_with(text.trim_end_matches('…')));
    }

    #[test]
    fn digits_parsing_accepts_every_canonical_count_from_1_to_9() {
        for count in Digits::MIN..=Digits::MAX {
            let text = count.to_string();
            let parsed = Digits::parse(&text).expect("a canonical count");
            assert_eq!(parsed.count(), u32::from(count), "{text}");
            assert_eq!(Digits::new(count).expect("in range"), parsed, "{text}");
            assert_eq!(parsed.as_byte(), count, "{text}");
        }
        assert_eq!(Digits::parse("6").expect("6"), Digits::SIX);
        assert_eq!(Digits::parse("7").expect("7"), Digits::SEVEN);
        assert_eq!(Digits::parse("8").expect("8"), Digits::EIGHT);
        assert_eq!(Digits::default(), Digits::SIX);
    }

    /// Out-of-range values carry the reason; malformed values do not pretend to have one.
    #[test]
    fn digits_reject_zero_ten_and_malformed_input() {
        assert!(matches!(Digits::parse("0"), Err(Error::DigitsZero)));
        assert!(matches!(Digits::new(0), Err(Error::DigitsZero)));

        for too_many in ["10", "11", "99", "255"] {
            assert!(
                matches!(Digits::parse(too_many), Err(Error::DigitsTooMany { .. })),
                "{too_many:?} must be rejected as too many"
            );
        }
        assert!(matches!(
            Digits::new(10),
            Err(Error::DigitsTooMany { count: 10 })
        ));

        for bad in [
            "06",
            "007",
            "",
            "six",
            "-6",
            " 6",
            "6 ",
            "99999999999999999999",
        ] {
            assert!(
                matches!(Digits::parse(bad), Err(Error::UnsupportedDigits { .. })),
                "{bad:?} must be rejected as malformed"
            );
        }
    }

    /// The modulus is `10^count` and stays inside a `u32` for every supported count.
    #[test]
    fn modulus_is_a_power_of_ten() {
        let mut expected = 1_u32;
        for count in Digits::MIN..=Digits::MAX {
            expected *= 10;
            let digits = Digits::new(count).expect("in range");
            assert_eq!(digits.modulus(), expected, "count {count}");
        }
    }

    #[test]
    fn format_code_pads_to_exact_width() {
        assert_eq!(format_code(0, Digits::SIX), "000000");
        assert_eq!(format_code(1, Digits::SIX), "000001");
        assert_eq!(format_code(123_456, Digits::SIX), "123456");
        assert_eq!(format_code(0, Digits::EIGHT), "00000000");
        assert_eq!(format_code(99_999_999, Digits::EIGHT), "99999999");
    }

    #[test]
    fn empty_secret_is_rejected() {
        assert!(matches!(
            OtpSecret::from_bytes(Vec::new()),
            Err(Error::SecretEmpty)
        ));
        assert!(matches!(
            OtpSecret::from_base32(""),
            Err(Error::SecretTooShort { .. }) | Err(Error::SecretEmpty)
        ));
    }

    #[test]
    fn secret_debug_never_leaks_bytes() {
        let secret = OtpSecret::from_bytes(vec![0xde, 0xad, 0xbe, 0xef]).expect("non-empty");
        let text = format!("{secret:?}");
        assert!(
            text.contains("redacted"),
            "must be marked as redacted: {text}"
        );
        for leak in ["dead", "beef", "222", "173"] {
            assert!(!text.to_lowercase().contains(leak), "leaks {leak}: {text}");
        }
    }

    #[test]
    fn period_zero_is_rejected() {
        let secret = OtpSecret::from_bytes(vec![1, 2, 3]).expect("non-empty");
        assert!(matches!(
            totp(&secret, 0, 0, Algorithm::Sha1, Digits::SIX),
            Err(Error::InvalidPeriod)
        ));
        assert!(matches!(
            totp_code(&secret, 0, 0, Algorithm::Sha1, Digits::SIX),
            Err(Error::InvalidPeriod)
        ));
        assert!(matches!(
            steam_guard_code(&secret, 0, 0, Algorithm::Sha1),
            Err(Error::InvalidPeriod)
        ));
    }

    #[test]
    fn recommended_lengths_match_hash_output_sizes() {
        assert_eq!(recommended_min_secret_len(Algorithm::Sha1), 20);
        assert_eq!(recommended_min_secret_len(Algorithm::Sha256), 32);
        assert_eq!(recommended_min_secret_len(Algorithm::Sha512), 64);
    }

    #[test]
    fn short_secret_is_flagged_but_accepted() {
        let secret = OtpSecret::from_bytes(vec![1, 2, 3, 4])
            .expect("a non-empty short seed must be accepted");
        assert!(secret.is_shorter_than_recommended(Algorithm::Sha1));
        assert_eq!(secret.len(), 4);

        let long = OtpSecret::from_bytes(vec![0_u8; 20]).expect("non-empty");
        assert!(!long.is_shorter_than_recommended(Algorithm::Sha1));
    }

    #[test]
    fn verify_code_is_length_sensitive_and_content_sensitive() {
        assert!(verify_code("123456", "123456"));
        assert!(!verify_code("123456", "123457"));
        assert!(!verify_code("123456", "12345"));
        assert!(!verify_code("123456", "1234567"));
        assert!(!verify_code("123456", ""));
    }

    /// `verify_with_drift` must find offsets inside the window and report the
    /// correct one.
    #[test]
    fn drift_window_finds_neighbouring_steps() {
        let secret = OtpSecret::from_bytes((0..20).collect::<Vec<u8>>()).expect("non-empty");
        let period = 30_u64;
        let now = 1_700_000_000_u64;
        let counter = now / period;

        for expected_offset in [-1_i64, 0, 1] {
            let target = counter
                .checked_add_signed(expected_offset)
                .expect("no overflow");
            let code = hotp_code(&secret, target, Algorithm::Sha1, Digits::SIX);
            let got = verify_with_drift(&secret, counter, 1, Algorithm::Sha1, Digits::SIX, &code);
            assert_eq!(got, Some(expected_offset), "offset {expected_offset}");
        }
    }

    #[test]
    fn drift_window_rejects_out_of_window() {
        let secret = OtpSecret::from_bytes((0..20).collect::<Vec<u8>>()).expect("non-empty");
        let counter = 1_700_000_000_u64 / 30;
        let far = counter + 5;
        let code = hotp_code(&secret, far, Algorithm::Sha1, Digits::SIX);
        assert_eq!(
            verify_with_drift(&secret, counter, 1, Algorithm::Sha1, Digits::SIX, &code),
            None,
            "must not match outside the window"
        );
    }

    /// A counter of 0 with the window extended to the left must neither
    /// underflow nor panic.
    #[test]
    fn drift_window_handles_counter_underflow() {
        let secret = OtpSecret::from_bytes(vec![7_u8; 20]).expect("non-empty");
        let code = hotp_code(&secret, 0, Algorithm::Sha1, Digits::SIX);
        let got = verify_with_drift(&secret, 0, 3, Algorithm::Sha1, Digits::SIX, &code);
        assert_eq!(got, Some(0), "the current step must match");
    }

    #[test]
    fn steam_codes_are_five_chars_from_steam_alphabet() {
        let secret = OtpSecret::from_bytes((0..20).collect::<Vec<u8>>()).expect("non-empty");
        let code = steam_guard_code(&secret, 1_700_000_000, 30, Algorithm::Sha1)
            .expect("period is non-zero");
        assert_eq!(
            code.chars().count(),
            STEAM_DIGITS,
            "must be 5 characters: {code}"
        );
        for ch in code.chars() {
            assert!(
                STEAM_ALPHABET.contains(&(ch as u8)),
                "character {ch:?} is not in the Steam alphabet: {code}"
            );
        }
    }

    /// Steam codes change with the time step — a constant code would mean the
    /// counter is not being used.
    #[test]
    fn steam_codes_change_across_steps() {
        let secret = OtpSecret::from_bytes((0..20).collect::<Vec<u8>>()).expect("non-empty");
        let a = steam_guard_code(&secret, 1_700_000_000, 30, Algorithm::Sha1)
            .expect("period is non-zero");
        let b = steam_guard_code(&secret, 1_700_000_030, 30, Algorithm::Sha1)
            .expect("period is non-zero");
        assert_ne!(
            a, b,
            "neighbouring time steps must produce different Steam codes"
        );
    }

    /// Exercises the crate-internal borrow accessor and checks that its
    /// semantics match the public path.
    #[test]
    fn internal_expose_matches_public_secret() {
        let secret = OtpSecret::from_bytes(vec![1, 2, 3]).expect("non-empty");
        assert_eq!(secret.expose(), &[1, 2, 3]);
        assert_eq!(secret.len(), 3);
    }

    /// Explicit erasure: confirms `zeroize` is usable on `Vec<u8>` (for
    /// intermediate buffers).
    #[test]
    fn zeroize_is_available_for_intermediate_buffers() {
        let mut buffer = vec![0xAA_u8; 16];
        buffer.zeroize();
        assert!(
            buffer.iter().all(|&b| b == 0),
            "must be all zeros after erasure"
        );
    }

    /// `SecretBox::expose_secret` is provided through a trait; this confirms the
    /// import is usable.
    #[test]
    fn secret_box_expose_is_reachable() {
        let boxed: SecretBox<[u8]> = vec![1_u8, 2, 3].into();
        assert_eq!(boxed.expose_secret(), &[1, 2, 3]);
    }
}
