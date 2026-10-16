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

//! Yandex OTP (`yaotp`), the scheme behind Yandex.Key.
//!
//! # The algorithm
//!
//! ```text
//! key_hash = SHA-256( UTF8(pin) || secret16 )
//! if key_hash[0] == 0 { key_hash = key_hash[1..] }      // a 25-byte key, not 32
//! counter  = floor(unix_seconds / 30)                   // 8 bytes, big endian
//! hash     = HMAC-SHA256(key = key_hash, message = counter)
//! offset   = hash[31] & 0x0f
//! hash[offset] &= 0x7f
//! value    = hash[offset..offset + 8] as a big-endian integer
//! code     = value % 26^8, written as eight base-26 characters
//! ```
//!
//! # The code is letters, not digits
//!
//! **The eight characters are lower-case `a`-`z`**, not decimal digits: `value` is written
//! in base 26, so a code looks like `umozdicq`. Callers that render codes must therefore
//! treat the result as a string — padding it to a width, grouping it into threes, or
//! sorting it as a number all produce something the user cannot type into the login page.
//!
//! # Three details that are easy to get wrong
//!
//! 1. The HMAC key is the **SHA-256 of the PIN followed by the secret**, and when that
//!    digest happens to start with a zero byte the first byte is **dropped**. The branch
//!    fires for roughly one input in 256, so random testing will not reach it.
//! 2. The truncation reads **eight bytes**, not the four bytes (31 bits) of RFC 4226 §5.3.
//! 3. The digest must be at least `offset + 8` bytes long. With SHA-256 (32 bytes) that
//!    always holds, which is why this module accepts **no algorithm parameter**: the
//!    `algorithm` parameter of an `otpauth://yaotp/` URI is not a knob here. With SHA-1 the
//!    same construction would index out of bounds, so such an entry is rejected by the
//!    caller rather than computed.
//!
//! # Secret forms
//!
//! A Yandex secret is either **16 bytes** (what a QR code carries) or **26 bytes**
//! (16 bytes plus a trailing checksum). Only the first 16 bytes take part in the
//! computation, see [`normalize_secret`].
//!
//! # Known gap: the trailing checksum is not verified
//!
//! The 26-byte form ends with a 12-bit checksum over the secret. It is **not verified
//! here**, for a licensing reason rather than a technical one: no specification of that
//! checksum exists, and the only published descriptions of it are GPL-3.0 implementations,
//! which cannot be copied into this LGPL-3.0-or-later crate. The effect is that a corrupted
//! 26-byte secret is accepted and produces codes the server rejects, instead of being
//! reported as damaged at import time. The first 16 bytes — the part that determines the
//! code — are used identically either way, so a **valid** secret behaves exactly as it does
//! in the reference implementation.
//!
//! # Purity
//!
//! Like [`crate::otp`], this module **does not read the clock**: the Unix timestamp is
//! passed in by the caller.

use hmac::digest::{Digest, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{Error, ExposeSecret, Result, otp::OtpSecret, secret::SecretString};

/// Time step of Yandex OTP in seconds.
pub const PERIOD: u64 = 30;

/// Length of a Yandex OTP code, in characters.
pub const CODE_LEN: usize = 8;

/// Length of a Yandex secret without a checksum (what a QR code carries), in bytes.
pub const SECRET_LEN: usize = 16;

/// Length of a Yandex secret with its trailing checksum, in bytes.
pub const SECRET_FULL_LEN: usize = 26;

/// Size of the code alphabet: `a`-`z`.
const ALPHABET_LEN: u64 = 26;

/// A Yandex OTP PIN.
///
/// A dedicated type rather than a bare `String` for the same reason [`OtpSecret`] is one:
/// the PIN is secret material (it is hashed together with the secret to form the HMAC key),
/// so it must be erased on drop and must never appear in `Debug` output, logs or error
/// messages.
///
/// **`Clone` is deliberately not implemented**: a clone means a second plaintext copy with
/// its own independent erasure. Pass a reference.
pub struct YandexPin {
    /// The PIN itself, erased on drop and redacted in `Debug` by `SecretString`.
    pin: SecretString,
}

impl YandexPin {
    /// Wraps a PIN.
    ///
    /// # Why any string is accepted
    ///
    /// A Yandex PIN is **not** four digits in practice — the reference implementation's
    /// vectors include a sixteen-character one — and no length is enforced there either. An
    /// **empty** PIN is accepted as a value; only an **absent** PIN is an error, see
    /// [`Error::PinRequired`].
    #[must_use]
    pub fn new(pin: String) -> Self {
        Self { pin: pin.into() }
    }

    /// Borrows the PIN for computation.
    ///
    /// `pub(crate)` rather than public: the PIN leaves the type only towards the code
    /// computation and the vault's serialisation path, never towards an outside caller as a
    /// plain string.
    pub(crate) fn expose(&self) -> &str {
        self.pin.expose_secret()
    }

    /// PIN length in bytes. The length itself is not a secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.expose().len()
    }

    /// Whether the PIN is empty.
    ///
    /// An empty PIN is a valid value (see [`YandexPin::new`]), so this reports a property of
    /// the stored PIN rather than an invalid state.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.expose().is_empty()
    }
}

impl core::fmt::Debug for YandexPin {
    /// Prints only the length, **never** the contents.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("YandexPin")
            .field("len", &self.len())
            .field("pin", &"<redacted>")
            .finish()
    }
}

impl PartialEq for YandexPin {
    /// Compares in constant time.
    ///
    /// The result of this comparison reaches the sync merge (a differing PIN makes two
    /// entries different), so a short-circuiting `==` would leak how many leading bytes of
    /// the PIN were guessed right.
    fn eq(&self, other: &Self) -> bool {
        self.expose()
            .as_bytes()
            .ct_eq(other.expose().as_bytes())
            .into()
    }
}

impl Eq for YandexPin {}

/// Normalises a Yandex secret to the 16 bytes the algorithm uses.
///
/// A 16-byte secret is taken as is. A 26-byte secret keeps its first 16 bytes and drops the
/// trailing checksum, which is **not verified** — see the module documentation for why, and
/// for what that means in practice.
///
/// # Errors
///
/// Returns [`Error::YandexSecretLength`] for any other length. The length is reported but
/// the bytes are not: a rejected secret is still secret material.
pub fn normalize_secret(secret: &[u8]) -> Result<OtpSecret> {
    match secret.len() {
        SECRET_LEN => OtpSecret::from_bytes(secret.to_vec()),
        SECRET_FULL_LEN => OtpSecret::from_bytes(secret[..SECRET_LEN].to_vec()),
        len => Err(Error::YandexSecretLength { len }),
    }
}

/// Computes the Yandex OTP code.
///
/// `unix_time` is Unix seconds (**supplied by the caller; this module does not read the
/// clock**). The counter is `unix_time / period`; the code is [`CODE_LEN`] lower-case
/// letters.
///
/// # Errors
///
/// - [`Error::InvalidPeriod`] if `period == 0`;
/// - [`Error::PinRequired`] if `pin` is `None`.
///
/// # Examples
///
/// ```
/// use qualia2fa_core::otp::OtpSecret;
/// use qualia2fa_core::yaotp::{self, YandexPin};
///
/// let secret = OtpSecret::from_bytes(vec![
///     0x58, 0x35, 0x5f, 0x29, 0x82, 0x36, 0x19, 0x6b, 0x54, 0x96, 0xf7, 0x22, 0xd7, 0xed,
///     0x20, 0xda,
/// ])
/// .expect("a non-empty secret");
/// let pin = YandexPin::new("7586".to_owned());
/// let code = yaotp::yaotp_code(&secret, Some(&pin), yaotp::PERIOD, 1_581_064_020)
///     .expect("period is non-zero and a PIN is present");
/// assert_eq!(code, "oactmacq");
/// ```
pub fn yaotp_code(
    secret: &OtpSecret,
    pin: Option<&YandexPin>,
    period: u64,
    unix_time: u64,
) -> Result<String> {
    if period == 0 {
        return Err(Error::InvalidPeriod);
    }
    let Some(pin) = pin else {
        return Err(Error::PinRequired {
            otp_type: "Yandex OTP",
        });
    };

    let key_hash = {
        let mut hasher = Sha256::new();
        hasher.update(pin.expose().as_bytes());
        hasher.update(secret.expose());
        hasher.finalize()
    };
    let key: &[u8] = if key_hash[0] == 0 {
        &key_hash[1..]
    } else {
        &key_hash[..]
    };

    let counter = unix_time / period;
    let mut mac = <hmac::SimpleHmac<Sha256> as KeyInit>::new_from_slice(key)
        .expect("HMAC accepts a key of any length");
    Mac::update(&mut mac, &counter.to_be_bytes());
    let hash = Mac::finalize(mac).into_bytes();

    let offset = usize::from(hash[hash.len() - 1] & 0x0f);
    let mut truncated = [0_u8; 8];
    truncated.copy_from_slice(
        hash.get(offset..offset + 8)
            .expect("a SHA-256 digest has 32 bytes and the offset is at most 15"),
    );
    truncated[0] &= 0x7f;
    let mut value = u64::from_be_bytes(truncated);

    let mut code = [0_u8; CODE_LEN];
    for slot in code.iter_mut().rev() {
        *slot = b'a'
            + u8::try_from(value % ALPHABET_LEN).expect("a remainder below 26 always fits in u8");
        value /= ALPHABET_LEN;
    }
    Ok(String::from_utf8(code.to_vec()).expect("the alphabet is ASCII"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The vectors published by Aegis in `crypto/otp/YAOTPTest.java` (tag v3.4.3): a PIN, a
    /// Base32 secret, a Unix timestamp and the expected code.
    ///
    /// There is no specification for this scheme either, so the provenance has to be stated
    /// rather than implied. Every entry below was recomputed with an implementation unrelated
    /// to the one under test (SHA-256 and HMAC-SHA256 from the .NET base class library)
    /// before being written down.
    const VECTORS: [(&str, &str, u64, &str); 5] = [
        (
            "5239",
            "6SB2IKNM6OBZPAVBVTOHDKS4FAAAAAAADFUTQMBTRY",
            1_641_559_648,
            "umozdicq",
        ),
        (
            "7586",
            "LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI",
            1_581_064_020,
            "oactmacq",
        ),
        (
            "7586",
            "LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI",
            1_581_090_810,
            "wemdwrix",
        ),
        (
            "5210481216086702",
            "JBGSAU4G7IEZG6OY4UAXX62JU4AAAAAAHTSG4HXU3M",
            1_581_091_469,
            "dfrpywob",
        ),
        (
            "5210481216086702",
            "JBGSAU4G7IEZG6OY4UAXX62JU4AAAAAAHTSG4HXU3M",
            1_581_093_059,
            "vunyprpd",
        ),
    ];

    /// A secret and PIN whose `SHA-256(pin || secret)` starts with a zero byte, found by
    /// searching an unrelated counter-based series.
    ///
    /// The "drop the first byte" branch fires for roughly one input in 256, so it needs a
    /// vector of its own; the expected code was computed outside this crate.
    const ZERO_PREFIX_SECRET: &str = "6a87d52d0afb0baab93811cd80dcff03";
    /// The PIN of [`ZERO_PREFIX_SECRET`].
    const ZERO_PREFIX_PIN: &str = "0";
    /// Expected code for [`ZERO_PREFIX_SECRET`] at [`ZERO_PREFIX_TIME`].
    const ZERO_PREFIX_CODE: &str = "khfjdkeg";
    /// Timestamp of the zero-prefix vector.
    const ZERO_PREFIX_TIME: u64 = 1_700_000_000;

    /// Decodes a Base32 secret the way an `otpauth://yaotp/` URI carries it.
    fn secret_from_base32(encoded: &str) -> OtpSecret {
        let decoded = crate::base32::decode(encoded).expect("a valid Base32 secret");
        normalize_secret(decoded.expose_secret()).expect("a valid Yandex secret length")
    }

    /// Decodes a lower-case hex string into bytes.
    fn unhex(text: &str) -> Vec<u8> {
        assert!(
            text.len().is_multiple_of(2),
            "hex input must have an even length"
        );
        text.as_bytes()
            .chunks(2)
            .map(|pair| {
                let text = core::str::from_utf8(pair).expect("hex is ASCII");
                u8::from_str_radix(text, 16).expect("hex digits")
            })
            .collect()
    }

    /// A second, independent implementation of the same algorithm, written for this test
    /// only: HMAC-SHA-256 is assembled by hand from the hash function (RFC 2104's ipad/opad
    /// construction) instead of going through the `hmac` crate, and the base-26 conversion is
    /// written as a division chain rather than as index arithmetic.
    ///
    /// A vector can only prove that two implementations agree; this is what keeps the module
    /// from agreeing with itself.
    fn reference_code(secret: &[u8], pin: &str, unix_time: u64) -> String {
        /// SHA-256 block size in bytes (RFC 6234 §2).
        const BLOCK: usize = 64;

        fn sha256(data: &[u8]) -> [u8; 32] {
            let digest = Sha256::digest(data);
            let mut out = [0_u8; 32];
            out.copy_from_slice(&digest);
            out
        }

        let mut key_input = Vec::with_capacity(pin.len() + secret.len());
        key_input.extend_from_slice(pin.as_bytes());
        key_input.extend_from_slice(secret);
        let digest = sha256(&key_input);
        let key: &[u8] = if digest[0] == 0 {
            &digest[1..]
        } else {
            &digest
        };

        let mut padded = [0_u8; BLOCK];
        if key.len() <= BLOCK {
            padded[..key.len()].copy_from_slice(key);
        } else {
            padded[..32].copy_from_slice(&sha256(key));
        }
        let mut inner = Vec::with_capacity(BLOCK + 8);
        inner.extend(padded.iter().map(|byte| byte ^ 0x36));
        inner.extend_from_slice(&(unix_time / PERIOD).to_be_bytes());
        let inner_hash = sha256(&inner);
        let mut outer = Vec::with_capacity(BLOCK + 32);
        outer.extend(padded.iter().map(|byte| byte ^ 0x5c));
        outer.extend_from_slice(&inner_hash);
        let hash = sha256(&outer);

        let offset = usize::from(hash[31] & 0x0f);
        let mut eight = [0_u8; 8];
        eight.copy_from_slice(&hash[offset..offset + 8]);
        eight[0] &= 0x7f;
        let mut value = u64::from_be_bytes(eight);

        let mut letters = Vec::with_capacity(CODE_LEN);
        for _ in 0..CODE_LEN {
            letters.push(b'a' + (value % ALPHABET_LEN) as u8);
            value /= ALPHABET_LEN;
        }
        letters.reverse();
        String::from_utf8(letters).expect("ASCII")
    }

    #[test]
    fn vectors_from_the_reference_implementation() {
        for (pin, secret_base32, time, expected) in VECTORS {
            let secret = secret_from_base32(secret_base32);
            let pin = YandexPin::new(pin.to_owned());
            let code = yaotp_code(&secret, Some(&pin), PERIOD, time).expect("valid inputs");
            assert_eq!(
                code, expected,
                "pin={pin:?} secret={secret_base32} time={time}"
            );
        }
    }

    /// The module must agree with the second implementation in this file.
    #[test]
    fn agrees_with_the_independent_implementation() {
        let secret = unhex("58355f298236196b5496f722d7ed20da");
        for time in [
            0,
            1,
            29,
            30,
            1_581_064_020,
            1_581_090_810,
            1_700_000_000,
            4_102_444_800,
        ] {
            for pin in ["", "0", "7586", "5210481216086702", "pin with spaces"] {
                let ours = yaotp_code(
                    &OtpSecret::from_bytes(secret.clone()).expect("a secret"),
                    Some(&YandexPin::new(pin.to_owned())),
                    PERIOD,
                    time,
                )
                .expect("valid inputs");
                assert_eq!(
                    ours,
                    reference_code(&secret, pin, time),
                    "pin={pin:?} time={time}"
                );
            }
        }
    }

    /// The "drop a leading zero byte" branch, which one input in 256 reaches.
    #[test]
    fn zero_prefixed_key_hash_drops_the_first_byte() {
        let secret = OtpSecret::from_bytes(unhex(ZERO_PREFIX_SECRET)).expect("a secret");
        let pin = YandexPin::new(ZERO_PREFIX_PIN.to_owned());

        // The premise of this vector, asserted rather than assumed: the key hash really does
        // start with a zero byte, so the code below can only be right if that byte is dropped.
        let mut hasher = Sha256::new();
        hasher.update(ZERO_PREFIX_PIN.as_bytes());
        hasher.update(secret.expose());
        assert_eq!(
            hasher.finalize()[0],
            0,
            "this vector must exercise the zero-prefix branch"
        );

        let code = yaotp_code(&secret, Some(&pin), PERIOD, ZERO_PREFIX_TIME).expect("valid");
        assert_eq!(code, ZERO_PREFIX_CODE);
        assert_eq!(
            code,
            reference_code(
                &unhex(ZERO_PREFIX_SECRET),
                ZERO_PREFIX_PIN,
                ZERO_PREFIX_TIME
            )
        );
    }

    /// Both secret forms are accepted and normalise to the same 16 bytes.
    #[test]
    fn both_secret_forms_normalise_to_sixteen_bytes() {
        let short = secret_from_base32("LA2V6KMCGYMWWVEW64RNP3JA3I");
        let long = secret_from_base32("LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI");
        assert_eq!(short.len(), SECRET_LEN);
        assert_eq!(long.len(), SECRET_LEN);
        assert_eq!(short.expose(), long.expose());
        assert_eq!(long.to_base32(), "LA2V6KMCGYMWWVEW64RNP3JA3I");
    }

    #[test]
    fn other_secret_lengths_are_rejected() {
        for len in [0_usize, 1, 15, 17, 25, 27, 32] {
            let bytes = vec![0x42_u8; len];
            assert!(
                matches!(
                    normalize_secret(&bytes),
                    Err(Error::YandexSecretLength { len: reported }) if reported == len
                ),
                "length {len} must be rejected"
            );
        }
    }

    /// A missing PIN is an error; an empty PIN is a value.
    #[test]
    fn missing_pin_is_rejected_and_empty_pin_is_not() {
        let secret = secret_from_base32("LA2V6KMCGYMWWVEW64RNP3JA3I");
        assert!(matches!(
            yaotp_code(&secret, None, PERIOD, 1_700_000_000),
            Err(Error::PinRequired {
                otp_type: "Yandex OTP"
            })
        ));

        let empty = YandexPin::new(String::new());
        let code = yaotp_code(&secret, Some(&empty), PERIOD, 1_700_000_000).expect("valid inputs");
        assert_eq!(code.len(), CODE_LEN);
    }

    #[test]
    fn zero_period_is_rejected() {
        let secret = secret_from_base32("LA2V6KMCGYMWWVEW64RNP3JA3I");
        let pin = YandexPin::new("7586".to_owned());
        assert!(matches!(
            yaotp_code(&secret, Some(&pin), 0, 1_700_000_000),
            Err(Error::InvalidPeriod)
        ));
    }

    /// The shape of a code: exactly [`CODE_LEN`] lower-case letters.
    #[test]
    fn code_shape_is_eight_lower_case_letters() {
        let secret = secret_from_base32("LA2V6KMCGYMWWVEW64RNP3JA3I");
        let pin = YandexPin::new("7586".to_owned());
        for time in (1_600_000_000..1_600_000_000 + 100 * PERIOD).step_by(PERIOD as usize) {
            let code = yaotp_code(&secret, Some(&pin), PERIOD, time).expect("valid inputs");
            assert_eq!(code.len(), CODE_LEN, "time={time}");
            assert!(
                code.bytes().all(|b| b.is_ascii_lowercase()),
                "not a lower-case letter code: {code}"
            );
        }
    }

    /// The secret and the PIN both take part, and the same inputs give the same code.
    #[test]
    fn secret_and_pin_both_affect_the_code() {
        let secret = secret_from_base32("LA2V6KMCGYMWWVEW64RNP3JA3I");
        let other = OtpSecret::from_bytes(unhex("58355f298236196b5496f722d7ed20db"))
            .expect("a non-empty secret");
        let pin = YandexPin::new("7586".to_owned());
        let other_pin = YandexPin::new("7587".to_owned());

        let base = yaotp_code(&secret, Some(&pin), PERIOD, 1_700_000_000).expect("valid");
        assert_eq!(
            base,
            yaotp_code(&secret, Some(&pin), PERIOD, 1_700_000_000).expect("valid")
        );
        assert_ne!(
            base,
            yaotp_code(&other, Some(&pin), PERIOD, 1_700_000_000).expect("valid")
        );
        assert_ne!(
            base,
            yaotp_code(&secret, Some(&other_pin), PERIOD, 1_700_000_000).expect("valid")
        );
    }

    /// A 26-character Base32 secret carries 130 bits, of which only the first 128 reach the
    /// 16-byte secret: the last two bits are padding and are dropped.
    ///
    /// This is a property of the encoding rather than of this module, and it is easy to trip
    /// over — two secrets that differ only in their final Base32 character are **the same
    /// secret** and produce the same codes.
    #[test]
    fn trailing_base32_padding_bits_do_not_change_the_secret() {
        let padded = secret_from_base32("LA2V6KMCGYMWWVEW64RNP3JA3I");
        let other_padding = secret_from_base32("LA2V6KMCGYMWWVEW64RNP3JA3J");
        assert_eq!(padded.expose(), other_padding.expose());

        let meaningful = secret_from_base32("LA2V6KMCGYMWWVEW64RNP3JA3A");
        assert_ne!(padded.expose(), meaningful.expose());
    }

    /// `Debug` must redact the PIN.
    #[test]
    fn debug_never_leaks_the_pin() {
        let pin = YandexPin::new("5210481216086702".to_owned());
        let debug = format!("{pin:?}");
        assert!(
            debug.contains("redacted"),
            "not marked as redacted: {debug}"
        );
        for leak in ["5210481216086702", "5210", "6702"] {
            assert!(!debug.contains(leak), "Debug leaks the PIN: {debug}");
        }
    }

    /// PIN equality is what the sync merge compares.
    #[test]
    fn pin_equality() {
        let a = YandexPin::new("7586".to_owned());
        let b = YandexPin::new("7586".to_owned());
        let c = YandexPin::new("7587".to_owned());
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(YandexPin::new(String::new()).len(), 0);
        assert!(YandexPin::new(String::new()).is_empty());
    }

    proptest! {
        /// For arbitrary secrets, PINs and timestamps, the module agrees with the second
        /// implementation in this file and the code keeps its shape.
        ///
        /// The fixed vectors in [`VECTORS`] cover the values the reference implementation
        /// happened to publish; this covers the rest of the input space, including the
        /// counter wrapping to values far beyond the current epoch.
        #[test]
        fn agrees_with_the_independent_implementation_for_arbitrary_inputs(
            secret in proptest::collection::vec(any::<u8>(), SECRET_LEN),
            pin in "[ -~]{0,24}",
            time in any::<u64>(),
        ) {
            let code = yaotp_code(
                &OtpSecret::from_bytes(secret.clone()).expect("a non-empty secret"),
                Some(&YandexPin::new(pin.clone())),
                PERIOD,
                time,
            )
            .expect("valid inputs");

            prop_assert_eq!(&code, &reference_code(&secret, &pin, time));
            prop_assert_eq!(code.len(), CODE_LEN);
            prop_assert!(code.bytes().all(|byte| byte.is_ascii_lowercase()));
        }
    }
}
