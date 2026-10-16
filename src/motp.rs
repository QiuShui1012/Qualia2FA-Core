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

//! mOTP (Mobile-OTP).
//!
//! The code is six characters taken from the lower-case hexadecimal MD5 digest of
//!
//! ```text
//! decimal_counter || lowerhex(secret) || pin
//! ```
//!
//! where `decimal_counter = floor(unix_seconds / 10)`, concatenated **without separators**
//! and hashed as UTF-8 bytes.
//!
//! # There is no specification
//!
//! mOTP predates the OATH specifications and was never standardised. The definition above
//! is the one the original project described and the one the implementations that followed
//! it agree on. The test vectors in this module come from Aegis' `MOTPTest.java` (tag
//! v3.4.3) and were independently recomputed before being written down; the test module
//! records the full provenance.
//!
//! # Two properties that are easy to get wrong
//!
//! - **The code is hexadecimal, not decimal.** The original description says "the first 6
//!   digits of the MD5-hash", but the value being sliced is the *hexadecimal string*, so a
//!   code such as `e7d8b6` is normal. It is six characters from `0-9a-f`, not six decimal
//!   digits.
//! - **The PIN is mandatory.** Without it the algorithm has no defined output, so a missing
//!   PIN is an error ([`Error::PinRequired`]) rather than an empty-string substitution.
//!
//! # Purity
//!
//! Like [`crate::otp`], this module **does not read the clock**: the Unix timestamp is
//! passed in by the caller.
//!
//! # MD5
//!
//! MD5 is required by the algorithm itself, not chosen here. It takes no part in AEAD, in
//! any KDF, in signatures, or in any integrity or freshness decision this library makes.

use core::fmt::Write as _;

use md5::{Digest, Md5};
use subtle::ConstantTimeEq;

use crate::{Error, ExposeSecret, Result, otp::OtpSecret, secret::SecretString};

/// Time step of mOTP in seconds.
pub const PERIOD: u64 = 10;

/// Length of an mOTP code, in characters of the hexadecimal digest.
pub const CODE_LEN: usize = 6;

/// An mOTP PIN.
///
/// A dedicated type rather than a bare `String` for the same reason [`OtpSecret`] is one:
/// the PIN is secret material (it is mixed into the code computation), so it must be erased
/// on drop and must never appear in `Debug` output, logs or error messages.
///
/// **`Clone` is deliberately not implemented**: a clone means a second plaintext copy with
/// its own independent erasure. Pass a reference.
pub struct MotpPin {
    /// The PIN itself, erased on drop and redacted in `Debug` by `SecretString`.
    pin: SecretString,
}

impl MotpPin {
    /// Wraps a PIN.
    ///
    /// # Why any string is accepted
    ///
    /// The original description calls for four digits, but neither reference implementation
    /// enforces a length, and an entry that the user's previous authenticator accepted must
    /// not be rejected here on a style rule. An **empty** PIN is accepted as well: it means
    /// the PIN is the empty string, which the algorithm handles like any other value. Only
    /// an **absent** PIN is an error, see [`Error::PinRequired`].
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
    /// An empty PIN is a valid value (see [`MotpPin::new`]), so this reports a property of
    /// the stored PIN rather than an invalid state.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.expose().is_empty()
    }
}

impl core::fmt::Debug for MotpPin {
    /// Prints only the length, **never** the contents.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MotpPin")
            .field("len", &self.len())
            .field("pin", &"<redacted>")
            .finish()
    }
}

impl PartialEq for MotpPin {
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

impl Eq for MotpPin {}

/// Lower-case hexadecimal MD5 digest of `input`.
fn md5_hex(input: &[u8]) -> String {
    let digest = Md5::digest(input);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

/// Computes the mOTP code.
///
/// `unix_time` is Unix seconds (**supplied by the caller; this module does not read the
/// clock**). The counter is `unix_time / period`.
///
/// # Errors
///
/// - [`Error::InvalidPeriod`] if `period == 0`;
/// - [`Error::PinRequired`] if `pin` is `None`.
///
/// # Examples
///
/// ```
/// use qualia2fa_core::motp::{self, MotpPin};
/// use qualia2fa_core::otp::OtpSecret;
///
/// let secret = OtpSecret::from_bytes(vec![0xe3, 0x15, 0x2a, 0xfe, 0xe6, 0x25, 0x99, 0xc8])
///     .expect("a non-empty secret");
/// let pin = MotpPin::new("1234".to_owned());
/// let code = motp::motp_code(&secret, Some(&pin), motp::PERIOD, 165_892_298)
///     .expect("period is non-zero and a PIN is present");
/// assert_eq!(code, "e7d8b6");
/// ```
pub fn motp_code(
    secret: &OtpSecret,
    pin: Option<&MotpPin>,
    period: u64,
    unix_time: u64,
) -> Result<String> {
    if period == 0 {
        return Err(Error::InvalidPeriod);
    }
    let Some(pin) = pin else {
        return Err(Error::PinRequired { otp_type: "mOTP" });
    };

    let counter = unix_time / period;
    let mut input = String::with_capacity(20 + secret.len() * 2 + pin.len());
    write!(input, "{counter}").expect("writing to a String cannot fail");
    for byte in secret.expose() {
        write!(input, "{byte:02x}").expect("writing to a String cannot fail");
    }
    input.push_str(pin.expose());

    let digest = md5_hex(input.as_bytes());
    Ok(digest.chars().take(CODE_LEN).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vectors published by Aegis in `crypto/otp/MOTPTest.java` (tag v3.4.3): a hex
    /// secret, a PIN, a Unix timestamp and the expected code.
    ///
    /// `MOTPTest.java` is the only source of mOTP vectors that exists — there is no
    /// specification and no vendor-published set — so the provenance has to be stated rather
    /// than implied. Every entry below was recomputed with an implementation unrelated to
    /// the one under test (MD5 from the .NET base class library) before being written down.
    const VECTORS: [(&str, &str, u64, &str); 6] = [
        ("e3152afee62599c8", "1234", 165_892_298, "e7d8b6"),
        ("e3152afee62599c8", "1234", 123_456_789, "4ebfb2"),
        ("bbb1912bb5c515be", "9999", 1_659_540_020, "ced7b1"),
        ("bbb1912bb5c515be", "9999", 1_659_540_022, "ced7b1"),
        ("bbb1912bb5c515be", "9999", 1_659_539_870, "1a14f8"),
        ("bbb1912bb5c515be", "9999", 1_659_539_878, "1a14f8"),
    ];

    /// Digest vectors from the same file (`MOTPTest.testGetDigest`), used to pin the
    /// hexadecimal encoding itself: a mix-up between upper and lower case, or between bytes
    /// and their hex form, shows up here rather than in a code comparison.
    const DIGEST_VECTORS: [(&str, &str); 2] = [
        ("BOB", "355938cfe3b73a624297591972d27c01"),
        ("test1234", "16d7a4fca7442dda3ad93c9a726597e4"),
    ];

    /// Decodes a lower-case hex string into bytes, so the vectors can be written the way
    /// their source writes them.
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

    #[test]
    fn armed_vectors_from_the_reference_implementation() {
        for (secret_hex, pin, time, expected) in VECTORS {
            let secret = OtpSecret::from_bytes(unhex(secret_hex)).expect("a non-empty secret");
            let pin = MotpPin::new(pin.to_owned());
            let code = motp_code(&secret, Some(&pin), PERIOD, time).expect("valid inputs");
            assert_eq!(
                code, expected,
                "secret={secret_hex} pin={pin:?} time={time}"
            );
        }
    }

    #[test]
    fn digest_vectors_pin_the_hexadecimal_encoding() {
        for (input, expected) in DIGEST_VECTORS {
            assert_eq!(md5_hex(input.as_bytes()), expected, "input={input:?}");
        }
    }

    /// The counter is floor-divided, not rounded: the two samples inside one step must
    /// produce the same code.
    #[test]
    fn counter_is_floor_divided() {
        let secret = OtpSecret::from_bytes(unhex("bbb1912bb5c515be")).expect("a secret");
        let pin = MotpPin::new("9999".to_owned());
        let first = motp_code(&secret, Some(&pin), PERIOD, 1_659_539_870).expect("valid");
        let last = motp_code(&secret, Some(&pin), PERIOD, 1_659_539_879).expect("valid");
        let next = motp_code(&secret, Some(&pin), PERIOD, 1_659_539_880).expect("valid");
        assert_eq!(first, last, "the whole 10-second step must give one code");
        assert_ne!(first, next, "the next step must give a different code");
    }

    /// A missing PIN is an error; an empty PIN is a value.
    #[test]
    fn missing_pin_is_rejected_and_empty_pin_is_not() {
        let secret = OtpSecret::from_bytes(unhex("e3152afee62599c8")).expect("a secret");
        assert!(matches!(
            motp_code(&secret, None, PERIOD, 1_700_000_000),
            Err(Error::PinRequired { otp_type: "mOTP" })
        ));

        let empty = MotpPin::new(String::new());
        let code = motp_code(&secret, Some(&empty), PERIOD, 1_700_000_000).expect("valid inputs");
        assert_eq!(code.len(), CODE_LEN);
    }

    #[test]
    fn zero_period_is_rejected() {
        let secret = OtpSecret::from_bytes(unhex("e3152afee62599c8")).expect("a secret");
        let pin = MotpPin::new("1234".to_owned());
        assert!(matches!(
            motp_code(&secret, Some(&pin), 0, 1_700_000_000),
            Err(Error::InvalidPeriod)
        ));
    }

    /// The shape of a code: exactly [`CODE_LEN`] lower-case hexadecimal characters.
    #[test]
    fn code_shape_is_lower_case_hex() {
        let secret = OtpSecret::from_bytes(unhex("e3152afee62599c8")).expect("a secret");
        let pin = MotpPin::new("1234".to_owned());
        for time in (1_600_000_000..1_600_000_000 + 100 * PERIOD).step_by(PERIOD as usize) {
            let code = motp_code(&secret, Some(&pin), PERIOD, time).expect("valid inputs");
            assert_eq!(code.len(), CODE_LEN, "time={time}");
            assert!(
                code.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "not a lower-case hex code: {code}"
            );
        }
    }

    /// The same inputs give the same code, and the secret and the PIN both take part.
    #[test]
    fn secret_and_pin_both_affect_the_code() {
        let secret = OtpSecret::from_bytes(unhex("e3152afee62599c8")).expect("a secret");
        let other = OtpSecret::from_bytes(unhex("e3152afee62599c9")).expect("a secret");
        let pin = MotpPin::new("1234".to_owned());
        let other_pin = MotpPin::new("1235".to_owned());

        let base = motp_code(&secret, Some(&pin), PERIOD, 1_700_000_000).expect("valid");
        assert_eq!(
            base,
            motp_code(&secret, Some(&pin), PERIOD, 1_700_000_000).expect("valid")
        );
        assert_ne!(
            base,
            motp_code(&other, Some(&pin), PERIOD, 1_700_000_000).expect("valid")
        );
        assert_ne!(
            base,
            motp_code(&secret, Some(&other_pin), PERIOD, 1_700_000_000).expect("valid")
        );
    }

    /// `Debug` must redact the PIN.
    #[test]
    fn debug_never_leaks_the_pin() {
        let pin = MotpPin::new("1234".to_owned());
        let debug = format!("{pin:?}");
        assert!(
            debug.contains("redacted"),
            "not marked as redacted: {debug}"
        );
        assert!(!debug.contains("1234"), "Debug leaks the PIN: {debug}");
    }

    /// PIN equality is what the sync merge compares, so it must be correct (and is
    /// deliberately constant time, which cannot be observed from a test).
    #[test]
    fn pin_equality() {
        let a = MotpPin::new("1234".to_owned());
        let b = MotpPin::new("1234".to_owned());
        let c = MotpPin::new("12345".to_owned());
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(MotpPin::new(String::new()).is_empty());
        assert_eq!(MotpPin::new(String::new()).len(), 0);
    }
}
