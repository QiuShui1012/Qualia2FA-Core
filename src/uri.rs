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

//! `otpauth://` URI parsing (Google Authenticator Key URI Format), plus the `motp:` scheme.
//!
//! This is the project's **primary attacker-controlled input surface**: QR code
//! contents, links typed by the user and clipboard text all end up here. The
//! module therefore aims to **reject strictly** rather than "understand
//! generously" — accepting a structurally valid but semantically wrong
//! configuration is far more dangerous than returning an error.
//!
//! # URI structure
//!
//! ```text
//! otpauth://TYPE/LABEL?PARAMETERS      for totp, hotp, motp, yaotp and steam
//! motp:/LABEL?PARAMETERS               the shape Aegis writes for mOTP
//! ```
//!
//! - `TYPE` is `totp`, `hotp`, `motp`, `yaotp` or `steam`.
//! - `LABEL` is `accountname` or `issuer:accountname`; both parts are
//!   percent-decoded. **The account name itself must not contain `:`** (see the
//!   rejection rules below).
//! - `PARAMETERS` is `key=value&...`, decoded as
//!   `application/x-www-form-urlencoded`.
//!
//! The `motp:` form has no authority component and carries its secret as **Hex**, which is
//! what the only implementation of that scheme writes. Both mOTP forms are read; `serialize`
//! writes `motp:`.
//!
//! # Supported parameters
//!
//! | Parameter | Required | Value | Default |
//! |---|---|---|---|
//! | `secret` | **required** | Base32, or Hex for the `motp:` form | — |
//! | `issuer` | optional | text | `Yandex` for `yaotp` |
//! | `algorithm` | optional | `SHA1` / `SHA256` / `SHA512` | `SHA1` (`SHA256` for `yaotp`) |
//! | `digits` | optional | `1` … `9` | `6` (`8` for `yaotp`, `5` for `steam`) |
//! | `period` | optional | seconds, non-zero | `30` (`10` for `motp`) |
//! | `counter` | **required for HOTP** | integer | — |
//! | `pin` | optional | Base32 (decoded to UTF-8) | — |
//!
//! `pin` is read for `motp` and `yaotp` only. It is this library's own extension for mOTP: the
//! reference implementation's URI has no such parameter, so without it an exported entry comes
//! back without its PIN and every code it produces is wrong.
//!
//! # Which parameters mean something, per type
//!
//! `algorithm` and `digits` are read back out of the entry for `totp` and `hotp` only, and
//! `period` for everything except `hotp` (which advances by counter). The other combinations
//! are **rejected**, not ignored: a value that is silently dropped is a configuration the user
//! believes in and the code does not implement. `yaotp` additionally accepts only SHA-256,
//! because its eight-byte truncation would read past the end of a shorter digest.
//!
//! # Rejection rules (all covered by tests)
//!
//! - the scheme is neither `otpauth://` nor `motp:`, or the type is not one of the five
//! - `secret` is missing, or cannot be decoded (Base32, or Hex for the `motp:` form)
//! - a Yandex secret is neither 16 nor 26 bytes, or 26 bytes with a mismatching checksum
//! - `algorithm` is unrecognised — **rejected rather than falling back to
//!   SHA-1**, because a silent fallback gives the user a permanently wrong code
//!   and leaves nothing to diagnose
//! - `digits` is not the canonical decimal form of a count from 1 to 9: `0` and `10`
//!   are rejected with their own reasons (see [`crate::otp::Digits`]) and anything
//!   non-canonical, such as `06`, is rejected as malformed
//! - `period` is 0 or cannot be parsed, or appears for a type that has none
//! - `totp` carries a `counter`, or `hotp` lacks a `counter`
//! - `counter` cannot be parsed as an integer
//! - a parameter that means nothing for the type is present (`pin` outside `motp`/`yaotp`,
//!   `algorithm` on `motp`, `period` or `counter` on `steam`, and so on)
//! - `pin` is not valid Base32, or decodes to bytes that are not UTF-8
//! - **duplicate parameters** (the same key appearing twice) — implementations
//!   disagree on whether the first or the last occurrence wins, a classic
//!   parsing ambiguity, so this is rejected outright
//! - the issuer in the label and the `issuer` parameter are **both present and
//!   differ**
//! - **the account name contains `:`** — it cannot be told apart from the issuer
//!   separator and would make round-tripping ambiguous (percent-encoding does
//!   not save it either). `serialize` rejects it as well, so both ends agree.

use crate::otp::{Algorithm, Digits, OtpSecret};
use crate::vault::EntryKind;
use crate::{Error, ExposeSecret as _, Result};

/// The type declared by the URI.
///
/// Each variant names a **scheme**, not a hash function: `Motp`, `Yandex` and `Steam` fix
/// their own algorithm and code shape, and only `Totp` / `Hotp` let the URI choose among
/// SHA-1, SHA-256 and SHA-512.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriType {
    /// Time-based one-time password (RFC 6238).
    Totp,
    /// Counter-based one-time password (RFC 4226).
    Hotp,
    /// mOTP: MD5-based, ten-second step, optional PIN ([`crate::motp`]).
    Motp,
    /// Yandex OTP: SHA-256 based, eight letters, thirty-second step ([`crate::yaotp`]).
    Yandex,
    /// Steam Guard: five characters, fixed thirty-second step ([`crate::otp`]).
    Steam,
}

impl UriType {
    /// Parses the URI's authority part.
    ///
    /// Case-insensitive: the Key URI Format writes `totp`/`hotp`, and generators vary in case.
    fn parse(value: &str) -> Result<Self> {
        if value.eq_ignore_ascii_case("totp") {
            Ok(Self::Totp)
        } else if value.eq_ignore_ascii_case("hotp") {
            Ok(Self::Hotp)
        } else if value.eq_ignore_ascii_case("motp") {
            Ok(Self::Motp)
        } else if value.eq_ignore_ascii_case("yaotp") {
            Ok(Self::Yandex)
        } else if value.eq_ignore_ascii_case("steam") {
            Ok(Self::Steam)
        } else {
            Err(Error::UriUnsupportedType {
                name: truncate(value, 16),
            })
        }
    }

    /// The URI type of an entry kind.
    #[must_use]
    pub const fn of(kind: &EntryKind) -> Self {
        match kind {
            EntryKind::Totp { .. } => Self::Totp,
            EntryKind::Hotp { .. } => Self::Hotp,
            EntryKind::Motp { .. } => Self::Motp,
            EntryKind::Yandex { .. } => Self::Yandex,
            EntryKind::Steam => Self::Steam,
        }
    }

    /// The authority an `otpauth://` URI writes for this type.
    const fn authority(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Hotp => "hotp",
            Self::Motp => "motp",
            Self::Yandex => "yaotp",
            Self::Steam => "steam",
        }
    }

    /// The name used in error messages and diagnostics.
    const fn name(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Hotp => "hotp",
            Self::Motp => "motp",
            Self::Yandex => "yaotp",
            Self::Steam => "steam",
        }
    }

    /// The default digit count of this type.
    ///
    /// `Totp` / `Hotp` default to six (RFC 4226 §4); mOTP is six hexadecimal characters;
    /// Yandex OTP is eight **letters**; Steam Guard is five characters from its own alphabet.
    /// Only the first two read the digit count back out of the entry — for the others the code
    /// shape is fixed by the scheme, and the stored count is metadata that keeps an imported
    /// entry faithful to its source.
    pub const fn default_digits(self) -> Digits {
        match self {
            Self::Totp | Self::Hotp | Self::Motp => Digits::SIX,
            Self::Yandex => Digits::EIGHT,
            Self::Steam => Digits::FIVE,
        }
    }

    /// The time step this type **stores**, and its default.
    ///
    /// [`None`] for HOTP (which advances by counter) and for Steam Guard (whose
    /// [`crate::otp::STEAM_PERIOD`] is fixed by the scheme rather than carried by the entry). The
    /// distinction is what makes a `period` parameter on those two a rejection rather than a
    /// value that is read and then dropped: an entry cannot hold it, so honouring it is
    /// impossible.
    ///
    /// Use [`crate::vault::EntryKind::step_seconds`] for the effective refresh interval, which
    /// answers for Steam Guard as well.
    pub const fn default_period(self) -> Option<u64> {
        match self {
            Self::Totp | Self::Yandex => Some(DEFAULT_PERIOD),
            Self::Motp => Some(crate::motp::PERIOD),
            Self::Hotp | Self::Steam => None,
        }
    }
}

/// A parsed `otpauth://` (or `motp:`) configuration.
///
/// `Debug` is **hand-written** because the struct holds a secret
/// ([`OtpSecret`]): a derived `Debug` would delegate to each field's `Debug`,
/// and although `OtpSecret` and the PIN types redact themselves, the hand-written form lets a
/// reviewer confirm at a glance that no field can leak.
pub struct OtpAuth {
    /// Which scheme this configuration describes, with the state that belongs to it: the time
    /// step, the HOTP counter and any PIN.
    ///
    /// The same type the entry model stores, so a scanned configuration becomes an entry by
    /// copying fields rather than by re-deciding what it means.
    pub kind: EntryKind,
    /// OTP secret. Validated to be non-empty (and, for Yandex, to carry a valid checksum).
    pub secret: OtpSecret,
    /// Issuer (service name). Taken from the `issuer` parameter or the label
    /// prefix.
    pub issuer: Option<String>,
    /// Account name (the part of the label after the issuer, or the whole
    /// label).
    pub account: String,
    /// Hash algorithm.
    ///
    /// Meaningful only for [`UriType::Totp`] and [`UriType::Hotp`]: the other schemes fix their
    /// algorithm (mOTP is MD5-based, Yandex OTP is SHA-256, Steam Guard is SHA-1), and a URI
    /// that asks for something else for them is rejected rather than accepted and ignored.
    pub algorithm: Algorithm,
    /// Digit count.
    ///
    /// Meaningful only for [`UriType::Totp`] and [`UriType::Hotp`]; see
    /// [`UriType::default_digits`].
    pub digits: Digits,
}

impl OtpAuth {
    /// The URI type of this configuration.
    #[must_use]
    pub const fn uri_type(&self) -> UriType {
        UriType::of(&self.kind)
    }
}

/// Maximum printed length (bytes) of the `issuer` / `account` fields in `Debug`.
///
/// See the `Debug` implementation of [`OtpAuth`].
const DEBUG_MAX_FIELD: usize = 64;

impl core::fmt::Debug for OtpAuth {
    /// Hand-written for two reasons:
    ///
    /// 1. **It never prints the secret or the PIN.** `OtpSecret`'s own `Debug` redacts
    ///    itself, but the hand-written form lets a reviewer confirm at a glance
    ///    that no path can carry the secret out.
    /// 2. **It truncates `issuer` / `account`.** Both fields come from an
    ///    attacker-controlled URI and are unbounded in length; they are **not**
    ///    secret but may be private (real-world values are commonly
    ///    `issuer = "GitHub"`, `account = "alice@example.com"`). Printing them
    ///    unbounded would let a malicious QR code push arbitrary amounts of text
    ///    into logs, and such logs are often attached to issue trackers.
    ///    Truncation is the compromise between "enough to debug" and "not an
    ///    amplifier".
    ///
    /// Note that truncation is **not** there to prevent secret leakage — the
    /// secret lives in the `secret` field and is never printed. It guards
    /// against log amplification and privacy spill.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OtpAuth")
            .field("uri_type", &self.uri_type())
            .field("secret", &"<redacted>")
            .field(
                "issuer",
                &self.issuer.as_deref().map(|s| truncate(s, DEBUG_MAX_FIELD)),
            )
            .field("account", &truncate(&self.account, DEBUG_MAX_FIELD))
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("kind", &self.kind)
            .finish()
    }
}

/// Truncates a possibly oversized input before placing it into an error, so that
/// attacker-controlled text of arbitrary length never reaches the logs.
///
/// The cut is moved back to the nearest UTF-8 character boundary and the result
/// ends with `…`.
fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::from(&value[..end]);
    out.push('…');
    out
}

/// Parses an OTP configuration URI.
///
/// Two shapes are accepted:
///
/// - `otpauth://<type>/<label>?<parameters>` for every type, with `totp`, `hotp`, `motp`,
///   `yaotp` and `steam` as the type;
/// - `motp:/<label>?<parameters>`, the shape Aegis writes for mOTP, whose `secret` is **Hex**
///   rather than Base32.
///
/// The other rules, and every rejection condition, are in the [module documentation](self).
/// A `#` (fragment) does not exist in this format; if one appears it counts as
/// part of the query and is rejected while the parameters are parsed, because it
/// cannot form a valid `key=value`.
///
/// # Examples
///
/// ```
/// use qualia2fa_core::uri;
/// use qualia2fa_core::otp::{Algorithm, Digits};
///
/// let uri = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8";
/// let parsed = uri::parse(uri).expect("valid URI");
/// assert_eq!(parsed.issuer.as_deref(), Some("GitHub"));
/// assert_eq!(parsed.account, "alice");
/// assert_eq!(parsed.digits, Digits::EIGHT);
/// assert_eq!(parsed.algorithm, Algorithm::Sha1);
/// assert_eq!(parsed.kind, qualia2fa_core::vault::EntryKind::Totp { period: 30 });
/// ```
pub fn parse(input: &str) -> Result<OtpAuth> {
    // ── 1. Split off the scheme and the query ───────────────────────────
    let (uri_type, secret_form, after_authority) = split_scheme(input)?;
    let (path, query) = match after_authority.split_once('?') {
        Some((left, right)) => (left, Some(right)),
        None => (after_authority, None),
    };

    // ── 2. Decode the label and parse the query parameters ──────────────
    let label = percent_decode_path(path)?;
    let params = parse_params(query)?;

    // ── 3. The secret, whose encoding depends on the scheme ─────────────
    let secret_raw = params.secret.as_deref().ok_or(Error::UriMissingSecret)?;
    let decoded = match secret_form {
        SecretForm::Hex => OtpSecret::from_bytes(decode_hex(secret_raw)?)?,
        SecretForm::Base32 => OtpSecret::from_base32(secret_raw)?,
    };
    let secret = match uri_type {
        UriType::Yandex => crate::yaotp::normalize_secret(decoded.expose())?,
        _ => decoded,
    };

    // ── 4. Algorithm, digits, step and counter ──────────────────────────
    let algorithm = resolve_algorithm(uri_type, params.algorithm.as_deref())?;
    let digits = resolve_digits(uri_type, params.digits.as_deref())?;
    let period = resolve_period(uri_type, params.period.as_deref())?;
    let pin = resolve_pin(uri_type, params.pin.as_deref())?;
    let kind = resolve_kind(uri_type, &params, period, pin)?;

    // ── 5. The label, and the issuer default of the scheme ──────────────
    let (label_issuer, account) = split_label(&label)?;
    let issuer = resolve_issuer(label_issuer, params.issuer)?;
    let issuer = match (uri_type, issuer) {
        (UriType::Yandex, None) => Some(YANDEX_DEFAULT_ISSUER.to_owned()),
        (_, issuer) => issuer,
    };

    Ok(OtpAuth {
        kind,
        secret,
        issuer,
        account,
        algorithm,
        digits,
    })
}

/// Issuer a Yandex OTP entry gets when the URI names none.
///
/// Without it such an entry appears in a list as a code with no source, which is
/// indistinguishable from a mis-import.
const YANDEX_DEFAULT_ISSUER: &str = "Yandex";

/// How the secret of the URI that was read is encoded.
///
/// The **form** decides this, not the type: `otpauth://motp/…` follows the Key URI Format and
/// carries Base32 like every other `otpauth://` URI, while Aegis's `motp:/…` carries Hex. A
/// single type therefore has two possible encodings, and guessing wrong would silently produce
/// a different secret - so the spelling that was used is carried along.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretForm {
    /// Base32, as every `otpauth://` URI writes it.
    Base32,
    /// Hexadecimal, as the `motp:` form writes it.
    Hex,
}

/// Splits the scheme off and returns the URI type, the secret encoding and the rest of the
/// input.
///
/// `motp:` has no authority component: Aegis writes `motp:/<label>?…`, so any leading
/// slashes are skipped and the label starts right after them.
fn split_scheme(input: &str) -> Result<(UriType, SecretForm, &str)> {
    if let Some(rest) = strip_prefix_ignore_ascii_case(input, "otpauth://") {
        let (authority, after_authority) = rest.split_once('/').ok_or(Error::UriMissingType)?;
        return Ok((
            UriType::parse(authority)?,
            SecretForm::Base32,
            after_authority,
        ));
    }
    if let Some(rest) = strip_prefix_ignore_ascii_case(input, "motp:") {
        return Ok((UriType::Motp, SecretForm::Hex, rest.trim_start_matches('/')));
    }
    Err(Error::UriUnsupportedScheme)
}

/// Resolves the hash algorithm, honouring the schemes that fix their own.
fn resolve_algorithm(uri_type: UriType, value: Option<&str>) -> Result<Algorithm> {
    let fixed = match uri_type {
        UriType::Yandex => Some(Algorithm::Sha256),
        UriType::Steam => Some(Algorithm::Sha1),
        UriType::Motp | UriType::Totp | UriType::Hotp => None,
    };

    let Some(value) = value else {
        return Ok(fixed.unwrap_or_default());
    };
    let requested = Algorithm::parse(value)?;

    match uri_type {
        UriType::Yandex if requested != Algorithm::Sha256 => {
            Err(Error::YandexAlgorithmUnsupported {
                algorithm: algorithm_name(requested),
            })
        }
        UriType::Steam if requested != Algorithm::Sha1 => Err(Error::SteamAlgorithmUnsupported {
            algorithm: algorithm_name(requested),
        }),
        UriType::Motp => Err(Error::UriParameterNotSupported {
            parameter: "algorithm",
            uri_type: uri_type.name(),
        }),
        _ => Ok(requested),
    }
}

/// Resolves the digit count, honouring the schemes that fix their own.
fn resolve_digits(uri_type: UriType, value: Option<&str>) -> Result<Digits> {
    let Some(value) = value else {
        return Ok(uri_type.default_digits());
    };
    let digits = Digits::parse(value)?;
    if uri_type == UriType::Steam && digits != Digits::FIVE {
        return Err(Error::SteamDigitsUnsupported {
            digits: digits.as_byte(),
        });
    }
    Ok(digits)
}

/// Resolves the time step, rejecting it for the schemes that have none.
fn resolve_period(uri_type: UriType, value: Option<&str>) -> Result<Option<u64>> {
    let Some(value) = value else {
        return Ok(uri_type.default_period());
    };
    if uri_type.default_period().is_none() {
        return Err(Error::UriParameterNotSupported {
            parameter: "period",
            uri_type: uri_type.name(),
        });
    }
    Ok(Some(parse_period(value)?))
}

/// Decodes the `pin` parameter, where the scheme has one.
///
/// The value is Base32, so any character a user may pick - including `&`, `=` and non-ASCII
/// text - survives the query string without depending on percent-encoding rules that
/// implementations disagree about. The decoded bytes must be UTF-8.
fn resolve_pin(uri_type: UriType, value: Option<&str>) -> Result<Option<String>> {
    let supports_pin = matches!(uri_type, UriType::Motp | UriType::Yandex);
    let Some(value) = value else {
        return Ok(None);
    };
    if !supports_pin {
        return Err(Error::UriParameterNotSupported {
            parameter: "pin",
            uri_type: uri_type.name(),
        });
    }

    // An empty value means "no PIN": one state must have one representation, so `pin=` and a
    // missing `pin` cannot both be stored and later compare unequal.
    if value.is_empty() {
        return Ok(None);
    }

    let bytes = crate::base32::decode(value).map_err(|_| Error::UriInvalidPin {
        reason: "not valid Base32",
    })?;
    let text =
        String::from_utf8(bytes.expose_secret().to_vec()).map_err(|_| Error::UriInvalidPin {
            reason: "the decoded bytes are not valid UTF-8",
        })?;
    Ok(Some(text))
}

/// Builds the entry kind from the parameters, rejecting what the scheme cannot mean.
fn resolve_kind(
    uri_type: UriType,
    params: &Params,
    period: Option<u64>,
    pin: Option<String>,
) -> Result<EntryKind> {
    let no_extra = |parameter: &'static str| {
        Err(Error::UriParameterNotSupported {
            parameter,
            uri_type: uri_type.name(),
        })
    };

    match uri_type {
        UriType::Totp => {
            if params.counter.is_some() {
                return Err(Error::UriUnexpectedCounter);
            }
            Ok(EntryKind::Totp {
                period: period.ok_or(Error::InvalidPeriod)?,
            })
        }
        UriType::Hotp => {
            if params.counter.is_none() {
                return Err(Error::UriMissingCounter);
            }
            Ok(EntryKind::Hotp {
                counter: parse_counter(params.counter.as_deref().ok_or(Error::UriMissingCounter)?)?,
            })
        }
        UriType::Motp => {
            if params.counter.is_some() {
                return no_extra("counter");
            }
            Ok(EntryKind::Motp {
                period: period.ok_or(Error::InvalidPeriod)?,
                pin: pin.map(crate::motp::MotpPin::new),
            })
        }
        UriType::Yandex => {
            if params.counter.is_some() {
                return no_extra("counter");
            }
            Ok(EntryKind::Yandex {
                period: period.ok_or(Error::InvalidPeriod)?,
                pin: pin.map(crate::yaotp::YandexPin::new),
            })
        }
        UriType::Steam => {
            if params.counter.is_some() {
                return no_extra("counter");
            }
            Ok(EntryKind::Steam)
        }
    }
}

/// The name a URI writes for an algorithm.
const fn algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::Sha1 => "SHA1",
        Algorithm::Sha256 => "SHA256",
        Algorithm::Sha512 => "SHA512",
    }
}

/// Decodes a hexadecimal string, as the `motp:` scheme carries its secret.
///
/// Upper and lower case are both accepted; an odd length or a non-hex character is rejected.
fn decode_hex(input: &str) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return Err(Error::UriInvalidParameter {
            name: "secret".to_owned(),
            reason: "hexadecimal text must have an even length".to_owned(),
        });
    }

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for index in (0..bytes.len()).step_by(2) {
        let not_hex = || Error::UriInvalidParameter {
            name: "secret".to_owned(),
            reason: "not hexadecimal".to_owned(),
        };
        let high = bytes
            .get(index)
            .and_then(|byte| hex_value(*byte))
            .ok_or_else(not_hex)?;
        let low = bytes
            .get(index + 1)
            .and_then(|byte| hex_value(*byte))
            .ok_or_else(not_hex)?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

/// Encodes bytes as lower-case hexadecimal, the form Aegis writes for mOTP.
fn encode_hex(bytes: &[u8]) -> String {
    /// Hexadecimal digits, lower case.
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// The default TOTP time step in seconds, the value recommended by RFC 6238 §4.1.
pub const DEFAULT_PERIOD: u64 = 30;

/// Reasonable upper bound for `period`: one year.
///
/// The value is not required by any specification; it keeps obviously wrong
/// input (milliseconds written where seconds are expected, for instance) from
/// producing a code that never changes — such a configuration looks workable
/// while having lost the meaning of a second factor.
const MAX_PERIOD: u64 = 366 * 24 * 60 * 60;

/// Parses the `period` parameter.
fn parse_period(value: &str) -> Result<u64> {
    let Ok(period) = value.parse::<u64>() else {
        return Err(Error::UriInvalidParameter {
            name: "period".to_owned(),
            reason: format!("not a valid integer: {}", truncate(value, 16)),
        });
    };
    if period == 0 {
        return Err(Error::InvalidPeriod);
    }
    if period > MAX_PERIOD {
        return Err(Error::UriInvalidParameter {
            name: "period".to_owned(),
            reason: format!("exceeds the {MAX_PERIOD} second limit"),
        });
    }
    Ok(period)
}

/// Parses the `counter` parameter.
fn parse_counter(value: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|_| Error::UriInvalidParameter {
            name: "counter".to_owned(),
            reason: format!("not a valid unsigned integer: {}", truncate(value, 16)),
        })
}

/// Splits a label into `(issuer, account)`.
///
/// Per the specification the split happens at the **first** `:` only. An empty
/// prefix (`:account`) counts as "no issuer" rather than as an empty issuer.
///
/// The label uses `:` to separate issuer from account, so a `:` inside the
/// account name **cannot be told apart from the separator**, which makes
/// round-tripping ambiguous. Concrete counterexample:
///
/// ```text
/// input:        otpauth://totp/:a::a?secret=AA
/// first parse:  account = "a::a", issuer = None
/// serialized:   otpauth://totp/a%3A%3Aa?secret=AA
/// second parse: account = ":a",   issuer = Some("a")  ← ownership changed silently
/// ```
///
/// **Percent-encoding does not save it**: decoding turns `%3A` into `:` first,
/// and after that there is no way to tell whether the `:` was originally part of
/// the account name or served to separate the issuer. Rejecting the account name
/// enforces the invariant at both ends, so a violation is immediately visible.
/// It also matches the specification: in the Google Authenticator Key URI Format
/// the label is `issuer:accountname` and the account name itself contains no `:`.
///
/// # Errors
///
/// Returns [`Error::UriAccountContainsColon`] when the account name (the part
/// after the first `:`) contains a `:`.
fn split_label(label: &str) -> Result<(Option<&str>, String)> {
    let (prefix, account) = match label.split_once(':') {
        Some((prefix, rest)) if !prefix.is_empty() => (Some(prefix), rest),
        Some((_, rest)) => (None, rest),
        None => (None, label),
    };

    if account.contains(':') {
        return Err(Error::UriAccountContainsColon {
            account: truncate(account, 32),
        });
    }
    Ok((prefix, account.to_owned()))
}

/// Merges the label prefix and the `issuer` parameter, failing on a conflict.
fn resolve_issuer(
    label_issuer: Option<&str>,
    param_issuer: Option<String>,
) -> Result<Option<String>> {
    match (label_issuer, param_issuer) {
        (Some(from_label), Some(from_param)) => {
            if from_label == from_param {
                Ok(Some(from_param))
            } else {
                Err(Error::UriIssuerMismatch {
                    in_label: truncate(from_label, 32),
                    in_parameter: truncate(&from_param, 32),
                })
            }
        }
        (Some(from_label), None) => Ok(Some(from_label.to_owned())),
        (None, from_param) => Ok(from_param),
    }
}

/// Strips a prefix, ignoring ASCII case.
///
/// Per RFC 3986 the scheme is case-insensitive, so `OTPAUTH://` is accepted too.
///
/// The check uses `str::get`, which returns `None` for an out-of-range index or
/// one that is not a character boundary, rather than the panic `split_at` would
/// raise on non-ASCII input from a QR code or the clipboard.
fn strip_prefix_ignore_ascii_case<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    let head = input.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| input.get(prefix.len()..).unwrap_or_default())
}

/// Percent-decodes a URI path segment.
///
/// **Different from query decoding**: in a path segment `+` is a literal plus,
/// not a space. Handing the label to `form_urlencoded` would turn a `+` inside
/// `issuer` into a space.
///
/// A multibyte UTF-8 character is encoded as several consecutive `%XX` escapes
/// (for example a three-byte character as `%E4%B8%AD`), so the bytes are
/// collected first and validated as UTF-8 once at the end; decoding each `%XX`
/// on its own would yield separate Latin-1 characters instead. Validating the
/// whole sequence also rejects illegal byte sequences such as `%FF` rather than
/// silently accepting them as a wrong character.
fn percent_decode_path(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(Error::UriInvalidPercentEncoding);
            }
            let hi = hex_value(bytes[i + 1]).ok_or(Error::UriInvalidPercentEncoding)?;
            let lo = hex_value(bytes[i + 2]).ok_or(Error::UriInvalidPercentEncoding)?;
            decoded.push(hi << 4 | lo);
            i += 3;
        } else {
            let start = i;
            while i < bytes.len() && bytes[i] != b'%' {
                i += 1;
            }
            decoded.extend_from_slice(&bytes[start..i]);
        }
    }
    String::from_utf8(decoded).map_err(|_| Error::UriInvalidPercentEncoding)
}

/// The numeric value of a hexadecimal digit.
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The set of query parameters. Named fields rather than a `HashMap`, so the
/// compiler checks which parameters are read.
#[derive(Default)]
struct Params {
    /// `secret`: Base32 secret (required).
    secret: Option<String>,
    /// `issuer`: issuer.
    issuer: Option<String>,
    /// `algorithm`: hash algorithm name.
    algorithm: Option<String>,
    /// `digits`: digit count.
    digits: Option<String>,
    /// `period`: TOTP time step.
    period: Option<String>,
    /// `counter`: HOTP counter.
    counter: Option<String>,
    /// `pin`: Base32-encoded PIN, for the schemes that have one.
    pin: Option<String>,
}

/// Parses the query string.
///
/// Values are decoded as `application/x-www-form-urlencoded`, so `+` means a
/// space. An empty query (`?` with nothing after it) is valid and means "no
/// parameters". Unknown parameters are ignored (generators add extensions such
/// as `image=`), but **duplicate parameters are rejected outright**: different
/// implementations disagree on whether the first or the last occurrence wins,
/// a classic parsing ambiguity (and an attack surface — an attacker can build a
/// URI that two applications understand differently).
fn parse_params(query: Option<&str>) -> Result<Params> {
    let mut params = Params::default();
    let Some(query) = query else {
        return Ok(params);
    };

    if query.is_empty() {
        return Ok(params);
    }

    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        let slot = match key.as_ref() {
            "secret" => &mut params.secret,
            "issuer" => &mut params.issuer,
            "algorithm" => &mut params.algorithm,
            "digits" => &mut params.digits,
            "period" => &mut params.period,
            "counter" => &mut params.counter,
            "pin" => &mut params.pin,
            _ => continue,
        };
        if slot.is_some() {
            return Err(Error::UriDuplicateParameter {
                name: truncate(&key, 16),
            });
        }
        *slot = Some(value.into_owned());
    }
    Ok(params)
}

/// Serialises a parsed configuration back into a URI.
///
/// Used for export and QR code generation. The output is **not guaranteed to be
/// byte-identical to the input** (parameter order and whether defaults are
/// omitted are normalised), but `parse(serialize(x)?)` is equivalent to `x`.
///
/// The label is written as `issuer:account` with both parts percent-encoded, and
/// the secret is re-encoded as **unpadded upper-case** Base32 — what
/// authenticators most commonly write, which also keeps `=` out of the QR code.
/// `algorithm`, `digits` and `period` are written only when they differ from
/// their defaults, which keeps the URI short and close to what generators emit.
///
/// # Errors
///
/// Returns [`Error::UriAccountContainsColon`] when `auth.account` contains `:`.
///
/// Encoding the colon instead of failing is not an option: after parsing, `%3A`
/// decodes back to `:` and is just as indistinguishable from the issuer
/// separator, so a quietly encoded colon would produce a URI that parses back
/// differently from the original — silent data corruption. Returning an error
/// tells the caller immediately that the configuration cannot be represented.
///
/// # The mOTP shape, and the `pin` parameter
///
/// mOTP is written as `motp:/<label>?…` with a **Hex** secret, which is the shape Aegis reads;
/// every other type keeps the `otpauth://` form with a Base32 secret.
///
/// A PIN is written as `pin=<Base32>`. That parameter is **this library's extension** for mOTP:
/// the reference implementation's mOTP URI carries no PIN at all, so an entry exported to it and
/// read back loses the PIN, after which every code it produces is wrong. The value is Base32
/// rather than percent-encoded text so that a PIN may contain any character a user picks -
/// including `&`, `=` and non-ASCII text - without depending on query-encoding rules that
/// implementations disagree about. For Yandex OTP the same parameter is what the reference
/// implementation itself writes.
///
/// A time step is written only for the types that have one, and an algorithm only for the two
/// types that let the URI choose: the others fix their own, and writing a value they would
/// ignore invites the reader to believe it matters.
pub fn serialize(auth: &OtpAuth) -> Result<String> {
    if auth.account.contains(':') {
        return Err(Error::UriAccountContainsColon {
            account: truncate(&auth.account, 32),
        });
    }

    let uri_type = auth.uri_type();
    let hex_secret = uri_type == UriType::Motp;

    let mut out = String::new();
    if hex_secret {
        out.push_str("motp:/");
    } else {
        out.push_str("otpauth://");
        out.push_str(uri_type.authority());
        out.push('/');
    }

    if let Some(issuer) = &auth.issuer {
        out.push_str(&percent_encode_path(issuer));
        out.push(':');
    }
    out.push_str(&percent_encode_path(&auth.account));

    out.push('?');
    out.push_str("secret=");
    if hex_secret {
        out.push_str(&encode_hex(auth.secret.expose()));
    } else {
        out.push_str(&auth.secret.to_base32());
    }

    if let Some(issuer) = &auth.issuer {
        out.push_str("&issuer=");
        out.push_str(&percent_encode_query(issuer));
    }
    if matches!(uri_type, UriType::Totp | UriType::Hotp) && auth.algorithm != Algorithm::default() {
        out.push_str("&algorithm=");
        out.push_str(algorithm_name(auth.algorithm));
    }
    if auth.digits != uri_type.default_digits() {
        out.push_str("&digits=");
        out.push_str(&auth.digits.count().to_string());
    }
    if let Some(period) = auth.kind.period()
        && Some(period) != uri_type.default_period()
    {
        out.push_str("&period=");
        out.push_str(&period.to_string());
    }
    if let EntryKind::Hotp { counter } = &auth.kind {
        out.push_str("&counter=");
        out.push_str(&counter.to_string());
    }
    if let Some(pin) = auth.kind.motp_pin() {
        out.push_str("&pin=");
        out.push_str(&crate::base32::encode(pin.expose().as_bytes()));
    }
    if let Some(pin) = auth.kind.yandex_pin() {
        out.push_str("&pin=");
        out.push_str(&crate::base32::encode(pin.expose().as_bytes()));
    }
    Ok(out)
}

/// Percent-encodes a URI **path segment**.
///
/// Characters that need no escaping inside RFC 3986 `pchar` are kept; everything
/// else (`:`, `/`, `?`, `#`, `%` and every non-ASCII byte) becomes `%XX`. `+`
/// **must** be encoded here, otherwise the query decoding rules would read it as
/// a space.
fn percent_encode_path(input: &str) -> String {
    /// Characters that need no encoding in a path segment (RFC 3986
    /// `unreserved` plus part of `sub-delims`).
    const SAFE: &[u8] = b"-._~!$&'()*+,;=@";

    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        if byte.is_ascii_alphanumeric() || SAFE.contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

/// Percent-encodes a query **value** (a space becomes `%20` rather than `+`,
/// which is less ambiguous).
fn percent_encode_query(input: &str) -> String {
    /// Characters that need no encoding in a query value.
    const SAFE: &[u8] = b"-._~";

    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        if byte.is_ascii_alphanumeric() || SAFE.contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_value_accepts_both_cases() {
        assert_eq!(hex_value(b'0'), Some(0));
        assert_eq!(hex_value(b'9'), Some(9));
        assert_eq!(hex_value(b'a'), Some(10));
        assert_eq!(hex_value(b'F'), Some(15));
        for &bad in b"gG/: " {
            assert_eq!(hex_value(bad), None, "{bad:?} must not be accepted");
        }
    }

    #[test]
    fn path_decoding_does_not_treat_plus_as_space() {
        assert_eq!(percent_decode_path("a+b").expect("must decode"), "a+b");
        assert_eq!(percent_decode_path("a%2Bb").expect("must decode"), "a+b");
        assert_eq!(percent_decode_path("a%20b").expect("must decode"), "a b");
    }

    #[test]
    fn path_decoding_handles_multibyte_utf8() {
        assert_eq!(percent_decode_path("%E4%B8%AD").expect("must decode"), "中");
        assert_eq!(percent_decode_path("中").expect("must decode"), "中");
        assert_eq!(
            percent_decode_path("a%E4%B8%ADb").expect("must decode"),
            "a中b"
        );
    }

    #[test]
    fn path_decoding_rejects_malformed_escapes() {
        for bad in ["%", "%A", "%GG", "abc%", "abc%A"] {
            assert!(
                matches!(
                    percent_decode_path(bad),
                    Err(Error::UriInvalidPercentEncoding)
                ),
                "{bad:?} must be rejected for its escape format"
            );
        }
    }

    /// The decoding result must be valid UTF-8: an illegal byte sequence is
    /// rejected rather than silently accepted.
    ///
    /// This also pins the "collect bytes first, then validate as a whole"
    /// implementation — reverting to a per-byte `char::from` would fail
    /// `path_decoding_handles_multibyte_utf8` first.
    #[test]
    fn path_decoding_rejects_invalid_utf8() {
        for bad in ["%FF", "%80", "%E4%B8", "%C0%80", "ok%FE"] {
            assert!(
                matches!(
                    percent_decode_path(bad),
                    Err(Error::UriInvalidPercentEncoding)
                ),
                "{bad:?} must be rejected for invalid UTF-8"
            );
        }
    }

    #[test]
    fn strip_prefix_is_case_insensitive() {
        assert_eq!(
            strip_prefix_ignore_ascii_case("OTPAUTH://x", "otpauth://"),
            Some("x")
        );
        assert_eq!(
            strip_prefix_ignore_ascii_case("otpauth://x", "otpauth://"),
            Some("x")
        );
        assert_eq!(
            strip_prefix_ignore_ascii_case("http://x", "otpauth://"),
            None
        );
        assert_eq!(strip_prefix_ignore_ascii_case("otp", "otpauth://"), None);
    }

    #[test]
    fn label_splits_on_first_colon_only() {
        assert_eq!(
            split_label("ACME:john@example.com").expect("valid"),
            (Some("ACME"), "john@example.com".to_owned())
        );
        assert_eq!(
            split_label("justaccount").expect("valid"),
            (None, "justaccount".to_owned())
        );
        assert_eq!(
            split_label(":acct").expect("valid"),
            (None, "acct".to_owned())
        );
    }

    /// A `:` in the account name must be rejected — it is indistinguishable from
    /// the issuer separator.
    ///
    /// This test covers `split_label` only, hence **literal** colons. A
    /// percent-encoded colon (`%3A`) becomes a colon only after
    /// `percent_decode_path`, which is end-to-end behaviour covered by
    /// `regression_account_with_colon_is_rejected_on_both_ends` in
    /// `tests/proptest.rs`.
    #[test]
    fn label_rejects_colon_in_account() {
        for bad in ["ACME:john:8080", ":a::a", "a::b", "x:y:z"] {
            assert!(
                matches!(split_label(bad), Err(Error::UriAccountContainsColon { .. })),
                "{bad:?} must be rejected"
            );
        }

        assert_eq!(
            split_label("a:").expect("an empty account name must be accepted"),
            (Some("a"), String::new())
        );

        assert!(
            matches!(
                split_label("::"),
                Err(Error::UriAccountContainsColon { .. })
            ),
            "the account name of \"::\" is \":\" and must be rejected"
        );
    }

    /// `serialize` must reject an account name containing a colon instead of
    /// quietly producing a URI that parses back differently.
    #[test]
    fn serialize_rejects_colon_in_account() {
        let auth = OtpAuth {
            kind: EntryKind::Totp {
                period: DEFAULT_PERIOD,
            },
            secret: OtpSecret::from_bytes(vec![1, 2, 3, 4]).expect("non-empty"),
            issuer: Some("ACME".to_owned()),
            account: "john:8080".to_owned(),
            algorithm: Algorithm::Sha1,
            digits: Digits::SIX,
        };
        assert!(matches!(
            serialize(&auth),
            Err(Error::UriAccountContainsColon { .. })
        ));
    }

    #[test]
    fn issuer_mismatch_is_rejected() {
        let result = resolve_issuer(Some("GitHub"), Some("Gitlab".to_owned()));
        assert!(matches!(result, Err(Error::UriIssuerMismatch { .. })));
    }

    #[test]
    fn issuer_may_come_from_either_source() {
        assert_eq!(
            resolve_issuer(Some("GitHub"), None).expect("must succeed"),
            Some("GitHub".to_owned())
        );
        assert_eq!(
            resolve_issuer(None, Some("GitHub".to_owned())).expect("must succeed"),
            Some("GitHub".to_owned())
        );
        assert_eq!(
            resolve_issuer(Some("GitHub"), Some("GitHub".to_owned()))
                .expect("must succeed when they agree"),
            Some("GitHub".to_owned())
        );
    }

    #[test]
    fn period_bounds_are_enforced() {
        assert_eq!(parse_period("30").expect("30 is valid"), 30);
        assert!(matches!(parse_period("0"), Err(Error::InvalidPeriod)));
        assert!(matches!(
            parse_period("99999999999999999999"),
            Err(Error::UriInvalidParameter { .. })
        ));
        assert!(matches!(
            parse_period(&(MAX_PERIOD + 1).to_string()),
            Err(Error::UriInvalidParameter { .. })
        ));
        assert!(parse_period(&MAX_PERIOD.to_string()).is_ok());
    }

    #[test]
    fn counter_parsing_is_strict() {
        assert_eq!(parse_counter("0").expect("0 is valid"), 0);
        assert_eq!(
            parse_counter("18446744073709551615").expect("the u64 maximum is valid"),
            u64::MAX
        );
        for bad in ["-1", "1.5", "", "abc", "18446744073709551616"] {
            assert!(
                matches!(parse_counter(bad), Err(Error::UriInvalidParameter { .. })),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn percent_encoding_roundtrips_through_decoding() {
        for original in [
            "simple",
            "with space",
            "with+plus",
            "with:colon",
            "with/slash",
            "中文",
            "a%b",
            "a&b=c",
            "100%",
        ] {
            let encoded = percent_encode_path(original);
            let decoded = percent_decode_path(&encoded).unwrap_or_else(|e| {
                panic!("{original:?} encoded as {encoded:?} cannot be decoded back: {e}")
            });
            assert_eq!(
                decoded, original,
                "path encoding round trip failed: {encoded:?}"
            );
        }
    }

    #[test]
    fn query_encoding_roundtrips_through_form_decoding() {
        for original in ["simple", "with space", "with+plus", "中文", "a&b=c", "a%b"] {
            let encoded = percent_encode_query(original);
            let decoded = form_urlencoded::parse(format!("v={encoded}").as_bytes())
                .next()
                .expect("there must be one parameter")
                .1
                .into_owned();
            assert_eq!(
                decoded, original,
                "query encoding round trip failed: {encoded:?}"
            );
        }
    }

    #[test]
    fn truncate_never_splits_a_character() {
        let long = "中".repeat(20);
        let text = truncate(&long, 16);
        assert!(text.ends_with('…'));
        assert!(long.starts_with(text.trim_end_matches('…')));
    }

    #[test]
    fn debug_output_hides_the_secret() {
        let auth = parse("otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME")
            .expect("valid URI");
        let text = format!("{auth:?}");
        assert!(
            text.contains("redacted"),
            "must be marked as redacted: {text}"
        );
        assert!(
            !text.contains("JBSWY3DPEHPK3PXP"),
            "Debug output leaks the Base32 seed: {text}"
        );
        assert!(text.contains("ACME"), "must show the issuer: {text}");
        assert!(text.contains("alice"), "must show the account: {text}");
    }

    /// `Debug` must truncate an oversized `issuer` / `account`.
    ///
    /// Both fields come from an attacker-controlled URI, are unbounded in length
    /// and may hold private data (an email address in real-world entries).
    /// Printing them unbounded would let a malicious QR code push arbitrary
    /// amounts of content into logs, and such logs are often attached to issue
    /// trackers.
    #[test]
    fn debug_truncates_oversized_issuer_and_account() {
        let long_issuer = "I".repeat(500);
        let long_account = "A".repeat(500);
        let input = format!("otpauth://totp/{long_issuer}:{long_account}?secret=AA");
        let auth = parse(&input).expect("must parse");

        let text = format!("{auth:?}");

        assert!(
            !text.contains(&long_issuer),
            "the oversized issuer was not truncated: {text}"
        );
        assert!(
            !text.contains(&long_account),
            "the oversized account was not truncated: {text}"
        );
        assert!(
            text.contains('…'),
            "truncation must add an ellipsis: {text}"
        );

        assert_eq!(
            auth.account, long_account,
            "truncation must not modify the real data"
        );
        assert_eq!(auth.issuer.as_deref(), Some(long_issuer.as_str()));

        assert!(
            text.len() < 512,
            "Debug output must be length-limited, actually {} bytes: {text}",
            text.len()
        );
    }

    /// A valid 16-byte Yandex secret, in Base32.
    const YANDEX_SECRET: &str = "LA2V6KMCGYMWWVEW64RNP3JA3I";

    /// The `motp:` form Aegis writes: a scheme of its own, no authority, a **Hex** secret.
    #[test]
    fn the_motp_scheme_carries_a_hex_secret() {
        let auth =
            parse("motp:/ACME:alice?secret=deadbeef&issuer=ACME").expect("the motp form parses");

        assert_eq!(auth.uri_type(), UriType::Motp);
        assert_eq!(auth.account, "alice");
        assert_eq!(auth.issuer.as_deref(), Some("ACME"));
        assert_eq!(
            auth.kind,
            EntryKind::Motp {
                period: crate::motp::PERIOD,
                pin: None,
            },
            "mOTP defaults to its own ten-second step"
        );
        assert_eq!(
            auth.secret.expose().to_vec(),
            vec![0xde, 0xad, 0xbe, 0xef],
            "the secret is hexadecimal on this form, not Base32"
        );
    }

    /// The `otpauth://motp/` spelling is read too, so an exporter that follows the Key URI
    /// Format for the authority is not turned away.
    #[test]
    fn otpauth_motp_is_accepted_with_a_base32_secret() {
        let auth = parse("otpauth://motp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME&period=15")
            .expect("the otpauth spelling parses");

        assert_eq!(auth.uri_type(), UriType::Motp);
        assert_eq!(
            auth.kind,
            EntryKind::Motp {
                period: 15,
                pin: None,
            }
        );
        assert_eq!(auth.secret.to_base32(), "JBSWY3DPEHPK3PXP");
    }

    /// The mOTP PIN survives our own round trip. The reference implementation's mOTP URI has no
    /// PIN parameter, so this is where an exported entry would otherwise come back unusable.
    #[test]
    fn motp_round_trip_keeps_the_pin() {
        let encoded = crate::base32::encode(b"1234");
        let auth = parse(&format!(
            "motp:/ACME:alice?secret=deadbeef&issuer=ACME&pin={encoded}"
        ))
        .expect("the motp form parses");
        assert_eq!(
            auth.kind,
            EntryKind::Motp {
                period: crate::motp::PERIOD,
                pin: Some(crate::motp::MotpPin::new("1234".to_owned())),
            },
            "the PIN travels Base32-encoded and comes back as the text the user typed"
        );

        let text = serialize(&auth).expect("it serializes");
        assert!(text.starts_with("motp:/"), "actual {text}");
        assert!(text.contains("secret=deadbeef"), "actual {text}");
        assert!(text.contains("pin="), "the PIN must be written: {text}");

        let reparsed = parse(&text).expect("it parses back");
        assert_eq!(
            reparsed.kind, auth.kind,
            "the PIN and the step must survive the round trip"
        );
    }

    /// A Yandex URI: `pin` is Base32, the issuer defaults to `Yandex`, the secret is Base32.
    #[test]
    fn yaotp_round_trip_keeps_the_pin_and_defaults_the_issuer() {
        let uri = format!(
            "otpauth://yaotp/alice?secret={YANDEX_SECRET}&pin={}",
            crate::base32::encode(b"1234")
        );
        let auth = parse(&uri).expect("a yaotp URI parses");

        assert_eq!(auth.uri_type(), UriType::Yandex);
        assert_eq!(
            auth.issuer.as_deref(),
            Some("Yandex"),
            "an entry with no source is indistinguishable from a mis-import"
        );
        assert_eq!(auth.algorithm, Algorithm::Sha256);
        assert_eq!(
            auth.digits,
            Digits::EIGHT,
            "eight characters, not eight digits"
        );
        assert_eq!(
            auth.kind,
            EntryKind::Yandex {
                period: DEFAULT_PERIOD,
                pin: Some(crate::yaotp::YandexPin::new("1234".to_owned())),
            }
        );

        let text = serialize(&auth).expect("it serializes");
        assert!(text.starts_with("otpauth://yaotp/"), "actual {text}");
        assert!(text.contains("pin="), "the PIN must be written: {text}");
        assert!(
            !text.contains("algorithm="),
            "the algorithm is fixed by the scheme: {text}"
        );

        let reparsed = parse(&text).expect("it parses back");
        assert_eq!(
            reparsed.kind, auth.kind,
            "the PIN must survive the round trip"
        );
    }

    /// A 26-byte Yandex secret is accepted (and reduced to its first 16 bytes); a 26-byte one
    /// with a broken checksum is not.
    #[test]
    fn yaotp_accepts_the_26_byte_form_and_rejects_a_broken_checksum() {
        let full = "LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI";
        let pin = crate::base32::encode(b"1234");
        let auth = parse(&format!("otpauth://yaotp/alice?secret={full}&pin={pin}"))
            .expect("the 26-byte form parses");
        assert_eq!(
            auth.secret.len(),
            16,
            "the checksum is verified, then only the first 16 bytes are used"
        );

        let mut damaged = String::from(full);
        damaged.replace_range(0..1, "B");
        let result = parse(&format!("otpauth://yaotp/alice?secret={damaged}&pin={pin}"));
        assert!(
            matches!(result, Err(Error::YandexSecretChecksum)),
            "a damaged 26-byte secret must be rejected, actual ok={}",
            result.is_ok()
        );
    }

    /// Yandex OTP truncates eight bytes, so a shorter digest cannot carry it.
    #[test]
    fn yaotp_rejects_another_algorithm() {
        for name in ["SHA1", "SHA512"] {
            let uri = format!("otpauth://yaotp/alice?secret={YANDEX_SECRET}&algorithm={name}");
            let result = parse(&uri);
            assert!(
                matches!(result, Err(Error::YandexAlgorithmUnsupported { .. })),
                "{name} must be rejected, actual ok={}",
                result.is_ok()
            );
        }

        let uri = format!("otpauth://yaotp/alice?secret={YANDEX_SECRET}&algorithm=SHA256");
        assert!(
            parse(&uri).is_ok(),
            "the algorithm the scheme uses is accepted when written out"
        );
    }

    /// Steam Guard fixes its algorithm, its code length and its step, so a URI that asks for
    /// something else is rejected rather than silently trimmed to fit.
    #[test]
    fn steam_uri_rejects_parameters_that_mean_nothing() {
        let auth = parse("otpauth://steam/alice?secret=JBSWY3DPEHPK3PXP").expect("it parses");
        assert_eq!(auth.uri_type(), UriType::Steam);
        assert_eq!(auth.kind, EntryKind::Steam);
        assert_eq!(auth.algorithm, Algorithm::Sha1);
        assert_eq!(auth.digits, Digits::FIVE);

        let text = serialize(&auth).expect("it serializes");
        assert!(text.starts_with("otpauth://steam/"), "actual {text}");
        for absent in ["digits=", "period=", "algorithm=", "counter=", "pin="] {
            assert!(
                !text.contains(absent),
                "{absent} means nothing for Steam Guard: {text}"
            );
        }
        assert_eq!(parse(&text).expect("it parses back").kind, EntryKind::Steam);

        for query in [
            "algorithm=SHA256",
            "digits=6",
            "period=60",
            "counter=1",
            "pin=GEZDGNBV",
        ] {
            let uri = format!("otpauth://steam/alice?secret=JBSWY3DPEHPK3PXP&{query}");
            let result = parse(&uri);
            assert!(
                result.is_err(),
                "{query} must be rejected for steam, actual ok={}",
                result.is_ok()
            );
            let message = result.expect_err("it is rejected").to_string();
            assert!(
                !message.to_lowercase().contains("internal"),
                "the rejection must be a real diagnosis: {message}"
            );
        }

        // The two that carry a reason of their own rather than "means nothing here".
        assert!(matches!(
            parse("otpauth://steam/alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256"),
            Err(Error::SteamAlgorithmUnsupported { .. })
        ));
        assert!(matches!(
            parse("otpauth://steam/alice?secret=JBSWY3DPEHPK3PXP&digits=6"),
            Err(Error::SteamDigitsUnsupported { .. })
        ));
    }

    /// `pin` belongs to the two schemes that have one.
    #[test]
    fn a_pin_outside_the_pin_schemes_is_rejected() {
        for uri in [
            "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&pin=GEZDGNBV",
            "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=0&pin=GEZDGNBV",
        ] {
            let result = parse(uri);
            assert!(
                matches!(
                    result,
                    Err(Error::UriParameterNotSupported {
                        parameter: "pin",
                        ..
                    })
                ),
                "{uri} must be rejected, actual ok={}",
                result.is_ok()
            );
        }
    }

    /// A PIN that is not Base32, or whose bytes are not UTF-8, is rejected without echoing it.
    #[test]
    fn an_unusable_pin_is_rejected_without_echoing_it() {
        let not_base32 = parse("motp:/ACME:alice?secret=deadbeef&pin=1234");
        assert!(
            matches!(not_base32, Err(Error::UriInvalidPin { .. })),
            "a PIN that is not Base32 must be rejected, actual ok={}",
            not_base32.is_ok()
        );

        // `0xFF` alone is not valid UTF-8, and `74` is its Base32 encoding.
        let not_utf8 = parse("motp:/ACME:alice?secret=deadbeef&pin=74");
        assert!(
            matches!(not_utf8, Err(Error::UriInvalidPin { .. })),
            "a PIN whose bytes are not text must be rejected, actual ok={}",
            not_utf8.is_ok()
        );

        for uri in [
            "motp:/ACME:alice?secret=deadbeef&pin=1234",
            "motp:/ACME:alice?secret=deadbeef&pin=74",
        ] {
            let message = parse(uri).expect_err("it is rejected").to_string();
            assert!(
                !message.contains("1234") && !message.contains("74"),
                "the error must not echo the PIN: {message}"
            );
        }
    }

    /// An empty `pin` means "no PIN": one state must have one representation.
    #[test]
    fn an_empty_pin_is_no_pin() {
        let auth = parse("motp:/ACME:alice?secret=deadbeef&pin=").expect("it parses");
        assert_eq!(
            auth.kind,
            EntryKind::Motp {
                period: crate::motp::PERIOD,
                pin: None,
            }
        );
    }

    /// `serialize` writes the scheme each type needs, and a `period` only where it means
    /// something.
    #[test]
    fn serialization_writes_the_scheme_of_each_type() {
        let cases = [
            (
                "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP",
                "otpauth://totp/",
            ),
            (
                "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=0",
                "otpauth://hotp/",
            ),
            ("motp:/alice?secret=deadbeef", "motp:/"),
            (
                "otpauth://yaotp/alice?secret=LA2V6KMCGYMWWVEW64RNP3JA3I",
                "otpauth://yaotp/",
            ),
            (
                "otpauth://steam/alice?secret=JBSWY3DPEHPK3PXP",
                "otpauth://steam/",
            ),
        ];

        for (uri, expected_prefix) in cases {
            let auth = parse(uri).expect("the URI parses");
            let text = serialize(&auth).expect("it serializes");
            assert!(
                text.starts_with(expected_prefix),
                "{uri} must serialize as {expected_prefix}, actual {text}"
            );
            assert_eq!(
                parse(&text).expect("it parses back").kind,
                auth.kind,
                "the kind must survive {uri}"
            );
        }
    }
}
