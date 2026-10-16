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

//! `otpauth://` URI parsing (Google Authenticator Key URI Format).
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
//! otpauth://TYPE/LABEL?PARAMETERS
//! ```
//!
//! - `TYPE` is `totp` or `hotp`.
//! - `LABEL` is `accountname` or `issuer:accountname`; both parts are
//!   percent-decoded. **The account name itself must not contain `:`** (see the
//!   rejection rules below).
//! - `PARAMETERS` is `key=value&...`, decoded as
//!   `application/x-www-form-urlencoded`.
//!
//! # Supported parameters
//!
//! | Parameter | Required | Value | Default |
//! |---|---|---|---|
//! | `secret` | **required** | Base32 | — |
//! | `issuer` | optional | text | — |
//! | `algorithm` | optional | `SHA1` / `SHA256` / `SHA512` | `SHA1` |
//! | `digits` | optional | `1` … `9` | `6` |
//! | `period` | optional | seconds, non-zero | `30` |
//! | `counter` | **required for HOTP** | integer | — |
//!
//! # Rejection rules (all covered by tests)
//!
//! - the scheme is not `otpauth`, or the type is neither `totp` nor `hotp`
//! - `secret` is missing, or `secret` cannot be Base32-decoded
//! - `algorithm` is unrecognised — **rejected rather than falling back to
//!   SHA-1**, because a silent fallback gives the user a permanently wrong code
//!   and leaves nothing to diagnose
//! - `digits` is not the canonical decimal form of a count from 1 to 9: `0` and `10`
//!   are rejected with their own reasons (see [`crate::otp::Digits`]) and anything
//!   non-canonical, such as `06`, is rejected as malformed
//! - `period` is 0 or cannot be parsed
//! - `totp` carries a `counter`, or `hotp` lacks a `counter`
//! - `counter` cannot be parsed as an integer
//! - **duplicate parameters** (the same key appearing twice) — implementations
//!   disagree on whether the first or the last occurrence wins, a classic
//!   parsing ambiguity, so this is rejected outright
//! - the issuer in the label and the `issuer` parameter are **both present and
//!   differ**
//! - **the account name contains `:`** — it cannot be told apart from the issuer
//!   separator and would make round-tripping ambiguous (percent-encoding does
//!   not save it either). `serialize` rejects it as well, so both ends agree.

use crate::otp::{Algorithm, Digits, OtpSecret};
use crate::{Error, Result};

/// The type declared by the URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriType {
    /// Time-based one-time password (RFC 6238).
    Totp,
    /// Counter-based one-time password (RFC 4226).
    Hotp,
}

impl UriType {
    /// Parses the URI's authority part.
    ///
    /// Case-insensitive: the specification writes `totp`/`hotp`, but some
    /// generators emit upper case.
    fn parse(value: &str) -> Result<Self> {
        if value.eq_ignore_ascii_case("totp") {
            Ok(Self::Totp)
        } else if value.eq_ignore_ascii_case("hotp") {
            Ok(Self::Hotp)
        } else {
            Err(Error::UriUnsupportedType {
                name: truncate(value, 16),
            })
        }
    }
}

/// A parsed `otpauth://` configuration.
///
/// `Debug` is **hand-written** because the struct holds a secret
/// ([`OtpSecret`]): a derived `Debug` would delegate to each field's `Debug`,
/// and although `OtpSecret` redacts itself, the hand-written form lets a
/// reviewer confirm at a glance that no field can leak.
pub struct OtpAuth {
    /// Whether the entry is TOTP or HOTP.
    pub uri_type: UriType,
    /// OTP secret. Validated to be non-empty.
    pub secret: OtpSecret,
    /// Issuer (service name). Taken from the `issuer` parameter or the label
    /// prefix.
    pub issuer: Option<String>,
    /// Account name (the part of the label after the issuer, or the whole
    /// label).
    pub account: String,
    /// Hash algorithm.
    pub algorithm: Algorithm,
    /// Digit count.
    pub digits: Digits,
    /// TOTP time step in seconds.
    ///
    /// **Invariant**: meaningful only for [`UriType::Totp`]. HOTP advances by
    /// counter, not by time, so for an HOTP entry this field is always
    /// [`DEFAULT_PERIOD`]. Parsing normalises it and trusts nothing the URI says.
    pub period: u64,
    /// HOTP counter. `None` for TOTP.
    pub counter: Option<u64>,
}

/// Maximum printed length (bytes) of the `issuer` / `account` fields in `Debug`.
///
/// See the `Debug` implementation of [`OtpAuth`].
const DEBUG_MAX_FIELD: usize = 64;

impl core::fmt::Debug for OtpAuth {
    /// Hand-written for two reasons:
    ///
    /// 1. **It never prints the secret.** `OtpSecret`'s own `Debug` redacts
    ///    itself, but the hand-written form lets a reviewer confirm at a glance
    ///    that no path can carry the secret out.
    /// 2. **It truncates `issuer` / `account`.** Both fields come from an
    ///    attacker-controlled URI and are unbounded in length; they are **not
    ///    secret but may be private** (real-world values are commonly
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
            .field("uri_type", &self.uri_type)
            .field("secret", &"<redacted>")
            .field(
                "issuer",
                &self.issuer.as_deref().map(|s| truncate(s, DEBUG_MAX_FIELD)),
            )
            .field("account", &truncate(&self.account, DEBUG_MAX_FIELD))
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("counter", &self.counter)
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

/// Parses an `otpauth://` URI.
///
/// Rules and rejection conditions are in the [module documentation](self).
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
/// ```
pub fn parse(input: &str) -> Result<OtpAuth> {
    // ── 1. Split off the scheme ─────────────────────────────────────────
    let after_scheme =
        strip_prefix_ignore_ascii_case(input, "otpauth://").ok_or(Error::UriUnsupportedScheme)?;

    // ── 2. Split off the query ──────────────────────────────────────────
    let (path_and_authority, query) = match after_scheme.split_once('?') {
        Some((left, right)) => (left, Some(right)),
        None => (after_scheme, None),
    };

    // ── 3. Split type and label ─────────────────────────────────────────
    let (type_part, label_part) = path_and_authority
        .split_once('/')
        .ok_or(Error::UriMissingType)?;
    let uri_type = UriType::parse(type_part)?;

    let label = percent_decode_path(label_part)?;

    // ── 4. Parse the query parameters ───────────────────────────────────
    let params = parse_params(query)?;

    // ── 5. Assemble and validate ────────────────────────────────────────
    let secret_raw = params.secret.ok_or(Error::UriMissingSecret)?;
    let secret = OtpSecret::from_base32(&secret_raw)?;

    let algorithm = match &params.algorithm {
        Some(name) => Algorithm::parse(name)?,
        None => Algorithm::default(),
    };

    let digits = match &params.digits {
        Some(value) => Digits::parse(value)?,
        None => Digits::default(),
    };

    let period = match &params.period {
        Some(value) => parse_period(value)?,
        None => DEFAULT_PERIOD,
    };

    let counter = match uri_type {
        UriType::Hotp => Some(parse_counter(
            params.counter.as_deref().ok_or(Error::UriMissingCounter)?,
        )?),
        UriType::Totp => {
            if params.counter.is_some() {
                return Err(Error::UriUnexpectedCounter);
            }
            None
        }
    };
    let period = if uri_type == UriType::Hotp {
        DEFAULT_PERIOD
    } else {
        period
    };

    let (label_issuer, account) = split_label(&label)?;
    let issuer = resolve_issuer(label_issuer, params.issuer)?;

    Ok(OtpAuth {
        uri_type,
        secret,
        issuer,
        account,
        algorithm,
        digits,
        period,
        counter,
    })
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

/// Serialises a parsed configuration back into an `otpauth://` URI.
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
/// Likewise `auth.period` is meaningless for HOTP and is not written out (see
/// the invariant on [`OtpAuth::period`]).
pub fn serialize(auth: &OtpAuth) -> Result<String> {
    if auth.account.contains(':') {
        return Err(Error::UriAccountContainsColon {
            account: truncate(&auth.account, 32),
        });
    }

    let mut out = String::from("otpauth://");
    out.push_str(match auth.uri_type {
        UriType::Totp => "totp",
        UriType::Hotp => "hotp",
    });
    out.push('/');

    if let Some(issuer) = &auth.issuer {
        out.push_str(&percent_encode_path(issuer));
        out.push(':');
    }
    out.push_str(&percent_encode_path(&auth.account));

    out.push('?');
    out.push_str("secret=");
    out.push_str(&auth.secret.to_base32());

    if let Some(issuer) = &auth.issuer {
        out.push_str("&issuer=");
        out.push_str(&percent_encode_query(issuer));
    }
    if auth.algorithm != Algorithm::default() {
        out.push_str("&algorithm=");
        out.push_str(match auth.algorithm {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        });
    }
    if auth.digits != Digits::default() {
        out.push_str("&digits=");
        out.push_str(&auth.digits.count().to_string());
    }
    if auth.uri_type == UriType::Totp && auth.period != DEFAULT_PERIOD {
        out.push_str("&period=");
        out.push_str(&auth.period.to_string());
    }
    if let Some(counter) = auth.counter {
        out.push_str("&counter=");
        out.push_str(&counter.to_string());
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
            uri_type: UriType::Totp,
            secret: OtpSecret::from_bytes(vec![1, 2, 3, 4]).expect("non-empty"),
            issuer: Some("ACME".to_owned()),
            account: "john:8080".to_owned(),
            algorithm: Algorithm::Sha1,
            digits: Digits::SIX,
            period: DEFAULT_PERIOD,
            counter: None,
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
}
