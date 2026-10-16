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

//! Vault entries: the plaintext structure and the entry identifier.
//!
//! # What the plaintext holds
//!
//! After decryption a 2FA entry is carried by [`Entry`]: display name, issuer, account,
//! secret, algorithm, digits, the entry kind (with the time step, the HOTP counter and any PIN
//! the scheme needs), note, and the creation and modification timestamps.
//!
//! # What the plaintext does not hold
//!
//! **An entry has no globally readable metadata.** In a vault file an entry is nothing
//! but its [`EntryId`] and a ciphertext - not even "TOTP or HOTP" is visible, because
//! that lives inside the ciphertext. A vault file is expected to travel through
//! untrusted places (a cloud drive the user picked, a QR code, another device), and any
//! plaintext field would leak there.
//!
//! [`EntryId`] is therefore the **only** exception, and it is a 128-bit CSPRNG random
//! value carrying no semantics: its only purpose is to let two devices talk about "the
//! same entry".

use crate::{Error, Result, otp};

/// Entry identifier: a 128-bit CSPRNG random value.
///
/// It carries no semantics: its only purpose is to let two devices talk about the same
/// entry. The collision probability reaches the birthday bound only around 2^64 entries,
/// and it reveals nothing about the content, so it can safely sit in the vault file in
/// plaintext.
///
/// # Display
///
/// [`Debug`] and [`Display`](core::fmt::Display) both print the hexadecimal form only.
/// The ID is not a secret (it sits in the file in plaintext), but it is not meant for end
/// users either: its purpose is telling entries apart in logs and diagnostics.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryId([u8; Self::LEN]);

impl EntryId {
    /// Byte length of an identifier.
    pub const LEN: usize = 16;

    /// Generates a new random identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`] when the OS random source is unavailable.
    /// There is **no** fallback to a userspace PRNG: predictable IDs make two devices
    /// generate the same entry and merge them silently during sync.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0_u8; Self::LEN];
        crate::getrandom::fill(&mut bytes).map_err(|_| Error::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    /// Builds an identifier from a byte array.
    ///
    /// Used to parse an existing ID from a file. **Creating a new entry goes through
    /// [`EntryId::generate`]**, otherwise two devices end up with the same ID.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes, used to write the file and to build the AAD.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl core::fmt::Debug for EntryId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EntryId({self})")
    }
}

impl core::fmt::Display for EntryId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Timestamp: Unix seconds.
///
/// Supplied by the caller; this library reads no clock (see the purity convention in the
/// crate documentation).
///
/// # Used only for user-visible metadata
///
/// These timestamps take **no** part in deciding the winner of a sync merge. The merge
/// rule is "the originator version wins" and never compares timestamps, which would
/// require synchronized clocks - and the clock of an offline device is not trustworthy.
pub type Timestamp = u64;

/// What kind of one-time-password entry this is.
///
/// # Why the kind is a field of its own
///
/// The earlier model decided between TOTP and HOTP from `counter: Option<u64>`. That has room
/// for exactly two schemes and nowhere to put a PIN, so every additional scheme (mOTP, Yandex
/// OTP, Steam Guard) would have needed another field — and a parser that does not know a field
/// skips it by length, after which the entry looks like a plain TOTP entry whose code never
/// works. One tagged field makes the scheme explicit, and the file format version was raised
/// so that an older parser refuses such a file instead of guessing.
///
/// # What each variant carries
///
/// The time step lives in the variant that uses it, so "HOTP with a period" and "TOTP with a
/// counter" are not representable. Steam Guard's step is fixed by the scheme
/// ([`otp::STEAM_PERIOD`]) and is therefore not stored.
#[derive(Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// TOTP (RFC 6238): time-based, with the step in seconds.
    Totp {
        /// Time step in seconds. Never 0.
        period: u64,
    },
    /// HOTP (RFC 4226): counter-based, with the next counter value.
    Hotp {
        /// Next counter value. The caller advances it after a successful use.
        counter: u64,
    },
    /// mOTP: MD5-based, ten-second step, optional PIN.
    ///
    /// See [`crate::motp`]. A missing PIN is not a default: generating a code fails with
    /// [`Error::PinRequired`] rather than computing one from an empty string.
    Motp {
        /// Time step in seconds. Never 0.
        period: u64,
        /// User-entered PIN, mixed into the hash.
        pin: Option<crate::motp::MotpPin>,
    },
    /// Yandex OTP: SHA-256 based, eight letters, thirty-second step, optional PIN.
    ///
    /// See [`crate::yaotp`]. As with mOTP, a missing PIN fails code generation.
    Yandex {
        /// Time step in seconds. Never 0.
        period: u64,
        /// User-entered PIN, hashed together with the secret.
        pin: Option<crate::yaotp::YandexPin>,
    },
    /// Steam Guard: five characters from the Steam alphabet, fixed 30-second step.
    Steam,
}

impl EntryKind {
    /// The stored time step, where the variant has one.
    ///
    /// `None` for HOTP (counter-based) and Steam Guard (fixed step; see
    /// [`EntryKind::step_seconds`] for the effective value).
    #[must_use]
    pub const fn period(&self) -> Option<u64> {
        match self {
            Self::Totp { period } | Self::Motp { period, .. } | Self::Yandex { period, .. } => {
                Some(*period)
            }
            Self::Hotp { .. } | Self::Steam => None,
        }
    }

    /// Seconds between code changes, as a user interface needs it to know when to refresh.
    ///
    /// Unlike [`EntryKind::period`] this answers for every variant that has a time component:
    /// Steam Guard changes every [`otp::STEAM_PERIOD`] seconds even though the step is not
    /// stored. HOTP is the one variant with none, and it returns `None`.
    #[must_use]
    pub const fn step_seconds(&self) -> Option<u64> {
        match self {
            Self::Totp { period } | Self::Motp { period, .. } | Self::Yandex { period, .. } => {
                Some(*period)
            }
            Self::Steam => Some(otp::STEAM_PERIOD),
            Self::Hotp { .. } => None,
        }
    }

    /// The mOTP PIN, for a variant that has one.
    #[must_use]
    pub const fn motp_pin(&self) -> Option<&crate::motp::MotpPin> {
        match self {
            Self::Motp { pin, .. } => pin.as_ref(),
            _ => None,
        }
    }

    /// The Yandex OTP PIN, for a variant that has one.
    #[must_use]
    pub const fn yandex_pin(&self) -> Option<&crate::yaotp::YandexPin> {
        match self {
            Self::Yandex { pin, .. } => pin.as_ref(),
            _ => None,
        }
    }
}

/// One decrypted 2FA entry.
///
/// Every field is public. This is a plain data carrier with no invariant that
/// encapsulation would keep: validity is checked in [`Entry::new`] and during
/// deserialization, so getters would only add noise. The one distinction is `secret`,
/// whose type [`otp::OtpSecret`] offers neither `Clone` nor a plaintext `Debug` output,
/// so secret handling is enforced by the type rather than by visibility.
///
/// # Invariant: `issuer` is `None`, never `Some("")`
///
/// "No issuer" has exactly one representation, [`None`]. Allowing `Some("")` would give
/// an entry a state that does not survive a round trip: the storage format writes an
/// empty string as a zero-length node and reads it back as `None`, so writing and reading
/// back would yield an entry that differs from the original. That would not break
/// anything immediately, but comparisons such as "are these two vaults equivalent" would
/// give a wrong answer - and sync is built on exactly those comparisons. [`Entry::new`]
/// normalizes the value, so the invalid state cannot be constructed.
///
/// # Equality is hand-written, not derived
///
/// The `secret` field has type [`otp::OtpSecret`], which deliberately does not implement
/// `PartialEq`. Deriving it on `Entry` would require that implementation and turn
/// "compare two secrets with `==`" into a convenient operation - a non-constant-time
/// comparison that leaks the length of a matching prefix through timing.
///
/// To decide whether two entries are equivalent, compare field by field and handle the
/// secret with a constant-time primitive such as [`otp::verify_code`], or compare
/// [`otp::OtpSecret::to_base32`] (not constant time, but used only for tests and display,
/// never for an authentication decision).
#[derive(Debug)]
pub struct Entry {
    /// Display name. User-readable; need not relate to `issuer` or `account`.
    pub name: String,
    /// Issuer (the `issuer` of an `otpauth://` URI).
    pub issuer: Option<String>,
    /// Account name.
    pub account: String,
    /// OTP secret. The type guarantees it is neither printed nor cloned by accident.
    pub secret: otp::OtpSecret,
    /// HMAC algorithm.
    pub algorithm: otp::Algorithm,
    /// Number of digits in a code.
    pub digits: otp::Digits,
    /// Which scheme this entry uses, and the state that belongs to it.
    ///
    /// The time step, the HOTP counter and the PINs live here rather than in fields of their
    /// own, so an entry cannot be "TOTP with a counter" or "mOTP without a step".
    pub kind: EntryKind,
    /// Note from the user. May be empty.
    pub note: String,
    /// Creation time (Unix seconds).
    pub created_at: Timestamp,
    /// Last modification time (Unix seconds).
    pub updated_at: Timestamp,
}

impl PartialEq for Entry {
    /// Compares field by field, with the secret compared in constant time.
    ///
    /// # The order is deliberate
    ///
    /// Cheap fields that almost always differ (name, account, timestamps) come first and
    /// the secret comes last. The secret comparison is constant time (see the `PartialEq`
    /// of [`OtpSecret`](crate::otp::OtpSecret)), so it always reads every byte; going last
    /// means entry pairs whose names already differ are rejected at the first field and
    /// never pay that cost. The sync merge loop runs this check on thousands of entry
    /// pairs, and most pairs do not even share a name.
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.issuer == other.issuer
            && self.account == other.account
            && self.note == other.note
            && self.created_at == other.created_at
            && self.updated_at == other.updated_at
            && self.algorithm == other.algorithm
            && self.digits == other.digits
            && self.kind == other.kind
            && self.secret == other.secret
    }
}

impl Eq for Entry {}

impl Entry {
    /// Copies an entry with identical contents.
    ///
    /// Sync needs the copy in two places: presenting the peer version and the local
    /// version side by side to the adjudication UI (a conflict *is* two different
    /// versions), and storing the peer version in the local vault (a received entry is
    /// written to disk while also being recorded in the conflict record).
    /// [`OtpSecret`](crate::otp::OtpSecret) deliberately does not implement `Clone`, so
    /// the copy goes through this **explicit** entry point instead of a derived `Clone` on
    /// `Entry`: a call site must spell out `duplicate()`, which makes another copy of key
    /// material visible in review, whereas a derived `Clone` would let copies happen
    /// silently in any number of places.
    ///
    /// # Implementation
    ///
    /// A full encode/decode round trip rather than a field-by-field copy, so a newly added
    /// field needs no change here: a field-by-field copy that misses one shows up as "the
    /// new field is empty after syncing", a silent data loss that easily escapes tests. The
    /// cost is one encode/decode, on a user-triggered sync path rather than any hot path.
    /// The encoding and decoding functions are private items of the parent `vault` module.
    ///
    /// # Errors
    ///
    /// Fails only when the entry itself violates the format constraints (for example a
    /// field longer than [`Entry::MAX_FIELD_LEN`]). Constructing such an entry is already a
    /// bug.
    pub fn duplicate(&self) -> Result<Self> {
        let encoded = super::encode_entry(self)?;
        super::decode_entry(&encoded)
    }

    /// Size limit: maximum byte length of a single variable-length field.
    ///
    /// These fields become `String`s after decryption, and a ciphertext length has no
    /// natural bound - a constructed vault file can claim a 4 GiB name, which would eat all
    /// memory at decryption time. Noticing an over-long field **after** decrypting is too
    /// late, so the limit has to apply at allocation.
    ///
    /// 64 KiB far exceeds any real field (even a long account name or note rarely passes a
    /// few hundred bytes) and bounds the worst-case memory of a few hundred entries to
    /// something acceptable.
    pub const MAX_FIELD_LEN: usize = 64 * 1024;

    /// Maximum number of fields in an entry, used to bound the number of unknown nodes
    /// during parsing.
    ///
    /// The parser skips unknown nodes instead of failing (forward compatibility), and
    /// without a limit a file made entirely of unknown nodes would keep the skip loop
    /// running for a long time.
    pub const MAX_FIELDS: usize = 64;

    /// Constructs an entry.
    ///
    /// The empty-secret check is redundant with the guarantee of `OtpSecret` itself
    /// (`from_bytes` rejects empty input), but it stays so that the invariants of `Entry`
    /// do not depend on the behaviour of another type.
    ///
    /// # Errors
    ///
    /// - Empty secret -> [`Error::SecretEmpty`] (an empty secret is meaningless and would
    ///   make every code identical)
    /// - Any field longer than [`Entry::MAX_FIELD_LEN`] -> [`Error::FieldTooLong`]
    /// - A time step of 0 in a kind that carries one -> [`Error::InvalidPeriod`] (would
    ///   divide by zero)
    ///
    /// A secret shorter than the recommended length is **not** checked: short secrets exist
    /// in the real world and that is a warning rather than a refusal, see
    /// [`otp::recommended_min_secret_len`].
    ///
    /// # The kind is a value, not a pair of fields
    ///
    /// [`EntryKind`] carries the scheme together with the state that belongs to it, so
    /// "HOTP without a counter" and "TOTP with a counter" are not representable, and a PIN
    /// cannot end up on a scheme that has no place for it.
    ///
    /// # Ten parameters
    ///
    /// All ten are mandatory fields of the entry and none can be omitted or derived. A
    /// builder would turn "forgot to set a field" from a compile error into a runtime one,
    /// on cryptographic data where a silent default (a step of 0, an empty secret) is very
    /// hard to diagnose. The parameter list makes the type system enforce that every field
    /// is supplied.
    ///
    /// Callers rarely fill this list by hand: the QR path goes through
    /// [`entry_from_parsed_uri`] and the file path through
    /// [`crate::vault::VaultFile::parse`].
    #[expect(
        clippy::too_many_arguments,
        reason = "every parameter is a required field; a builder would trade compile-time guarantees for runtime defaults"
    )]
    pub fn new(
        name: String,
        issuer: Option<String>,
        account: String,
        secret: otp::OtpSecret,
        algorithm: otp::Algorithm,
        digits: otp::Digits,
        kind: EntryKind,
        note: String,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Result<Self> {
        if secret.len() == 0 {
            return Err(Error::SecretEmpty);
        }
        if kind.period() == Some(0) {
            return Err(Error::InvalidPeriod);
        }
        for (field, value) in [
            ("name", Some(&name)),
            ("issuer", issuer.as_ref()),
            ("account", Some(&account)),
            ("note", Some(&note)),
        ] {
            if let Some(value) = value
                && value.len() > Self::MAX_FIELD_LEN
            {
                return Err(Error::FieldTooLong {
                    field,
                    limit: Self::MAX_FIELD_LEN,
                    actual: value.len(),
                });
            }
        }
        Ok(Self {
            name,
            issuer: issuer.filter(|text| !text.is_empty()),
            account,
            secret,
            algorithm,
            digits,
            kind,
            note,
            created_at,
            updated_at,
        })
    }

    /// The `otpauth://` type that can express this entry, if any.
    ///
    /// [`None`] means the scheme has no URI representation in this library **yet** (mOTP,
    /// Yandex OTP and Steam Guard are stored and computed, but their URI forms are not
    /// implemented). Returning an option rather than a default keeps a caller from silently
    /// writing an mOTP entry out as TOTP, which is a code that never works.
    #[must_use]
    pub const fn uri_type(&self) -> Option<crate::uri::UriType> {
        match self.kind {
            EntryKind::Totp { .. } => Some(crate::uri::UriType::Totp),
            EntryKind::Hotp { .. } => Some(crate::uri::UriType::Hotp),
            EntryKind::Motp { .. } | EntryKind::Yandex { .. } | EntryKind::Steam => None,
        }
    }
}

/// Builds an entry from a parsed `otpauth://` result.
///
/// This is the step joining a scanned QR configuration to the storage model of this
/// library. `now` is the current Unix second supplied by the caller (this library reads no
/// clock) and is used as both the creation and the modification time.
///
/// # Errors
///
/// The same checks as [`Entry::new`], so a URI that parsed normally does not fail here:
/// `uri::parse` already guarantees a non-empty secret and a non-zero `period`. Both checks
/// are kept so that the invariants of [`Entry`] do not depend on the order of calls.
pub fn entry_from_parsed_uri(parsed: &crate::uri::OtpAuth, now: Timestamp) -> Result<Entry> {
    let secret = otp::OtpSecret::from_base32(&parsed.secret.to_base32())?;
    let name = match &parsed.issuer {
        Some(issuer) => format!("{issuer}:{}", parsed.account),
        None => parsed.account.clone(),
    };
    Entry::new(
        name,
        parsed.issuer.clone(),
        parsed.account.clone(),
        secret,
        parsed.algorithm,
        parsed.digits,
        match parsed.uri_type {
            crate::uri::UriType::Totp => EntryKind::Totp {
                period: parsed.period,
            },
            crate::uri::UriType::Hotp => EntryKind::Hotp {
                counter: parsed.counter.ok_or(Error::UriMissingCounter)?,
            },
        },
        String::new(),
        now,
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secret() -> otp::OtpSecret {
        otp::OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("valid secret")
    }

    fn sample_entry() -> Entry {
        Entry::new(
            "GitHub".into(),
            Some("GitHub".into()),
            "alice".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::SIX,
            EntryKind::Totp { period: 30 },
            String::new(),
            1_700_000_000,
            1_700_000_000,
        )
        .expect("valid entry")
    }

    #[test]
    fn entry_id_is_16_bytes_and_hex_displayed() {
        let id = EntryId::generate().expect("OS randomness available");
        assert_eq!(id.as_bytes().len(), 16);
        let text = id.to_string();
        assert_eq!(text.len(), 32, "hexadecimal must be 32 characters: {text}");
        assert!(text.chars().all(|c| c.is_ascii_hexdigit()));

        assert_eq!(format!("{id:?}"), format!("EntryId({text})"));
    }

    #[test]
    fn entry_id_generation_does_not_repeat() {
        let ids: Vec<_> = (0..64)
            .map(|_| EntryId::generate().expect("OS randomness available"))
            .collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "random IDs repeated");
    }

    #[test]
    fn rejects_empty_secret() {
        let empty = otp::OtpSecret::from_bytes(Vec::new());
        assert!(matches!(empty, Err(Error::SecretEmpty)));
    }

    #[test]
    fn rejects_zero_period() {
        for kind in [
            EntryKind::Totp { period: 0 },
            EntryKind::Motp {
                period: 0,
                pin: None,
            },
            EntryKind::Yandex {
                period: 0,
                pin: None,
            },
        ] {
            let err = Entry::new(
                "x".into(),
                None,
                "a".into(),
                sample_secret(),
                otp::Algorithm::Sha1,
                otp::Digits::SIX,
                kind,
                String::new(),
                0,
                0,
            );
            assert!(
                matches!(err, Err(Error::InvalidPeriod)),
                "a zero step must be rejected"
            );
        }
    }

    #[test]
    fn rejects_oversized_field() {
        let err = Entry::new(
            "x".repeat(Entry::MAX_FIELD_LEN + 1),
            None,
            "a".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::SIX,
            EntryKind::Totp { period: 30 },
            String::new(),
            0,
            0,
        );
        match err {
            Err(Error::FieldTooLong { field, .. }) => assert_eq!(field, "name"),
            other => panic!("an over-long field must be rejected, actual {other:?}"),
        }
    }

    /// **Invariant test**: an empty issuer is normalized to `None` by the constructor, while
    /// a whitespace-only issuer is preserved as user-visible content.
    #[test]
    fn empty_issuer_is_normalized_to_none() {
        let entry = Entry::new(
            "x".into(),
            Some(String::new()),
            "a".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::SIX,
            EntryKind::Totp { period: 30 },
            String::new(),
            0,
            0,
        )
        .expect("the remaining fields are valid");
        assert_eq!(entry.issuer, None, "an empty issuer must normalize to None");

        let blank = Entry::new(
            "x".into(),
            Some("   ".into()),
            "a".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::SIX,
            EntryKind::Totp { period: 30 },
            String::new(),
            0,
            0,
        )
        .expect("the remaining fields are valid");
        assert_eq!(blank.issuer.as_deref(), Some("   "));
    }

    /// Every kind whose scheme has an `otpauth://` form maps to it; the others report `None`
    /// rather than silently claiming to be TOTP.
    #[test]
    fn uri_type_covers_totp_and_hotp_only() {
        assert_eq!(
            sample_entry().uri_type(),
            Some(crate::uri::UriType::Totp),
            "a TOTP entry"
        );

        let hotp = Entry::new(
            "h".into(),
            None,
            "a".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::SIX,
            EntryKind::Hotp { counter: 7 },
            String::new(),
            0,
            0,
        )
        .expect("valid entry");
        assert_eq!(hotp.uri_type(), Some(crate::uri::UriType::Hotp));
        assert_eq!(hotp.kind, EntryKind::Hotp { counter: 7 });

        for kind in [
            EntryKind::Motp {
                period: 10,
                pin: None,
            },
            EntryKind::Yandex {
                period: 30,
                pin: None,
            },
            EntryKind::Steam,
        ] {
            let entry = Entry::new(
                "k".into(),
                None,
                "a".into(),
                sample_secret(),
                otp::Algorithm::Sha1,
                otp::Digits::SIX,
                kind,
                String::new(),
                0,
                0,
            )
            .expect("valid entry");
            assert_eq!(
                entry.uri_type(),
                None,
                "this scheme has no URI form yet, and must not claim TOTP"
            );
        }
    }

    /// `step_seconds` answers for every kind that changes with time, including the one whose
    /// step is fixed by the scheme rather than stored.
    #[test]
    fn step_seconds_covers_every_kind() {
        assert_eq!(EntryKind::Totp { period: 45 }.step_seconds(), Some(45));
        assert_eq!(
            EntryKind::Motp {
                period: 10,
                pin: None
            }
            .step_seconds(),
            Some(10)
        );
        assert_eq!(
            EntryKind::Yandex {
                period: 30,
                pin: None
            }
            .step_seconds(),
            Some(30)
        );
        assert_eq!(EntryKind::Steam.step_seconds(), Some(otp::STEAM_PERIOD));
        assert_eq!(EntryKind::Hotp { counter: 0 }.step_seconds(), None);

        // `period` reports only what is stored, so Steam Guard answers `None` here.
        assert_eq!(EntryKind::Steam.period(), None);
        assert_eq!(EntryKind::Hotp { counter: 3 }.period(), None);
    }

    /// The PINs are reachable through the kind, and only through the variant that has one.
    #[test]
    fn pins_are_reachable_through_the_kind() {
        let motp = EntryKind::Motp {
            period: 10,
            pin: Some(crate::motp::MotpPin::new("1234".to_owned())),
        };
        let yandex = EntryKind::Yandex {
            period: 30,
            pin: Some(crate::yaotp::YandexPin::new("7586".to_owned())),
        };
        assert_eq!(motp.motp_pin().map(crate::motp::MotpPin::len), Some(4));
        assert_eq!(motp.yandex_pin(), None);
        assert_eq!(
            yandex.yandex_pin().map(crate::yaotp::YandexPin::len),
            Some(4)
        );
        assert_eq!(yandex.motp_pin(), None);
        assert_eq!(EntryKind::Steam.motp_pin(), None);
        assert_eq!(EntryKind::Steam.yandex_pin(), None);
    }

    /// Two entries that differ only in their PIN or their step are different entries, which
    /// is what the sync merge compares.
    #[test]
    fn kind_equality_distinguishes_state_that_affects_the_code() {
        let base = EntryKind::Motp {
            period: 10,
            pin: Some(crate::motp::MotpPin::new("1234".to_owned())),
        };
        let other_pin = EntryKind::Motp {
            period: 10,
            pin: Some(crate::motp::MotpPin::new("1235".to_owned())),
        };
        let no_pin = EntryKind::Motp {
            period: 10,
            pin: None,
        };
        let other_period = EntryKind::Motp {
            period: 20,
            pin: Some(crate::motp::MotpPin::new("1234".to_owned())),
        };

        assert_eq!(
            base,
            EntryKind::Motp {
                period: 10,
                pin: Some(crate::motp::MotpPin::new("1234".to_owned())),
            }
        );
        assert_ne!(base, other_pin);
        assert_ne!(base, no_pin);
        assert_ne!(base, other_period);
        assert_ne!(base, EntryKind::Hotp { counter: 10 });
    }

    /// `Debug` must not contain the secret.
    #[test]
    fn debug_does_not_leak_secret() {
        let entry = sample_entry();
        let debug = format!("{entry:?}");
        assert!(
            debug.contains("GitHub"),
            "non-secret fields must appear as usual: {debug}"
        );
        assert!(
            debug.contains("alice"),
            "non-secret fields must appear as usual: {debug}"
        );

        let base32 = entry.secret.to_base32();
        assert!(
            !debug.contains(&base32),
            "Debug leaked the Base32 secret: {debug}"
        );
        assert!(
            !debug.contains("JBSWY3DP"),
            "Debug leaked the secret: {debug}"
        );
    }

    #[test]
    fn convert_from_parsed_uri() {
        let parsed =
            crate::uri::parse("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
                .expect("valid URI");
        let entry = entry_from_parsed_uri(&parsed, 1_700_000_000).expect("conversion succeeds");
        assert_eq!(entry.issuer.as_deref(), Some("GitHub"));
        assert_eq!(entry.account, "alice");
        assert_eq!(entry.name, "GitHub:alice");
        assert_eq!(entry.uri_type(), Some(crate::uri::UriType::Totp));
        assert!(entry.note.is_empty());
        assert_eq!(entry.created_at, 1_700_000_000);
        assert_eq!(entry.created_at, entry.updated_at);

        assert_eq!(
            entry.secret.to_base32(),
            parsed.secret.to_base32(),
            "the secret changed after conversion"
        );
    }
}
