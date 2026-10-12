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
//! secret, algorithm, digits, period or counter, note, and the creation and modification
//! timestamps.
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
    /// Time step of TOTP (seconds). An HOTP entry ignores this field.
    pub period: u64,
    /// Counter of HOTP. `None` for a TOTP entry.
    pub counter: Option<u64>,
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
            && self.period == other.period
            && self.counter == other.counter
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
    /// - `period` of 0 -> [`Error::InvalidPeriod`] (would divide by zero)
    ///
    /// A secret shorter than the recommended length is **not** checked: short secrets exist
    /// in the real world and that is a warning rather than a refusal, see
    /// [`otp::recommended_min_secret_len`].
    ///
    /// # The entry type follows `counter`
    ///
    /// `Some` means HOTP and `None` means TOTP (see [`Entry::uri_type`]). There is no
    /// separate requirement that an HOTP entry supply a counter: `None` already reads as
    /// TOTP, so "HOTP without a counter" is not a state.
    ///
    /// # Eleven parameters
    ///
    /// All eleven are mandatory fields of the entry and none can be omitted or derived. A
    /// builder would turn "forgot to set a field" from a compile error into a runtime one,
    /// on cryptographic data where a silent default (`period` 0, an empty secret) is very
    /// hard to diagnose. The parameter list makes the type system enforce that every field
    /// is supplied.
    ///
    /// Callers rarely fill this list by hand: the QR path goes through
    /// [`entry_from_parsed_uri`] and the file path through
    /// [`crate::vault::VaultFile::parse`].
    #[expect(
        clippy::too_many_arguments,
        reason = "全部参数都是必填字段；改用 builder 会把编译期保证换成运行时默认值"
    )]
    pub fn new(
        name: String,
        issuer: Option<String>,
        account: String,
        secret: otp::OtpSecret,
        algorithm: otp::Algorithm,
        digits: otp::Digits,
        period: u64,
        counter: Option<u64>,
        note: String,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Result<Self> {
        if secret.len() == 0 {
            return Err(Error::SecretEmpty);
        }
        if period == 0 {
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
            period,
            counter,
            note,
            created_at,
            updated_at,
        })
    }

    /// Whether the entry is HOTP or TOTP.
    ///
    /// The presence of `counter` decides it, that being the **structural** difference
    /// between the two: TOTP derives its counter from time, while an HOTP counter must come
    /// from the user or from sync state.
    #[must_use]
    pub const fn uri_type(&self) -> crate::uri::UriType {
        if self.counter.is_some() {
            crate::uri::UriType::Hotp
        } else {
            crate::uri::UriType::Totp
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
        parsed.period,
        parsed.counter,
        String::new(),
        now,
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secret() -> otp::OtpSecret {
        otp::OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("合法种子")
    }

    fn sample_entry() -> Entry {
        Entry::new(
            "GitHub".into(),
            Some("GitHub".into()),
            "alice".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::Six,
            30,
            None,
            String::new(),
            1_700_000_000,
            1_700_000_000,
        )
        .expect("合法条目")
    }

    #[test]
    fn entry_id_is_16_bytes_and_hex_displayed() {
        let id = EntryId::generate().expect("OS 随机源可用");
        assert_eq!(id.as_bytes().len(), 16);
        let text = id.to_string();
        assert_eq!(text.len(), 32, "十六进制应为 32 字符：{text}");
        assert!(text.chars().all(|c| c.is_ascii_hexdigit()));

        assert_eq!(format!("{id:?}"), format!("EntryId({text})"));
    }

    #[test]
    fn entry_id_generation_does_not_repeat() {
        let ids: Vec<_> = (0..64)
            .map(|_| EntryId::generate().expect("OS 随机源可用"))
            .collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "随机 ID 出现重复");
    }

    #[test]
    fn rejects_empty_secret() {
        let empty = otp::OtpSecret::from_bytes(Vec::new());
        assert!(matches!(empty, Err(Error::SecretEmpty)));
    }

    #[test]
    fn rejects_zero_period() {
        let err = Entry::new(
            "x".into(),
            None,
            "a".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::Six,
            0,
            None,
            String::new(),
            0,
            0,
        );
        assert!(matches!(err, Err(Error::InvalidPeriod)));
    }

    #[test]
    fn rejects_oversized_field() {
        let err = Entry::new(
            "x".repeat(Entry::MAX_FIELD_LEN + 1),
            None,
            "a".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::Six,
            30,
            None,
            String::new(),
            0,
            0,
        );
        match err {
            Err(Error::FieldTooLong { field, .. }) => assert_eq!(field, "name"),
            other => panic!("应拒绝超长字段，实际 {other:?}"),
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
            otp::Digits::Six,
            30,
            None,
            String::new(),
            0,
            0,
        )
        .expect("其余字段合法");
        assert_eq!(entry.issuer, None, "空发行方应归一为 None");

        let blank = Entry::new(
            "x".into(),
            Some("   ".into()),
            "a".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::Six,
            30,
            None,
            String::new(),
            0,
            0,
        )
        .expect("其余字段合法");
        assert_eq!(blank.issuer.as_deref(), Some("   "));
    }

    #[test]
    fn uri_type_follows_counter_presence() {
        let totp = sample_entry();
        assert_eq!(totp.uri_type(), crate::uri::UriType::Totp);

        let hotp = Entry::new(
            "h".into(),
            None,
            "a".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::Six,
            30,
            Some(7),
            String::new(),
            0,
            0,
        )
        .expect("合法条目");
        assert_eq!(hotp.uri_type(), crate::uri::UriType::Hotp);
        assert_eq!(hotp.counter, Some(7));
    }

    /// `Debug` must not contain the secret.
    #[test]
    fn debug_does_not_leak_secret() {
        let entry = sample_entry();
        let debug = format!("{entry:?}");
        assert!(debug.contains("GitHub"), "非秘密字段应正常：{debug}");
        assert!(debug.contains("alice"), "非秘密字段应正常：{debug}");

        let base32 = entry.secret.to_base32();
        assert!(
            !debug.contains(&base32),
            "Debug 泄露了种子的 Base32：{debug}"
        );
        assert!(!debug.contains("JBSWY3DP"), "Debug 泄露了种子：{debug}");
    }

    #[test]
    fn convert_from_parsed_uri() {
        let parsed =
            crate::uri::parse("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
                .expect("合法 URI");
        let entry = entry_from_parsed_uri(&parsed, 1_700_000_000).expect("可转换");
        assert_eq!(entry.issuer.as_deref(), Some("GitHub"));
        assert_eq!(entry.account, "alice");
        assert_eq!(entry.name, "GitHub:alice");
        assert_eq!(entry.uri_type(), crate::uri::UriType::Totp);
        assert!(entry.note.is_empty());
        assert_eq!(entry.created_at, 1_700_000_000);
        assert_eq!(entry.created_at, entry.updated_at);

        assert_eq!(
            entry.secret.to_base32(),
            parsed.secret.to_base32(),
            "转换后种子发生了变化"
        );
    }
}
