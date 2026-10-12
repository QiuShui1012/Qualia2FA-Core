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

//! Error types.
//!
//! Every public function of this library returns [`Result`], and **no input may cause a
//! panic**.
//!
//! # Secret-handling discipline
//!
//! Error values **never carry secret material**: no raw input, no key bytes, no OTP code. The
//! variants in this module record only which class of input was invalid plus the **non-secret**
//! numbers needed to locate the problem (lengths, positions), so a caller can diagnose it
//! without the value leaking.

use thiserror::Error;

/// The unified error type of this library.
///
/// The enum is `#[non_exhaustive]`, so a `match` outside this crate must have a wildcard arm,
/// and adding a variant is not a breaking change for downstream code. Variants are added as
/// the library grows.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A failure reported by the device identity crate.
    ///
    /// # Why this wraps the foreign error instead of copying its variants
    ///
    /// Device identity (public key representation, fingerprints, signature verification and
    /// the platform key store) lives in [`qualia_dik`](https://docs.rs/qualia-dik), an
    /// independently reusable crate. This crate needs **the same** failure classification, not
    /// a look-alike one of its own.
    ///
    /// Copying the variants would let the two enums drift: the other crate gains a
    /// `HardwareUnavailable`, this one forgets it, and "no TPM" reaches Core callers through a
    /// silent `_ =>` wildcard arm. Wrapping makes the compiler point out every new variant that
    /// needs handling when the dependency is upgraded.
    ///
    /// The `source()` chain also shows that the failure came from the device identity crate,
    /// instead of flattening it into a local `reason` string.
    #[error(transparent)]
    Device(#[from] qualia_dik::Error),

    /// The Base32 input contains a character outside the alphabet.
    ///
    /// Only the **position** is reported, never the character at that position, so that input
    /// content (which may come from a key) does not reach the logs.
    #[error("Base32 输入在第 {index} 个字符处含非法字符")]
    Base32InvalidCharacter {
        /// Position of the invalid character in the character sequence **after ASCII whitespace
        /// has been removed**.
        ///
        /// It is not a raw byte offset because users often paste seeds from a web page with
        /// spaces or line breaks, and "which valid character" locates the problem more easily
        /// than "which byte".
        index: usize,
    },

    /// The Base32 input length (after padding is stripped) is not a valid remainder modulo 8.
    ///
    /// The only valid Base32 length remainders are 0, 2, 4, 5 and 7.
    #[error("Base32 长度非法：{length} 个有效字符")]
    Base32InvalidLength {
        /// Number of valid characters after padding is removed.
        length: usize,
    },

    /// Corrupt Base32 encoding: the unused bits of the last character are not zero.
    ///
    /// This is not a padding-format problem — padding itself may be absent or present (both are
    /// accepted). It means the encoded data itself is corrupt, for example significant bits
    /// written into padding bits that must be zero.
    #[error("Base32 编码尾部残留比特非零，数据已损坏")]
    Base32InvalidPadding,

    /// The OTP secret is empty.
    ///
    /// Kept separate from [`Error::SecretTooShort`]: an empty seed is a **structural** problem
    /// (the URI has no `secret` at all, or Base32 decodes to nothing), while a short seed is a
    /// **strength** problem. The former must be rejected, the latter is a UI warning — merging
    /// them leaves the caller unable to tell the two apart.
    #[error("OTP 密钥为空")]
    SecretEmpty,

    /// The OTP secret is shorter than the minimum required by the selected algorithm.
    ///
    /// **Note**: this library currently rejects only empty secrets and never returns this error
    /// for a short one. HMAC accepts keys of any length and short seeds exist in the real world;
    /// a short seed is a **warning** to be surfaced by the UI, see
    /// `otp::recommended_min_secret_len`.
    #[error("OTP 密钥过短：需要至少 {required} 字节，实际 {actual} 字节")]
    SecretTooShort {
        /// Minimum seed length in bytes required by RFC 6238 for this algorithm.
        required: usize,
        /// Actual length in bytes. The length itself is not a secret.
        actual: usize,
    },

    /// The `algorithm` parameter of an `otpauth://` URI is not recognized.
    ///
    /// **Rejected rather than falling back to SHA-1**: a silent fallback gives the user a code
    /// that is consistently wrong, with nothing in the error to trace it back.
    #[error("不支持的算法：{name}")]
    UnsupportedAlgorithm {
        /// The raw parameter value, truncated to at most 16 characters.
        ///
        /// Truncation is required: the value comes from an attacker-controlled URI, and
        /// arbitrary-length input must not be carried into the logs verbatim.
        name: String,
    },

    /// The `digits` parameter of an `otpauth://` URI is outside the supported range.
    ///
    /// Only 6, 7 and 8 are accepted. Validation must be strict — any other value overflows
    /// `10^digits`.
    #[error("不支持的位数：{value}（只接受 6、7、8）")]
    UnsupportedDigits {
        /// The raw parameter value, truncated to at most 16 characters.
        value: String,
    },

    /// The TOTP `period` is 0, which would cause a division by zero.
    #[error("TOTP 周期不能为 0")]
    InvalidPeriod,

    /// Cryptographic random bytes cannot be obtained from the operating system.
    ///
    /// This is an **unrecoverable** failure: the library deliberately uses no user-space PRNG as
    /// a fallback, because a deterministic seed makes independently generated keys collide.
    /// Failing the operation and letting the user retry is preferable to silently switching to a
    /// weak random source.
    ///
    /// Triggered when the `getrandom` backend is unavailable on the target platform (a
    /// restricted sandbox, a missing syscall, or a kernel entropy source that failed to
    /// initialize).
    ///
    /// **It carries no `getrandom::Error` detail**: that type's internal representation differs
    /// across versions and platforms and offers the caller nothing actionable — retrying or
    /// telling the user is all that can be done.
    #[error("无法从操作系统取得安全随机数")]
    RandomnessUnavailable,

    /// The URI scheme is not `otpauth`.
    #[error("URI 的 scheme 不是 otpauth")]
    UriUnsupportedScheme,

    /// The URI has no type component (no `/` after `otpauth://`).
    #[error("URI 缺少类型段（应为 totp 或 hotp）")]
    UriMissingType,

    /// The URI type is neither `totp` nor `hotp`.
    #[error("不支持的 URI 类型：{name}")]
    UriUnsupportedType {
        /// The raw type component, truncated to at most 16 characters.
        name: String,
    },

    /// The URI has no `secret` parameter.
    #[error("URI 缺少必需的 secret 参数")]
    UriMissingSecret,

    /// The HOTP URI has no `counter` parameter.
    #[error("HOTP 的 URI 缺少必需的 counter 参数")]
    UriMissingCounter,

    /// A TOTP URI carries a `counter` parameter.
    ///
    /// Rejected rather than ignored: such a URI signals a faulty generator, and ignoring it
    /// hands the user an entry that looks normal but means something else.
    #[error("TOTP 的 URI 不应包含 counter 参数")]
    UriUnexpectedCounter,

    /// The URI contains a known parameter more than once.
    ///
    /// Implementations disagree on whether the first or the last occurrence wins: a classic
    /// parsing ambiguity, and an attack surface.
    #[error("URI 含重复参数：{name}")]
    UriDuplicateParameter {
        /// The duplicated parameter name (truncated to 16 characters).
        name: String,
    },

    /// A URI parameter value is invalid.
    #[error("URI 参数 {name} 非法：{reason}")]
    UriInvalidParameter {
        /// Parameter name.
        name: String,
        /// Reason that does not include the full raw value (the value itself is truncated).
        reason: String,
    },

    /// The percent encoding in the URI is malformed.
    #[error("URI 含非法的百分号编码（% 后必须跟两个十六进制数字）")]
    UriInvalidPercentEncoding,

    /// The issuer in the label and the `issuer` parameter disagree.
    ///
    /// Rejected: two different issuers mean the URI was assembled or tampered with, and silently
    /// picking one would bind an entry's codes to the wrong service.
    #[error("issuer 冲突：label 里是 {in_label}，参数里是 {in_parameter}")]
    UriIssuerMismatch {
        /// The issuer from the label prefix (truncated).
        in_label: String,
        /// The value from the `issuer` parameter (truncated).
        in_parameter: String,
    },

    /// The account name in the URI label contains `:`.
    ///
    /// The label uses `:` to separate issuer from account, so a `:` inside the account name
    /// cannot be told apart from the separator and creates round-trip ambiguity: after a
    /// serialize-then-parse cycle, the ownership of issuer and account changes **silently**.
    /// Percent encoding does not help — `%3A` and a literal `:` are indistinguishable once
    /// decoded.
    ///
    /// Both parsing and serialization therefore reject it, enforcing the invariant.
    #[error("账号名不能包含冒号（会与 issuer 分隔符混淆）：{account}")]
    UriAccountContainsColon {
        /// The account name, truncated to 32 characters.
        account: String,
    },

    /// The vault file is shorter than its declared structure, or the structure is cut off here.
    ///
    /// The most common structural problem: the file was truncated, or a length field claims more
    /// bytes than actually remain.
    #[error("保险库文件不完整或被截断")]
    VaultTruncated,

    /// The magic number at the start of the vault file does not match.
    ///
    /// It means this is not a vault file (the wrong file was picked, or the file was replaced
    /// with something else).
    #[error("不是 Qualia2FA 保险库文件")]
    VaultBadMagic,

    /// The vault file format version is not supported by this build.
    #[error("不支持的保险库格式版本：{version}")]
    VaultUnsupportedVersion {
        /// Version declared in the file.
        version: u8,
    },

    /// The reserved byte in the vault file header is not 0.
    ///
    /// Reserved bytes exist precisely so that they may become non-zero later. The current
    /// version must reject a non-zero value: it means the file was written by a newer version
    /// that may have given the byte a meaning this version does not know, and reading on would
    /// parse it under wrong assumptions.
    #[error("保险库保留字节应为 0，实际为 {value}")]
    VaultReservedByteNotZero {
        /// Actual value in the file.
        value: u8,
    },

    /// The record kind byte in the vault file is not recognized.
    ///
    /// **Not treated as a live entry**: guessing that an unknown kind "is probably an entry"
    /// would let a tombstone written by a future version come back to life as an entry here.
    #[error("无法识别的保险库记录种类：{value}")]
    VaultUnknownRecordKind {
        /// Actual value in the file.
        value: u8,
    },

    /// A single record exceeds the length limit.
    ///
    /// The limit exists to reject a malicious file claiming to hold 4 GiB and to avoid allocating
    /// huge buffers for untrusted input. This is therefore a **structural** problem, not the
    /// business problem of "an entry that is too large".
    #[error("保险库记录过长：上限 {limit} 字节，实际声明 {actual} 字节")]
    VaultRecordTooLong {
        /// Allowed limit.
        limit: usize,
        /// Length declared in the file.
        actual: usize,
    },

    /// The vault holds more records than the limit allows.
    #[error("保险库记录数超出上限（最多 {})", crate::vault::MAX_RECORDS)]
    VaultTooManyRecords,

    /// The vault file has extra bytes at the end.
    ///
    /// **Rejected rather than ignored**: extra bytes mean content was appended and this version
    /// cannot explain what it is. Ignoring them would make the fact that the file was modified
    /// disappear.
    #[error("保险库文件末尾有多余的 {count} 字节")]
    VaultTrailingBytes {
        /// Number of extra bytes.
        count: usize,
    },

    /// The same `entry_id` appears twice in the vault file.
    ///
    /// **Rejected rather than overwritten**: a duplicate ID means the file was crafted or
    /// corrupted. Silently keeping one of them makes the user lose a 2FA entry, showing up as
    /// "one code suddenly stopped working" — extremely hard to trace.
    #[error("保险库文件含重复的条目 ID")]
    VaultDuplicateEntryId,

    /// The master key check value in the file has the wrong structure (length mismatch).
    ///
    /// Strictly separated from [`Error::VaultDecryptionFailed`]: **this one is a structural
    /// problem, that one means a wrong key or a modified file**. Merging the two reports a
    /// crafted file as "your key is wrong", sending the user to compare keys when the problem is
    /// somewhere else entirely.
    ///
    /// The check value is a fixed-length plaintext field, so a length mismatch means the file was
    /// truncated, appended to, or never written in the format at all — all three mean "this file
    /// is untrustworthy", not "wrong key".
    #[error("保险库文件的主密钥检查值长度不对")]
    VaultBadKeyCheck,

    /// No entry with this identifier exists.
    ///
    /// Different from "the vault is empty": the caller named one specific entry and it is not
    /// there. The layer above must tell two UI actions apart — "the list is empty, invite the
    /// user to add an entry" versus "the entry you were working on is gone, refresh the list".
    /// Treating the latter as the former shows an empty list while the user was just looking at
    /// the entry.
    ///
    /// A common cause is synchronization having deleted the entry on the other device while this
    /// one still holds its identifier.
    #[error("保险库里没有这条条目")]
    VaultEntryNotFound,

    /// The plaintext structure of a vault entry contains a duplicated field node.
    ///
    /// Implementations disagree on whether the first or the last occurrence wins: a classic
    /// parsing ambiguity, and an attack surface — an attacker can append an overriding node after
    /// a legitimate one.
    #[error("保险库条目含重复字段（标签 {tag:#04x}）")]
    VaultDuplicateField {
        /// The field tag that appears more than once.
        tag: u8,
    },

    /// The plaintext structure of a vault entry is corrupt (missing required field, wrong field
    /// length, and so on).
    ///
    /// Note that this error can only occur **after authentication has succeeded** — the AEAD tag
    /// covers the whole plaintext, so successful decryption means the plaintext is the one that
    /// was written. Reaching it means the writing side produced an invalid structure (a bug in
    /// this library), or the key comes from an implementation of another version. **A parser
    /// called directly with arbitrary plaintext can trigger it as well**, since such a call
    /// bypasses the AEAD.
    #[error("保险库条目结构损坏")]
    VaultCorrupt,

    /// A text field of a vault entry is not valid UTF-8.
    ///
    /// **Rejected rather than lossily replaced**: replacement turns corrupt data into an entry
    /// that looks normal but has different content, and the user never learns that the account
    /// name was changed.
    #[error("保险库条目的文本字段不是合法 UTF-8")]
    VaultInvalidUtf8,

    /// Vault decryption or authentication failed.
    ///
    /// **It does not distinguish** a wrong master key, tampered ciphertext and an AAD mismatch,
    /// for two reasons:
    ///
    /// - **Useful to an attacker**: telling them apart is an oracle that reveals whether a
    ///   guessed key is correct, or which part was modified.
    /// - **Useless to the user**: all three call for exactly the same action — this vault cannot
    ///   be opened.
    ///
    /// Whether the wrong master key was picked is something the layer above decides from where
    /// the key came from; the cryptographic layer need not leak anything for that.
    #[error("保险库无法解密：主密钥不匹配或文件已被篡改")]
    VaultDecryptionFailed,

    /// The master key has the wrong length.
    #[error("主密钥长度应为 {expected} 字节，实际 {actual} 字节")]
    MasterKeyWrongLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// A variable-length field of a vault entry exceeds the limit.
    ///
    /// The limit cannot be enforced **before** decryption from the ciphertext length (that length
    /// says nothing about the field length), so it must be checked while parsing after
    /// decryption. See [`crate::vault::Entry::MAX_FIELD_LEN`].
    #[error("字段 {field} 过长：上限 {limit} 字节，实际 {actual} 字节")]
    FieldTooLong {
        /// Field name (a fixed string, never user data).
        field: &'static str,
        /// Allowed limit.
        limit: usize,
        /// Actual length.
        actual: usize,
    },

    /// Reading or writing a vault file failed.
    ///
    /// It carries only the **operating system error description**, never file content — `reason`
    /// comes from `std::io::Error`, which does not include the bytes that were written.
    #[error("保险库文件读写失败：{reason}")]
    VaultIo {
        /// Operating system error description.
        reason: String,
    },

    /// A device identity public key is invalid.
    ///
    /// Public keys come from external input (QR codes, the network) and must be validated before
    /// use. **Invalid-curve attacks** are real: handing over a point that is not on the curve but
    /// lies in a small subgroup can leak private-key information through the peer's computation.
    /// This error is therefore part of the security boundary, not a format check.
    ///
    /// `reason` is a fixed internal description and **contains no raw input bytes** — they may
    /// come from an attacker, and putting them into an error message turns logs into an injection
    /// point.
    #[error("设备公钥非法：{reason}")]
    DevicePublicKeyInvalid {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// A device identity signature is malformed or fails verification.
    ///
    /// **A malformed signature and a failed verification deliberately share this variant.** The
    /// caller's response is identical (reject this authentication), and telling them apart would
    /// only give an attacker a small oracle.
    #[error("设备签名无效：{reason}")]
    DeviceSignatureInvalid {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// The pairing payload (QR code content) is structurally invalid.
    ///
    /// Separate from [`Error::PairingUnsupportedVersion`]: a wrong length or a missing required
    /// field is damage **this version can judge**, whereas an unrecognized version is something
    /// this version **cannot read**. For the user the advice differs — "regenerate the QR code"
    /// versus "upgrade the app" — so the two are not merged.
    ///
    /// `reason` is a fixed internal description and **contains no input bytes**: QR code content
    /// may come from an attacker.
    #[error("配对载荷非法：{reason}")]
    PairingPayloadMalformed {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// The pairing payload protocol version is not supported.
    ///
    /// It must be **rejected outright** rather than interpreted as best as possible: reading a
    /// future version's fields under this version's layout would turn a "this operation is
    /// forbidden" written by the future version into "allowed".
    #[error("配对协议版本不受支持：{version}")]
    PairingUnsupportedVersion {
        /// Version declared in the payload.
        version: u8,
    },

    /// Pairing message authentication failed.
    ///
    /// **Tampered ciphertext, a wrong tag, a message from another session and a joiner using the
    /// wrong public key** deliberately share this variant. The caller's response is identical
    /// (this pairing failed, scan the code again), and telling them apart would give an attacker
    /// an oracle to probe with.
    #[error("配对消息认证失败：密文被篡改、或不属于本次配对")]
    PairingAuthenticationFailed,

    /// The recovery file structure is invalid.
    ///
    /// Separate from [`Error::RecoveryAuthenticationFailed`] because the two mean completely
    /// different things to the **user**: this variant says "wrong file / broken file", while that
    /// one says "wrong passphrase". Merging them makes the user retry the passphrase in a
    /// direction where retrying cannot help.
    ///
    /// `reason` is a fixed internal description and **contains no input bytes**.
    #[error("恢复文件非法：{reason}")]
    RecoveryFileMalformed {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// The derivation parameters of the recovery file are invalid.
    ///
    /// These parameters **come from the file itself** and are therefore untrusted input. Without
    /// this validation, a file edited to say `m_cost = u32::MAX` would turn an import into a
    /// memory-exhaustion attack.
    #[error("恢复文件的派生参数非法：{reason}")]
    RecoveryParametersInvalid {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// The passphrase is empty.
    ///
    /// **Rejected outright rather than accepted as a weak passphrase**: accepting it would hand
    /// the user, behind a screen that looks successful, a backup that can be opened in about a
    /// second.
    #[error("恢复口令不得为空")]
    RecoveryPassphraseEmpty,

    /// Authentication of the recovery file failed: wrong passphrase, or a tampered file.
    ///
    /// The two causes deliberately share this variant (same reasoning as
    /// [`Error::PairingAuthenticationFailed`]).
    #[error("恢复文件认证失败：口令错误，或文件已被篡改")]
    RecoveryAuthenticationFailed,

    /// The encryption step of the recovery file failed.
    ///
    /// It can only come from an AEAD implementation limit (plaintext or AAD too long) and does
    /// not happen with the parameters in use; it is listed separately so that this case is not
    /// misreported as a wrong passphrase.
    #[error("恢复文件加密失败")]
    RecoveryEncryptionFailed,

    /// The Argon2id computation failed.
    ///
    /// The most common real cause is **out of memory**: the default parameters allocate 64 MiB
    /// at once.
    #[error("口令派生失败（可能是内存不足）")]
    RecoveryKdfFailed,

    /// The version of a persisted format is not supported.
    ///
    /// Used for data that is **kept for a long time**, such as recovery files: when a file written
    /// by a future version reaches an older one, it must be **rejected outright** instead of being
    /// interpreted under the current layout. The latter would turn "the new version improved
    /// security" into "the older version accepted it under a weaker interpretation".
    #[error("格式版本不受支持：{version}")]
    UnsupportedFormatVersion {
        /// Version declared in the file.
        version: u8,
    },

    /// A challenge-response message is structurally invalid.
    ///
    /// A wrong length, or a carried public key that is not a valid curve point. **This is a
    /// different thing from [`Error::AuthProofFailed`]**: this variant says the message is not
    /// even well-formed, that one says the message is well-formed but the peer cannot compute the
    /// correct tag.
    ///
    /// `reason` is a fixed internal description and **contains no input bytes**.
    #[error("认证消息非法：{reason}")]
    AuthMessageMalformed {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// The proof or confirmation tag of the challenge-response does not match.
    ///
    /// It means "the peer failed to prove that it holds the master key". A tampered tag, an
    /// inconsistent session identifier, or a peer that has no master key at all — the three causes
    /// deliberately share this variant, because the caller's response is identical (declare this
    /// authentication failed and disconnect) and telling them apart would give a probeable signal.
    #[error("认证失败：对方未能证明持有主密钥")]
    AuthProofFailed,

    // ── Orchestration (`crate::flow`) ─────────────────────────────────────────
    /// This device has no device identity yet, and this step needs one.
    ///
    /// Different from "creating the identity failed": this is a caller asking for a signature
    /// before obtaining an identity — a call-order error, not a platform capability problem.
    #[error("本设备还没有设备身份，请先取得身份再签名")]
    DeviceKeyMissing,

    /// This device has never registered or logged in.
    ///
    /// Deliberately separate from "a master key exists but cannot be read": the former is the
    /// normal path (send the user to register or log in), the latter means data may already be
    /// damaged. Sharing one error would make the UI treat the latter as "not logged in yet" and
    /// send the user to **register again**, permanently losing the existing data.
    #[error("本设备尚未注册或登录")]
    DeviceNotRegistered,

    /// The declared device identity is not the local one.
    #[error("设备身份不匹配：对方声明的身份与本机取得的不一致")]
    DeviceIdentityMismatch,

    /// Writing the master key to platform storage failed.
    ///
    /// `reason` is a **fixed string** and must not contain key material: it is logged, and this is
    /// one of the very few paths that touch the master key.
    #[error("主密钥无法写入平台存储：{reason}")]
    SecureStoreWriteFailed {
        /// Developer-facing reason, containing no secret.
        reason: &'static str,
    },

    /// The timestamp is `0`.
    ///
    /// `0` usually means the caller forgot to pass a time (this library never reads a clock; time
    /// always comes from the caller). Letting such a value into the vault pollutes the
    /// time-ordered merge logic, and the result is consistently wrong and hard to trace.
    #[error("时间戳不得为 0")]
    TimestampZero,

    // ── Sync ──────────────────────────────────────────────────────────────────
    /// The magic number of the sync payload does not match.
    ///
    /// Separate from "the payload is corrupt": a bad magic usually means **this is not a sync
    /// payload at all** (the user picked the wrong file, or another protocol's data was fed in),
    /// which points the investigation in a completely different direction than "a payload
    /// produced by this application is broken".
    #[error("不是 Qualia2FA 的同步载荷")]
    SyncBadMagic,

    /// The sync payload format version is not supported.
    #[error("同步载荷版本 {version} 不受支持")]
    SyncUnsupportedVersion {
        /// Version declared by the payload.
        version: u8,
    },

    /// The payload is empty.
    ///
    /// Reported whether it is discovered in the compression layer or in the outer envelope.
    /// "There is no payload at all" and "the payload is broken" point in completely different
    /// directions when investigating: the former is usually a caller passing an empty buffer, the
    /// latter a peer or transport problem.
    #[error("同步载荷为空")]
    SyncEmptyPayload,

    /// The payload is truncated.
    #[error("同步载荷被截断")]
    SyncTruncated,

    /// The record count declared in the payload does not match its actual content.
    ///
    /// Separate from [`Error::SyncTruncated`]: truncation means "not enough bytes", this one means
    /// "enough bytes, but they do not add up" — the payload was reassembled, a stronger signal
    /// than truncation.
    #[error("同步载荷声明有 {declared} 条记录，实际只解出 {actual} 条")]
    SyncRecordCountMismatch {
        /// Record count declared by the payload.
        declared: usize,
        /// Record count actually decoded.
        actual: usize,
    },

    /// The payload contains more records than the limit allows.
    #[error("同步载荷的记录数 {count} 超过上限 {limit}")]
    SyncTooManyRecords {
        /// Record count declared by the payload.
        count: usize,
        /// Allowed limit.
        limit: usize,
    },

    /// Compression failed.
    ///
    /// Deflate is defined for every input, so this does not occur in practice. It exists so that
    /// the return value of `miniz_oxide` is not `unwrap`ped.
    #[error("同步载荷压缩失败")]
    SyncCompressionFailed,

    /// The decompressed content exceeds [`MAX_DECOMPRESSED_LEN`], or the input is not a valid
    /// deflate stream at all.
    ///
    /// [`MAX_DECOMPRESSED_LEN`]: crate::sync::compress::MAX_DECOMPRESSED_LEN
    ///
    /// Corruption, truncation and a length mismatch deliberately share one variant: their handling
    /// is identical (reject this sync, ask the peer to resend), and separating them has no
    /// actionable value for the user.
    #[error("同步载荷解压失败")]
    SyncDecompressionFailed,

    /// The payload exceeds the length limit after decompression.
    ///
    /// # Why it is separate from [`Error::SyncDecompressionFailed`]
    ///
    /// Because it is the only cause in that group that does **not** represent an attack. A user who
    /// really has seventy thousand entries will hit the limit, and telling them "the payload is
    /// corrupt" would send them to check the network, the devices and the pairing — none of which
    /// is the problem. Telling them "too large, use the LAN instead" is actionable.
    ///
    /// The price is that an attacker can probe the limit's position with one bit, and the limit is
    /// in the open-source code anyway. A related fact: decompression happens **after** the outer
    /// AEAD, so input reaching this point has already been authenticated.
    #[error("同步载荷解压后超过 {limit} 字节上限，请改用局域网模式")]
    SyncPayloadTooLarge {
        /// The limit, attached to the error so callers need not look up the constant.
        limit: usize,
    },

    /// The payload contains an unknown record kind.
    ///
    /// As with the equivalent vault-file error, an unknown kind is rejected rather than skipped:
    /// skipping makes semantics added by a future version **silently disappear** on older
    /// versions, and "the sync finished but a few entries are missing" is one of the hardest
    /// failures to trace.
    #[error("同步载荷含未知记录种类 {value:#04x}")]
    SyncUnknownRecordKind {
        /// The kind byte that was read.
        value: u8,
    },

    /// The payload contains an unexplained field or structure.
    ///
    /// This variant is the **catch-all**: every structural problem that can be named has its own
    /// variant, so reaching this one means "the payload failed a self-consistency check, but which
    /// one cannot be said".
    #[error("同步载荷结构不合法：{reason}")]
    SyncMalformed {
        /// Human-readable reason for logs and diagnostics. **Must not contain secret material.**
        reason: &'static str,
    },

    /// Authentication of the payload's outer layer failed.
    ///
    /// Separate from [`Error::VaultDecryptionFailed`]: that one means "the vault file cannot be
    /// opened", this one means "this sync payload is untrustworthy". The client handles them
    /// differently — the former asks the user to check the master key, the latter only needs "this
    /// sync failed, please retry".
    ///
    /// **It does not distinguish** a wrong master key, a tampered payload and a mismatched sender
    /// identifier: telling them apart helps an attacker and has no actionable value for the user.
    #[error("同步载荷认证失败")]
    SyncAuthenticationFailed,

    /// This sync payload has already been processed.
    ///
    /// Replaying an old payload is harmless in itself (merging is idempotent), but **doing a full
    /// decryption and merge for nothing** is real cost, and it misleads the "last synced at" shown
    /// in the UI. Payload identifiers that have been seen are therefore remembered, and duplicates
    /// rejected.
    ///
    /// This is a **separate error** rather than a silent success: the caller needs to know "the
    /// sync did happen, this one is a duplicate", not "a sync just succeeded".
    #[error("这份同步载荷已经处理过了")]
    SyncAlreadyApplied,

    /// The log of used payload identifiers is full.
    ///
    /// Failing explicitly beats silently dropping the oldest entry: a silent drop makes a very old
    /// payload acceptable again, which is exactly what replay protection must prevent. On seeing
    /// this error the caller should tell the user that the sync history is too long; what to do
    /// about it is a higher-level policy decision.
    #[error("已用同步载荷标识的日志已满（上限 {limit}）")]
    SyncIdLogFull {
        /// Maximum number of entries allowed.
        limit: usize,
    },

    // ── Transport layer ──
    /// The transport channel itself failed (disconnect, timeout, platform refusal).
    ///
    /// # Why the underlying error is not passed through
    ///
    /// The underlying failures are things like `std::io::Error` or platform permission errors —
    /// **abstractions that do not belong to this crate**. This crate has
    /// `#![forbid(unsafe_code)]` and depends on no I/O, so writing those types into the error enum
    /// would freeze platform details into the protocol layer. Only an opaque `reason` is kept — it
    /// is meant for logs, not for program decisions.
    #[error("传输失败：{reason}")]
    TransportFailed {
        /// Opaque description for logs.
        reason: &'static str,
    },

    /// The device identifier reported by the peer disagrees with the sender claimed by the
    /// transport channel.
    ///
    /// # Why this check must exist
    ///
    /// The `sender` inside the payload is **self-reported**, and its presence in the AAD only
    /// guarantees that no third party changed it. On a broadcast channel (LAN multicast) any
    /// device can replay a payload **signed by somebody else** verbatim, so the payload says B
    /// while C actually sent it. This check takes "who sent this" from the transport channel and
    /// compares it with the value the payload claims.
    ///
    /// Note that it stops **impersonation**, not replay — replay is stopped by
    /// [`Error::SyncAlreadyApplied`].
    #[error("载荷自报的发送方与通道声称的发送方不一致")]
    SyncSenderMismatch,

    /// The kind claimed by the payload is not one this version knows.
    ///
    /// Separate from [`Error::SyncUnknownRecordKind`]: that one is about the kind of **one record
    /// inside** the payload (entry or tombstone), this one about the kind of **the whole payload**
    /// (state exchange or request). See [`crate::sync::PayloadKind`].
    #[error("未知的载荷种类 {value:#04x}")]
    SyncUnknownPayloadKind {
        /// Raw byte from the wire format.
        value: u8,
    },

    /// The transport channel does not support this operation.
    ///
    /// For example, a channel that can carry only a single message (a QR code) is asked to open a
    /// long-lived connection. It is **not** used for "this channel cannot fit the payload" — that
    /// is [`Error::TransportMessageTooLarge`], and the two are handled quite differently (the
    /// former can only switch channels; the latter can switch modes or send the user to the LAN).
    #[error("传输通道不支持该操作：{operation}")]
    TransportUnsupported {
        /// Name of the rejected operation.
        operation: &'static str,
    },
    /// The one-shot channel has already been used.
    ///
    /// A QR code is the typical one-shot channel: one code carries exactly one exchange. Treating
    /// it as reusable would turn "scan the same code twice" into two syncs, which is a side path
    /// around replay protection.
    #[error("该传输通道已经使用过，不能再次使用")]
    TransportAlreadyUsed,

    /// A single message exceeds what the channel can carry.
    ///
    /// The usual trigger is a QR code: it is a **fixed-capacity** channel, so when the message does
    /// not fit the only options are switching mode or switching channel. The caller should use this
    /// to steer the user towards the LAN, not truncate the payload — a truncated payload fails
    /// AEAD, so what the user sees is "corrupted data".
    #[error("单条消息需要 {needed} 字节，超过该通道的 {limit} 字节上限")]
    TransportMessageTooLarge {
        /// Number of bytes this message needs.
        needed: usize,
        /// Limit declared by the channel.
        limit: usize,
    },

    /// No joinable sync session was found.
    ///
    /// Separate from "found one, but the handshake failed": the former is the normal "nobody
    /// nearby", where the caller should let the user retry or check the network; only the latter is
    /// an anomaly.
    #[error("未发现可加入的同步会话")]
    SyncNoSessionFound,
}

/// The unified result type of this library.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The displayed error text must contain the numbers needed to locate the problem, and must
    /// not panic.
    #[test]
    fn display_includes_diagnostic_numbers() {
        let cases: [(Error, &str); 3] = [
            (Error::Base32InvalidCharacter { index: 7 }, "7"),
            (Error::Base32InvalidLength { length: 3 }, "3"),
            (
                Error::SecretTooShort {
                    required: 20,
                    actual: 4,
                },
                "20",
            ),
        ];
        for (err, needle) in cases {
            let text = err.to_string();
            assert!(text.contains(needle), "错误文本 {text:?} 未包含 {needle:?}");
        }
    }

    /// `Error` must implement `std::error::Error`, so that callers can chain it with `?` and
    /// `source()`.
    #[test]
    fn implements_std_error() {
        fn assert_is_std_error<E: std::error::Error>() {}
        assert_is_std_error::<Error>();
    }
}
