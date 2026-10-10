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

//! HOTP（RFC 4226）与 TOTP（RFC 6238）。
//!
//! # 纯度
//!
//! 本模块**不读取时钟**。HOTP 要计数器，TOTP 要 Unix 时间戳，两者都由调用方
//! 以参数传入。这不是风格偏好——时钟不可注入就无法对 RFC 测试向量做确定性
//! 验证，也就无法证明实现正确。
//!
//! # 支持的算法与种子长度
//!
//! | `Algorithm` | RFC 6238 附录 B 的种子长度 | HMAC 块大小 |
//! |---|---|---|
//! | [`Algorithm::Sha1`]（默认） | 20 字节 | 64 字节 |
//! | [`Algorithm::Sha256`] | 32 字节 | 64 字节 |
//! | [`Algorithm::Sha512`] | 64 字节 | 128 字节 |
//!
//! **为什么 SHA-1 是必需的，而不是安全妥协**：SHA-1 对**碰撞**已破，但 HMAC 的
//! 安全性不依赖碰撞抗性——HMAC-SHA1 在 TOTP 场景下仍安全，且绝大多数真实服务端
//! 只支持 SHA-1。RFC 6238 本身就把 SHA-1 列为必需实现。
//!
//! # 关于种子长度校验
//!
//! 上表的长度是 RFC 的**建议**，不是 HMAC 的**要求**（HMAC 接受任意长度密钥）。
//! 因此本模块**只拒绝空种子**，不拒绝短种子——真实世界里存在短种子，硬拒会让
//! 用户无法导入本可用的账号。长度不足应在 UI 层作为**警告**呈现，而不是核心层
//! 的错误。可用 [`recommended_min_secret_len`] 取建议长度用于告警。

use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::{Error, ExposeSecret, Result, secret::SecretBox};

// `zeroize` 不是本 crate 的直接依赖，从 `secrecy` 取用可保证与实际生效的版本一致。
// 仅在测试中用于验证中间缓冲可被显式擦除，故加 `cfg(test)` 以免生产构建告警。
#[cfg(test)]
use secrecy::zeroize::Zeroize;

/// HOTP/TOTP 使用的哈希算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Algorithm {
    /// HMAC-SHA-1。TOTP 的默认值，也是绝大多数服务的唯一选项。
    #[default]
    Sha1,
    /// HMAC-SHA-256。
    Sha256,
    /// HMAC-SHA-512。
    Sha512,
}

impl Algorithm {
    /// RFC 6238 建议的种子长度（字节），用于向用户告警。
    ///
    /// 这些值等于对应哈希函数的输出长度。
    #[must_use]
    pub const fn recommended_secret_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// 从 `otpauth://` 的 `algorithm` 参数解析。
    ///
    /// 接受大小写不敏感的 `SHA1` / `SHA256` / `SHA512`。
    /// 缺失该参数时由调用方使用 [`Algorithm::default`]。
    ///
    /// # 错误
    ///
    /// 无法识别时返回 [`Error::UnsupportedAlgorithm`]——**拒绝而非回退到 SHA-1**，
    /// 因为静默回退会让用户拿到一个恒错的验证码，而错误信息无从查起。
    pub fn parse(value: &str) -> Result<Self> {
        // 先做 ASCII 大写归一，避免为每个分支处理大小写。
        // 用栈缓冲而非 `to_uppercase()`：后者会为 `String` 分配，且做完整 Unicode
        // 映射（此处只需要 ASCII）。
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
        // 上面只填了前 len 个字节，这里按实际长度比较。
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

/// 把无法识别的算法名截断后再放进错误，避免把超长（甚至来自攻击者的）输入
/// 原样带进日志。
fn truncate_for_error(value: &str) -> String {
    const MAX: usize = 16;
    if value.len() <= MAX {
        return value.into();
    }
    // 必须在字符边界截断，否则 `&value[..MAX]` 会在多字节字符中间切开而 panic。
    let mut end = MAX;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::from(&value[..end]);
    out.push('…');
    out
}

/// 支持的数字位数。RFC 4226 只要求 6 位，RFC 6238 允许 8 位；
/// 7 位在真实世界存在（部分银行），故一并支持。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Digits {
    /// 6 位（默认，覆盖绝大多数场景）。
    #[default]
    Six,
    /// 7 位。
    Seven,
    /// 8 位。
    Eight,
}

impl Digits {
    /// 位数本身。
    #[must_use]
    pub const fn count(self) -> u32 {
        match self {
            Self::Six => 6,
            Self::Seven => 7,
            Self::Eight => 8,
        }
    }

    /// 从 `otpauth://` 的 `digits` 参数解析。
    ///
    /// # 错误
    ///
    /// 只接受 6、7、8；其它值返回 [`Error::UnsupportedDigits`]。
    /// 这是**攻击者可控参数**，必须严格校验——若接受任意值，`10^digits`
    /// 会在超大位数上溢出。
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "6" => Ok(Self::Six),
            "7" => Ok(Self::Seven),
            "8" => Ok(Self::Eight),
            _ => Err(Error::UnsupportedDigits {
                value: truncate_for_error(value),
            }),
        }
    }

    /// `10^digits`，用于取模。
    #[must_use]
    const fn modulus(self) -> u32 {
        match self {
            Self::Six => 1_000_000,
            Self::Seven => 10_000_000,
            Self::Eight => 100_000_000,
        }
    }
}

/// 一个已校验的 OTP 种子。
///
/// 用专属类型而非裸 `SecretBytes`，是为了把「非空」这一不变量固定在类型里，
/// 并让调用方无法把任意字节流误当作种子传入。
///
/// **刻意不实现 `Clone`**：克隆会让同一密钥在内存中多存一份、各自独立擦除，
/// 增加泄露面。需要多处使用时传引用。
pub struct OtpSecret {
    /// 种子字节。`SecretBox` 在 `Drop` 时擦除，且其 `Debug` 只输出脱敏标记。
    bytes: SecretBox<[u8]>,
}

impl OtpSecret {
    /// 用原始字节构造。
    ///
    /// # 错误
    ///
    /// 空输入返回 [`Error::SecretEmpty`]。
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::SecretEmpty);
        }
        Ok(Self {
            bytes: bytes.into(),
        })
    }

    /// 从 Base32 字符串构造（`otpauth://` 种子在 URI 里的表示形式）。
    ///
    /// 宽容策略与转义规则见 [`crate::base32::decode`]。
    pub fn from_base32(encoded: &str) -> Result<Self> {
        let decoded = crate::base32::decode(encoded)?;
        Self::from_bytes(decoded.expose_secret().to_vec())
    }

    /// 种子长度（字节）。长度本身不是秘密。
    ///
    /// # 为什么没有 `is_empty`
    ///
    /// clippy 的 `len_without_is_empty` 会对此告警，但本类型**不存在空状态**：
    /// `OtpSecret` 的唯一构造入口都会拒绝空输入（见 [`Error::SecretEmpty`]）。
    /// 加一个恒返回 `false` 的 `is_empty` 只会制造一个永不成立的 API 承诺，
    /// 反而误导调用方以为需要判断。故显式豁免并说明原因。
    #[expect(
        clippy::len_without_is_empty,
        reason = "本类型的不变量保证非空，`is_empty` 恒为 false，提供它反而误导"
    )]
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.expose_secret().len()
    }

    /// 是否短于该算法建议的长度——用于向用户**告警**，不是错误。
    #[must_use]
    pub fn is_shorter_than_recommended(&self, algorithm: Algorithm) -> bool {
        self.len() < algorithm.recommended_secret_len()
    }

    /// 借出种子字节，供计算使用。
    fn expose(&self) -> &[u8] {
        self.bytes.expose_secret()
    }

    /// 把种子导出为 Base32 字符串（**无填充**大写形式）。
    ///
    /// 供 URI 序列化与二维码生成使用。之所以提供这个方法而不是公开 `expose`，
    /// 是为了让「种子离开本类型」只有这一条窄路径：它产出的是可显示、可编码的
    /// 表示，而不是可被误当作普通字节流处理的裸切片。
    ///
    /// 无填充形式是各认证器最普遍的写法，也能避免二维码里出现 `=` 带来的转义问题。
    #[must_use]
    pub fn to_base32(&self) -> String {
        let encoded = crate::base32::encode(self.expose());
        // `trim_end_matches` 只会在有填充时截断，无填充时原样返回。
        encoded.trim_end_matches('=').to_owned()
    }
}

impl core::fmt::Debug for OtpSecret {
    /// 只打印长度，**绝不**打印内容。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OtpSecret")
            .field("len", &self.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// 返回该算法建议的最小种子长度（字节），供 UI 告警使用。
#[must_use]
pub const fn recommended_min_secret_len(algorithm: Algorithm) -> usize {
    algorithm.recommended_secret_len()
}

/// 计算 HMAC 摘要并按 RFC 4226 §5.3 做**动态截断**。
///
/// 动态截断：取摘要最后一字节的低 4 位作为偏移量 `offset`，然后从 `offset`
/// 起取 4 字节组成大端 31 位整数（最高位被掩掉）。
///
/// # 为什么用 `SimpleHmac` 而不是 `Hmac`
///
/// `hmac` 0.13 提供两个实现：`Hmac<D>` 要求 `D: EagerHash + CoreProxy`（为吞吐
/// 优化的块级实现），`SimpleHmac<D>` 只要求 `D: Digest + BlockSizeUser`（可移植
/// 实现）。两者产出**完全相同**的 HMAC 值。
///
/// 本模块按算法在运行时三选一分派，泛型约束的可写性直接决定代码可读性。
/// TOTP 每 30 秒算一次、每次几十字节，吞吐差异无实际意义，故选可移植实现。
fn hmac_truncate(secret: &OtpSecret, algorithm: Algorithm, message: &[u8]) -> u32 {
    // `BlockSizeUser` 在 `digest 0.11` 体系里由 `crypto-common` 定义，而 `digest`
    // 以 `pub use common` 再导出该 crate。不要写 `digest::block_buffer::*`——
    // 那个模块（包名已改为 `crypto-common`，模块名是历史沿用）并不再导出此 trait。
    use hmac::digest::common::BlockSizeUser;
    use hmac::digest::{Digest, KeyInit, Mac};

    /// 按算法分派到泛型实现。
    ///
    /// 写成嵌套函数是为了让 `D` 的约束只在一处出现，避免调用方被泛型纠缠。
    ///
    /// 注意 `SimpleHmac` 实现的是 `Mac`（含 `update` / `finalize`），**不是**
    /// `Digest`——虽然其类型参数 `D` 必须是 `Digest`。写成 `Digest::update` 会
    /// 编译失败。
    fn digest_with<D>(key: &[u8], message: &[u8]) -> Option<Vec<u8>>
    where
        D: Digest + BlockSizeUser,
    {
        // `KeyInit::new_from_slice` 唯一失败情形是「密钥长度非法」。HMAC 明确
        // 接受任意长度密钥（超长会先做哈希压缩），故此处实际不会失败；
        // 用 `ok()?` 而非 `unwrap` 以满足「库内禁 panic」。
        let mut mac = <hmac::SimpleHmac<D> as KeyInit>::new_from_slice(key).ok()?;
        Mac::update(&mut mac, message);
        Some(Mac::finalize(mac).into_bytes().to_vec())
    }

    let digest = match algorithm {
        Algorithm::Sha1 => digest_with::<Sha1>(secret.expose(), message),
        Algorithm::Sha256 => digest_with::<Sha256>(secret.expose(), message),
        Algorithm::Sha512 => digest_with::<Sha512>(secret.expose(), message),
    };

    // 万一将来约束被破坏，结果是恒定错误的验证码，而不是崩溃。
    let Some(bytes) = digest else {
        return 0;
    };

    // 摘要长度由算法保证 ≥ 20 字节，故偏移与切片恒在界内。
    // 仍然做条件判断而非直接索引，以便未来新增算法时不会悄悄越界。
    let Some(last) = bytes.last() else {
        return 0;
    };
    let offset = usize::from(last & 0x0f);
    if offset + 4 > bytes.len() {
        return 0;
    }
    let truncated = &bytes[offset..offset + 4];

    // 组装大端 31 位整数。用 fold 而非 `u32::from_be_bytes` + `try_into`，
    // 以避免为固定 4 字节引入 panic 路径。
    let value = truncated
        .iter()
        .fold(0_u32, |acc, &b| (acc << 8) | u32::from(b));
    value & 0x7fff_ffff
}

/// 计算 HOTP 数值（RFC 4226）。
///
/// `counter` 是 8 字节大端计数器。[`Digits::Six`] 时返回 0..=999_999。
///
/// 需要定宽字符串（含前导零）时用 [`hotp_code`]。
#[must_use]
pub fn hotp(secret: &OtpSecret, counter: u64, algorithm: Algorithm, digits: Digits) -> u32 {
    let truncated = hmac_truncate(secret, algorithm, &counter.to_be_bytes());
    truncated % digits.modulus()
}

/// 计算 TOTP 数值（RFC 6238）。
///
/// `unix_time` 是 Unix 秒（**由调用方提供，本模块不读时钟**）。
/// `period` 为 0 时返回 [`Error::InvalidPeriod`]。
///
/// # 错误
///
/// `period == 0` 会导致除零，故必须拒绝。
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

/// 把 OTP 数值格式化为**定宽**十进制字符串（含前导零）。
///
/// 这是显示给用户的最终形式。前导零不能丢——`012345` 与 `12345` 是不同的验证码。
#[must_use]
pub fn format_code(value: u32, digits: Digits) -> String {
    // 用 `{:0width$}` 而非手动补零：格式化宏直接处理宽度与补零，且不分配中间缓冲。
    format!("{:0width$}", value, width = digits.count() as usize)
}

/// 计算 HOTP 并直接返回定宽字符串。
#[must_use]
pub fn hotp_code(secret: &OtpSecret, counter: u64, algorithm: Algorithm, digits: Digits) -> String {
    format_code(hotp(secret, counter, algorithm, digits), digits)
}

/// 计算 TOTP 并直接返回定宽字符串。
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

/// 以**常量时间**比较两个 OTP 字符串。
///
/// # 为什么不能用 `==`
///
/// `==` 在首个不同字符处短路返回，比较耗时因而泄露「前多少个字符是对的」——
/// 攻击者可据此逐位爆破验证码。虽然网络抖动通常足以掩盖这类差异，但**远程计时
/// 攻击在 TOTP 上是有实际先例的**，且常量时间比较的成本几乎为零。
///
/// 长度不等时立即返回 `false` 是安全的：长度不是秘密。
///
/// # 示例
///
/// ```
/// use qualia2fa_core::otp::{self, Algorithm, Digits, OtpSecret};
///
/// let secret = OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("合法种子");
/// let code = otp::totp_code(&secret, 1_700_000_000, 30, Algorithm::Sha1, Digits::Six)
///     .expect("period 非零");
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

/// 校验提供的时间步是否落在允许的漂移窗口内，并返回命中的偏移量。
///
/// 返回 `Some(offset)` 表示 `provided_counter == counter + offset` 成立，
/// `offset ∈ [-window, +window]`。返回 `None` 表示窗口内均不匹配。
///
/// # 为什么要返回偏移量而不是 `bool`
///
/// 调用方通常需要在命中后**把服务端计数器校准到命中值**，否则用户每次都要
/// 依赖漂移窗口。把偏移量交出去，校准逻辑就不必重算一遍。
///
/// # 窗口方向
///
/// `window = 1` 时检查 `counter-1`、`counter`、`counter+1` 共 3 个时间步。
/// **先检查当前步**，命中即返回 0——绝大多数请求都是当前步命中，这样能让
/// 常见路径最快返回。注意这**不构成计时泄露**：偏移量本来就是攻击者已知的
/// 输入，泄露它无意义；真正的秘密是种子。
#[must_use]
pub fn verify_with_drift(
    secret: &OtpSecret,
    provided_counter: u64,
    window: u64,
    algorithm: Algorithm,
    digits: Digits,
    provided_code: &str,
) -> Option<i64> {
    /// 检查单个偏移量。返回是否匹配。
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

    // 当前步优先。
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
    // 其余偏移按「离当前步由近到远」的顺序检查，使常见情况尽早返回。
    for distance in 1..=window {
        let Ok(distance_i64) = i64::try_from(distance) else {
            // window 超过 i64 范围时不可能有合法偏移，直接停止。
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

/// Steam Guard 使用的自定义字母表（去掉了易混字符）。
const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

/// Steam Guard 验证码位数恒为 5。
pub const STEAM_DIGITS: usize = 5;

/// 计算 Steam Guard 验证码。
///
/// Steam 不用十进制：它把 31 位截断值反复对 26 取模，映射到
/// `23456789BCDFGHJKMNPQRTVWXY` 这个去掉了 `0/O/1/I/L/S/U` 等易混字符的字母表。
/// 5 位固定长度。
//
// 说明：此处刻意**不加** `#[must_use]`——返回类型是 `Result<String>`，
// 二者本身都已标记 `must_use`，再加会触发 clippy 的 `double_must_use`。
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
        // 字母表固定 26 项且索引来自取模，恒在界内。
        out.push(char::from(STEAM_ALPHABET[index]));
        value /= STEAM_ALPHABET.len() as u32;
    }
    Ok(out)
}

// 说明：本模块的测试向量放在 `tests/rfc_vectors.rs`（集成测试）而不是此处，
// 因为 RFC 4226 附录 D 与 RFC 6238 附录 B 的向量是**验收标准**，值得作为独立
// 测试文件存在以便审阅时一眼看到全貌。此处只放实现细节的单元测试。
//
// 但下面这条测试必须留在模块内：它验证 `Zeroize` 的接线，属于实现细节。

/// 让 `zeroize` 的导入有实际用途，并锁住「种子在被替换时会先擦除」的语义。
///
/// `SecretBox<[u8]>` 自身已实现 `ZeroizeOnDrop`；这里额外确认 `Vec<u8>`
/// 在交给构造器前若被中途丢弃，也能被显式擦除。
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
                "{bad:?} 应被拒绝"
            );
        }
    }

    /// 多字节字符的截断必须在字符边界发生，否则会 panic。
    #[test]
    fn truncate_for_error_handles_multibyte_boundary() {
        let long = "算".repeat(20); // 每个字符 3 字节
        let text = truncate_for_error(&long);
        // 不应 panic，且结果应是原串的前缀加省略号。
        assert!(text.ends_with('…'), "应带省略号：{text}");
        assert!(long.starts_with(text.trim_end_matches('…')));
    }

    #[test]
    fn digits_parsing_accepts_only_6_7_8() {
        assert_eq!(Digits::parse("6").expect("6"), Digits::Six);
        assert_eq!(Digits::parse("7").expect("7"), Digits::Seven);
        assert_eq!(Digits::parse("8").expect("8"), Digits::Eight);
        for bad in ["5", "9", "0", "06", "", "six", "99999999999999999999"] {
            assert!(
                matches!(Digits::parse(bad), Err(Error::UnsupportedDigits { .. })),
                "{bad:?} 应被拒绝"
            );
        }
    }

    #[test]
    fn format_code_pads_to_exact_width() {
        assert_eq!(format_code(0, Digits::Six), "000000");
        assert_eq!(format_code(1, Digits::Six), "000001");
        assert_eq!(format_code(123_456, Digits::Six), "123456");
        assert_eq!(format_code(0, Digits::Eight), "00000000");
        assert_eq!(format_code(99_999_999, Digits::Eight), "99999999");
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
        let secret = OtpSecret::from_bytes(vec![0xde, 0xad, 0xbe, 0xef]).expect("非空");
        let text = format!("{secret:?}");
        assert!(text.contains("redacted"), "应标注脱敏：{text}");
        for leak in ["dead", "beef", "222", "173"] {
            assert!(!text.to_lowercase().contains(leak), "泄露 {leak}：{text}");
        }
    }

    #[test]
    fn period_zero_is_rejected() {
        let secret = OtpSecret::from_bytes(vec![1, 2, 3]).expect("非空");
        assert!(matches!(
            totp(&secret, 0, 0, Algorithm::Sha1, Digits::Six),
            Err(Error::InvalidPeriod)
        ));
        assert!(matches!(
            totp_code(&secret, 0, 0, Algorithm::Sha1, Digits::Six),
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
        // 真实世界存在短种子；核心层不得拒绝，只负责标记。
        let secret = OtpSecret::from_bytes(vec![1, 2, 3, 4]).expect("非空短种子应被接受");
        assert!(secret.is_shorter_than_recommended(Algorithm::Sha1));
        assert_eq!(secret.len(), 4);

        let long = OtpSecret::from_bytes(vec![0_u8; 20]).expect("非空");
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

    /// `verify_with_drift` 必须能找到窗口内的偏移，并报告正确的偏移量。
    #[test]
    fn drift_window_finds_neighbouring_steps() {
        let secret = OtpSecret::from_bytes((0..20).collect::<Vec<u8>>()).expect("非空");
        let period = 30_u64;
        let now = 1_700_000_000_u64;
        let counter = now / period;

        // 分别用 -1、0、+1 步的验证码去校验，偏移量应被正确报出。
        for expected_offset in [-1_i64, 0, 1] {
            let target = counter.checked_add_signed(expected_offset).expect("不越界");
            let code = hotp_code(&secret, target, Algorithm::Sha1, Digits::Six);
            let got = verify_with_drift(&secret, counter, 1, Algorithm::Sha1, Digits::Six, &code);
            assert_eq!(got, Some(expected_offset), "偏移 {expected_offset}");
        }
    }

    #[test]
    fn drift_window_rejects_out_of_window() {
        let secret = OtpSecret::from_bytes((0..20).collect::<Vec<u8>>()).expect("非空");
        let counter = 1_700_000_000_u64 / 30;
        let far = counter + 5;
        let code = hotp_code(&secret, far, Algorithm::Sha1, Digits::Six);
        assert_eq!(
            verify_with_drift(&secret, counter, 1, Algorithm::Sha1, Digits::Six, &code),
            None,
            "窗口外不应命中"
        );
    }

    /// 计数器为 0 且窗口向左扩展时不得下溢 panic。
    #[test]
    fn drift_window_handles_counter_underflow() {
        let secret = OtpSecret::from_bytes(vec![7_u8; 20]).expect("非空");
        let code = hotp_code(&secret, 0, Algorithm::Sha1, Digits::Six);
        // counter = 0 时向左检查会下溢，必须安全返回而不是 panic。
        let got = verify_with_drift(&secret, 0, 3, Algorithm::Sha1, Digits::Six, &code);
        assert_eq!(got, Some(0), "当前步应命中");
    }

    #[test]
    fn steam_codes_are_five_chars_from_steam_alphabet() {
        let secret = OtpSecret::from_bytes((0..20).collect::<Vec<u8>>()).expect("非空");
        let code =
            steam_guard_code(&secret, 1_700_000_000, 30, Algorithm::Sha1).expect("period 非零");
        assert_eq!(code.chars().count(), STEAM_DIGITS, "应为 5 位：{code}");
        for ch in code.chars() {
            assert!(
                STEAM_ALPHABET.contains(&(ch as u8)),
                "字符 {ch:?} 不在 Steam 字母表内：{code}"
            );
        }
    }

    /// Steam 码随时间步变化——若恒定不变说明计数器没被用上。
    #[test]
    fn steam_codes_change_across_steps() {
        let secret = OtpSecret::from_bytes((0..20).collect::<Vec<u8>>()).expect("非空");
        let a = steam_guard_code(&secret, 1_700_000_000, 30, Algorithm::Sha1).expect("period 非零");
        let b = steam_guard_code(&secret, 1_700_000_030, 30, Algorithm::Sha1).expect("period 非零");
        assert_ne!(a, b, "相邻时间步应产出不同 Steam 码");
    }

    /// 借出接口只为测试提供的内部方法，确保其语义与公开路径一致。
    #[test]
    fn internal_expose_matches_public_secret() {
        let secret = OtpSecret::from_bytes(vec![1, 2, 3]).expect("非空");
        assert_eq!(secret.expose(), &[1, 2, 3]);
        assert_eq!(secret.len(), 3);
    }

    /// 显式擦除：确认 `Vec<u8>` 的 `zeroize` 可用（供将来处理中间缓冲）。
    #[test]
    fn zeroize_is_available_for_intermediate_buffers() {
        let mut buffer = vec![0xAA_u8; 16];
        buffer.zeroize();
        assert!(buffer.iter().all(|&b| b == 0), "擦除后应全为零");
    }

    /// `SecretBox` 的 `expose_secret` 通过 trait 提供；此处确认导入可用。
    #[test]
    fn secret_box_expose_is_reachable() {
        let boxed: SecretBox<[u8]> = vec![1_u8, 2, 3].into();
        assert_eq!(boxed.expose_secret(), &[1, 2, 3]);
    }
}
