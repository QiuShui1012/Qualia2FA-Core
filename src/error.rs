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

//! 错误类型。
//!
//! 本库所有对外函数返回 [`Result`]，**任何输入都不得导致 panic**。
//!
//! # 秘密信息纪律
//!
//! 错误类型**绝不能携带秘密材料**：不放原始输入、不放密钥字节、不放 OTP 码。
//! 本模块的变体只记录「哪一类输入非法」以及必要的**非秘密**数值（如长度、
//! 位置），以便调用方定位问题而不泄露值。

use thiserror::Error;

/// 本库的统一错误类型。
///
/// 当前只有 URI 解析与 Base32 相关变体（为 M1 准备）；后续里程碑会逐步扩充，
/// 因此本枚举**不标记 `#[non_exhaustive]` 之外的兼容承诺**，但保持变体新增
/// 不破坏下游 `match` 的方式演进。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Base32 输入含字母表外的字符。
    ///
    /// 只报告**位置**，不报告该位置上的字符，避免把（可能来自密钥的）输入
    /// 内容带进日志。
    #[error("Base32 输入在第 {index} 个字符处含非法字符")]
    Base32InvalidCharacter {
        /// 非法字符在**剔除 ASCII 空白后**的字符序列中的位置。
        ///
        /// 之所以不是原始字节偏移：用户常从网页复制带空格或换行的种子，
        /// 此时「第几个有效字符」比「第几个字节」更容易定位问题。
        index: usize,
    },

    /// Base32 输入的（去除填充后）长度不是 8 的合法余数。
    ///
    /// 合法的 Base32 长度余数只有 0、2、4、5、7 这几种。
    #[error("Base32 长度非法：{length} 个有效字符")]
    Base32InvalidLength {
        /// 去除填充后的有效字符数。
        length: usize,
    },

    /// Base32 编码损坏：最后一个字符中未被使用的比特不为零。
    ///
    /// 这不是「填充格式」问题——填充本身可缺失或可带（两者都接受）。此错误表示
    /// 编码数据本身损坏，例如把有效比特写进了应为零的填充位。
    #[error("Base32 编码尾部残留比特非零，数据已损坏")]
    Base32InvalidPadding,

    /// OTP 密钥为空。
    ///
    /// 与 [`Error::SecretTooShort`] 分开：空种子是**结构性问题**（URI 里根本没有
    /// `secret`、或 Base32 解出来是空），而短种子是**强度问题**。前者必须拒绝，
    /// 后者由 UI 告警——混在一起会让调用方无法区分。
    #[error("OTP 密钥为空")]
    SecretEmpty,

    /// OTP 密钥长度不满足所选算法的最小要求。
    ///
    /// **注意**：本库当前只在「密钥为空」时拒绝，不会因长度不足而返回此错误。
    /// HMAC 接受任意长度密钥，且真实世界存在短种子；长度不足应作为**告警**
    /// 在 UI 层呈现，见 `otp::recommended_min_secret_len`。
    #[error("OTP 密钥过短：需要至少 {required} 字节，实际 {actual} 字节")]
    SecretTooShort {
        /// RFC 6238 为该算法规定的最小种子长度（字节）。
        required: usize,
        /// 实际得到的长度（字节）。长度本身不是秘密。
        actual: usize,
    },

    /// `otpauth://` 的 `algorithm` 参数无法识别。
    ///
    /// **拒绝而非回退到 SHA-1**：静默回退会让用户拿到一个恒定错误的验证码，
    /// 而错误信息无从查起。
    #[error("不支持的算法：{name}")]
    UnsupportedAlgorithm {
        /// 被截断到 16 字符以内的原始参数值。
        ///
        /// 截断是必要的：该值来自攻击者可控的 URI，不允许把任意长度输入
        /// 原样带进日志。
        name: String,
    },

    /// `otpauth://` 的 `digits` 参数不在支持范围内。
    ///
    /// 只接受 6、7、8。必须严格校验——若接受任意值，`10^digits` 会溢出。
    #[error("不支持的位数：{value}（只接受 6、7、8）")]
    UnsupportedDigits {
        /// 被截断到 16 字符以内的原始参数值。
        value: String,
    },

    /// TOTP 的 `period` 为 0，会导致除零。
    #[error("TOTP 周期不能为 0")]
    InvalidPeriod,

    /// 无法从操作系统取得密码学安全的随机字节。
    ///
    /// 这是**不可恢复**的失败：本库刻意不使用任何用户态 PRNG 作为回退，
    /// 因为一个确定性种子会让「双方独立生成」的密钥发生碰撞。宁可让操作失败、
    /// 由用户重试，也不能悄悄换用弱随机源。
    ///
    /// 触发场景：目标平台的 `getrandom` 后端不可用（例如受限的沙箱、
    /// 缺少必要的 syscall、或内核熵源初始化失败）。
    ///
    /// **不携带 `getrandom::Error` 的细节**：它的内部表示在不同版本/平台上
    /// 不一致，且对调用方没有可操作价值——能做的只有重试或告知用户。
    #[error("无法从操作系统取得安全随机数")]
    RandomnessUnavailable,

    /// URI 的 scheme 不是 `otpauth`。
    #[error("URI 的 scheme 不是 otpauth")]
    UriUnsupportedScheme,

    /// URI 缺少 type 部分（`otpauth://` 后没有 `/`）。
    #[error("URI 缺少类型段（应为 totp 或 hotp）")]
    UriMissingType,

    /// URI 的 type 不是 `totp` 或 `hotp`。
    #[error("不支持的 URI 类型：{name}")]
    UriUnsupportedType {
        /// 截断到 16 字符以内的原始 type 段。
        name: String,
    },

    /// URI 缺少 `secret` 参数。
    #[error("URI 缺少必需的 secret 参数")]
    UriMissingSecret,

    /// HOTP 的 URI 缺少 `counter` 参数。
    #[error("HOTP 的 URI 缺少必需的 counter 参数")]
    UriMissingCounter,

    /// TOTP 的 URI 却带了 `counter` 参数。
    ///
    /// 严格拒绝而非忽略：这种 URI 是生成器出错的信号，忽略它会让用户拿到一个
    /// 看起来正常但语义错误的条目。
    #[error("TOTP 的 URI 不应包含 counter 参数")]
    UriUnexpectedCounter,

    /// URI 含重复的已知参数。
    ///
    /// 不同实现取「第一个」还是「最后一个」并不一致，是经典解析歧义，也是攻击面。
    #[error("URI 含重复参数：{name}")]
    UriDuplicateParameter {
        /// 重复的参数名（截断到 16 字符）。
        name: String,
    },

    /// URI 的参数值非法。
    #[error("URI 参数 {name} 非法：{reason}")]
    UriInvalidParameter {
        /// 参数名。
        name: String,
        /// 不含完整原始值的原因说明（值本身会被截断）。
        reason: String,
    },

    /// URI 的百分号编码格式错误。
    #[error("URI 含非法的百分号编码（% 后必须跟两个十六进制数字）")]
    UriInvalidPercentEncoding,

    /// label 里的 issuer 与 `issuer` 参数不一致。
    ///
    /// 严格拒绝：两个来源给出不同发行方意味着 URI 被拼接或篡改过，
    /// 静默选一个会让用户把一个条目的验证码错配到另一个服务上。
    #[error("issuer 冲突：label 里是 {in_label}，参数里是 {in_parameter}")]
    UriIssuerMismatch {
        /// label 前缀中的 issuer（截断）。
        in_label: String,
        /// `issuer` 参数中的值（截断）。
        in_parameter: String,
    },

    /// URI 的 label 中，账号名含 `:`。
    ///
    /// label 用 `:` 分隔 issuer 与 account，因此账号名里的 `:` 无法与分隔符区分，
    /// 会造成往返歧义——序列化后再解析，issuer/account 的归属会**静默改变**。
    /// 百分号编码救不了它：`%3A` 与字面 `:` 在解码后无从区分。
    ///
    /// 故**解析与序列化两端都拒绝**，把这个不变量强制住。
    #[error("账号名不能包含冒号（会与 issuer 分隔符混淆）：{account}")]
    UriAccountContainsColon {
        /// 截断到 32 字符的账号名。
        account: String,
    },
}

/// 本库的统一结果类型。
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// 展示的错误文本必须包含可定位的数值，且不得 panic。
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

    /// `Error` 必须实现 `std::error::Error`，以便调用方用 `?` 与 `source()` 链式处理。
    #[test]
    fn implements_std_error() {
        fn assert_is_std_error<E: std::error::Error>() {}
        assert_is_std_error::<Error>();
    }
}
