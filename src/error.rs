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
        /// 非法字符在输入中的字节偏移。
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

    /// Base32 填充格式非法（填充位置错误或填充数量超出上限）。
    #[error("Base32 填充格式非法")]
    Base32InvalidPadding,

    /// OTP 密钥长度不满足所选算法的最小要求。
    #[error("OTP 密钥过短：需要至少 {required} 字节，实际 {actual} 字节")]
    SecretTooShort {
        /// RFC 6238 为该算法规定的最小种子长度（字节）。
        required: usize,
        /// 实际得到的长度（字节）。长度本身不是秘密。
        actual: usize,
    },

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
