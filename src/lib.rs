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

//! Qualia2FA 核心库。
//!
//! 本 crate 承载 Qualia2FA 的双因素认证（2FA）核心逻辑，刻意不包含任何界面或
//! 命令行入口，以便 GUI、CLI、移动端等前端各自作为独立 crate 依赖本库。
//!
//! # 纯度约定
//!
//! 本库是**无 I/O、无时钟**的纯逻辑库：
//!
//! - 不访问文件系统、网络、环境变量，不读取系统时钟。
//! - 当前时间由调用方以 `u64` Unix 秒传入。
//! - 随机数只用 [`getrandom`]，不经过任何用户态 PRNG。
//! - [`#![forbid(unsafe_code)]`](self) —— 整个 crate 不含 `unsafe`。
//!
//! # 现状
//!
//! 已完成工程地基与 M1 的 Base32 层；HOTP / TOTP 计算、`otpauth://` 解析、
//! 保险库（vault）管理、设备配对与同步正在推进。
//!
//! # 用法
//!
//! ```
//! // 版本号
//! assert_eq!(qualia2fa_core::VERSION, env!("CARGO_PKG_VERSION"));
//!
//! // Base32 解码（RFC 4648），容忍小写、缺失填充与空白
//! use qualia2fa_core::{base32, ExposeSecret};
//! let seed = base32::decode("MZXW6YTBOI======").expect("合法 Base32");
//! assert_eq!(seed.expose_secret(), b"foobar");
//! ```
//!
//! # 许可
//!
//! 以 GNU Lesser General Public License v3.0 or later（`LGPL-3.0-or-later`）授权，
//! 详见仓库根目录的 `COPYING.LESSER` 与 `LICENSE`。

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

pub mod base32;
mod error;
pub mod otp;
mod secret;
pub mod uri;
pub mod vault;

pub use error::{Error, Result};
pub use secret::{
    ExposeSecret, ExposeSecretMut, SecretBox, SecretBytes, SecretSlice, SecretString,
};

/// 再导出 OS CSPRNG，供上层（FFI / 端侧）取用**同一份**随机数实现。
///
/// 动机与 `secret.rs` 对 `secrecy` 的再导出相同：本 crate 是唯一声明
/// `getrandom` 依赖的地方，上层需要随机数时从这里取，而不是各自再声明一次——
/// 各自声明会让两边的版本要求各自漂移，最终在一个二进制里出现两份不同的
/// CSPRNG 包装。
///
/// 上层的用法是 `qualia2fa_core::getrandom::fill(&mut buf)`。
///
/// 注意：需要随机字节时应优先调用本库已有的高层 API；直接调这里是给
/// 「生成新种子」这类上层必须自己决定长度与用途的场景留的口子。
pub use getrandom;

/// 本库的版本号，取自 `Cargo.toml` 的 `package.version`。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_starts_with_a_digit() {
        assert!(
            VERSION.starts_with(char::is_numeric),
            "bad version: {VERSION}"
        );
    }

    #[test]
    fn version_has_three_semver_components() {
        assert_eq!(VERSION.split('.').count(), 3, "bad version: {VERSION}");
    }
}
