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

pub mod auth;
pub mod base32;
mod error;
pub mod flow;
pub mod otp;
pub mod pairing;
pub mod recovery;
mod secret;
pub mod sync;
pub mod transport;
pub mod uri;
pub mod vault;

pub use auth::{Responder, Verified, Verifier};
pub use error::{Error, Result};

/// 注册与登录编排的公开类型。
///
/// 只导出**用户旅程**这一层的类型与两个注入点。刻意不导出任何按步骤拆开的中间
/// 类型：调用方按顺序自己调 `vault`/`pairing`/`device` 是合法的，但那样做就绕开了
/// 本模块保证的顺序（见 [`flow`] 的模块文档），因此不在公开面上鼓励。
pub use flow::{DeviceKeys, Joiner, Login, Registered, SecureStore};

/// 设备身份的公开类型。
///
/// # 它们为什么是**再导出**而不是本 crate 定义的
///
/// 设备身份住在 [`qualia_dik`] 里——那是一个独立可复用的 crate，任何需要「平台硬件
/// 里的一对 P-256 身份密钥」的项目都能用它，不需要接受本 crate 的保险库格式或同步
/// 协议。这里再导出是为了让下游不必同时依赖两个 crate。
///
/// `DevicePublicKey` 与 `DeviceSignature` **不是秘密**——它们本来就要印在二维码
/// 上、写进日志、在设备之间传播，所以在这里与秘密类型分开导出，让「哪些类型
/// 可以随便打印」在导入列表里就看得出来。
pub use qualia_dik::{DeviceId, DevicePublicKey, DeviceSignature};

/// 配对协议的公开类型。
///
/// 只导出「两端各自需要的东西」：二维码载荷、两个方向的会话、以及结果。内部的
/// 会话密钥、确认标签计算等一律不导出——它们是协议不变量的一部分，不该被上层
/// 组合出别的用法。
pub use pairing::{Adoption, JoinerSession, NonceLog, PendingSession, QrPayload};

/// 恢复密钥的公开类型。
pub use recovery::{KdfParams, export as export_recovery, import as import_recovery};

/// 传输层的公开类型。
///
/// 只有**协议**那一半：能力声明、通道契约、会话，以及它的结果类型。具体通道
/// （局域网、二维码、热点）在端侧实现 [`Transport`]——它们都要 I/O 与平台 API，
/// 而本 crate 不碰那些。
///
/// 刻意**不**导出任何「按步骤拆开」的中间类型：调用方要么用 [`SyncSession`]，要么
/// 自己组合 `sync` 里的零件。前者能保证顺序，后者不能。
pub use transport::{
    Recipient, Roster, SyncOutcome, SyncSession, Transport, TransportCapabilities,
};

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
