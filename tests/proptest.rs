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

//! 基于属性的测试。
//!
//! 与 `fuzz/` 下的 libFuzzer 目标分工：
//!
//! - **proptest（本文件）**：验证「对所有输入都应成立的**性质**」，用收缩
//!   （shrinking）给出最小反例。跑在 `cargo test` 里，CI 必然执行。
//! - **fuzz**：极大量随机输入 + 变异，找 panic、越界、挂起。需要显式触发。
//!
//! # 为什么这一层测的不是「显然成立」的东西
//!
//! 秘密类型的失败模式不是「算错」而是**泄露**：`Debug` 一旦把明文带出来，就可能
//! 落进日志、崩溃转储或遥测。这类 bug 不会被固定样例的单元测试发现，
//! 必须用「任意输入」来保证。
//!
//! 另外，这些性质同时是**对上游 `secrecy` 的回归防线**：将来升级 `secrecy` 时，
//! 若其脱敏行为发生变化，这里会直接失败。

use proptest::prelude::*;
use qualia2fa_core::{ExposeSecret, SecretBytes, SecretString};

/// 生成任意字节序列。
///
/// 上限取 2048 字节：既覆盖真实种子/密钥量级（20–64 字节），又给到手写
/// Base32 串、二维码载荷这类较长的输入，同时避免超长输入拖慢测试。
fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=2048)
}

proptest! {
    /// 性质：从 `Vec<u8>` 构造后取用，必须原样返回，不截断、不填充、不改写。
    #[test]
    fn expose_is_transparent(data in arb_bytes()) {
        let secret: SecretBytes = data.clone().into();
        prop_assert_eq!(secret.expose_secret(), data.as_slice());
    }

    /// 性质：`Clone` 必须逐字节一致。
    #[test]
    fn clone_is_exact(data in arb_bytes()) {
        let secret: SecretBytes = data.clone().into();
        let copy = secret.clone();
        prop_assert_eq!(copy.expose_secret(), secret.expose_secret());
    }

    /// 性质：`SecretString` 的构造与取用同样透明。
    ///
    /// 用 Rust 的 `String`（保证 UTF-8）作为输入，覆盖文本秘密路径。
    #[test]
    fn secret_string_is_transparent(text in ".*") {
        let secret = SecretString::from(text.clone());
        prop_assert_eq!(secret.expose_secret(), text.as_str());
    }

    /// **核心性质**：`Debug` 输出绝不含明文。
    ///
    /// 检查明文的十六进制与十进制两种表示。上游 `secrecy` 的 `Debug` 连长度都
    /// 不打印，因此这里**不**断言长度可读——只断言不泄露。
    ///
    /// 仅当长度 ≥ 4 时才做子串检查：更短的十进制串（如 2 字节的 "12"）会与
    /// `Debug` 里的类型名、数字等产生偶然碰撞，导致误报。
    #[test]
    fn debug_never_contains_plaintext(data in arb_bytes()) {
        let secret: SecretBytes = data.clone().into();
        let debug = format!("{secret:?}");
        let lower = debug.to_lowercase();

        // 必须标注脱敏。
        prop_assert!(
            lower.contains("redacted"),
            "Debug 未标注脱敏（长度 {}）：{}",
            data.len(),
            debug
        );

        if data.len() >= 4 {
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            prop_assert!(!lower.contains(&hex), "泄露十六进制明文：{}", debug);

            let decimal = data
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join("");
            prop_assert!(!debug.contains(&decimal), "泄露十进制明文：{}", debug);
        }
    }

    /// 性质：嵌套在 `#[derive(Debug)]` 结构里的秘密，同样不得泄露。
    #[test]
    fn debug_never_leaks_when_nested(data in arb_bytes()) {
        // 字段只用于构造 `Debug` 输出，不参与读取；`expect` 比 `allow` 严格：
        // 一旦这些字段真被读到，它会反过来报错提醒删除本属性。
        #[expect(
            dead_code,
            reason = "字段仅用于构造 Debug 输出；这是本测试的全部意图"
        )]
        #[derive(Debug)]
        struct Holder {
            /// 非秘密字段，用于确认 Debug 确实在输出内容。
            tag: u8,
            /// 秘密字段。
            secret: SecretBytes,
        }

        let holder = Holder { tag: 1, secret: data.clone().into() };
        let debug = format!("{holder:?}");

        if data.len() >= 4 {
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            prop_assert!(
                !debug.to_lowercase().contains(&hex),
                "嵌套 Debug 泄露十六进制明文：{}",
                debug
            );
        }
    }
}

// TODO(M1)：待 Base32 编解码实现后，在此追加往返性质：
//   base32_decode(base32_encode(bytes)) == bytes
// 以及 URI 序列化/解析的往返性质。当前这些入口尚不存在。
