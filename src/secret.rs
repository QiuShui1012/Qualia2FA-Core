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

//! 秘密材料容器。
//!
//! 本模块**不自己实现**秘密类型，而是把 [`secrecy`] 的能力按本项目的用法固定下来：
//! 统一导出、给出别名、并用测试锁住契约。库内所有密钥材料（OTP 种子、保险库主密钥、
//! 会话密钥）一律用这些类型承载。
//!
//! # 为什么选 `secrecy`
//!
//! - **依赖面极小**：`secrecy` 0.10.3 只有两个依赖——`zeroize ^1.6`（必需，且与
//!   本 crate 已用的 `zeroize 1.9.1` 同一 major，不产生重复版本）与 `serde ^1`
//!   （可选，本 crate **不启用**）。两者均 `default-features = false`。
//! - **仓库活跃**：上游 monorepo `iqlusioninc/crates` 未归档、最近推送时间即为当日，
//!   579 stars / 91 forks。
//! - **采用度极高**：累计下载 1.76 亿次，近 90 天 4660 万次——被持续实测。
//!
//! **已知事项（人工审计结论）**：`secrecy` **crate 本身自 2024-10-09 起无新版本发布**，
//! 而同一 monorepo 仍在活跃提交。这与「crate 已完成、接口稳定」是相容的，且其实现
//! 是纯逻辑封装（无 FFI、无 `unsafe`、无网络），但我们**不假设它会持续更新**：
//! 若上游长期无动作，替代成本很低（本模块是唯一接触点）。
//!
//! # 本模块导出的类型
//!
//! | 用途 | 类型 |
//! |---|---|
//! | 任意字节秘密（种子、密钥、nonce） | [`SecretSlice<u8>`] |
//! | 文本秘密（口令、恢复短语） | [`SecretString`] |
//! | 定长/其它秘密 | [`SecretBox`] |
//! | 取用明文 | [`ExposeSecret`] / [`ExposeSecretMut`] |
//!
//! # 现有边界（务必知晓）
//!
//! - **`secrecy` 的 `Debug` 连长度都不打印**（输出形如 `SecretSlice<u8>([REDACTED])`）。
//!   这比多数自建实现更保守：需要长度时请调用 [`ExposeSecret::expose_secret`] 自行取用，
//!   不要在 `Debug` 上做任何依赖。
//! - **只防「明文被打印 / 忘记擦除 / 误克隆」**，不防编译器把明文拷到寄存器、栈副本或
//!   交换区。`#![forbid(unsafe_code)]` 之下无法用 `mlock` 等机制阻止换页。
//! - **不防同进程内的恶意代码**：`expose_secret` 一旦调用，明文就在调用方手里。
//! - `Drop` 会擦除，但**不保证**编译器没有留下未被擦除的中间副本。

/// 字节型秘密：OTP 种子、主密钥、会话密钥等一律用它承载。
///
/// 之所以不是 `Vec<u8>` 的裸别名，是为了让「这是秘密」在类型上可见，
/// 从而无法被误当作普通字节流打印或序列化。
pub type SecretBytes = SecretSlice<u8>;

// 统一从本模块导出，使库内引用点只有一处；将来更换上游只改这里。
pub use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretSlice, SecretString};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_from_vec_and_expose_roundtrip() {
        let raw = vec![1_u8, 2, 3, 4, 5];
        let secret: SecretBytes = raw.clone().into();
        assert_eq!(secret.expose_secret(), raw.as_slice());
    }

    /// `Debug` 必须脱敏，且**不得出现明文的任何形态**。
    #[test]
    fn debug_never_leaks_bytes() {
        let secret: SecretBytes = vec![0xde_u8, 0xad, 0xbe, 0xef].into();
        let debug = format!("{secret:?}");
        let lower = debug.to_lowercase();

        assert!(lower.contains("redacted"), "Debug 未标注脱敏：{debug}");
        for leak in ["222", "173", "190", "239", "dead", "beef", "de ad"] {
            assert!(
                !lower.contains(leak),
                "Debug 输出泄露明文痕迹 {leak:?}：{debug}"
            );
        }
    }

    /// 秘密被裹进别的 `#[derive(Debug)]` 结构时同样不泄露。
    #[test]
    fn nested_in_derived_debug_still_safe() {
        #[expect(
            dead_code,
            reason = "字段仅用于构造 Debug 输出，不参与读取；这是本测试的全部意图"
        )]
        #[derive(Debug)]
        struct Wrapper {
            /// 业务字段，可打印。
            label: &'static str,
            /// 秘密字段，必须脱敏。
            secret: SecretBytes,
        }

        let w = Wrapper {
            label: "github",
            secret: vec![0xde_u8, 0xad].into(),
        };
        let text = format!("{w:?}");
        assert!(text.contains("github"), "非秘密字段应正常打印：{text}");
        assert!(!text.contains("222"), "嵌套 Debug 泄露明文：{text}");
    }

    /// 契约：秘密类型必须 `ZeroizeOnDrop`（Drop 时擦除）。
    ///
    /// `zeroize` 不是本 crate 的直接依赖，因此这里从 `secrecy::zeroize` 取用——
    /// 对方 `pub use zeroize`，可保证测试的是**实际生效的那个版本**，
    /// 而不是我们自己另指定的一份。
    #[test]
    fn zeroize_on_drop_contract_holds() {
        fn assert_zeroize_on_drop<T: secrecy::zeroize::ZeroizeOnDrop>() {}
        fn assert_zeroize<T: secrecy::zeroize::Zeroize>() {}
        assert_zeroize_on_drop::<SecretBytes>();
        assert_zeroize::<SecretBytes>();
        assert_zeroize_on_drop::<SecretString>();
    }

    /// 秘密必须可从 `Vec<u8>` 与 `String` 构造，覆盖实际调用路径。
    #[test]
    fn constructible_from_owned_input() {
        let bytes: SecretBytes = vec![0_u8; 32].into();
        assert_eq!(bytes.expose_secret().len(), 32);

        let text = SecretString::from("correct horse battery staple");
        assert_eq!(text.expose_secret(), "correct horse battery staple");
    }

    /// `SecretBytes`（即 `SecretSlice<u8>`）**可以**克隆：`u8` 实现了 `CloneableSecret`。
    /// 锁住该行为，避免将来升级 `secrecy` 时语义悄悄变化。
    ///
    /// 注意这**不是**鼓励克隆秘密——克隆会同时存在多份明文，各自独立擦除。
    /// 需要传参时优先传引用。
    #[test]
    fn secret_bytes_is_cloneable_and_clone_exposes_same() {
        let secret: SecretBytes = vec![9_u8, 8, 7].into();
        let copy = secret.clone();
        assert_eq!(copy.expose_secret(), secret.expose_secret());
        assert_eq!(copy.expose_secret(), &[9, 8, 7]);
    }

    /// 文档化一条**不可测**的约束：`SecretBox<T>` 本身不接受容器类型。
    ///
    /// `secrecy` 对 `CloneableSecret` 只为原始整数（`u8`…`u128`、`usize`）实现，
    /// **没有** `Vec<T>` / `String` / `Box<T>` 的实现。因此 `SecretBox<Vec<u8>>`
    /// **不可克隆**——这是上游拿类型系统拦住「秘密被静默复制」的手段。
    ///
    /// 该属性无法用运行时断言表达（`Clone` 是编译期能力，写 `secret.clone()` 会直接
    /// 编译失败）。因此这里只以注释记录，并**由本仓库的字节秘密一律使用
    /// `SecretSlice<u8>`（可克隆）来规避该限制**。若将来有人需要不可克隆的字节秘密，
    /// 应当改用 `SecretBox<[u8; N]>` 而不是试图绕过上游的约束。
    #[test]
    fn container_secret_box_is_not_cloneable_by_upstream_design() {
        // 用 `SecretBox` 包一个**原始整数**，确认它可克隆（与容器类型形成对照）。
        let scalar = SecretBox::new(Box::new(0xAB_u8));
        let copy = scalar.clone();
        assert_eq!(*copy.expose_secret(), 0xAB);
    }
}
