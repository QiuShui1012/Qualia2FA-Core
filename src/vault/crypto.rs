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

//! 保险库的密码学原语：主密钥、子密钥派生、条目 AEAD。
//!
//! # 这一层负责什么
//!
//! 只负责「把一段字节加密成另一段字节」以及密钥材料的生命周期。文件格式、
//! 条目语义、原子落盘都在别的模块——把格式与密码学混在一起会让「改格式」
//! 与「动密码学」变成同一件事，那是审计上最糟的耦合。
//!
//! # 三个不可协商的性质
//!
//! 1. **随机 nonce 必须 192-bit**。多设备各自独立加密、无中心协调，随机 nonce
//!    是唯一现实选择；96-bit 在保险库规模下会撞生日界。见 [`Nonce::LEN`]。
//! 2. **AAD 必须绑定条目身份与格式版本**。否则攻击者可以把条目 A 的密文搬到
//!    条目 B 的位置，或者把一个旧格式的密文塞进新格式的文件——两种搬运都不会
//!    被 AEAD 发现，因为密文本身完全合法。见 [`build_aad`]。
//! 3. **主密钥必须经 HKDF 派生子密钥后再使用**，不能直接当 AEAD 密钥。
//!    见 [`entry_key`]。

use super::entry::EntryId;
use crate::{Error, ExposeSecret, Result, SecretBytes};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// 主密钥的字节长度。
///
/// 256-bit。对称密码的密钥长度超过 256-bit 不带来实际安全增益（Grover 算法
/// 下的 128-bit 有效强度已是量子搜索的极限），却会让「恢复密钥」变长、
/// 更难人工抄写。
pub const MASTER_KEY_LEN: usize = 32;

/// 主密钥：256-bit CSPRNG 随机数。
///
/// # 它是整个应用唯一的长期秘密
///
/// OTP 种子、设备身份、同步内容全部由它派生或加密。「无中心、无账号密码」
/// 的设计下没有找回途径——**丢了就丢了**。这也是 M3 要把它放进平台硬件密钥库
/// （Windows TPM）的原因。
///
/// # 秘密保护的边界
///
/// - 不实现 `Clone`（那会静默复制明文）、不实现 `Debug` 的明文输出
/// - `Drop` 时擦除（由 [`SecretBytes`] 保证）
/// - **不防**编译器把明文复制到寄存器、栈副本或交换区；`forbid(unsafe_code)`
///   之下无法用 `mlock` 阻止换页
/// - **不防**同进程内的恶意代码。取用明文必须显式调用 [`MasterKey::expose`]，
///   使每一处使用点在代码审查中可见
pub struct MasterKey(SecretBytes);

impl MasterKey {
    /// 生成一个新的随机主密钥。
    ///
    /// # 错误
    ///
    /// OS 随机源不可用时返回 [`Error::RandomnessUnavailable`]。此时**必须失败**，
    /// 不得回退到任何用户态 PRNG：一个可预测的主密钥会让攻击者解密全部条目，
    /// 而且这种失败是静默的——用户看到功能正常，直到数据被读走。
    pub fn generate() -> Result<Self> {
        let mut bytes = [0_u8; MASTER_KEY_LEN];
        crate::getrandom::fill(&mut bytes).map_err(|_| Error::RandomnessUnavailable)?;
        // 用一个会被立即擦除的中间数组承接：`SecretBytes` 从 `Vec` 构造，
        // 那个 `Vec` 的所有权会转移进 `secrecy`，由它负责擦除。
        Ok(Self(Vec::from(bytes).into()))
    }

    /// 从已有字节恢复主密钥。
    ///
    /// **安全性契约**：调用方必须保证 `bytes` 来自可信来源且随后被擦除。
    /// 这个函数存在的唯一理由是 M3 的设备登录——主密钥需要从平台密钥库或
    /// 带外信道（二维码）取回。**不要**用它把主密钥存进普通文件。
    ///
    /// # 错误
    ///
    /// 长度不是 [`MASTER_KEY_LEN`] 时返回 [`Error::MasterKeyWrongLength`]。
    /// 长度错误必须拒绝而不是补齐或截断：补齐会静默降低强度，截断会让两台
    /// 设备派生出不同子密钥，表现为「同步后条目全都解不开」这种极难定位的故障。
    pub fn from_bytes(bytes: SecretBytes) -> Result<Self> {
        if bytes.expose_secret().len() != MASTER_KEY_LEN {
            return Err(Error::MasterKeyWrongLength {
                expected: MASTER_KEY_LEN,
                actual: bytes.expose_secret().len(),
            });
        }
        Ok(Self(bytes))
    }

    /// 显式取用主密钥明文。
    ///
    /// 之所以不实现 `Deref` 或 `AsRef`：那样「取明文」会在无数地方静默发生，
    /// 而显式方法名让每一处使用点在 `grep` 与代码审查中可见。
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl core::fmt::Debug for MasterKey {
    /// 只打印类型名，**连长度都不打印**。
    ///
    /// 长度在这里没有诊断价值（它是一个常量），所以没有理由打印它。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

/// 主密钥的序列化形式。
///
/// **只供 M3 的设备登录流程使用**：把主密钥交给平台密钥库或二维码封装。
/// 返回的容器会在 `Drop` 时擦除，但调用方仍须尽快交出去。
#[must_use]
pub fn master_key_to_bytes(key: &MasterKey) -> SecretBytes {
    // `SecretBytes`（`SecretSlice<u8>`）可克隆——此处刻意如此：调用方需要一份
    // 独立的所有权去交给密钥库，而克隆出的两份会各自独立擦除。
    key.0.clone()
}

/// nonce 的字节长度。
///
/// **192-bit，这不是可调参数。** 多设备各自独立加密、彼此无中心协调，
/// 随机 nonce 是唯一现实选择；而 96-bit nonce 在随机取值下会撞生日界——
/// 保险库规模下 `aes-gcm` 的随机 nonce 用法属于已知不安全。
pub const NONCE_LEN: usize = 24;

/// Poly1305 认证标签的字节长度。
pub const TAG_LEN: usize = 16;

/// 一条记录的加密 nonce。
///
/// 每次加密都**新生成**一个，不复用、不递增。递增计数器需要跨设备协调，
/// 而本应用没有协调中心。
pub type Nonce = [u8; NONCE_LEN];

/// 生成一个新的随机 nonce。
pub(crate) fn random_nonce() -> Result<Nonce> {
    let mut nonce = [0_u8; NONCE_LEN];
    crate::getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;
    Ok(nonce)
}

/// 子密钥派生用的 HKDF 上下文串。
///
/// # 为什么派生而不直接用主密钥
///
/// 主密钥将来还要参与设备配对与恢复流程（M3/M4）。用途分离意味着即使某个
/// 子密钥在某个场景下泄露，也不会连带暴露主密钥本身，更不会让攻击者能用
/// 同一个密钥去解开别的用途的数据。
///
/// 串里带版本号（`v1`）：将来若更换算法或密钥长度，新版本用新串，旧数据仍可
/// 用旧串解开——这比在文件里存一个算法标识更简单，且不扩大攻击面。
const HKDF_INFO_ENTRY: &[u8] = b"Qualia2FA vault v1 entry encryption";

/// HKDF 的 salt。
///
/// # 为什么是固定的空值
///
/// HKDF 的 salt 用于「多个不相关协议共享同一份输入密钥材料」的场景。这里
/// 输入材料（主密钥）本来就是 256-bit 均匀随机、专用于本应用，不存在需要
/// salt 来分离的多协议共享局面。固定为全零同时保证了派生结果是**确定性的**：
/// 同一主密钥在任何设备上都派生出同一子密钥，否则同步过来的条目将无法解开。
///
/// 域分离由 [`HKDF_INFO_ENTRY`] 承担，那才是这个场景的正确工具。
const HKDF_SALT: [u8; 32] = [0_u8; 32];

/// 从主密钥派生用于条目加密的子密钥。
///
/// 每次调用都重新派生而不缓存：HKDF 的代价是两次 HMAC-SHA256，在 30 秒一次的
/// 验证码场景下完全可以忽略，而缓存意味着子密钥要在内存里多活一段时间。
fn entry_key(master: &MasterKey) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(&HKDF_SALT), master.expose());
    let mut key = [0_u8; 32];
    // `expand` 只在输出长度超过 255 * HashLen 时失败，32 字节不可能触发。
    // 仍然不 `unwrap`：库内「任何输入都不得 panic」的约定不允许例外。
    hkdf.expand(HKDF_INFO_ENTRY, &mut key)
        .map_err(|_| Error::VaultDecryptionFailed)?;
    Ok(key)
}

/// 记录的种类，参与 AAD 构造。
///
/// # 为什么种类必须进 AAD
///
/// 「活条目」与「墓碑」用的是同一个密钥、同一种 AEAD。若种类不进 AAD，
/// 攻击者可以把一条墓碑记录的密文搬到活条目的位置，让一个条目凭空消失
/// （或反过来，把已删除的条目复活）。两者都是合法密文，AEAD 不会察觉。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordKind {
    /// 活条目。
    Entry,
    /// 墓碑（删除记录）。
    Tombstone,
}

impl RecordKind {
    /// 写入文件与参与 AAD 的字节值。
    pub(crate) const fn as_byte(self) -> u8 {
        match self {
            Self::Entry => 0x01,
            Self::Tombstone => 0x02,
        }
    }

    /// 从文件读到的字节还原种类。
    ///
    /// 未知值一律拒绝（返回 `None`）而不是当作活条目处理：把未知种类当成
    /// 「大概是个条目」会让一个未来版本写出的墓碑被旧版本当成活条目复活。
    pub(crate) const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Entry),
            0x02 => Some(Self::Tombstone),
            _ => None,
        }
    }
}

/// AAD 的字节长度：1（种类）+ 16（entry_id）+ 1（格式版本）。
const AAD_LEN: usize = 1 + EntryId::LEN + 1;

/// 构造附加认证数据（AAD）。
///
/// # 它防住的三件事
///
/// 1. **密文跨条目搬运**——把条目 A 的密文复制到条目 B 的位置。AAD 含
///    `entry_id`，位置一变认证即失败。
/// 2. **密文跨种类搬运**——把墓碑密文当作条目密文（删除被静默撤销），
///    或反过来（条目被静默删除）。AAD 含 [`RecordKind`]。
/// 3. **密文跨格式版本搬运**——把旧格式的密文塞进新格式的文件，绕过新格式
///    的额外校验。AAD 含格式版本。
///
/// # 为什么不做成可读的结构
///
/// 固定长度的字节串比任何自描述编码都更难写错，也更容易逐字节核对。
/// 它的布局必须与 [`crate::vault::FORMAT_VERSION`] 一同演进。
pub(crate) fn build_aad(kind: RecordKind, entry_id: &EntryId, format_version: u8) -> [u8; AAD_LEN] {
    let mut aad = [0_u8; AAD_LEN];
    aad[0] = kind.as_byte();
    aad[1..1 + EntryId::LEN].copy_from_slice(entry_id.as_bytes());
    aad[AAD_LEN - 1] = format_version;
    aad
}

/// 加密一段记录明文。
///
/// 返回的密文**含** 16 字节 Poly1305 认证标签（追加在末尾），因此长度是
/// `plaintext.len() + TAG_LEN`。调用方把 nonce 一并存进文件——nonce 不是秘密，
/// 但被篡改会导致解密失败，而失败正是我们要的结果。
///
/// # 错误
///
/// 只可能因随机源不可用而失败（[`Error::RandomnessUnavailable`]）。加密本身
/// 不会失败：XChaCha20-Poly1305 对任意长度的输入都有定义，不存在「明文太长」
/// 这类情况。
pub(crate) fn seal(
    master: &MasterKey,
    kind: RecordKind,
    entry_id: &EntryId,
    format_version: u8,
    plaintext: &[u8],
) -> Result<(Nonce, Vec<u8>)> {
    let key = entry_key(master)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(key));
    let nonce = random_nonce()?;
    let aad = build_aad(kind, entry_id, format_version);
    let mut buffer = plaintext.to_vec();
    // 原地加密，避免再多一份明文副本在内存里停留。
    cipher
        .encrypt_in_place(&XNonce::from(nonce), &aad, &mut buffer)
        .map_err(|_| Error::VaultDecryptionFailed)?;
    Ok((nonce, buffer))
}

/// 解密一段记录密文。
///
/// # 错误
///
/// 认证失败一律返回 [`Error::VaultDecryptionFailed`]，**不区分**「密钥不对」
/// 「密文被篡改」「AAD 不匹配」三种原因。区分它们对攻击者有用（可以据此判断
/// 猜测的密钥是否正确、篡改的是哪一部分），对使用者没有可操作价值——三种
/// 情况的应对都是「这份保险库打不开」。
pub(crate) fn open(
    master: &MasterKey,
    kind: RecordKind,
    entry_id: &EntryId,
    format_version: u8,
    nonce: &Nonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let key = entry_key(master)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(key));
    let aad = build_aad(kind, entry_id, format_version);
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place(&XNonce::from(*nonce), &aad, &mut buffer)
        .map_err(|_| Error::VaultDecryptionFailed)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> MasterKey {
        MasterKey::generate().expect("OS 随机源可用")
    }

    #[test]
    fn master_key_is_32_bytes_and_debug_is_redacted() {
        let k = key();
        assert_eq!(k.expose().len(), MASTER_KEY_LEN);

        let debug = format!("{k:?}");
        assert!(debug.contains("REDACTED"), "Debug 未脱敏：{debug}");
        // 明文不得以十进制或十六进制形态出现。
        for byte in k.expose() {
            assert!(
                !debug.contains(&format!("{byte}")),
                "Debug 泄露了密钥字节：{debug}"
            );
        }
    }

    #[test]
    fn master_key_rejects_wrong_length() {
        for len in [0_usize, 1, 31, 33, 64] {
            let bytes: SecretBytes = vec![0_u8; len].into();
            match MasterKey::from_bytes(bytes) {
                Err(Error::MasterKeyWrongLength { expected, actual }) => {
                    assert_eq!(expected, MASTER_KEY_LEN);
                    assert_eq!(actual, len);
                }
                other => panic!("长度 {len} 应被拒绝，实际 ok={}", other.is_ok()),
            }
        }
    }

    #[test]
    fn master_key_accepts_exactly_32_bytes() {
        let bytes: SecretBytes = vec![7_u8; MASTER_KEY_LEN].into();
        let k = MasterKey::from_bytes(bytes).expect("长度正确");
        assert_eq!(k.expose(), &[7_u8; MASTER_KEY_LEN]);
    }

    /// 同一主密钥必须派生出同一子密钥，否则同步过来的条目解不开。
    #[test]
    fn derived_key_is_deterministic() {
        let bytes: SecretBytes = vec![3_u8; MASTER_KEY_LEN].into();
        let a = MasterKey::from_bytes(bytes.clone()).expect("长度正确");
        let b = MasterKey::from_bytes(bytes).expect("长度正确");
        assert_eq!(
            entry_key(&a).expect("可派生"),
            entry_key(&b).expect("可派生")
        );
    }

    /// 不同主密钥必须派生出不同子密钥。
    #[test]
    fn derived_key_differs_per_master_key() {
        let a = MasterKey::from_bytes(vec![1_u8; MASTER_KEY_LEN].into()).expect("长度正确");
        let b = MasterKey::from_bytes(vec![2_u8; MASTER_KEY_LEN].into()).expect("长度正确");
        assert_ne!(
            entry_key(&a).expect("可派生"),
            entry_key(&b).expect("可派生")
        );
    }

    /// 子密钥**不得**等于主密钥本身。
    ///
    /// 若派生被误实现成恒等映射（例如 info 拼错导致走了一条退化路径），
    /// 这个测试会抓住它。
    #[test]
    fn derived_key_is_not_the_master_key() {
        let bytes: SecretBytes = vec![5_u8; MASTER_KEY_LEN].into();
        let k = MasterKey::from_bytes(bytes).expect("长度正确");
        assert_ne!(
            entry_key(&k).expect("可派生"),
            *k.expose().first_chunk::<32>().expect("32 字节")
        );
    }

    #[test]
    fn seal_then_open_roundtrips() {
        let k = key();
        let id = EntryId::generate().expect("OS 随机源可用");
        let plaintext = b"the quick brown fox";

        let (nonce, ciphertext) = seal(&k, RecordKind::Entry, &id, 1, plaintext).expect("可加密");
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_LEN);
        assert_ne!(
            &ciphertext[..plaintext.len()],
            &plaintext[..],
            "密文与明文相同"
        );

        let opened = open(&k, RecordKind::Entry, &id, 1, &nonce, &ciphertext).expect("可解密");
        assert_eq!(opened, plaintext);
    }

    /// 每次加密必须用新 nonce——随机 nonce 的安全性依赖这一点。
    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let k = key();
        let id = EntryId::generate().expect("OS 随机源可用");
        let (n1, _) = seal(&k, RecordKind::Entry, &id, 1, b"same").expect("可加密");
        let (n2, _) = seal(&k, RecordKind::Entry, &id, 1, b"same").expect("可加密");
        assert_ne!(n1, n2, "两次加密复用了 nonce");
    }

    /// 同一明文两次加密的密文必须不同（否则等于泄露「这两条内容相同」）。
    #[test]
    fn ciphertext_is_not_deterministic() {
        let k = key();
        let id = EntryId::generate().expect("OS 随机源可用");
        let (_, c1) = seal(&k, RecordKind::Entry, &id, 1, b"same").expect("可加密");
        let (_, c2) = seal(&k, RecordKind::Entry, &id, 1, b"same").expect("可加密");
        assert_ne!(c1, c2);
    }

    /// 换一个主密钥必须解不开。
    #[test]
    fn wrong_master_key_fails() {
        let id = EntryId::generate().expect("OS 随机源可用");
        let (nonce, ciphertext) =
            seal(&key(), RecordKind::Entry, &id, 1, b"secret").expect("可加密");
        let err = open(&key(), RecordKind::Entry, &id, 1, &nonce, &ciphertext);
        assert!(matches!(err, Err(Error::VaultDecryptionFailed)));
    }

    /// **AAD 的核心测试**：密文跨条目搬运必须失败。
    #[test]
    fn ciphertext_cannot_move_between_entry_ids() {
        let k = key();
        let a = EntryId::generate().expect("OS 随机源可用");
        let b = EntryId::generate().expect("OS 随机源可用");
        let (nonce, ciphertext) = seal(&k, RecordKind::Entry, &a, 1, b"payload").expect("可加密");

        // 原位置能解开
        assert!(open(&k, RecordKind::Entry, &a, 1, &nonce, &ciphertext).is_ok());

        // 搬到另一个 entry_id 的位置必须失败
        let err = open(&k, RecordKind::Entry, &b, 1, &nonce, &ciphertext);
        assert!(
            matches!(err, Err(Error::VaultDecryptionFailed)),
            "密文被搬运到别的条目却仍能解开"
        );
    }

    /// 密文跨种类搬运必须失败（墓碑冒充条目、条目冒充墓碑）。
    #[test]
    fn ciphertext_cannot_move_between_kinds() {
        let k = key();
        let id = EntryId::generate().expect("OS 随机源可用");

        let (nonce, ciphertext) = seal(&k, RecordKind::Entry, &id, 1, b"payload").expect("可加密");
        assert!(open(&k, RecordKind::Tombstone, &id, 1, &nonce, &ciphertext).is_err());

        let (nonce2, ciphertext2) =
            seal(&k, RecordKind::Tombstone, &id, 1, b"payload").expect("可加密");
        assert!(open(&k, RecordKind::Entry, &id, 1, &nonce2, &ciphertext2).is_err());
    }

    /// 密文跨格式版本搬运必须失败。
    #[test]
    fn ciphertext_cannot_move_between_format_versions() {
        let k = key();
        let id = EntryId::generate().expect("OS 随机源可用");
        let (nonce, ciphertext) = seal(&k, RecordKind::Entry, &id, 1, b"payload").expect("可加密");
        assert!(open(&k, RecordKind::Entry, &id, 2, &nonce, &ciphertext).is_err());
    }

    /// **篡改密文、nonce、标签的任意一个字节都必须失败。**
    ///
    /// 逐个位置翻转，覆盖密文体、nonce 全部 24 字节、以及标签 16 字节。
    #[test]
    fn flipping_any_ciphertext_byte_fails_authentication() {
        let k = key();
        let id = EntryId::generate().expect("OS 随机源可用");
        let plaintext = b"0123456789abcdef0123456789abcdef";
        let (nonce, ciphertext) = seal(&k, RecordKind::Entry, &id, 1, plaintext).expect("可加密");

        for index in 0..ciphertext.len() {
            let mut tampered = ciphertext.clone();
            tampered[index] ^= 0x01;
            let err = open(&k, RecordKind::Entry, &id, 1, &nonce, &tampered);
            assert!(
                matches!(err, Err(Error::VaultDecryptionFailed)),
                "密文第 {index} 字节被翻转却仍通过认证"
            );
        }

        for index in 0..NONCE_LEN {
            let mut tampered = nonce;
            tampered[index] ^= 0x01;
            let err = open(&k, RecordKind::Entry, &id, 1, &tampered, &ciphertext);
            assert!(
                matches!(err, Err(Error::VaultDecryptionFailed)),
                "nonce 第 {index} 字节被翻转却仍通过认证"
            );
        }
    }

    /// AAD 的长度与布局是对外契约（写进文件语义），锁住它。
    #[test]
    fn aad_layout_is_stable() {
        let id = EntryId::from_bytes([0xAB; EntryId::LEN]);
        let aad = build_aad(RecordKind::Entry, &id, 1);
        assert_eq!(aad.len(), AAD_LEN);
        assert_eq!(aad[0], 0x01, "种类字节");
        assert_eq!(&aad[1..17], &[0xAB; 16], "entry_id 应紧随其后");
        assert_eq!(aad[17], 1, "格式版本应在末字节");

        assert_eq!(build_aad(RecordKind::Tombstone, &id, 7)[0], 0x02);
        assert_eq!(build_aad(RecordKind::Tombstone, &id, 7)[17], 7);
    }

    /// 种类字节必须能往返，且未知值被拒绝。
    #[test]
    fn record_kind_byte_roundtrips_and_rejects_unknown() {
        for kind in [RecordKind::Entry, RecordKind::Tombstone] {
            assert_eq!(RecordKind::from_byte(kind.as_byte()), Some(kind));
        }
        for unknown in [0_u8, 3, 0xFF] {
            assert_eq!(RecordKind::from_byte(unknown), None);
        }
    }

    /// 空明文也必须能往返（边界）。
    #[test]
    fn empty_plaintext_roundtrips() {
        let k = key();
        let id = EntryId::generate().expect("OS 随机源可用");
        let (nonce, ciphertext) = seal(&k, RecordKind::Entry, &id, 1, b"").expect("可加密");
        assert_eq!(ciphertext.len(), TAG_LEN, "空明文只剩标签");
        let opened = open(&k, RecordKind::Entry, &id, 1, &nonce, &ciphertext).expect("可解密");
        assert!(opened.is_empty());
    }

    /// 截断密文必须失败——不能把「标签不完整」当成合法短明文。
    #[test]
    fn truncated_ciphertext_fails() {
        let k = key();
        let id = EntryId::generate().expect("OS 随机源可用");
        let (nonce, ciphertext) = seal(&k, RecordKind::Entry, &id, 1, b"payload").expect("可加密");

        for cut in 1..=ciphertext.len() {
            let truncated = &ciphertext[..ciphertext.len() - cut];
            let err = open(&k, RecordKind::Entry, &id, 1, &nonce, truncated);
            assert!(
                matches!(err, Err(Error::VaultDecryptionFailed)),
                "截断 {cut} 字节后仍通过认证"
            );
        }
    }

    /// `master_key_to_bytes` 必须给出可用于重建的字节。
    #[test]
    fn master_key_bytes_roundtrip() {
        let original = MasterKey::from_bytes(vec![9_u8; MASTER_KEY_LEN].into()).expect("长度正确");
        let bytes = master_key_to_bytes(&original);
        let rebuilt = MasterKey::from_bytes(bytes).expect("长度正确");
        assert_eq!(original.expose(), rebuilt.expose());
    }
}
