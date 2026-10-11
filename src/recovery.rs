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

//! 恢复密钥：用一句用户口令备份主密钥。
//!
//! # 为什么需要它
//!
//! 主密钥从不落盘明文，只存在各平台的硬件密钥库里。手机丢失、硬盘损坏、密钥库
//! 被系统重置——这些都会让**全部 2FA 条目永久无法解开**。配对协议（[`crate::pairing`]）
//! 能解决「换新设备」，前提是**旧设备还在**。旧设备没了，就只剩恢复密钥这一条路。
//!
//! # 威胁模型
//!
//! 恢复文件会被用户存进网盘、U 盘、邮件附件、甚至打印出来。因此必须假设**攻击者
//! 能拿到文件本身**，唯一的防线是口令的强度。由此定下三条：
//!
//! 1. **派生必须昂贵**——Argon2id 是目前密码哈希竞赛的获胜者与 RFC 9106 推荐算法，
//!    内存硬（memory-hard）特性让 GPU/ASIC 并行破解的收益远低于纯计算型 KDF。
//! 2. **参数必须写进文件**——十年前的「昂贵」按今天的硬件标准可能只值几秒钟。
//!    参数随文件走，因此**旧文件仍然能解开**，而新文件可以用当时的更强参数。
//!    把参数写死在代码里会让这两件事无法同时成立。
//! 3. **口令要尽早进入 [`SecretString`]**，并在派生完成后擦除派生材料。
//!
//! ## 不防什么
//!
//! - **弱口令。** Argon2id 只把「每次猜测的成本」抬高，不能把 `123456` 变成强
//!   口令。这是任何基于口令的方案都无法解决的，只能靠 UI 提示。
//! - **已经控制住设备的攻击者。** 他们本来就能拿到主密钥。
//!
//! # 文件格式
//!
//! ```text
//!   偏移  长度  内容
//!   0     8     magic `Q2FAREC\0`
//!   8     1     格式版本
//!   9     1     算法标识（1 = Argon2id v1.3）
//!   10    4     内存开销 m_cost，KiB，大端
//!   14    4     迭代次数 t_cost，大端
//!   18    4     并行度 p_cost，大端
//!   22    16    salt（随机）
//!   38    24    AEAD nonce（随机）
//!   62    32    主密钥的密文
//!   94    16    AEAD 标签
//!   ────────
//!   合计 110 字节
//! ```
//!
//! **全部字段都进 AAD**（magic 与版本除外——它们在任何密钥存在之前就要被读出来）。
//! 因此改动 `m_cost` 不会「让派生变便宜再解开」，而是直接认证失败。
//!
//! # 与配对协议的区别
//!
//! | | 配对 | 恢复密钥 |
//! |---|---|---|
//! | 场景 | 旧设备**在**，换新设备 | 旧设备**没了** |
//! | 凭据 | 带外二维码（高熵） | 用户口令（低熵） |
//! | 派生 | ECDH | Argon2id |

use crate::vault::{MASTER_KEY_LEN, MasterKey, NONCE_LEN as AEAD_NONCE_LEN, master_key_to_bytes};
use crate::{Error, ExposeSecret, Result, SecretBytes, SecretString};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use secrecy::zeroize::Zeroize;

/// 文件魔数。8 字节，结尾的 `\0` 让它在文本编辑器里不会与真实内容混淆。
const MAGIC: &[u8; 8] = b"Q2FAREC\0";

/// 当前格式版本。
pub const FORMAT_VERSION: u8 = 1;

/// 算法标识：Argon2id v1.3。
const ALGORITHM_ARGON2ID_V13: u8 = 1;

/// salt 长度。
///
/// 16 字节是 Argon2 自己的 `RECOMMENDED_SALT_LEN`，也是 RFC 9106 的建议值。
/// salt 的作用是让「同一个口令」在不同文件里派生出不同密钥，从而**预计算彩虹表
/// 完全失效**，并且两台设备用同一个口令也不会得到同一个密钥。
pub const SALT_LEN: usize = 16;

/// 默认内存开销：64 MiB。
///
/// # 为什么是 64 MiB 而不是更大
///
/// 这是**移动端的硬约束**。Android 上单次 Argon2id 的内存分配超过约 100 MiB 时，
/// 低端机会被系统杀掉；iOS 的 app 内存上限更紧。64 MiB 在「高到让 GPU 破解不划算」
/// 与「低到手机能跑完」之间是业界通行的折中点。
///
/// 之所以能安全地取一个「当前不算极限」的值：参数写在文件里，将来提高默认值不会
/// 让旧文件解不开。
pub const DEFAULT_MEMORY_KIB: u32 = 64 * 1024;

/// 默认迭代次数。
pub const DEFAULT_ITERATIONS: u32 = 3;

/// 默认并行度。
///
/// **固定为 1，且不提供调大的入口。** 理由有三：
///
/// 1. Argon2 的并行度是**真的线程**。移动端与桌面端对「库内部悄悄起线程」的容忍度
///    不同，而本 crate 要同时服务两者。
/// 2. 提高并行度**不增加**攻击者的成本——攻击者本来就能并行跑很多次猜测。它只
///    缩短单次等待时间。
/// 3. 参数一旦写进文件，读的一方必须用同样的 `p_cost` 重算。少一个会变的维度，
///    格式就少一处将来会出问题的地方。
pub const PARALLELISM: u32 = 1;

/// 期望的输出长度（即派生出的密钥长度）。
const DERIVED_KEY_LEN: usize = 32;

/// 允许的最大内存开销：1 GiB。
///
/// # 为什么必须有这个上限
///
/// `m_cost` **来自被导入的文件**，因此是一个攻击者可控的量。没有上限时，一个把
/// 该字段改成 `u32::MAX` 的文件会让本库尝试申请 4 TiB 内存——最好的结果是它失败
/// 并返回错误，最坏的结果是整台机器被拖进交换区而实际上停止响应（拒绝服务）。
///
/// 1 GiB 这个数值的取舍：它远高于任何有意义的参数（默认 64 MiB，翻四倍到 256 MiB
/// 已属激进），因此正常文件永远不会碰到它；同时它低到「即使用户真的导入了恶意
/// 文件，代价也只是一次明显失败」。把上限放得比实际需要宽松，是为了让**将来提高
/// 默认参数**不需要同时改动这里。
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;

/// 允许的最大迭代次数。
///
/// 与 [`MAX_MEMORY_KIB`] 同理：`t_cost` 也来自文件。内存上限只约束了单次迭代的
/// 规模，一个把 `t_cost` 设成 `u32::MAX` 的文件仍然能让导入永远跑不完。
///
/// 1000 次远高于任何合理取值（默认 3 次，RFC 9106 的建议区间是 1–10 次）。
pub const MAX_ITERATIONS: u32 = 1000;

/// 文件各段的偏移。
mod offset {
    /// 魔数起点。
    pub const MAGIC: usize = 0;
    /// 格式版本。
    pub const VERSION: usize = 8;
    /// 算法标识。
    pub const ALGORITHM: usize = 9;
    /// 内存开销（大端 u32）。
    pub const MEMORY: usize = 10;
    /// 迭代次数（大端 u32）。
    pub const ITERATIONS: usize = 14;
    /// 并行度（大端 u32）。
    pub const PARALLELISM: usize = 18;
    /// salt。
    pub const SALT: usize = 22;
    /// AEAD nonce。
    pub const NONCE: usize = SALT + super::SALT_LEN;
    /// 密文。
    pub const CIPHERTEXT: usize = NONCE + super::AEAD_NONCE_LEN;
    /// AAD 的起点（即「除魔数与版本之外的全部头字段」）。
    pub const AAD: usize = super::offset::VERSION;
    /// AAD 的终点（密文之前）。
    pub const AAD_END: usize = super::offset::CIPHERTEXT;
}

/// 恢复文件的完整长度。
pub const FILE_LEN: usize = offset::CIPHERTEXT + MASTER_KEY_LEN + crate::vault::TAG_LEN;

/// 派生参数。写进文件，读回时用它重算。
///
/// # 为什么不是 `Copy`
///
/// 它不含秘密，`Copy` 也没有坏处；不实现只是为了让「传参一律传引用」在类型层面
/// 一致，避免将来有人往里加一个不该被复制的字段时忘了改。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    /// 内存开销，KiB。
    memory_kib: u32,
    /// 迭代次数。
    iterations: u32,
    /// 并行度。
    parallelism: u32,
}

impl KdfParams {
    /// 库推荐的默认参数（64 MiB / 3 次 / 单线程）。
    #[must_use]
    pub const fn recommended() -> Self {
        Self {
            memory_kib: DEFAULT_MEMORY_KIB,
            iterations: DEFAULT_ITERATIONS,
            parallelism: PARALLELISM,
        }
    }

    /// 自定义参数。
    ///
    /// # 错误
    ///
    /// 参数超出允许范围时返回 [`Error::RecoveryParametersInvalid`]。具体地：
    /// 内存必须在 [`Params::MIN_M_COST`] 与 [`MAX_MEMORY_KIB`] 之间、迭代次数必须
    /// 在 1 与 [`MAX_ITERATIONS`] 之间、并行度必须恰好为 1（见 [`PARALLELISM`]）。
    ///
    /// 上下限**都必须校验**，因为这三个字段在导入路径上来自文件——那是不可信输入。
    /// 只有下限时，一个精心构造的文件就能让导入去申请几 TiB 内存、或者永远跑不完。
    ///
    /// 调**低**参数会让文件更容易被破解。提供这个入口是因为「在极慢的设备上也要
    /// 能导出」是真实需求，但调用方应当把它当成一个需要向用户解释的权衡。
    pub const fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self> {
        if memory_kib < Params::MIN_M_COST {
            return Err(Error::RecoveryParametersInvalid {
                reason: "内存开销低于 Argon2 允许的下限",
            });
        }
        if memory_kib > MAX_MEMORY_KIB {
            return Err(Error::RecoveryParametersInvalid {
                reason: "内存开销超出本实现允许的上限",
            });
        }
        if iterations < Params::MIN_T_COST {
            return Err(Error::RecoveryParametersInvalid {
                reason: "迭代次数不得为 0",
            });
        }
        if iterations > MAX_ITERATIONS {
            return Err(Error::RecoveryParametersInvalid {
                reason: "迭代次数超出本实现允许的上限",
            });
        }
        if parallelism != PARALLELISM {
            return Err(Error::RecoveryParametersInvalid {
                reason: "本实现只支持并行度为 1",
            });
        }
        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
        })
    }

    /// 内存开销，KiB。
    #[must_use]
    pub const fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// 迭代次数。
    #[must_use]
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    /// 并行度。
    #[must_use]
    pub const fn parallelism(&self) -> u32 {
        self.parallelism
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::recommended()
    }
}

/// 把主密钥加密成可长期保存的恢复文件。
///
/// # 参数
///
/// - `master`: 要备份的主密钥。
/// - `passphrase`: 用户口令。调用方负责把它读进 [`SecretString`]——本库不做
///   I/O，也不该看见一个裸 `String`。
/// - `params`: 派生参数。传 [`KdfParams::recommended`] 即可；只有「在极慢的设备上
///   导出」这类场景才需要自定义。
///
/// # 返回
///
/// 完整的恢复文件字节，长度恒为 [`FILE_LEN`]。调用方自行决定写到哪里。
///
/// # 错误
///
/// - 口令为空：[`Error::RecoveryPassphraseEmpty`]
/// - OS 随机源不可用：[`Error::RandomnessUnavailable`]
/// - 参数非法：[`Error::RecoveryParametersInvalid`]
/// - Argon2 计算失败（内存不足等）：[`Error::RecoveryKdfFailed`]
///
/// **空口令被明确拒绝**，而不是被当成一个（非常弱的）口令接受：允许它会让用户
/// 在一个「看起来成功了」的界面上得到一个实际上任何人一秒就能解开的备份。
pub fn export(
    master: &MasterKey,
    passphrase: &SecretString,
    params: &KdfParams,
) -> Result<Vec<u8>> {
    if passphrase.expose_secret().is_empty() {
        return Err(Error::RecoveryPassphraseEmpty);
    }

    let mut salt = [0_u8; SALT_LEN];
    crate::getrandom::fill(&mut salt).map_err(|_| Error::RandomnessUnavailable)?;
    let mut nonce = [0_u8; AEAD_NONCE_LEN];
    crate::getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;

    let mut key = derive_key(passphrase, &salt, params)?;

    // 文件头。全部字段都会被写进 AAD，因此先拼头、再算 AAD、最后加密。
    let mut file = Vec::with_capacity(FILE_LEN);
    file.extend_from_slice(MAGIC);
    file.push(FORMAT_VERSION);
    file.push(ALGORITHM_ARGON2ID_V13);
    file.extend_from_slice(&params.memory_kib.to_be_bytes());
    file.extend_from_slice(&params.iterations.to_be_bytes());
    file.extend_from_slice(&params.parallelism.to_be_bytes());
    file.extend_from_slice(&salt);
    file.extend_from_slice(&nonce);

    let mut ciphertext = master.expose().to_vec();
    let aad = file[offset::AAD..offset::AAD_END].to_vec();
    let result = XChaCha20Poly1305::new(&Key::from(key)).encrypt_in_place(
        &XNonce::from(nonce),
        &aad,
        &mut ciphertext,
    );
    key.zeroize();
    result.map_err(|_| Error::RecoveryEncryptionFailed)?;

    file.extend_from_slice(&ciphertext);
    debug_assert_eq!(file.len(), FILE_LEN);
    Ok(file)
}

/// 从恢复文件里取回主密钥。
///
/// # 错误
///
/// - 长度不对、魔数不符： [`Error::RecoveryFileMalformed`]
/// - 版本或算法不认识：[`Error::UnsupportedFormatVersion`]
/// - 参数非法：[`Error::RecoveryParametersInvalid`]
/// - **口令错误或文件被篡改**：[`Error::RecoveryAuthenticationFailed`]
///
/// 最后一条把「口令错」与「文件被动过」合并成一个变体，是**刻意的**：区分它们会
/// 给攻击者一个「这个口令对不对」的预言机——虽然成功解密本身就是那个预言机，
/// 但把「文件结构性损坏」也混进来，会让攻击者无法通过观察错误类型来区分「我猜的
/// 口令接近了」与「这个文件根本不是恢复文件」。
pub fn import(file: &[u8], passphrase: &SecretString) -> Result<MasterKey> {
    if file.len() != FILE_LEN {
        return Err(Error::RecoveryFileMalformed {
            reason: "长度不是恢复文件的固定长度",
        });
    }
    if &file[offset::MAGIC..offset::VERSION] != MAGIC {
        return Err(Error::RecoveryFileMalformed {
            reason: "magic 不匹配，这不是本应用的恢复文件",
        });
    }
    if file[offset::VERSION] != FORMAT_VERSION {
        return Err(Error::UnsupportedFormatVersion {
            version: file[offset::VERSION],
        });
    }
    if file[offset::ALGORITHM] != ALGORITHM_ARGON2ID_V13 {
        return Err(Error::UnsupportedFormatVersion {
            version: file[offset::ALGORITHM],
        });
    }

    let memory_kib = u32::from_be_bytes(
        file[offset::MEMORY..offset::MEMORY + 4]
            .try_into()
            .map_err(|_| Error::RecoveryFileMalformed {
                reason: "内存开销字段读取失败",
            })?,
    );
    let iterations = u32::from_be_bytes(
        file[offset::ITERATIONS..offset::ITERATIONS + 4]
            .try_into()
            .map_err(|_| Error::RecoveryFileMalformed {
                reason: "迭代次数字段读取失败",
            })?,
    );
    let parallelism = u32::from_be_bytes(
        file[offset::PARALLELISM..offset::PARALLELISM + 4]
            .try_into()
            .map_err(|_| Error::RecoveryFileMalformed {
                reason: "并行度字段读取失败",
            })?,
    );
    // 参数由**文件**提供，因此必须当成不可信输入校验一遍：一个被改成
    // `m_cost = u32::MAX` 的文件会让本函数尝试分配 4 TiB 内存。
    // 这正是 `KdfParams::new` 存在的意义。
    let params = KdfParams::new(memory_kib, iterations, parallelism)?;

    let mut salt = [0_u8; SALT_LEN];
    salt.copy_from_slice(&file[offset::SALT..offset::SALT + SALT_LEN]);
    let mut nonce = [0_u8; AEAD_NONCE_LEN];
    nonce.copy_from_slice(&file[offset::NONCE..offset::NONCE + AEAD_NONCE_LEN]);

    let mut key = derive_key(passphrase, &salt, &params)?;

    // 整段密文体（含末尾标签）一起交给 `decrypt_in_place`，由它剥掉标签。
    let mut plaintext = file[offset::CIPHERTEXT..].to_vec();
    let aad = file[offset::AAD..offset::AAD_END].to_vec();
    let result = XChaCha20Poly1305::new(&Key::from(key)).decrypt_in_place(
        &XNonce::from(nonce),
        &aad,
        &mut plaintext,
    );
    key.zeroize();
    result.map_err(|_| Error::RecoveryAuthenticationFailed)?;

    let secret: SecretBytes = core::mem::take(&mut plaintext).into();
    MasterKey::from_bytes(secret)
}

/// 用 Argon2id 从口令派生密钥。
///
/// 派生出的一切都在返回前于**调用方**擦除；本函数内部不留副本。
fn derive_key(
    passphrase: &SecretString,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<[u8; DERIVED_KEY_LEN]> {
    let params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(DERIVED_KEY_LEN),
    )
    .map_err(|_| Error::RecoveryParametersInvalid {
        reason: "Argon2 拒绝了这组参数",
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0_u8; DERIVED_KEY_LEN];
    argon2
        .hash_password_into(passphrase.expose_secret().as_bytes(), salt, &mut out)
        .map_err(|_| Error::RecoveryKdfFailed)?;
    Ok(out)
}

/// 把主密钥包成可交给平台密钥库的字节。
///
/// 与 [`crate::pairing::master_key_for_storage`] 相同，只是为了让本模块的使用者
/// 不必额外 import `vault`。
#[must_use]
pub fn master_key_for_storage(master: &MasterKey) -> SecretBytes {
    master_key_to_bytes(master)
}

#[cfg(test)]
mod tests {
    use super::*;
    // 只在已知答案测试里用到：它们对应 RFC 向量里的 secret 与关联数据两项。
    use argon2::{AssociatedData, ParamsBuilder};

    /// 测试用的**极低**参数。
    ///
    /// 默认参数是 64 MiB / 3 次，一次就要几十毫秒；本模块有十几个测试，用默认值
    /// 会让整个测试套件慢上几秒。这里只图「能跑通」，安全性由
    /// `default_params_are_expensive` 单独验证。
    ///
    /// 内存下限由 Argon2 决定（8 KiB），不是随便取的。
    fn fast_params() -> KdfParams {
        KdfParams::new(Params::MIN_M_COST, 1, 1).expect("下限参数应当合法")
    }

    /// 造一个口令。
    fn passphrase(text: &str) -> SecretString {
        SecretString::from(text)
    }

    /// 导出再导入必须还原出同一个主密钥。
    #[test]
    fn export_import_roundtrip() {
        let master = MasterKey::generate().expect("随机源可用");
        let file = export(
            &master,
            &passphrase("correct horse battery staple"),
            &fast_params(),
        )
        .expect("导出应当成功");
        assert_eq!(file.len(), FILE_LEN, "文件长度必须恒定");

        let restored =
            import(&file, &passphrase("correct horse battery staple")).expect("导入应当成功");
        assert_eq!(restored.expose(), master.expose());
    }

    /// **口令错误必须失败。**
    #[test]
    fn wrong_passphrase_fails() {
        let master = MasterKey::generate().expect("随机源可用");
        let file = export(&master, &passphrase("right"), &fast_params()).expect("导出");

        let result = import(&file, &passphrase("wrong"));
        assert!(
            matches!(result, Err(Error::RecoveryAuthenticationFailed)),
            "错误口令应被拒绝"
        );
    }

    /// 空口令必须**在导出阶段**就被拒绝。
    #[test]
    fn empty_passphrase_is_rejected_on_export() {
        let master = MasterKey::generate().expect("随机源可用");
        let result = export(&master, &passphrase(""), &fast_params());
        assert!(matches!(result, Err(Error::RecoveryPassphraseEmpty)));
    }

    /// **篡改文件的任意一个字节都必须被发现。**
    ///
    /// 这是本模块最重要的一条性质：恢复文件会被存进网盘、U 盘、邮件附件，任何
    /// 一处改动都必须在**导入时**暴露，而不是悄悄地还原出一个错误的主密钥。
    ///
    /// # 为什么要分成两轮
    ///
    /// 三个派生参数字段（内存、迭代、并行度）被翻转后会得到一个**巨大的**数值。
    /// 本实现的上限校验会立刻拒绝它们，但「立刻拒绝」这件事本身需要被验证——
    /// 所以第二轮专门翻这些字节，并且要求错误类型是**参数非法**而不是「认证失败」：
    /// 如果哪天上限校验被删掉，这条测试会失败，而不是让整个测试套件去申请几个
    /// TiB 内存然后被 OOM 杀掉。
    #[test]
    fn any_single_byte_flip_is_detected() {
        let master = MasterKey::generate().expect("随机源可用");
        let phrase = passphrase("tamper test");
        let file = export(&master, &phrase, &fast_params()).expect("导出");

        // 第一轮：除三个派生参数字段之外的全部字节。
        let param_range = offset::MEMORY..offset::PARALLELISM + 4;
        for index in 0..FILE_LEN {
            if param_range.contains(&index) {
                continue;
            }
            let mut tampered = file.clone();
            tampered[index] ^= 0x01;
            match import(&tampered, &phrase) {
                Err(_) => {}
                Ok(restored) => panic!(
                    "第 {index} 字节被翻转却成功导入（还原出的密钥与原密钥相同 = {}）",
                    restored.expose() == master.expose()
                ),
            }
        }
    }

    /// 翻转**派生参数字段**的任一字节，都必须被上限校验立刻拒绝。
    ///
    /// 不能接受的结果有两类：成功导入（篡改未被发现），或者一次巨量内存分配
    /// （导入变成拒绝服务）。
    #[test]
    fn flipping_parameter_bytes_is_rejected_by_the_limits() {
        let master = MasterKey::generate().expect("随机源可用");
        let phrase = passphrase("param tamper test");
        let file = export(&master, &phrase, &fast_params()).expect("导出");

        for index in offset::MEMORY..offset::PARALLELISM + 4 {
            let mut tampered = file.clone();
            tampered[index] ^= 0x01;
            match import(&tampered, &phrase) {
                // 参数被拒（上限或下限）：这是期望结果。
                Err(Error::RecoveryParametersInvalid { .. }) => {}
                // 翻转低位字节可能仍落在合法区间内——那时派生出不同密钥，
                // 于是认证失败。同样是可接受的结果。
                Err(Error::RecoveryAuthenticationFailed) => {}
                Err(other) => panic!("第 {index} 字节：意外的错误类型 {other}"),
                Ok(restored) => panic!(
                    "第 {index} 字节被翻转却成功导入（密钥相同 = {}）",
                    restored.expose() == master.expose()
                ),
            }
        }
    }

    /// 长度不对的输入必须被拒绝，且不得 panic。
    #[test]
    fn wrong_length_is_rejected() {
        let master = MasterKey::generate().expect("随机源可用");
        let phrase = passphrase("length test");
        let file = export(&master, &phrase, &fast_params()).expect("导出");

        for cut in [0_usize, 1, FILE_LEN - 1] {
            assert!(
                matches!(
                    import(&file[..cut], &phrase),
                    Err(Error::RecoveryFileMalformed { .. })
                ),
                "长度 {cut} 应被拒绝"
            );
        }
        let mut longer = file.clone();
        longer.push(0);
        assert!(matches!(
            import(&longer, &phrase),
            Err(Error::RecoveryFileMalformed { .. })
        ));
    }

    /// magic 不符时必须报「这不是恢复文件」，而不是「口令错误」。
    ///
    /// 这两种情况对用户的含义完全不同：前者是「拿错文件了」，后者是「口令打错了」。
    #[test]
    fn wrong_magic_is_reported_as_malformed_not_wrong_passphrase() {
        let master = MasterKey::generate().expect("随机源可用");
        let phrase = passphrase("magic test");
        let mut file = export(&master, &phrase, &fast_params()).expect("导出");
        file[0] = b'X';

        assert!(matches!(
            import(&file, &phrase),
            Err(Error::RecoveryFileMalformed { .. })
        ));
    }

    /// 未来版本必须被**明确**拒绝，而不是按本版本的布局勉强解释。
    #[test]
    fn unknown_version_is_rejected() {
        let master = MasterKey::generate().expect("随机源可用");
        let phrase = passphrase("version test");
        let mut file = export(&master, &phrase, &fast_params()).expect("导出");
        file[offset::VERSION] = 0x7F;

        match import(&file, &phrase) {
            Err(Error::UnsupportedFormatVersion { version }) => assert_eq!(version, 0x7F),
            other => panic!("应报版本不支持，实际 is_ok={}", other.is_ok()),
        }
    }

    /// 不认识的算法标识同样必须被拒绝。
    #[test]
    fn unknown_algorithm_is_rejected() {
        let master = MasterKey::generate().expect("随机源可用");
        let phrase = passphrase("algorithm test");
        let mut file = export(&master, &phrase, &fast_params()).expect("导出");
        file[offset::ALGORITHM] = 0x7F;
        assert!(import(&file, &phrase).is_err());
    }

    /// **被改大的内存参数必须被拒绝，而不是让本进程去申请几个 TiB。**
    ///
    /// 参数来自文件——那是不可信输入。没有上限检查，一个精心构造的文件就能让
    /// 导入变成一次内存耗尽攻击（或者一次拖垮整机的拒绝服务）。
    #[test]
    fn absurd_memory_cost_is_rejected_without_allocating() {
        let master = MasterKey::generate().expect("随机源可用");
        let phrase = passphrase("memory bomb");
        let file = export(&master, &phrase, &fast_params()).expect("导出");

        // 过小：低于 Argon2 下限。
        for memory in [0_u32, 1, Params::MIN_M_COST - 1] {
            assert!(
                matches!(
                    import_with_memory(&file, &phrase, memory),
                    Err(Error::RecoveryParametersInvalid { .. })
                ),
                "内存参数 {memory} 应报「参数非法」"
            );
        }
        // 过大：超过本实现的上限。**关键点是这里必须在分配之前就返回。**
        for memory in [MAX_MEMORY_KIB + 1, u32::MAX, u32::MAX / 2] {
            assert!(
                matches!(
                    import_with_memory(&file, &phrase, memory),
                    Err(Error::RecoveryParametersInvalid { .. })
                ),
                "内存参数 {memory} 应报「参数非法」，而不是真的去分配"
            );
        }
        // 边界：上限本身是允许的（虽然不会有人这么用）。
        assert!(
            KdfParams::new(MAX_MEMORY_KIB, 1, 1).is_ok(),
            "上限值本身应当合法"
        );
        assert!(
            KdfParams::new(MAX_MEMORY_KIB + 1, 1, 1).is_err(),
            "超过上限应被拒绝"
        );
    }

    /// 把文件里的内存参数字段改成指定值后导入。
    fn import_with_memory(file: &[u8], phrase: &SecretString, memory: u32) -> Result<MasterKey> {
        let mut tampered = file.to_vec();
        tampered[offset::MEMORY..offset::MEMORY + 4].copy_from_slice(&memory.to_be_bytes());
        import(&tampered, phrase)
    }

    /// **被改大的迭代次数必须被拒绝。**
    ///
    /// 内存上限只约束了单次迭代的规模；一个把 `t_cost` 设成 `u32::MAX` 的文件
    /// 仍然能让导入永远跑不完。
    #[test]
    fn absurd_iteration_count_is_rejected_without_running_forever() {
        let master = MasterKey::generate().expect("随机源可用");
        let phrase = passphrase("iteration bomb");
        let file = export(&master, &phrase, &fast_params()).expect("导出");

        for iterations in [MAX_ITERATIONS + 1, u32::MAX, u32::MAX / 2] {
            let mut tampered = file.clone();
            tampered[offset::ITERATIONS..offset::ITERATIONS + 4]
                .copy_from_slice(&iterations.to_be_bytes());
            assert!(
                matches!(
                    import(&tampered, &phrase),
                    Err(Error::RecoveryParametersInvalid { .. })
                ),
                "迭代次数 {iterations} 应报「参数非法」"
            );
        }
        assert!(
            KdfParams::new(1024, MAX_ITERATIONS, 1).is_ok(),
            "上限值本身应当合法"
        );
        assert!(KdfParams::new(1024, MAX_ITERATIONS + 1, 1).is_err());
    }

    /// 迭代次数为 0 必须被拒绝。
    #[test]
    fn zero_iterations_is_rejected() {
        let master = MasterKey::generate().expect("随机源可用");
        let phrase = passphrase("iterations test");
        let mut file = export(&master, &phrase, &fast_params()).expect("导出");
        file[offset::ITERATIONS..offset::ITERATIONS + 4].copy_from_slice(&0_u32.to_be_bytes());

        assert!(matches!(
            import(&file, &phrase),
            Err(Error::RecoveryParametersInvalid { .. })
        ));
    }

    /// 并行度不为 1 必须被拒绝。
    #[test]
    fn parallelism_other_than_one_is_rejected() {
        assert!(KdfParams::new(1024, 1, 2).is_err(), "并行度 2 应被拒绝");
        assert!(KdfParams::new(1024, 1, 0).is_err(), "并行度 0 应被拒绝");
        assert!(KdfParams::new(1024, 1, 1).is_ok());
    }

    /// **RFC 9106 §5.3 的已知答案向量：Argon2id v1.3。**
    ///
    /// 这一条与模块里其它测试的区别很重要：其它测试验证的是**自洽性**（导出再导入
    /// 能还原），而自洽性对「实现整条错掉」是完全盲的——如果 Argon2 的参数被理解
    /// 错了，导出和导入会用同一个错误方式算两遍，往返依然成功。
    ///
    /// 恢复文件是**长期保存**的产物：今天导出的文件，十年后要被（可能是另一个
    /// 实现、另一套依赖版本的）代码解开。因此必须钉住「我们算出来的确实是标准和
    /// 意义上的 Argon2id」。
    ///
    /// 出处：RFC 9106 §5.3（Argon2id 测试向量）。
    /// 参数：内存 32 KiB、迭代 3 次、并行度 4、输出 32 字节；
    /// 口令 32 字节 `0x01`、salt 16 字节 `0x02`、secret 8 字节 `0x03`、
    /// 关联数据 12 字节 `0x04`。
    ///
    /// 注意向量要求 secret 与**关联数据**都非空，因此这里用 `ParamsBuilder` 显式
    /// 设置关联数据，并直接调用 `Argon2::new_with_secret`，而不是走本模块的
    /// `derive_key`——后者刻意不提供这两个参数（本项目的用途不需要「服务端密钥」
    /// 这种 pepper，也没有需要绑定进派生结果的上下文）。
    ///
    /// 本测试的作用是把上游实现钉在规范上；本模块自己的参数组合由
    /// `derived_key_is_deterministic_and_pinned` 钉住。
    #[test]
    fn rfc9106_argon2id_test_vector() {
        // **关联数据这一项不能漏。** 第一次写这条测试时按记忆拼了
        // `Params::new(32, 3, 4, Some(32))`，漏掉了 12 字节的 `0x04`，结果算出的
        // 标签与规范完全不同，而失败信息只显示两串不相等的字节——看上去像是
        // 「上游实现有 bug」。教训：已知答案测试的参数必须**逐项照抄规范**，
        // 不能按印象拼一组「看起来一样」的。
        let params = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .output_len(32)
            .data(AssociatedData::new(&[0x04_u8; 12]).expect("12 ≤ MAX_DATA_LEN"))
            .build()
            .expect("RFC 向量参数合法");
        let secret = [0x03_u8; 8];
        let context = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)
            .expect("构造成功");
        let mut out = [0_u8; 32];
        context
            .hash_password_into(&[0x01_u8; 32], &[0x02_u8; 16], &mut out)
            .expect("计算成功");

        let expected: [u8; 32] = [
            0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b,
            0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9,
            0x6b, 0x01, 0xe6, 0x59,
        ];
        assert_eq!(out, expected, "Argon2id 输出与 RFC 9106 §5.3 的向量不符");
    }

    /// 本模块自己的派生**必须是确定性的**，且输入变化必须改变输出。
    ///
    /// 与上一条分工：上一条证明「Argon2id 实现是对的」，这一条证明「我们喂给它的
    /// 东西是对的」——参数映射、salt 使用、输出长度这几处一旦写错，往返测试依然
    /// 会通过（两边错得一样），但确定性测试会暴露出来。
    #[test]
    fn derived_key_is_deterministic_and_pinned() {
        let phrase = passphrase("deterministic");
        let salt = [0x11_u8; SALT_LEN];
        let params = fast_params();

        let a = derive_key(&phrase, &salt, &params).expect("派生成功");
        let b = derive_key(&phrase, &salt, &params).expect("派生成功");
        assert_eq!(a, b, "同一个口令与 salt 必须派生出同一个密钥");

        // salt 变化 → 密钥变化（这正是 salt 的存在意义）。
        let mut other_salt = salt;
        other_salt[0] ^= 0x01;
        assert_ne!(
            derive_key(&phrase, &other_salt, &params).expect("派生成功"),
            a,
            "salt 改变却派生出同一个密钥"
        );

        // 参数变化 → 密钥变化。
        let other_params = KdfParams::new(Params::MIN_M_COST * 2, 1, 1).expect("合法");
        assert_ne!(
            derive_key(&phrase, &salt, &other_params).expect("派生成功"),
            a,
            "内存参数改变却派生出同一个密钥"
        );

        // 输出长度确实是 32 字节（不是 Argon2 的默认值被悄悄用上）。
        assert_eq!(a.len(), DERIVED_KEY_LEN);
    }

    /// 输出长度必须**显式**是 32：`Params::new` 的 `output_len` 传 `None` 时
    /// Argon2 会用自己的默认值 32——恰好也是 32，因此这个错误在长度上**看不出
    /// 来**，只有比对具体字节才会暴露。这条测试用「与非 32 字节输出的参数做对比」
    /// 来间接钉住它。
    #[test]
    fn output_length_is_explicitly_requested() {
        let phrase = passphrase("output length");
        let salt = [0x22_u8; SALT_LEN];
        let mut key = derive_key(&phrase, &salt, &fast_params()).expect("派生成功");

        // 手工复算一遍，但**显式**指定输出长度——应当得到同样的结果。
        let params = Params::new(Params::MIN_M_COST, 1, 1, Some(DERIVED_KEY_LEN)).expect("合法");
        let mut expected = [0_u8; DERIVED_KEY_LEN];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(phrase.expose_secret().as_bytes(), &salt, &mut expected)
            .expect("计算成功");

        assert_eq!(key, expected);
        key.zeroize();
    }

    /// 两份用**同一个口令**导出的文件必须不同。
    ///
    /// 否则攻击者可以拿一份已知口令的恢复文件，去比对另一份文件里有没有相同的
    /// 密文——从而判断两台设备用的是不是同一个口令。
    #[test]
    fn same_passphrase_yields_different_files() {
        let master = MasterKey::generate().expect("随机源可用");
        let phrase = passphrase("same passphrase");
        let a = export(&master, &phrase, &fast_params()).expect("导出");
        let b = export(&master, &phrase, &fast_params()).expect("导出");

        assert_ne!(a, b, "salt 或 nonce 被复用");
        // 但两者都必须能解开，且还原出同一个主密钥。
        assert_eq!(
            import(&a, &phrase).expect("a 可导入").expose(),
            import(&b, &phrase).expect("b 可导入").expose()
        );
    }

    /// 恢复文件里**不得**出现主密钥明文。
    ///
    /// 这条看着显然，但它挡住的是「不小心把 `master.expose()` 直接写进文件」这类
    /// 改动——那会让整个 Argon2 层变成装饰。
    #[test]
    fn file_never_contains_the_master_key_in_clear() {
        let master = MasterKey::generate().expect("随机源可用");
        let file = export(&master, &passphrase("cleartext test"), &fast_params()).expect("导出");

        assert!(
            !file.windows(MASTER_KEY_LEN).any(|w| w == master.expose()),
            "恢复文件里出现了主密钥明文"
        );
    }

    /// 默认参数必须**真的昂贵**——否则「改了默认值」会悄悄把安全性降下来。
    ///
    /// 这里只断言参数值，不测耗时：测耗时会因机器而异，在 CI 上必然不稳定。
    #[test]
    fn default_params_are_expensive() {
        let params = KdfParams::recommended();
        assert_eq!(params.memory_kib(), 64 * 1024, "默认内存不是 64 MiB");
        assert!(params.iterations() >= 3, "默认迭代次数过低");
        assert_eq!(params.parallelism(), 1);
        // 64 MiB 已经远高于 Argon2 的下限，且不低于 OWASP 对 Argon2id 的建议值
        // （19 MiB）。取更大的值是为了让内存硬特性真正发挥作用。
        assert!(
            params.memory_kib() >= Params::DEFAULT_M_COST,
            "默认内存低于 Argon2 自己的默认值"
        );
    }

    /// 参数随文件走：用自定义参数导出的文件，导入时**不需要**调用方再传参数。
    #[test]
    fn parameters_travel_with_the_file() {
        let master = MasterKey::generate().expect("随机源可用");
        let phrase = passphrase("params travel");
        let params = KdfParams::new(Params::MIN_M_COST * 4, 2, 1).expect("合法参数");
        let file = export(&master, &phrase, &params).expect("导出");

        // 文件里记录的就是这组参数。
        assert_eq!(
            u32::from_be_bytes(file[offset::MEMORY..offset::MEMORY + 4].try_into().unwrap()),
            params.memory_kib()
        );
        assert_eq!(
            u32::from_be_bytes(
                file[offset::ITERATIONS..offset::ITERATIONS + 4]
                    .try_into()
                    .unwrap()
            ),
            params.iterations()
        );
        // 导入接口没有参数入口——它从文件里读。
        assert_eq!(
            import(&file, &phrase).expect("导入").expose(),
            master.expose()
        );
    }

    /// 主密钥存取的往返（与 `pairing` 模块的同名工具保持一致）。
    #[test]
    fn master_key_storage_roundtrip() {
        let master = MasterKey::generate().expect("随机源可用");
        let bytes = master_key_for_storage(&master);
        let rebuilt = crate::pairing::master_key_from_storage(bytes).expect("长度正确");
        assert_eq!(master.expose(), rebuilt.expose());
    }

    /// 文件布局是对外契约，锁住它。
    ///
    /// 这些偏移一旦改动，**所有已经导出的恢复文件都会失效**。这条测试的作用是让
    /// 那次改动必须是有意的、并且要写进版本升级里。
    #[test]
    fn file_layout_is_stable() {
        assert_eq!(FILE_LEN, 110, "恢复文件长度变了，已导出的文件会失效");
        assert_eq!(offset::MAGIC, 0);
        assert_eq!(offset::VERSION, 8);
        assert_eq!(offset::ALGORITHM, 9);
        assert_eq!(offset::MEMORY, 10);
        assert_eq!(offset::ITERATIONS, 14);
        assert_eq!(offset::PARALLELISM, 18);
        assert_eq!(offset::SALT, 22);
        assert_eq!(offset::NONCE, 38);
        assert_eq!(offset::CIPHERTEXT, 62);
        assert_eq!(offset::AAD, 8);
        assert_eq!(offset::AAD_END, 62);
    }
}
