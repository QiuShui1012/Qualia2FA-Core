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

//! 加密保险库：本地存储格式、条目加解密、原子落盘。
//!
//! # 威胁模型
//!
//! 保险库文件被假定**可以被攻击者完整读写**。它会经过用户自己选的网盘、
//! 二维码、另一台设备，这些通道都不受本应用控制。因此：
//!
//! - 文件里除 [`EntryId`] 之外**没有任何明文语义**。连「这是 TOTP 还是 HOTP」
//!   都看不出来，因为那在密文里。
//! - 任何一个字节被改动都必须导致解密失败，而不是悄悄解出一份被篡改的数据。
//! - 攻击者能观察到的只有「有多少条条目」「每条密文多长」。
//!
//! **长度本身仍会泄露信息**（用户备注的长短、账号名的长短）。要掩盖它需要
//! 填充到定长块，代价是文件变大数倍。当前不做，但这是已知的、有意的取舍。
//!
//! # 文件格式 v2
//!
//! 全部整数为**大端**。布局：
//!
//! ```text
//! 偏移      长度   内容
//! 0         8      魔数 "Q2FAVLT\0"
//! 8         1      格式版本（当前 2）
//! 9         1      保留字节（必须为 0，拒绝非 0 以便将来扩展时不误读旧文件）
//! 10        4      记录数（大端 u32）
//! 14        ...    记录，紧邻排列
//! 末尾      32     主密钥检查值
//! ```
//!
//! 每条记录：
//!
//! ```text
//! 偏移      长度        内容
//! 0         1           记录种类（1 = 活条目，2 = 墓碑）
//! 1         16          条目 ID
//! 17        24          XChaCha20-Poly1305 nonce
//! 41        4           密文长度（大端 u32）
//! 45        N           密文（含 16 字节认证标签）
//! ```
//!
//! **记录尾部不做对齐填充**，也不在记录之间放校验和——AEAD 的认证标签已经覆盖了
//! 「这条记录是否完整、是否属于这个位置、是否属于这个版本」，再加一层校验和只会
//! 增加出错面。文件末尾那 32 字节不是校验和：它是主密钥检查值，回答的是「这个
//! 文件是不是用这把密钥写的」，而记录标签回答的是「这条记录有没有被改过」。
//!
//! ## 版本 1 的文件仍然可读
//!
//! 版本 1 没有末尾那 32 字节，解析时跳过检查值那一步即可，其余完全相同。这是
//! 刻意的：用户升级应用之后，他原有的文件必须还能打开。
//!
//! **反向不成立。** 版本 1 的解析器会拒绝版本 2 的文件，因为它有一条「拒绝任何
//! 尾部多余字节」的检查，而那 32 字节在它看来就是多余内容。补救它要解锁那条检查，
//! 而解锁会让「文件被追加过内容」这个事实静默消失——代价比「旧版本打不开新文件」
//! 更大。旧版本用户看到的是一个明确的错误，不是一份错乱的数据。
//!
//! # 密钥从哪里来
//!
//! 文件本身**不含**主密钥，也不含任何由它派生的可验证信息。主密钥存放在平台
//! 硬件密钥库（M3，Windows TPM）。这意味着**主密钥丢失 = 数据永久无法解密**，
//! 这是「无中心、无账号密码」设计的必然代价。

mod codec;
mod crypto;
mod entry;

pub use crypto::{
    KEY_CHECK_LEN, MASTER_KEY_LEN, MasterKey, NONCE_LEN, TAG_LEN, key_check, master_key_to_bytes,
    verify_key_check,
};
pub use entry::{Entry, EntryId, Timestamp, entry_from_parsed_uri};

use std::collections::BTreeMap;
use std::path::Path;

use crate::{Error, Result, otp};
use codec::{Reader, put_bytes, put_u32};
use crypto::RecordKind;
use entry::Entry as VaultEntry;

/// 文件魔数。8 字节，末尾的 NUL 让它在十六进制编辑器里就能认出来。
pub const MAGIC: &[u8; 8] = b"Q2FAVLT\0";

/// 当前写入的格式版本。
///
/// # 版本 2 与版本 1 的区别只有一处：文件末尾多了主密钥检查值
///
/// 目的是让「这个文件是用哪把主密钥写的」能在**读第一条记录之前**判定。版本 1
/// 里主密钥只参与每条记录的 AEAD，于是**一个条目为空的文件对任何 32 字节密钥都
/// 能解析成功**——密钥存错了要等到加进第一条条目才暴露，而那时界面早已显示
/// 「打开成功」。
///
/// # 这个常量**同时**是记录 AAD 里的版本号
///
/// 因此它不能只表示「布局长什么样」：AAD 里换了号，旧记录的标签就全部验不过。
/// 解析时用的**必须是被解析的那个文件自己声明的版本**，不能是这个常量——否则读
/// 一个版本 1 的旧文件会全线认证失败。见 [`VaultFile::parse`] 里的 `version`。
///
/// # 版本 1 仍然可读
///
/// 版本 1 的文件没有检查值，`parse` 会跳过那一步校验，行为与从前一致（包括那条
/// 已知限制）。反过来**不成立**：版本 1 的解析器会因为末尾多出的字节拒绝版本 2
/// 的文件（它有一条「拒绝任何尾部多余字节」的检查），并报
/// [`Error::VaultTrailingBytes`] 而不是版本不支持。这是版本 1 设计时没有为「更
/// 丰富的未来版本」留出跳过路径的直接后果，无法在不解锁这个检查的前提下补救——
/// 而解锁它等于让「文件被追加过内容」这个事实静默消失，代价更大。
pub const FORMAT_VERSION: u8 = 2;

/// 能解析的格式版本集合。
///
/// 只增不改：一个版本号一旦进入这个列表就不能移除，否则用户手里的旧文件会突然
/// 打不开，而错误信息（「版本不支持」）会让人以为文件坏了。
///
/// 暴露出来是为了让「旧版本仍可读」这条承诺能被测试直接钉住，而不是靠测试去
/// 复述一遍版本号——那样两边一起改就永远不会失败。
pub const READABLE_VERSIONS: &[u8] = &[1, FORMAT_VERSION];

/// 单条记录的密文长度上限。
///
/// # 为什么必须设限
///
/// 记录长度来自文件内容，而文件是攻击者可控的。若不加限制，一个 100 字节的
/// 恶意文件可以声称「下一条记录有 4 GiB」，解析器就会尝试分配它。
///
/// 1 MiB 远大于任何真实条目：即使每条可变长字段都顶到
/// [`Entry::MAX_FIELD_LEN`]（64 KiB），一个条目也就几百 KiB。
pub const MAX_RECORD_LEN: usize = 1024 * 1024;

/// 记录条数上限。
///
/// 同样是为了挡住「声称有 40 亿条」的恶意文件。100 万条 2FA 条目对任何真实
/// 用户都远远够用。
pub const MAX_RECORDS: usize = 1_000_000;

/// 明文条目的字段标签。
///
/// # 为什么用节点编码而不是固定布局
///
/// 每个节点带标签与长度，未知标签可以**按长度跳过**。这让新版本增加字段时
/// 旧版本仍能读出它认识的字段，而不是整个文件解析失败——用户不会因为
/// 「用了新版本存过一次」就在旧版本里再也打不开保险库。
///
/// 这个性质有代价：解析器必须能正确处理「跳过未知节点」，而跳过的实现一旦
/// 写错就是越界。因此有一个专门的 fuzz 目标盯着它。
mod tag {
    /// 显示名。
    pub(super) const NAME: u8 = 0x01;
    /// 发行方。
    pub(super) const ISSUER: u8 = 0x02;
    /// 账号名。
    pub(super) const ACCOUNT: u8 = 0x03;
    /// OTP 种子（原始字节，不是 Base32）。
    pub(super) const SECRET: u8 = 0x04;
    /// HMAC 算法。
    pub(super) const ALGORITHM: u8 = 0x05;
    /// 验证码位数。
    pub(super) const DIGITS: u8 = 0x06;
    /// TOTP 周期（秒）。
    pub(super) const PERIOD: u8 = 0x07;
    /// HOTP 计数器。
    pub(super) const COUNTER: u8 = 0x08;
    /// 备注。
    pub(super) const NOTE: u8 = 0x09;
    /// 创建时间。
    pub(super) const CREATED_AT: u8 = 0x0A;
    /// 最后修改时间。
    pub(super) const UPDATED_AT: u8 = 0x0B;
    /// 墓碑的删除时间。
    pub(super) const DELETED_AT: u8 = 0x0C;
    /// 墓碑的发起设备（尚未使用，为 M4 的「发起方裁定」预留）。
    pub(super) const DELETED_BY: u8 = 0x0D;

    /// 算法字段的取值。
    pub(super) const ALG_SHA1: u8 = 1;
    /// 算法字段的取值。
    pub(super) const ALG_SHA256: u8 = 2;
    /// 算法字段的取值。
    pub(super) const ALG_SHA512: u8 = 3;

    /// 位数：6 位。
    pub(super) const DIGITS_SIX: u8 = 6;
    /// 位数：7 位。
    pub(super) const DIGITS_SEVEN: u8 = 7;
    /// 位数：8 位。
    pub(super) const DIGITS_EIGHT: u8 = 8;
}

/// 一条删除记录。
///
/// # 为什么删除要留记录
///
/// 直接删掉条目会让「另一台设备还有这条」变成无法裁决的局面：那台设备同步
/// 过来时，本机看到一条自己从没见过的条目，只能当成新条目加回来——删除被
/// 静默撤销。墓碑让「我删过它」成为一个可同步的事实。
///
/// # 墓碑里没有明文
///
/// 墓碑**不含**被删条目的名称、账号或种子。它只有 ID 与时间戳，且整个记录
/// 同样被 AEAD 加密。攻击者拿到文件后无法从墓碑得知「用户删掉过哪个服务」。
///
/// # 保留期限
///
/// 墓碑**不设过期**。这与「取并集」的同步语义一致：只要有一台设备从未见过
/// 这条删除，墓碑就有用。代价是文件会随删除次数缓慢增长，而这是可以接受的
/// ——每条墓碑 45 字节密文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tombstone {
    /// 被删除条目的 ID。
    pub entry_id: EntryId,
    /// 删除时间（Unix 秒）。
    pub deleted_at: Timestamp,
    /// 发起删除的设备 ID。
    ///
    /// 当前恒为 `None`：设备身份在 M3 才建立。这个字段是为设计决定 D2 的
    /// 「裁决冲突由发起方裁定」预留的——届时墓碑要记录是哪台设备删的。
    pub deleted_by: Option<EntryId>,
}

/// 一个解密后的保险库。
///
/// # 顺序是确定的
///
/// 内部用 [`BTreeMap`] 而不是 `HashMap`：序列化结果必须**逐字节可复现**。
/// 否则同一份内容在两台设备上会产生不同的文件，让「文件是否相同」这个最
/// 直观的一致性判据失效，也会让测试里的往返比较变得不可靠。
#[derive(Debug, Default)]
pub struct Vault {
    /// 活条目，按 ID 排序。
    entries: BTreeMap<EntryId, VaultEntry>,
    /// 墓碑，按 ID 排序。
    tombstones: BTreeMap<EntryId, Tombstone>,
}

impl Vault {
    /// 创建空保险库。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 条目数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否没有任何活条目（墓碑不计入）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 墓碑数。
    #[must_use]
    pub fn tombstone_count(&self) -> usize {
        self.tombstones.len()
    }

    /// 按 ID 遍历活条目，顺序确定。
    pub fn iter(&self) -> impl Iterator<Item = (&EntryId, &VaultEntry)> {
        self.entries.iter()
    }

    /// 按 ID 取一条条目。
    #[must_use]
    pub fn get(&self, id: &EntryId) -> Option<&VaultEntry> {
        self.entries.get(id)
    }

    /// 按 ID 取一条墓碑。
    #[must_use]
    pub fn get_tombstone(&self, id: &EntryId) -> Option<&Tombstone> {
        self.tombstones.get(id)
    }

    /// 插入一条条目，返回它的 ID。
    ///
    /// # 为什么由本方法分配 ID
    ///
    /// ID 必须来自 CSPRNG，而把「生成 ID」暴露给调用方等于请它自己保证这一点。
    /// 调用方拿到 ID 后要做的是显示与排错，不是自行构造。
    ///
    /// # 错误
    ///
    /// OS 随机源不可用时返回 [`Error::RandomnessUnavailable`]。
    pub fn insert(&mut self, entry: VaultEntry) -> Result<EntryId> {
        let id = EntryId::generate()?;
        // 同 ID 覆盖在实践中不可达（128-bit 随机），但显式处理比假设更好：
        // 覆盖时必须同时清掉同名墓碑，否则会出现「条目存在且被标记删除」。
        self.tombstones.remove(&id);
        self.entries.insert(id, entry);
        Ok(id)
    }

    /// 用指定的 ID 插入条目。
    ///
    /// **只供解析已存在的保险库文件使用。** 创建新条目请用
    /// [`Vault::insert`]，否则两台设备会独立生成相同 ID，同步时静默合并成
    /// 一条、丢掉另一条。
    ///
    /// # 错误
    ///
    /// 该 ID 已有活条目时返回 [`Error::VaultDuplicateEntryId`]。这是拒绝而不是
    /// 覆盖：文件里出现重复 ID 意味着它被构造或损坏过，静默取其一会让用户
    /// 悄悄丢掉一条条目。
    pub fn insert_with_id(&mut self, id: EntryId, entry: VaultEntry) -> Result<()> {
        if self.entries.contains_key(&id) {
            return Err(Error::VaultDuplicateEntryId);
        }
        self.entries.insert(id, entry);
        Ok(())
    }

    /// 用新内容替换一条**已存在**的条目，标识不变，且**不留下墓碑**。
    ///
    /// # 为什么必须有这个入口，而不能用「删掉再插入」
    ///
    /// 标识是设备之间谈论「同一条条目」的唯一依据。若修改走「删掉 + 用新标识插入」
    /// 的路子，另一台设备在同步时会把它读成「删了一条、又加了一条」，于是那条条目
    /// 的历史与墓碑全部错位——用户看到的是改名之后条目变成了两条，或者原来的被删掉。
    ///
    /// 走「先用 [`Vault::remove`] 再 [`Vault::insert_with_id`]」也不行：`remove`
    /// 会**按设计**留下墓碑，而一次改名不是删除。墓碑一旦留下就会被同步出去，另一
    /// 端可能据此把条目真的删掉。
    ///
    /// # 调用方的责任
    ///
    /// 创建时间（`created_at`）由调用方决定保不保留。经验做法是**保留**：它记录的
    /// 是「用户什么时候把这条加进来的」，改一次名字就变掉会让界面上的排序跳位。
    ///
    /// # 错误
    ///
    /// 该 ID 没有活条目时返回 [`Error::VaultEntryNotFound`]。这是拒绝而不是退化成
    /// 「新增」：调用方以为自己在改一条已有的条目（例如用户在编辑界面点了保存），
    /// 而它其实已经不在了（另一端删掉了），此时应当提示用户刷新，而不是凭空把它
    /// 加回去。
    pub fn replace(&mut self, id: EntryId, entry: VaultEntry) -> Result<()> {
        if !self.entries.contains_key(&id) {
            return Err(Error::VaultEntryNotFound);
        }
        self.entries.insert(id, entry);
        Ok(())
    }

    /// 删除一条条目，留下墓碑。
    ///
    /// 返回被删掉的条目（若存在），以便调用方实现撤销。
    ///
    /// `now` 由调用方传入（本库不读时钟）。
    ///
    /// # 为什么返回条目而不是就地丢弃
    ///
    /// `OtpSecret` 的明文需要由调用方决定如何处理——通常是交给 UI 做「撤销」
    /// 提示。本库不替它做决定，也不把它留在内存里更久。
    pub fn remove(&mut self, id: &EntryId, now: Timestamp) -> Option<VaultEntry> {
        let removed = self.entries.remove(id)?;
        // 若已有墓碑则保留原时间：重复删除不应刷新删除时间，否则一台设备反复
        // 删除会让墓碑看起来比另一台设备的选择更新，干扰 D2 的裁决。
        self.tombstones.entry(*id).or_insert_with(|| Tombstone {
            entry_id: *id,
            deleted_at: now,
            deleted_by: None,
        });
        Some(removed)
    }

    /// 记录一条墓碑（不检查是否存在对应活条目）。
    ///
    /// 供同步使用：对端发来墓碑时，本机可能从来没有过那条条目。
    ///
    /// # 语义
    ///
    /// 若该 ID 的活条目存在，**不会**被删除——调用方需要自己决定 D2 的裁决
    /// 结果。这个函数只负责把墓碑记下来。
    pub fn record_tombstone(&mut self, tombstone: Tombstone) {
        self.tombstones.insert(tombstone.entry_id, tombstone);
    }

    /// 遍历全部墓碑。
    pub fn iter_tombstones(&self) -> impl Iterator<Item = (&EntryId, &Tombstone)> {
        self.tombstones.iter()
    }
}

/// 保险库文件 + 打开它的主密钥。
///
/// # 为什么把两者绑在一起
///
/// 密文与密钥分离存放（密钥在硬件密钥库）是有意的安全选择，但**分开传递**
/// 极易写出「用了 A 文件的密钥去解 B 文件」这类错误，而且失败现象是
/// 「什么都解不开」，很难定位。这个类型让「文件与能打开它的密钥」成为一个
/// 不可分的值。
///
/// # 生命周期
///
/// 打开文件时解密全部条目——条目数在真实使用中是几十到几百，一次性解密的开销
/// 远小于维护「哪些条目已解密」的状态机。这也意味着**解锁期间全部明文都在
/// 内存里**，这与「秘密材料只以 `secrecy` 类型存在」的约定一致，但换页与
/// 内存转储仍是已知的残余风险。
#[derive(Debug)]
pub struct VaultFile {
    /// 主密钥。
    master: MasterKey,
    /// 解密后的内容。
    vault: Vault,
}

impl VaultFile {
    /// 用新随机主密钥创建一个空保险库。
    ///
    /// # 错误
    ///
    /// OS 随机源不可用时返回 [`Error::RandomnessUnavailable`]。
    pub fn create() -> Result<Self> {
        Ok(Self {
            master: MasterKey::generate()?,
            vault: Vault::new(),
        })
    }

    /// 用指定主密钥打开一份空保险库。
    ///
    /// 用于「主密钥已经在硬件密钥库里，但本地还没有文件」的场景。
    #[must_use]
    pub fn with_master_key(master: MasterKey) -> Self {
        Self {
            master,
            vault: Vault::new(),
        }
    }

    /// 主密钥的只读引用。
    #[must_use]
    pub const fn master_key(&self) -> &MasterKey {
        &self.master
    }

    /// 取出主密钥的所有权，把 `VaultFile` 拆开。
    ///
    /// 供上层把主密钥存进硬件密钥库。
    #[must_use]
    pub fn into_parts(self) -> (MasterKey, Vault) {
        (self.master, self.vault)
    }

    /// 内容的只读引用。
    #[must_use]
    pub const fn vault(&self) -> &Vault {
        &self.vault
    }

    /// 内容的可变引用。
    pub const fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }

    /// 序列化为文件字节。
    ///
    /// # 错误
    ///
    /// 条目字段超出格式可表示的范围时返回对应错误；随机源不可用时返回
    /// [`Error::RandomnessUnavailable`]（每条记录都要一个新 nonce）。
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let total = self
            .vault
            .entries
            .len()
            .checked_add(self.vault.tombstones.len())
            .ok_or(Error::VaultTooManyRecords)?;
        if total > MAX_RECORDS {
            return Err(Error::VaultTooManyRecords);
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "total 已与 MAX_RECORDS（远小于 u32::MAX）比较过"
        )]
        let count = total as u32;

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.push(0); // 保留字节
        put_u32(&mut out, count);

        for (id, entry) in &self.vault.entries {
            let plaintext = encode_entry(entry)?;
            write_record(
                &mut out,
                &self.master,
                FORMAT_VERSION,
                RecordKind::Entry,
                id,
                &plaintext,
            )?;
        }
        for (id, tombstone) in &self.vault.tombstones {
            let plaintext = encode_tombstone(tombstone);
            write_record(
                &mut out,
                &self.master,
                FORMAT_VERSION,
                RecordKind::Tombstone,
                id,
                &plaintext,
            )?;
        }

        // 主密钥检查值放在**末尾**而不是头部。
        //
        // 放头部要挤进那 14 字节的定长头，而那会让版本 1 的解析器从错误的偏移读
        // 记录数（它按固定偏移读，不会看版本号之后的分支）。放末尾则版本 1 的解析器
        // 会在读完记录后撞上尾部检查，报一个**明确**的 VaultTrailingBytes 而不是
        // 解出一份错乱的保险库。
        out.extend_from_slice(&crypto::key_check(&self.master));
        Ok(out)
    }

    /// 从文件字节解析。
    ///
    /// # 错误
    ///
    /// 任何结构问题（魔数不符、版本不支持、记录越界、长度超限）返回结构性错误；
    /// **任何认证失败返回 [`Error::VaultDecryptionFailed`]**，且不区分原因。
    /// 版本 2 的文件里主密钥检查值不符也返回它——那与「第一条记录解不开」是同一件
    /// 事的更早发现点。
    ///
    /// # 版本 1 的文件仍然可读
    ///
    /// 版本 1 没有检查值，因此这一步跳过，行为与从前完全一致。**这是刻意的**：
    /// 用户升级应用之后，他原有的文件必须还能打开。
    ///
    /// # 版本 1 的文件仍然判定不了密钥对错
    ///
    /// 这不是回归，而是那份文件里确实没有可判定的信息。需要对密钥做权威确认时用
    /// 挑战-应答（`auth` 模块），它不依赖文件内容。
    ///
    /// # 这个函数必须永不 panic
    ///
    /// 输入完全来自攻击者可控的文件。所有越界都由内部的读取游标挡掉，所有长度
    /// 都先与上限比较再分配。fuzz 目标 `vault_parse` 专门验证这一点。
    pub fn parse(master: MasterKey, data: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(data);

        let magic = reader.take(MAGIC.len()).ok_or(Error::VaultTruncated)?;
        if magic != MAGIC {
            return Err(Error::VaultBadMagic);
        }

        let version = reader.u8().ok_or(Error::VaultTruncated)?;
        if !READABLE_VERSIONS.contains(&version) {
            return Err(Error::VaultUnsupportedVersion { version });
        }

        let reserved = reader.u8().ok_or(Error::VaultTruncated)?;
        if reserved != 0 {
            return Err(Error::VaultReservedByteNotZero { value: reserved });
        }

        let count = reader.u32().ok_or(Error::VaultTruncated)? as usize;
        if count > MAX_RECORDS {
            return Err(Error::VaultTooManyRecords);
        }

        let mut vault = Vault::new();
        for _ in 0..count {
            let kind_byte = reader.u8().ok_or(Error::VaultTruncated)?;
            let kind = RecordKind::from_byte(kind_byte)
                .ok_or(Error::VaultUnknownRecordKind { value: kind_byte })?;
            let id = reader.entry_id().ok_or(Error::VaultTruncated)?;
            let nonce = reader.nonce().ok_or(Error::VaultTruncated)?;
            let len = reader.u32().ok_or(Error::VaultTruncated)? as usize;
            if len > MAX_RECORD_LEN {
                return Err(Error::VaultRecordTooLong {
                    limit: MAX_RECORD_LEN,
                    actual: len,
                });
            }
            let ciphertext = reader.take(len).ok_or(Error::VaultTruncated)?;

            // AAD 里的版本号必须是**这个文件自己声明的**版本，不能是
            // `FORMAT_VERSION`：否则读一个版本 1 的旧文件会全线认证失败，而原因
            // 会是「密钥不对」——一个把用户引向完全错误方向的诊断。
            let plaintext = crypto::open(&master, kind, &id, version, &nonce, ciphertext)?;
            match kind {
                RecordKind::Entry => {
                    let entry = decode_entry(&plaintext)?;
                    vault.insert_with_id(id, entry)?;
                }
                RecordKind::Tombstone => {
                    let tombstone = decode_tombstone(id, &plaintext)?;
                    vault.record_tombstone(tombstone);
                }
            }
        }

        // 版本 2 末尾是主密钥检查值。放在记录之后读，于是「先判定密钥、再动记录」
        // 对这个顺序做不到——记录已经解完了。但代价可以接受：密钥不对时第一条记录
        // 就会失败，检查值的价值在于**空文件**（`count == 0`，循环一次都不进）。
        //
        // 之所以不为此改成「检查值放头部」：头部是定长的 14 字节，而版本 1 的解析器
        // 按固定偏移读记录数，插进去会让它读出一份错乱的保险库而不是干净地拒绝。
        if version >= 2 {
            let stored = reader
                .take(crypto::KEY_CHECK_LEN)
                .ok_or(Error::VaultTruncated)?;
            crypto::verify_key_check(&master, stored)?;
        }

        // 末尾多余字节一律拒绝：它意味着文件被追加过内容，而我们无法解释那
        // 是什么。静默忽略会让「文件被篡改」这一事实消失。
        if !reader.is_empty() {
            return Err(Error::VaultTrailingBytes {
                count: reader.remaining(),
            });
        }

        Ok(Self { master, vault })
    }
}

/// 把一条记录追加到输出缓冲区。
///
/// `format_version` 显式传入而不是读 [`FORMAT_VERSION`]：它同时被写进 AAD，而
/// 解析时必须能与文件里声明的版本对上。
fn write_record(
    out: &mut Vec<u8>,
    master: &MasterKey,
    format_version: u8,
    kind: RecordKind,
    id: &EntryId,
    plaintext: &[u8],
) -> Result<()> {
    let (nonce, ciphertext) = crypto::seal(master, kind, id, format_version, plaintext)?;
    out.push(kind.as_byte());
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&nonce);
    put_bytes(out, &ciphertext);
    Ok(())
}

/// 序列化一条条目的明文。
///
/// # 编码规则：**每个**节点都是「标签 + u32 长度 + 内容」
///
/// 没有例外，包括单字节的枚举值与 8 字节的时间戳。让定长字段省掉长度前缀
/// 能省几个字节，但代价是解析器要为「哪些标签带长度」维护一张表——而那张表
/// 正是「跳过未知节点」这一向前兼容机制最容易被写错的地方（未知标签的长度
/// 从哪读？）。
///
/// 统一格式后，「跳过未知节点」只有一条路径：读标签、读 u32 长度、跳过那么多
/// 字节。这条路径被 fuzz 目标 `vault_parse` 反复敲打。
fn encode_entry(entry: &VaultEntry) -> Result<Vec<u8>> {
    let mut out = Vec::new();

    put_node(&mut out, tag::NAME, entry.name.as_bytes());
    // `issuer` 的 `None` 与空串都编码为零长度节点，解码时统一归一为 `None`。
    put_node(
        &mut out,
        tag::ISSUER,
        entry.issuer.as_deref().unwrap_or_default().as_bytes(),
    );
    put_node(&mut out, tag::ACCOUNT, entry.account.as_bytes());
    // 种子以**原始字节**序列化，不用 Base32。
    //
    // Base32 是跨 FFI 边界与人类可读场景的表示，不是存储表示——它会让种子
    // 白白膨胀 60%。明文层本来就已经在密文之内，没有「可读性」的需求。
    put_node(&mut out, tag::SECRET, entry.secret.expose());
    put_node(
        &mut out,
        tag::ALGORITHM,
        &[algorithm_to_byte(entry.algorithm)],
    );
    put_node(&mut out, tag::DIGITS, &[digits_to_byte(entry.digits)]);
    put_node(&mut out, tag::PERIOD, &entry.period.to_be_bytes());
    if let Some(counter) = entry.counter {
        put_node(&mut out, tag::COUNTER, &counter.to_be_bytes());
    }
    put_node(&mut out, tag::NOTE, entry.note.as_bytes());
    put_node(&mut out, tag::CREATED_AT, &entry.created_at.to_be_bytes());
    put_node(&mut out, tag::UPDATED_AT, &entry.updated_at.to_be_bytes());

    Ok(out)
}

/// 追加一个「标签 + 长度 + 内容」节点。
fn put_node(out: &mut Vec<u8>, tag: u8, payload: &[u8]) {
    out.push(tag);
    put_bytes(out, payload);
}

/// 序列化一条墓碑的明文。
///
/// 与条目用同一套节点编码，因而同样支持「跳过未知节点」。
fn encode_tombstone(tombstone: &Tombstone) -> Vec<u8> {
    let mut out = Vec::new();
    put_node(
        &mut out,
        tag::DELETED_AT,
        &tombstone.deleted_at.to_be_bytes(),
    );
    if let Some(by) = &tombstone.deleted_by {
        put_node(&mut out, tag::DELETED_BY, by.as_bytes());
    }
    out
}

/// 解析一条条目的明文。
fn decode_entry(data: &[u8]) -> Result<VaultEntry> {
    /// 解析期间累积的字段。用 `Option` 逐个填写，最后统一检查必填项。
    #[derive(Default)]
    struct Fields {
        /// 显示名。
        name: Option<String>,
        /// 发行方；`Some(None)` 表示「节点存在但为空」。
        issuer: Option<String>,
        /// 账号名。
        account: Option<String>,
        /// 种子。
        secret: Option<Vec<u8>>,
        /// 算法。
        algorithm: Option<otp::Algorithm>,
        /// 位数。
        digits: Option<otp::Digits>,
        /// 周期。
        period: Option<u64>,
        /// 计数器。
        counter: Option<u64>,
        /// 备注。
        note: String,
        /// 创建时间。
        created_at: Option<u64>,
        /// 修改时间。
        updated_at: Option<u64>,
    }

    let mut reader = Reader::new(data);
    let mut f = Fields::default();
    // 位图，第 `tag` 位表示该标签已出现过。
    //
    // 用 `u16` 并按标签值直接移位（标签最大 0x0D，落在 16 位之内）。不用
    // `1 << (tag & 0x0F)` 那种「压缩到 4 位」的写法：压缩会引入意外的位碰撞，
    // 而且 `tag & 0x0F` 对 0x10 以上的标签会静默回绕，把两个不同的标签当成
    // 同一个——那是数据损坏，不是检测。
    let mut seen: u16 = 0;

    // 迭代次数以「剩余字节数」为硬上界：每个节点至少 5 字节（标签 + u32 长度），
    // 因此不可能有超过 remaining/5 个节点。这样即使文件全是 1 字节的垃圾，
    // 循环次数也被输入长度本身限制住。
    let mut guard = data.len() + 1;
    while !reader.is_empty() {
        guard = guard.checked_sub(1).ok_or(Error::VaultCorrupt)?;
        let node_tag = reader.u8().ok_or(Error::VaultTruncated)?;
        let len = reader.u32().ok_or(Error::VaultTruncated)? as usize;
        if len > Entry::MAX_FIELD_LEN {
            return Err(Error::FieldTooLong {
                field: "vault node",
                limit: Entry::MAX_FIELD_LEN,
                actual: len,
            });
        }
        let payload = reader.take(len).ok_or(Error::VaultTruncated)?;

        // 重复节点一律拒绝：取第一个还是最后一个在不同实现里不一致，是经典
        // 解析歧义。文件里出现重复说明它被构造过。
        //
        // 只对**已知**标签做这个检查。未知标签必然来自更新的版本，那个版本
        // 可能合法地写出多个同名未知节点，本版本无从判断，因而只跳过。
        if node_tag <= tag::DELETED_BY {
            let bit = 1_u16 << node_tag;
            if seen & bit != 0 {
                return Err(Error::VaultDuplicateField { tag: node_tag });
            }
            seen |= bit;
        }

        match node_tag {
            tag::NAME => f.name = Some(utf8(payload)?),
            tag::ISSUER => {
                let text = utf8(payload)?;
                // 空串归一为 `None`：序列化时 `None` 写的是零长度节点，
                // 因此「空发行方」与「无发行方」在往返中必须是同一个值。
                f.issuer = if text.is_empty() { None } else { Some(text) };
            }
            tag::ACCOUNT => f.account = Some(utf8(payload)?),
            tag::SECRET => {
                f.secret = Some(payload.to_vec());
            }
            tag::ALGORITHM => {
                f.algorithm =
                    Some(algorithm_from_byte(single_byte(payload)?).ok_or(Error::VaultCorrupt)?);
            }
            tag::DIGITS => {
                f.digits =
                    Some(digits_from_byte(single_byte(payload)?).ok_or(Error::VaultCorrupt)?);
            }
            tag::PERIOD => f.period = Some(u64_from(payload)?),
            tag::COUNTER => f.counter = Some(u64_from(payload)?),
            tag::NOTE => f.note = utf8(payload)?,
            tag::CREATED_AT => f.created_at = Some(u64_from(payload)?),
            tag::UPDATED_AT => f.updated_at = Some(u64_from(payload)?),
            // 未知标签按长度跳过——这正是节点编码的目的，也是向前兼容的全部
            // 实现。`reader.take(len)` 已经把 payload 消耗掉了，这里什么都不做
            // 就是「跳过」。
            _ => {}
        }
    }

    let created_at = f.created_at.ok_or(Error::VaultCorrupt)?;
    Entry::new(
        f.name.ok_or(Error::VaultCorrupt)?,
        f.issuer,
        f.account.ok_or(Error::VaultCorrupt)?,
        otp::OtpSecret::from_bytes(f.secret.ok_or(Error::VaultCorrupt)?)?,
        f.algorithm.ok_or(Error::VaultCorrupt)?,
        f.digits.ok_or(Error::VaultCorrupt)?,
        f.period.ok_or(Error::VaultCorrupt)?,
        f.counter,
        f.note,
        created_at,
        f.updated_at.unwrap_or(created_at),
    )
}

/// 解析一条墓碑的明文。
fn decode_tombstone(id: EntryId, data: &[u8]) -> Result<Tombstone> {
    let mut reader = Reader::new(data);
    let mut deleted_at = None;
    let mut deleted_by = None;
    let mut guard = data.len() + 1;

    while !reader.is_empty() {
        guard = guard.checked_sub(1).ok_or(Error::VaultCorrupt)?;
        let node_tag = reader.u8().ok_or(Error::VaultTruncated)?;
        let len = reader.u32().ok_or(Error::VaultTruncated)? as usize;
        if len > Entry::MAX_FIELD_LEN {
            return Err(Error::VaultCorrupt);
        }
        let payload = reader.take(len).ok_or(Error::VaultTruncated)?;
        match node_tag {
            tag::DELETED_AT => deleted_at = Some(u64_from(payload)?),
            tag::DELETED_BY => {
                let bytes: [u8; EntryId::LEN] =
                    payload.try_into().map_err(|_| Error::VaultCorrupt)?;
                deleted_by = Some(EntryId::from_bytes(bytes));
            }
            _ => {}
        }
    }

    Ok(Tombstone {
        entry_id: id,
        deleted_at: deleted_at.ok_or(Error::VaultCorrupt)?,
        deleted_by,
    })
}

/// 把字节按 UTF-8 解释。
fn utf8(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::VaultInvalidUtf8)
}

/// 从恰好 1 字节的节点读出该字节。
///
/// 长度不符即拒绝：多出来的字节无法解释，而「忽略多余字节」会让攻击者能在
/// 一个已知字段后面夹带数据而不被察觉。
fn single_byte(payload: &[u8]) -> Result<u8> {
    let bytes: [u8; 1] = payload.try_into().map_err(|_| Error::VaultCorrupt)?;
    Ok(bytes[0])
}

/// 从一个 8 字节节点读出 `u64`。
fn u64_from(payload: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = payload.try_into().map_err(|_| Error::VaultCorrupt)?;
    Ok(u64::from_be_bytes(bytes))
}

/// 算法 → 存储字节。
const fn algorithm_to_byte(algorithm: otp::Algorithm) -> u8 {
    match algorithm {
        otp::Algorithm::Sha1 => tag::ALG_SHA1,
        otp::Algorithm::Sha256 => tag::ALG_SHA256,
        otp::Algorithm::Sha512 => tag::ALG_SHA512,
    }
}

/// 存储字节 → 算法。未知值返回 `None`。
///
/// **不**回退到 SHA-1：静默回退会让用户拿到一个恒定错误的验证码，且错误
/// 信息无从查起。
const fn algorithm_from_byte(byte: u8) -> Option<otp::Algorithm> {
    match byte {
        tag::ALG_SHA1 => Some(otp::Algorithm::Sha1),
        tag::ALG_SHA256 => Some(otp::Algorithm::Sha256),
        tag::ALG_SHA512 => Some(otp::Algorithm::Sha512),
        _ => None,
    }
}

/// 位数 → 存储字节。
const fn digits_to_byte(digits: otp::Digits) -> u8 {
    match digits {
        otp::Digits::Six => tag::DIGITS_SIX,
        otp::Digits::Seven => tag::DIGITS_SEVEN,
        otp::Digits::Eight => tag::DIGITS_EIGHT,
    }
}

/// 存储字节 → 位数。未知值返回 `None`。
const fn digits_from_byte(byte: u8) -> Option<otp::Digits> {
    match byte {
        tag::DIGITS_SIX => Some(otp::Digits::Six),
        tag::DIGITS_SEVEN => Some(otp::Digits::Seven),
        tag::DIGITS_EIGHT => Some(otp::Digits::Eight),
        _ => None,
    }
}

/// 以原子方式把字节写入文件。
///
/// # 为什么必须原子
///
/// 「写文件」在操作系统层面不是一次操作：先截断、再写入。若在截断之后、写完
/// 之前断电或崩溃，用户得到的是一份**被截断的保险库**——全部条目损坏，且没有
/// 任何备份。对存放 2FA 种子的应用，这是灾难性的。
///
/// 正确做法是先写同目录下的临时文件，`fsync` 落盘，再用 `rename` 覆盖目标。
/// `rename` 在 POSIX 与 Windows（同卷）上都是原子的：目标文件要么是旧内容，
/// 要么是新内容，不存在中间态。
///
/// # 为什么是 `sync_all` 而不是 `flush`
///
/// `flush` 只把数据从用户态缓冲区交给内核。崩溃时内核页缓存仍可能丢失，
/// 于是 `rename` 之后目标指向一个**内容为空或不全**的文件——比不原子更糟，
/// 因为它看起来成功了。`sync_all` 才会把数据真正写到存储介质。
///
/// # 错误
///
/// 任何 I/O 失败都返回 [`Error::VaultIo`]。失败时**保证不动已有的目标文件**：
/// 临时文件可能残留，但那是可清理的垃圾，而不是数据损坏。
pub fn write_file_atomically(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    // 临时文件名带上进程号，避免同一目录下两个进程互相覆盖对方的临时文件。
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".tmp{}", std::process::id()));
    let tmp_path = parent.join(tmp_name);

    let cleanup = |err| {
        // 尽力删除临时文件，但不让清理失败掩盖真正的错误。
        let _ = std::fs::remove_file(&tmp_path);
        err
    };

    let mut file = std::fs::File::create(&tmp_path).map_err(|e| Error::VaultIo {
        reason: e.to_string(),
    })?;
    file.write_all(data).map_err(|e| {
        cleanup(Error::VaultIo {
            reason: e.to_string(),
        })
    })?;
    file.sync_all().map_err(|e| {
        cleanup(Error::VaultIo {
            reason: e.to_string(),
        })
    })?;
    drop(file);

    std::fs::rename(&tmp_path, path).map_err(|e| {
        cleanup(Error::VaultIo {
            reason: e.to_string(),
        })
    })?;
    Ok(())
}

/// 从文件读取并解析保险库。
///
/// # 错误
///
/// 读取失败返回 [`Error::VaultIo`]；其余同 [`VaultFile::parse`]。
pub fn read_file(master: MasterKey, path: &Path) -> Result<VaultFile> {
    let data = std::fs::read(path).map_err(|e| Error::VaultIo {
        reason: e.to_string(),
    })?;
    VaultFile::parse(master, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> otp::OtpSecret {
        otp::OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("合法种子")
    }

    fn sample_entry(name: &str) -> VaultEntry {
        Entry::new(
            name.into(),
            Some("Example".into()),
            "alice".into(),
            secret(),
            otp::Algorithm::Sha256,
            otp::Digits::Eight,
            30,
            None,
            "note".into(),
            1_700_000_000,
            1_700_000_123,
        )
        .expect("合法条目")
    }

    fn sample_hotp_entry() -> VaultEntry {
        Entry::new(
            "HOTP".into(),
            None,
            "bob".into(),
            secret(),
            otp::Algorithm::Sha1,
            otp::Digits::Six,
            30,
            Some(42),
            String::new(),
            1_700_000_000,
            1_700_000_000,
        )
        .expect("合法条目")
    }

    /// 断言两个条目在**所有**字段上相等。
    ///
    /// `OtpSecret` 不实现 `PartialEq`（那会让「比较两个秘密」变成一件随手可做
    /// 的事），因此这里显式比较它的 Base32 表示。
    fn assert_entry_eq(a: &VaultEntry, b: &VaultEntry) {
        assert_eq!(a.name, b.name, "name");
        assert_eq!(a.issuer, b.issuer, "issuer");
        assert_eq!(a.account, b.account, "account");
        assert_eq!(a.secret.to_base32(), b.secret.to_base32(), "secret");
        assert_eq!(a.algorithm, b.algorithm, "algorithm");
        assert_eq!(a.digits, b.digits, "digits");
        assert_eq!(a.period, b.period, "period");
        assert_eq!(a.counter, b.counter, "counter");
        assert_eq!(a.note, b.note, "note");
        assert_eq!(a.created_at, b.created_at, "created_at");
        assert_eq!(a.updated_at, b.updated_at, "updated_at");
    }

    #[test]
    fn create_starts_empty() {
        let file = VaultFile::create().expect("OS 随机源可用");
        assert!(file.vault().is_empty());
        assert_eq!(file.vault().len(), 0);
        assert_eq!(file.vault().tombstone_count(), 0);
    }

    /// 落盘 → 重读 → 解密，全部字段必须一致。
    #[test]
    fn roundtrip_preserves_every_field() {
        let mut file = VaultFile::create().expect("OS 随机源可用");
        let id = file
            .vault_mut()
            .insert(sample_entry("GitHub"))
            .expect("可插入");

        let bytes = file.serialize().expect("可序列化");
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("长度正确"),
            &bytes,
        )
        .expect("可解析");

        assert_eq!(reopened.vault().len(), 1);
        let restored = reopened.vault().get(&id).expect("条目应存在");
        assert_entry_eq(&sample_entry("GitHub"), restored);
    }

    /// HOTP 条目必须保住它的计数器。
    #[test]
    fn roundtrip_preserves_hotp_counter() {
        let mut file = VaultFile::create().expect("OS 随机源可用");
        let id = file
            .vault_mut()
            .insert(sample_hotp_entry())
            .expect("可插入");
        let bytes = file.serialize().expect("可序列化");
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("长度正确"),
            &bytes,
        )
        .expect("可解析");
        let restored = reopened.vault().get(&id).expect("条目应存在");
        assert_eq!(restored.counter, Some(42));
        assert_eq!(restored.uri_type(), crate::uri::UriType::Hotp);
    }

    /// 墓碑必须往返，且**不得**变成活条目。
    #[test]
    fn roundtrip_preserves_tombstones() {
        let mut file = VaultFile::create().expect("OS 随机源可用");
        let id = file
            .vault_mut()
            .insert(sample_entry("Doomed"))
            .expect("可插入");
        file.vault_mut().remove(&id, 1_800_000_000);

        let bytes = file.serialize().expect("可序列化");
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("长度正确"),
            &bytes,
        )
        .expect("可解析");

        assert!(reopened.vault().is_empty(), "条目应已被删除");
        assert_eq!(reopened.vault().tombstone_count(), 1);
        let tombstone = reopened.vault().get_tombstone(&id).expect("墓碑应存在");
        assert_eq!(tombstone.entry_id, id);
        assert_eq!(tombstone.deleted_at, 1_800_000_000);
        assert_eq!(tombstone.deleted_by, None);
    }

    /// 重复删除不得刷新墓碑时间。
    #[test]
    fn repeated_removal_keeps_original_timestamp() {
        let mut vault = Vault::new();
        let id = vault.insert(sample_entry("x")).expect("可插入");
        vault.remove(&id, 100);
        // 第二次删除时条目已不存在，返回 None 且不动墓碑。
        assert!(vault.remove(&id, 999).is_none());
        assert_eq!(vault.get_tombstone(&id).expect("墓碑存在").deleted_at, 100);
    }

    /// 多条目往返，顺序确定。
    #[test]
    fn roundtrip_preserves_many_entries() {
        let mut file = VaultFile::create().expect("OS 随机源可用");
        let mut ids = Vec::new();
        for i in 0..64 {
            ids.push(
                file.vault_mut()
                    .insert(sample_entry(&format!("entry-{i}")))
                    .expect("可插入"),
            );
        }
        let bytes = file.serialize().expect("可序列化");
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("长度正确"),
            &bytes,
        )
        .expect("可解析");
        assert_eq!(reopened.vault().len(), 64);
        for id in ids {
            assert!(reopened.vault().get(&id).is_some(), "缺少条目 {id}");
        }
    }

    /// **序列化必须是确定性的**：同一内容两次序列化结果不同的话，「文件是否
    /// 相同」这个判据就失效了。
    ///
    /// 注意 nonce 是随机的，所以两次序列化的**字节不同**——但解析回来后内容
    /// 必须一致。这里检验的是后者，以及记录顺序的确定性。
    #[test]
    fn serialization_is_deterministic_in_structure() {
        let mut file = VaultFile::create().expect("OS 随机源可用");
        for i in 0..16 {
            file.vault_mut()
                .insert(sample_entry(&format!("e{i}")))
                .expect("可插入");
        }
        let a = file.serialize().expect("可序列化");
        let b = file.serialize().expect("可序列化");

        // 头与记录头（不含 nonce 与密文）必须完全一致，长度也必须一致。
        assert_eq!(a.len(), b.len(), "两次序列化长度不同");
        assert_eq!(a[..9], b[..9], "魔数与版本应一致");
        assert_eq!(a[9], b[9], "保留字节应一致");

        // 解析两次并按顺序取出条目名称，必须完全一致。
        let names = |bytes: &[u8]| -> Vec<String> {
            let f = VaultFile::parse(
                MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("长度正确"),
                bytes,
            )
            .expect("可解析");
            f.vault().iter().map(|(_, e)| e.name.clone()).collect()
        };
        assert_eq!(names(&a), names(&b), "条目顺序不确定");
    }

    /// 换一个主密钥必须解不开。
    #[test]
    fn wrong_master_key_cannot_open() {
        let mut file = VaultFile::create().expect("OS 随机源可用");
        file.vault_mut().insert(sample_entry("x")).expect("可插入");
        let bytes = file.serialize().expect("可序列化");

        let other = MasterKey::generate().expect("OS 随机源可用");
        let err = VaultFile::parse(other, &bytes);
        assert!(matches!(err, Err(Error::VaultDecryptionFailed)));
    }

    /// **篡改文件里的任意一个字节都必须被发现。**
    ///
    /// 结构字节（魔数、版本、保留字节、条数、记录头）会触发结构性错误；
    /// nonce 与密文会触发认证失败。两者都是拒绝，绝不允许「改了一个字节却
    /// 仍然解出一份看起来正常的数据」。
    #[test]
    fn tampering_any_byte_is_rejected() {
        let mut file = VaultFile::create().expect("OS 随机源可用");
        file.vault_mut().insert(sample_entry("x")).expect("可插入");
        file.vault_mut()
            .insert(sample_hotp_entry())
            .expect("可插入");
        let bytes = file.serialize().expect("可序列化");
        let key_bytes = master_key_to_bytes(file.master_key());

        for index in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[index] ^= 0x01;
            let result = VaultFile::parse(
                MasterKey::from_bytes(key_bytes.clone()).expect("长度正确"),
                &tampered,
            );
            assert!(
                result.is_err(),
                "第 {index} 字节被翻转（{:#04x} → {:#04x}）却仍被接受",
                bytes[index],
                tampered[index]
            );
        }
    }

    /// 截断文件的任何位置都必须被拒绝。
    #[test]
    fn truncation_at_any_point_is_rejected() {
        let mut file = VaultFile::create().expect("OS 随机源可用");
        file.vault_mut().insert(sample_entry("x")).expect("可插入");
        file.vault_mut()
            .insert(sample_hotp_entry())
            .expect("可插入");
        // 先取出 ID 再改 `vault`：`iter()` 借出的是不可变引用，与 `vault_mut()`
        // 冲突。`EntryId` 是 `Copy`，复制一份即可。
        let first_id = *file.vault().iter().next().expect("有条目").0;
        file.vault_mut().remove(&first_id, 1);
        let bytes = file.serialize().expect("可序列化");
        let key_bytes = master_key_to_bytes(file.master_key());

        for cut in 1..bytes.len() {
            let result = VaultFile::parse(
                MasterKey::from_bytes(key_bytes.clone()).expect("长度正确"),
                &bytes[..cut],
            );
            assert!(result.is_err(), "截断到 {cut} 字节却仍被接受");
        }
    }

    /// 追加内容必须被拒绝——静默忽略会让「文件被改过」这一事实消失。
    #[test]
    fn trailing_bytes_are_rejected() {
        let mut file = VaultFile::create().expect("OS 随机源可用");
        file.vault_mut().insert(sample_entry("x")).expect("可插入");
        let mut bytes = file.serialize().expect("可序列化");
        bytes.push(0x00);

        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("长度正确"),
            &bytes,
        );
        assert!(matches!(err, Err(Error::VaultTrailingBytes { count: 1 })));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let file = VaultFile::create().expect("OS 随机源可用");
        let mut bytes = file.serialize().expect("可序列化");
        bytes[0] = b'X';
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("长度正确"),
            &bytes,
        );
        assert!(matches!(err, Err(Error::VaultBadMagic)));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let file = VaultFile::create().expect("OS 随机源可用");
        let mut bytes = file.serialize().expect("可序列化");
        bytes[8] = 99;
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("长度正确"),
            &bytes,
        );
        match err {
            Err(Error::VaultUnsupportedVersion { version }) => assert_eq!(version, 99),
            other => panic!("应拒绝未知版本，实际 ok={}", other.is_ok()),
        }
    }

    #[test]
    fn nonzero_reserved_byte_is_rejected() {
        let file = VaultFile::create().expect("OS 随机源可用");
        let mut bytes = file.serialize().expect("可序列化");
        bytes[9] = 1;
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("长度正确"),
            &bytes,
        );
        assert!(matches!(
            err,
            Err(Error::VaultReservedByteNotZero { value: 1 })
        ));
    }

    #[test]
    fn unknown_record_kind_is_rejected() {
        let mut file = VaultFile::create().expect("OS 随机源可用");
        file.vault_mut().insert(sample_entry("x")).expect("可插入");
        let mut bytes = file.serialize().expect("可序列化");
        // 第一条记录的种类字节位于固定的 14 偏移处。
        bytes[14] = 0x7F;
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("长度正确"),
            &bytes,
        );
        assert!(matches!(
            err,
            Err(Error::VaultUnknownRecordKind { value: 0x7F })
        ));
    }

    #[test]
    fn duplicate_entry_id_is_rejected() {
        let mut file = VaultFile::create().expect("OS 随机源可用");
        let id = file.vault_mut().insert(sample_entry("x")).expect("可插入");

        // 直接构造一个含两条相同 ID 记录的保险库。
        let mut vault = Vault::new();
        vault
            .insert_with_id(id, sample_entry("a"))
            .expect("首次插入");
        let err = vault.insert_with_id(id, sample_entry("b"));
        assert!(matches!(err, Err(Error::VaultDuplicateEntryId)));

        // `insert_with_id` 失败后不得留下半个条目。
        assert_eq!(vault.len(), 1);
        assert_eq!(vault.get(&id).expect("条目存在").name, "a");
    }

    /// 用 `replace` 改名：标识不变、不留墓碑、创建时间由调用方保住。
    ///
    /// 这三条正是「删掉再插入」做不到的，而任何一条做不到都会被同步解读成
    /// 「这条被删了」或「又来了一条新的」。
    #[test]
    fn replace_keeps_the_id_and_leaves_no_tombstone() {
        let mut vault = Vault::new();
        let id = vault.insert(sample_entry("original")).expect("可插入");
        let created = vault.get(&id).expect("条目存在").created_at;

        let mut renamed = sample_entry("renamed");
        renamed.created_at = created;
        vault.replace(id, renamed).expect("替换应当成功");

        let entry = vault.get(&id).expect("标识必须仍然指向该条目");
        assert_eq!(entry.name, "renamed");
        assert_eq!(entry.created_at, created, "创建时间应当被保留");
        assert_eq!(vault.len(), 1, "替换不该多出一条");
        assert_eq!(
            vault.tombstone_count(),
            0,
            "改名不是删除，不该留下墓碑——墓碑会被同步出去，另一端可能据此真的删掉条目"
        );
    }

    /// 替换一条不存在的条目必须报错，而不是悄悄变成「新增」。
    ///
    /// 退化成新增的后果是：用户在编辑界面点了保存，而那条已经在另一端被删掉了，
    /// 于是它又「复活」回两台设备上——一次本该提示用户刷新列表的操作变成了
    /// 数据回流。
    #[test]
    fn replace_of_a_missing_entry_is_rejected() {
        let mut vault = Vault::new();
        let missing = EntryId::from_bytes([0x5A; EntryId::LEN]);
        let err = vault.replace(missing, sample_entry("ghost"));
        assert!(matches!(err, Err(Error::VaultEntryNotFound)));
        assert!(vault.is_empty(), "失败不得凭空插入条目");
    }

    /// 空保险库的往返。
    #[test]
    fn empty_vault_roundtrips() {
        let file = VaultFile::create().expect("OS 随机源可用");
        let bytes = file.serialize().expect("可序列化");
        assert_eq!(
            bytes.len(),
            14 + crypto::KEY_CHECK_LEN,
            "空文件应是文件头加主密钥检查值"
        );
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("长度正确"),
            &bytes,
        )
        .expect("可解析");
        assert!(reopened.vault().is_empty());
        assert_eq!(reopened.vault().tombstone_count(), 0);
    }

    /// **这个文件格式缺口的核心测试**：空的保险库也必须能判定主密钥对错。
    ///
    /// 版本 1 里这条是**做不到**的——主密钥只参与每条记录的 AEAD，而空文件没有
    /// 记录，于是任何 32 字节密钥都能解析成功。用户看到「打开成功」，而真正的问题
    /// （密钥存错了）要等到他加进第一条条目才浮现。
    ///
    /// 注意这里断言的是**空的**保险库。有内容的保险库在版本 1 下也能被拒绝，因此
    /// 只测有内容的情形对这个缺口完全是盲的。
    #[test]
    fn an_empty_vault_detects_a_wrong_master_key() {
        let file = VaultFile::create().expect("OS 随机源可用");
        assert!(file.vault().is_empty(), "前提：这个保险库确实是空的");
        let bytes = file.serialize().expect("可序列化");

        // 一把不同的密钥——长度合法、随机，但不是写这份文件的那把。
        let wrong = MasterKey::generate().expect("OS 随机源可用");
        assert_ne!(
            wrong.expose(),
            file.master_key().expose(),
            "两把密钥必须不同"
        );

        let err = VaultFile::parse(wrong, &bytes);
        assert!(
            matches!(err, Err(Error::VaultDecryptionFailed)),
            "空保险库用错误的密钥也必须被拒绝，实际 ok={}",
            err.is_ok()
        );
    }

    /// 版本 1 的文件仍然必须能读——用户升级应用之后原有的文件不能打不开。
    ///
    /// 这里手工构造一份版本 1 的文件（版本号为 1、没有末尾的检查值、记录的 AAD
    /// 版本也是 1），因为序列化现在总是写版本 2。手工构造是**刻意的**：一个「把
    /// `FORMAT_VERSION` 临时改回 1」的测试会随常量一起漂移，而这里要钉的是**字节
    /// 布局本身**。
    #[test]
    fn version_1_files_are_still_readable() {
        let master = MasterKey::generate().expect("OS 随机源可用");
        let id = EntryId::generate().expect("OS 随机源可用");
        let entry = sample_entry("old-format");
        let plaintext = encode_entry(&entry).expect("可编码");
        // 版本 1 的 AAD 用的是版本号 1。
        let (nonce, ciphertext) =
            crypto::seal(&master, RecordKind::Entry, &id, 1, &plaintext).expect("可加密");

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(1);
        out.push(0);
        put_u32(&mut out, 1);
        out.push(RecordKind::Entry.as_byte());
        out.extend_from_slice(id.as_bytes());
        out.extend_from_slice(&nonce);
        put_u32(
            &mut out,
            u32::try_from(ciphertext.len()).expect("测试数据远小于 u32::MAX"),
        );
        out.extend_from_slice(&ciphertext);
        // 没有主密钥检查值。

        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(&master)).expect("长度正确"),
            &out,
        )
        .expect("版本 1 的文件必须仍可解析");
        assert_eq!(reopened.vault().len(), 1, "条目应当被读出来");
        assert_eq!(
            reopened.vault().iter().next().expect("一条").1.name,
            "old-format"
        );

        // 而且用**错误的**密钥读它仍然会失败——失败点是记录的 AEAD，不是检查值。
        let wrong = MasterKey::generate().expect("OS 随机源可用");
        assert!(
            VaultFile::parse(wrong, &out).is_err(),
            "有内容的版本 1 文件用错误密钥必须失败"
        );
    }

    /// 版本 1 的文件判定不了密钥对错——这不是回归，而是那份文件里确实没有可判定
    /// 的信息。把这条限制钉住，免得后人以为「修好了」。
    #[test]
    fn a_version_1_empty_file_still_cannot_detect_a_wrong_key() {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(1);
        out.push(0);
        put_u32(&mut out, 0);

        let wrong = MasterKey::generate().expect("OS 随机源可用");
        let parsed = VaultFile::parse(wrong, &out);
        assert!(
            parsed.is_ok(),
            "版本 1 的空文件没有检查值，因此任何密钥都能解析——这是该格式的已知限制"
        );
    }

    /// 检查值被改动必须被拒绝。
    #[test]
    fn a_tampered_key_check_is_rejected() {
        let file = VaultFile::create().expect("OS 随机源可用");
        let master =
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("长度正确");
        let bytes = file.serialize().expect("可序列化");

        for index in 0..crypto::KEY_CHECK_LEN {
            let mut tampered = bytes.clone();
            let last = tampered.len() - crypto::KEY_CHECK_LEN + index;
            tampered[last] ^= 0x01;
            let err = VaultFile::parse(
                MasterKey::from_bytes(master_key_to_bytes(&master)).expect("长度正确"),
                &tampered,
            );
            assert!(
                matches!(err, Err(Error::VaultDecryptionFailed)),
                "检查值第 {index} 字节被翻转却仍被接受"
            );
        }
    }

    /// 检查值被截断必须报**结构**错误，而不是「密钥不对」。
    ///
    /// 两者在界面上的处置完全不同：结构坏了要提示文件不可用，密钥不对要提示重新
    /// 登录。合并它们会让用户去比对密钥，而问题不在那里。
    #[test]
    fn a_truncated_key_check_is_a_structural_error() {
        let file = VaultFile::create().expect("OS 随机源可用");
        let master =
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("长度正确");
        let bytes = file.serialize().expect("可序列化");

        // 只砍掉几个字节——`reader.take` 会失败，因此报的是「截断」。
        let mut cut = bytes.clone();
        cut.truncate(cut.len() - 3);
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(&master)).expect("长度正确"),
            &cut,
        );
        assert!(
            matches!(err, Err(Error::VaultTruncated)),
            "截断的检查值应报截断，实际 ok={}",
            err.is_ok()
        );

        // 长度够但不是 32 字节时（多出来的会被尾部检查抓到）走的是另一条路。
        // 直接调用校验函数覆盖长度不符那一条。
        let err = crypto::verify_key_check(&master, &[0_u8; 8]);
        assert!(
            matches!(err, Err(Error::VaultBadKeyCheck)),
            "长度不符应报 VaultBadKeyCheck"
        );
    }

    /// 文件头布局是对外契约，锁住它。
    #[test]
    fn file_header_layout_is_stable() {
        let file = VaultFile::create().expect("OS 随机源可用");
        let bytes = file.serialize().expect("可序列化");
        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(bytes[8], FORMAT_VERSION);
        assert_eq!(bytes[9], 0, "保留字节");
        assert_eq!(
            u32::from_be_bytes(bytes[10..14].try_into().expect("4 字节")),
            0
        );
    }

    /// 未知节点标签必须被跳过而不是报错——这是向前兼容的全部实现。
    #[test]
    fn unknown_entry_node_is_skipped() {
        let entry = sample_entry("x");
        let mut plaintext = encode_entry(&entry).expect("可编码");

        // 追加一个未知标签的节点，长度合法。
        plaintext.push(0xEE);
        put_bytes(&mut plaintext, b"future field");

        let decoded = decode_entry(&plaintext).expect("未知节点应被跳过");
        assert_entry_eq(&entry, &decoded);
    }

    /// 未知标签的**长度**必须被真正使用——否则跳过的位置会错位。
    #[test]
    fn skipping_unknown_node_uses_its_length() {
        let entry = sample_entry("x");
        let mut plaintext = Vec::new();
        // 未知节点放在最前面，长度声明为 100。
        plaintext.push(0xEE);
        put_bytes(&mut plaintext, &[0xAA; 100]);
        plaintext.extend_from_slice(&encode_entry(&entry).expect("可编码"));

        let decoded = decode_entry(&plaintext).expect("应跳过 100 字节");
        assert_entry_eq(&entry, &decoded);
    }

    /// 未知标签声明了超出剩余数据的长度时，必须报错而不是越界。
    #[test]
    fn unknown_node_with_overlong_length_is_rejected() {
        let mut plaintext = Vec::new();
        plaintext.push(0xEE);
        put_u32(&mut plaintext, 9999);
        plaintext.extend_from_slice(b"short");
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::VaultTruncated)));
    }

    /// 重复的已知节点必须被拒绝。
    #[test]
    fn duplicate_known_node_is_rejected() {
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, b"first");
        put_node(&mut plaintext, tag::NAME, b"second");
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::VaultDuplicateField { .. })));
    }

    /// 缺少必填节点必须被拒绝。
    #[test]
    fn missing_required_node_is_rejected() {
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, b"only a name");
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::VaultCorrupt)));
    }

    /// 空种子节点必须被拒绝。
    #[test]
    fn empty_secret_node_is_rejected() {
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, b"n");
        put_node(&mut plaintext, tag::ACCOUNT, b"a");
        put_node(&mut plaintext, tag::SECRET, b"");
        put_node(&mut plaintext, tag::ALGORITHM, &[tag::ALG_SHA1]);
        put_node(&mut plaintext, tag::DIGITS, &[tag::DIGITS_SIX]);
        put_node(&mut plaintext, tag::PERIOD, &30_u64.to_be_bytes());
        put_node(&mut plaintext, tag::CREATED_AT, &0_u64.to_be_bytes());
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::SecretEmpty)));
    }

    /// 非 UTF-8 的文本节点必须被拒绝，而不是被 lossy 替换。
    #[test]
    fn invalid_utf8_is_rejected() {
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, &[0xFF, 0xFE]);
        put_node(&mut plaintext, tag::ACCOUNT, b"a");
        put_node(&mut plaintext, tag::SECRET, b"secret");
        put_node(&mut plaintext, tag::ALGORITHM, &[tag::ALG_SHA1]);
        put_node(&mut plaintext, tag::DIGITS, &[tag::DIGITS_SIX]);
        put_node(&mut plaintext, tag::PERIOD, &30_u64.to_be_bytes());
        put_node(&mut plaintext, tag::CREATED_AT, &0_u64.to_be_bytes());
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::VaultInvalidUtf8)));
    }

    /// 算法字节必须在存储格式里往返。
    #[test]
    fn algorithm_and_digits_bytes_roundtrip() {
        for algorithm in [
            otp::Algorithm::Sha1,
            otp::Algorithm::Sha256,
            otp::Algorithm::Sha512,
        ] {
            assert_eq!(
                algorithm_from_byte(algorithm_to_byte(algorithm)),
                Some(algorithm)
            );
        }
        for digits in [otp::Digits::Six, otp::Digits::Seven, otp::Digits::Eight] {
            assert_eq!(digits_from_byte(digits_to_byte(digits)), Some(digits));
        }
        // 未知取值必须拒绝，不得回退。
        assert_eq!(algorithm_from_byte(0), None);
        assert_eq!(algorithm_from_byte(99), None);
        assert_eq!(digits_from_byte(5), None);
        assert_eq!(digits_from_byte(9), None);
    }

    /// `issuer` 的 `None` 与 `Some("")` 在往返中必须归一。
    #[test]
    fn issuer_none_and_empty_normalize() {
        let mut entry = sample_entry("x");
        entry.issuer = None;
        let decoded = decode_entry(&encode_entry(&entry).expect("可编码")).expect("可解码");
        assert_eq!(decoded.issuer, None);

        entry.issuer = Some(String::new());
        let decoded = decode_entry(&encode_entry(&entry).expect("可编码")).expect("可解码");
        assert_eq!(decoded.issuer, None, "空串应归一为 None");
    }

    /// 原子落盘：写完后文件内容必须与传入字节完全一致。
    #[test]
    fn atomic_write_produces_exact_content() {
        let dir = std::env::temp_dir().join(format!("q2fa-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("可建目录");
        let path = dir.join("vault.bin");

        let data = b"hello atomic world";
        write_file_atomically(&path, data).expect("可写入");
        assert_eq!(std::fs::read(&path).expect("可读"), data);

        // 覆盖写：旧内容必须被完全替换，而不是被截断后残留。
        let longer = b"a much longer replacement payload";
        write_file_atomically(&path, longer).expect("可写入");
        assert_eq!(std::fs::read(&path).expect("可读"), longer);

        // 临时文件不得残留。
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("可读目录")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "残留临时文件: {leftovers:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 完整的落盘 → 重读往返。
    #[test]
    fn write_then_read_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("q2fa-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("可建目录");
        let path = dir.join("vault.bin");

        let mut file = VaultFile::create().expect("OS 随机源可用");
        let id = file
            .vault_mut()
            .insert(sample_entry("GitHub"))
            .expect("可插入");
        let bytes = file.serialize().expect("可序列化");
        write_file_atomically(&path, &bytes).expect("可写入");

        let key = MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("长度正确");
        let reopened = read_file(key, &path).expect("可读回");
        assert_eq!(reopened.vault().len(), 1);
        assert_entry_eq(
            &sample_entry("GitHub"),
            reopened.vault().get(&id).expect("条目存在"),
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 读取不存在的文件必须返回 I/O 错误而不是 panic。
    #[test]
    fn reading_missing_file_reports_io_error() {
        let key = MasterKey::generate().expect("OS 随机源可用");
        let err = read_file(key, Path::new("definitely/not/here/vault.bin"));
        assert!(matches!(err, Err(Error::VaultIo { .. })));
    }

    /// 空输入必须被拒绝且不 panic。
    #[test]
    fn empty_input_is_rejected() {
        let key = MasterKey::generate().expect("OS 随机源可用");
        assert!(matches!(
            VaultFile::parse(key, &[]),
            Err(Error::VaultTruncated)
        ));
    }

    /// 声称有巨量记录的文件必须被拒绝，且**不得尝试分配**。
    #[test]
    fn absurd_record_count_is_rejected() {
        let key = MasterKey::generate().expect("OS 随机源可用");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.push(0);
        put_u32(&mut bytes, u32::MAX);
        let err = VaultFile::parse(key, &bytes);
        assert!(matches!(err, Err(Error::VaultTooManyRecords)));
    }

    /// 声称记录超长的文件必须被拒绝，且不得分配。
    #[test]
    fn absurd_record_length_is_rejected() {
        let key = MasterKey::generate().expect("OS 随机源可用");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.push(0);
        put_u32(&mut bytes, 1);
        bytes.push(0x01); // 活条目
        bytes.extend_from_slice(&[0_u8; EntryId::LEN]);
        bytes.extend_from_slice(&[0_u8; NONCE_LEN]);
        put_u32(&mut bytes, u32::MAX); // 声称 4 GiB
        let err = VaultFile::parse(key, &bytes);
        match err {
            Err(Error::VaultRecordTooLong { limit, actual }) => {
                assert_eq!(limit, MAX_RECORD_LEN);
                assert_eq!(actual, u32::MAX as usize);
            }
            other => panic!("应拒绝超长记录，实际 ok={}", other.is_ok()),
        }
    }

    /// 未加密的垃圾数据必须被拒绝（魔数或认证会挡住）。
    #[test]
    fn garbage_with_correct_magic_is_rejected() {
        let key = MasterKey::generate().expect("OS 随机源可用");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.push(0);
        put_u32(&mut bytes, 1);
        // 一条结构完整但密文是垃圾的记录
        bytes.push(0x01);
        bytes.extend_from_slice(&[0x11; EntryId::LEN]);
        bytes.extend_from_slice(&[0x22; NONCE_LEN]);
        put_u32(&mut bytes, 32);
        bytes.extend_from_slice(&[0x33; 32]);
        let err = VaultFile::parse(key, &bytes);
        assert!(matches!(err, Err(Error::VaultDecryptionFailed)));
    }
}
