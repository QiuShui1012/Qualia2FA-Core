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

//! 同步载荷的信封：序列化 → 压缩 → 整体 AEAD。
//!
//! # 这一层负责什么
//!
//! 把「一台设备的条目与墓碑」变成一段**可以经由任何通道搬运的字节**，以及反过来。
//! 它不知道载荷会走二维码、局域网还是别的什么，也不知道对面是谁——**传输无关性
//! 是设计决定，不是巧合**（见 [`crate::sync`] 的模块文档）。
//!
//! # 三层结构，以及每层各自挡住什么
//!
//! ```text
//! ┌─ 外层信封（明文头 + 整体 AEAD）──────────────────────────────────┐
//! │  魔数 8 | 版本 1 | sync_id 32 | 设备 ID 16 | 长度 2 | 密文      │
//! │                                                        ↑ 含标签 │
//! │  ┌─ 内层：压缩 ─────────────────────────────────────────────┐   │
//! │  │  ┌─ 载荷明文 ────────────────────────────────────────┐  │   │
//! │  │  │ 记录数 4 | 记录 × N                                │  │   │
//! │  │  │   每条：种类 1 | entry_id 16 | nonce 24 | 长度 4  │  │   │
//! │  │  │          | 密文（含标签）                          │  │   │
//! │  │  └────────────────────────────────────────────────────┘  │   │
//! │  └──────────────────────────────────────────────────────────┘   │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! - **内层逐条 AEAD**（种类 + entry_id + 版本入 AAD）：挡住「把条目 A 的密文搬到
//!   条目 B 的位置」「把墓碑当成条目」。这一层的密钥与保险库文件的**不是同一把**
//!   （HKDF 的 salt 不同），因此两个域的密文互不可解。见 [`derive_record_key`]。
//! - **外层整体 AEAD**：挡住「从两份不同的载荷里各取一部分拼起来」。内层逐条认证
//!   无法发现这种拼接——每一条单独都是合法的。外层的 AAD 含整个明文头，因此任何
//!   一条挪动都会让外层认证失败。
//! - **压缩**不参与任何安全性质，只把字节变短。
//!
//! # 为什么内层还要逐条认证（外层不是已经整体认证了吗）
//!
//! 外层保证了「这一整份载荷确实来自持有主密钥的设备」，但**合并是逐条进行的**：
//! 一条条目被接受之后，它的密文会被原样收进本地保险库。若内层不逐条认证，一份
//! 合法的载荷就能让接收方**永久存下**一条内容与标识不匹配的记录——外层的保护在
//! 那一刻已经用完了。
//!
//! # 重放
//!
//! 载荷带一个 32 字节随机 `sync_id`。合并本身是幂等的（重复合并同一份数据结果
//! 不变），因此重放**不破坏正确性**；但它会白做一次完整的解密与合并，还会让界面上
//! 的「上次同步时间」变成攻击者可任意推动的值。因此 [`SeenSyncIds`] 记住处理过的
//! 标识，重复的直接拒绝。

pub mod compress;
mod merge;
pub mod record;
mod seen;

pub use merge::{
    Conflict, ConflictKind, HasEntryId, MergeOutcome, MergedRecord, RecordSet, merge_into,
};
pub use record::{OpenedRecord, open as open_record, seal_entry, seal_tombstone};
pub use seen::{MAX_SEEN_SYNC_IDS, SeenSyncIds};

use crate::vault::crypto;
use crate::vault::{EntryId, MasterKey, NONCE_LEN, TAG_LEN};
use crate::{Error, Result};

/// 载荷魔数。8 字节，与保险库文件一样留一个 NUL 让它能在十六进制编辑器里认出来。
pub const MAGIC: &[u8; 8] = b"Q2FASYNC";

/// 当前写入的同步载荷格式版本。
///
/// 与 [`crate::vault::FORMAT_VERSION`] **完全独立**：那个管保险库文件的布局，这个管
/// 载荷的布局。两者各自演进，互不牵连——把「载荷格式变了」与「文件格式变了」绑成
/// 一件事，会让任一处的改动都要求另一处跟着表态。
///
/// 它参与**内层**记录的 AAD（作为那个「格式版本」字段），因此改它会让所有既有载荷
/// 的内层记录解不开。这正是跨版本搬运要挡的东西：一个旧版本的内层记录不该被塞进
/// 新版本的载荷。
pub const FORMAT_VERSION: u8 = 1;

/// 载荷明文头的长度：魔数 + 版本 + sync_id + 设备 ID + 密文长度。
///
/// 这里**没有**「发送方是谁」的明文——发送方标识在密文里。见 [`Payload::sender`]。
pub const HEADER_LEN: usize = MAGIC.len() + 1 + SYNC_ID_LEN + EntryId::LEN + 2;

/// 载荷标识的长度。
///
/// 256-bit，与条目 ID 同宽：它只需要抗碰撞，不需要抗猜测（知道别人的载荷标识没有
/// 任何用处——载荷本身是被 AEAD 保护的）。
pub const SYNC_ID_LEN: usize = 32;

/// 一次同步的标识。
///
/// 由发起方随机生成，用于**接收方**识别重复载荷。它不是秘密。
pub type SyncId = [u8; SYNC_ID_LEN];

/// 单条记录在载荷明文里的固定部分长度：`entry_id` + nonce + 密文长度。
///
/// # 为什么这里**没有**种类字节
///
/// 种类是内层 AAD 的一部分，但**不**在明文里——这是刻意的，让攻击者连「这次同步
/// 带了几条删除」都看不出来。代价是解密时要按两种种类各试一次（见 [`record`] 的
/// 模块文档）。
///
/// 这个常量曾经写成 `1 + EntryId::LEN + NONCE_LEN + 4`，那个 `1` 是从更早一版
/// 「明文里写一个占位种类字节」的设计留下来的。它不会造成解析错误（解析器按长度
/// 前缀读，不按这个常量），只会让 [`Record::encoded_len`] 每条多报一个字节——也
/// 就是让任何按它算出来的载荷大小估计偏大。
const RECORD_HEADER_LEN: usize = EntryId::LEN + NONCE_LEN + 4;

/// 载荷里允许的记录数上限。
///
/// 与保险库文件的 [`crate::vault::MAX_RECORDS`] 同源但不共用常量：两者是**不同**的
/// 限制（文件是本地存储，载荷来自网络）。分开定义让「放宽其中一个」不必同时放宽
/// 另一个。
pub const MAX_RECORDS: usize = 1_000_000;

/// 载荷明文的长度上限（压缩**前**）。
///
/// 记录数上限与实际记录长度共同决定这个值；解压层另有自己的上限
/// （[`compress::MAX_DECOMPRESSED_LEN`]），两者都要过。这里限制的是**我们自己
/// 生成**的载荷，用于在生成阶段就拒绝明显不合理的数据集。
pub const MAX_PLAINTEXT_LEN: usize = 64 * 1024 * 1024;

/// 从主密钥派生**同步记录**子密钥所用的 HKDF salt。
///
/// # 为什么是两个不同的 salt，而不是两组不同的 info
///
/// HKDF 的 `salt` 与 `info` 都能做到域分离，但**用 salt 分离是更强的那种**：它让两个
/// 域的子密钥在计算上完全独立（salt 直接参与 HKDF-Extract），而 info 只参与 Expand。
///
/// 这里必须强分离，因为两个域的**记录种类字节与格式版本字段都可能相同**。若域分离
/// 只靠那两个字节，就得依赖「同步的记录种类恰好与保险库的不一样」这个巧合一直成立
/// ——而它是一个可以悄悄失效的性质：后人给同步加一种记录、顺手用了 `0x03`，就与保险
/// 库将来的某种记录撞上了。用不同的 salt 让两域在**密钥层面**分开，与 AAD 怎么排无关。
/// （`sync.rs` 末尾另有一个编译期断言盯着种类字节不重叠，那是第二道防线。）
///
/// 保险库那边的条目密钥用的是全零 salt（那是这个仓库里最早定下的派生，改它会让所有
/// 既有的 `.q2fa` 文件打不开）。
///
/// # 这个常量的值是对外契约
///
/// 它就是 32 字节 ASCII，改一个字符会让所有既有同步载荷（含二维码里那些已经发出去的）
/// 解不开。写成字面量的 32 字节数组而不是字符串常量加断言，是为了让长度错误在**编译
/// 期**就被 `[u8; 32]` 的类型检查发现——一个写成 31 或 33 的字符串常量在断言版本里
/// 要等到构建才报错，而报错信息指向断言而不是那个字符串。
pub const HKDF_SALT_SYNC: [u8; 32] = *b"Qualia2FA sync salt v1 (records)";

/// 从主密钥派生**同步记录**子密钥。
///
/// 与保险库文件的条目子密钥**不是同一把**，理由见 [`HKDF_SALT_SYNC`]。
///
/// 一次同步只派生一次，然后传给每条记录——载荷里可能有上万条，逐条重新派生会把
/// 两次 HMAC-SHA256 乘以条目数。
pub fn derive_record_key(master: &MasterKey) -> Result<[u8; 32]> {
    crypto::derive_key_with_salt(master, &HKDF_SALT_SYNC, crypto::HKDF_INFO_SYNC_RECORD)
}

/// 从主密钥派生**外层信封**子密钥。
///
/// 与同步记录子密钥、保险库子密钥、检查值派生各自独立。外层与内层用不同的密钥是
/// 刻意的：外层加密的是「已经逐条加密过的字节」，两层若共用一把密钥，内层密文就
/// 成了外层明文的一部分，而「同一把密钥既加密明文又加密密文」是教科书式的误用。
pub fn derive_envelope_key(master: &MasterKey) -> Result<[u8; 32]> {
    crypto::derive_key_with_salt(master, &HKDF_SALT_SYNC, crypto::HKDF_INFO_SYNC_ENVELOPE)
}

/// 载荷里的一条记录：一段已经逐条加密的密文，连同它明文部分的定位信息。
///
/// # 一条记录不知道自己是「条目」还是「墓碑」
///
/// 种类在密文里（它是 AAD 的一部分，但**不**在记录头里）。这是刻意的：让攻击者连
/// 「这次同步带了几条删除」都看不出来。代价是解密时要按两种种类各试一次，理由与代价
/// 的权衡见 [`record`] 的模块文档。
///
/// # `Clone` 为什么可以有
///
/// 它只带**密文**，不带任何解密后的内容，因此复制它不扩大密钥材料的泄露面。测试需要
/// 复制它来逐字节篡改，那是这条 `derive` 存在的主要理由。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// 这条记录属于哪个条目。
    pub entry_id: EntryId,
    /// 加密这条记录用的随机 nonce。
    pub nonce: [u8; NONCE_LEN],
    /// 密文，**含** 16 字节认证标签。
    pub ciphertext: Vec<u8>,
}

impl merge::HasEntryId for Record {
    /// 这条记录讲的是哪一个条目。
    ///
    /// `entry_id` 同时参与内层 AAD，因此它是被认证的——攻击者无法把一条记录的标识改
    /// 成另一个值而让它仍然解得开。
    fn entry_id(&self) -> EntryId {
        self.entry_id
    }
}

impl Record {
    /// 这条记录在载荷明文里占的字节数。
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        RECORD_HEADER_LEN + self.ciphertext.len()
    }
}

/// 一份载荷的内容：本次要送出去的全部记录。
///
/// # 为什么用 [`RecordSet`] 而不是 `Vec<Record>`
///
/// 并集合并以 [`EntryId`] 为键，因此同一条目在一份载荷里出现两次是**没有意义**的
/// ——而它又是一件载荷生成方可以做到的事。用集合类型表达「每条目至多一条记录」，这个
/// 不变量就不必靠调用方自觉，解析时也能直接把重复当成结构错误报出来。
///
/// # 记录的顺序是确定的
///
/// [`RecordSet`] 内部是 `BTreeMap`，遍历按 [`EntryId`] 升序，因此**同一份内容序列化
/// 出的明文逐字节相同**。这不等于「载荷逐字节相同」——每条记录的 nonce 是随机的，
/// 密文自然不同。确定性在这里的用处是让测试能做精确的字节比较，以及让「两份载荷是否
/// 承载同样的数据」有一个廉价判据。
#[derive(Debug)]
pub struct Payload {
    /// 本次同步的标识。接收方用它识别重复载荷。
    pub sync_id: SyncId,
    /// 发起这次同步的设备。
    ///
    /// 参与**外层** AAD，因此它是被认证的：攻击者无法把一份载荷的发送方改成别人。
    /// 用于 D2 的「裁决冲突由发起方裁定」——合并时要知道是谁在发起。
    ///
    /// # 它是设备标识，但**不**参与 D3 的挑战-应答
    ///
    /// 这里的「发送方」只是一个被认证的**声明**：它证明「持有主密钥的那一方声称自己
    /// 是这台设备」。要真正证明设备身份（私钥在硬件里）是 [`crate::auth`] 的事，走
    /// 的是另一条路径。两者不可互相替代：这个字段挡的是「把载荷说成别人发的」，而
    /// 那个挡不住。
    pub sender: EntryId,
    /// 载荷里的记录，**仍然加密**。
    pub records: RecordSet<Record>,
}

impl Payload {
    /// 生成一份新的载荷标识。
    ///
    /// # 错误
    ///
    /// [`Error::RandomnessUnavailable`]：OS 随机源不可用。此时**不得**回退到任何用户态
    /// PRNG：可预测的载荷标识会让重放防护失效（攻击者可以预先算出一个「将来会被接受」
    /// 的标识）。
    pub fn new_sync_id() -> Result<SyncId> {
        let mut id = [0_u8; SYNC_ID_LEN];
        crate::getrandom::fill(&mut id).map_err(|_| Error::RandomnessUnavailable)?;
        Ok(id)
    }

    /// 从本地保险库生成一份载荷。
    ///
    /// 会把**全部**活条目与**全部**墓碑都封进去。这是 D9 的「全量提供」模式，也是
    /// 二维码全量模式的来源；将来做增量同步时，是本函数加一个过滤参数，而不是换一套
    /// 载荷格式。
    ///
    /// # 活条目与墓碑并存时**只**发墓碑
    ///
    /// 保险库里可以同时有一条活条目和它的墓碑——那是裁决还没做完的状态
    /// （[`crate::vault::Vault::record_tombstone`] 刻意不删活条目）。这种状态下**不能**
    /// 把活条目也发出去：对端会把它解读成「这条还没被删」，于是每次同步都在对端触发
    /// 同一个冲突，用户每同步一次就要看一次同样的裁决界面。
    ///
    /// 只发墓碑的另一个理由更硬：墓碑代表一次**已经发生**的删除动作，而那条活条目是
    /// 待裁决的本地状态。把待裁决状态广播出去，等于让每台设备都替用户做一遍尚未做出
    /// 的决定。
    ///
    /// # 记录密钥只派生一次
    ///
    /// 载荷里可能有上万条，逐条重新派生 HKDF 会把两次 HMAC-SHA256 乘以条目数。派生
    /// 一次然后传给每条记录，代价从 O(n) 次派生降到 1 次。
    ///
    /// # 错误
    ///
    /// - [`Error::SyncTooManyRecords`]：条目与墓碑之和超过 [`MAX_RECORDS`]。
    /// - [`Error::RandomnessUnavailable`]：随机源不可用。
    /// - 编码失败（见 [`record::seal_entry`]）。
    pub fn from_vault(
        master: &MasterKey,
        sender: EntryId,
        vault: &crate::vault::Vault,
    ) -> Result<Self> {
        let record_key = derive_record_key(master)?;
        let mut records = RecordSet::<Record>::new();
        for (id, entry) in vault.iter() {
            // 有墓碑的条目**不**发出去：那是「裁决未完成」的本地状态，广播它会让
            // 每台设备都替用户做一遍尚未做出的决定。见本函数的文档。
            if vault.get_tombstone(id).is_some() {
                continue;
            }
            records.insert(record::seal_entry(&record_key, id, entry)?);
        }
        for (_, tombstone) in vault.iter_tombstones() {
            records.insert(record::seal_tombstone(&record_key, tombstone)?);
        }
        Ok(Self {
            sync_id: Self::new_sync_id()?,
            sender,
            records,
        })
    }

    /// 有多少条记录（条目与墓碑之和）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// 是否一条记录都没有。
    ///
    /// 空载荷是**合法**的：一台刚注册、还没添过条目的设备发起同步时就是这个样子。
    /// 它必须能被正常收下（对面据此知道「你这边什么都没有」），而不是被当成错误——
    /// 那会让「新设备加入」这条路径上多一个必须特判的分支。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// 把载荷打包成可以搬运的字节。
    ///
    /// 顺序是**序列化 → 压缩 → 整体 AEAD**。
    ///
    /// # 错误
    ///
    /// - [`Error::SyncTooManyRecords`]：记录数超过 [`MAX_RECORDS`]。
    /// - [`Error::SyncMalformed`]：打包后的明文超过 [`MAX_PLAINTEXT_LEN`]。
    /// - [`Error::RandomnessUnavailable`]：随机源不可用。
    pub fn seal(&self, master: &MasterKey) -> Result<Vec<u8>> {
        if self.records.len() > MAX_RECORDS {
            return Err(Error::SyncTooManyRecords {
                count: self.records.len(),
                limit: MAX_RECORDS,
            });
        }

        // ── 1. 序列化 ────────────────────────────────────────────────────
        let mut plaintext = Vec::new();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "已在上面与 MAX_RECORDS 比较过，它远小于 u32::MAX"
        )]
        let count = self.records.len() as u32;
        plaintext.extend_from_slice(&count.to_be_bytes());
        for record in &self.records {
            plaintext.extend_from_slice(record.entry_id.as_bytes());
            plaintext.extend_from_slice(&record.nonce);
            let len = u32::try_from(record.ciphertext.len()).map_err(|_| Error::SyncMalformed {
                reason: "单条记录的密文超过 4 GiB",
            })?;
            plaintext.extend_from_slice(&len.to_be_bytes());
            plaintext.extend_from_slice(&record.ciphertext);
        }

        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::SyncMalformed {
                reason: "载荷明文超过上限",
            });
        }

        // ── 2. 压缩 ──────────────────────────────────────────────────────
        let compressed = compress::compress(&plaintext)?;

        // ── 3. 整体 AEAD ─────────────────────────────────────────────────
        let key = derive_envelope_key(master)?;
        let (nonce, ciphertext) = crypto::seal_bytes(&key, &self.aad(), &compressed)?;

        let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&self.sync_id);
        out.extend_from_slice(self.sender.as_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// 拆开一段搬运来的字节，得到**仍然加密**的记录。
    ///
    /// # 它只做外层
    ///
    /// 返回的 [`Record`] 还没有解密——那要逐条调 [`record::open`]。分两步是刻意的：
    /// 外层认证失败与某一条记录解不开是**不同**的故障（前者是整份载荷不可信，后者是
    /// 载荷可信但内容坏了），而调用方对它们的处置也不同——前者只能重试，后者值得报
    /// 一个具体的诊断。
    ///
    /// # 错误
    ///
    /// - [`Error::SyncBadMagic`]：不是本应用的载荷。
    /// - [`Error::SyncUnsupportedVersion`]：版本不受支持。
    /// - [`Error::SyncTruncated`]：字节不够。
    /// - [`Error::SyncAuthenticationFailed`]：外层认证失败。**不区分**原因。
    /// - [`Error::SyncEmptyPayload`] / [`Error::SyncDecompressionFailed`]：压缩层。
    /// - 其余结构错误。
    ///
    /// # 这个函数必须永不 panic
    ///
    /// 输入完全来自攻击者可控的通道（局域网上任何一台设备、或任何一段字节）。所有
    /// 越界都由读取游标挡掉：长度先用 `checked_add` 算终点，再走 `get(range)`，因此
    /// 溢出与越界都会返回 `None` 而不是 panic。
    pub fn open(master: &MasterKey, data: &[u8]) -> Result<Self> {
        // 魔数与版本要先于任何分配检查——否则一个 3 字节的输入就能让我们走进后面的
        // 读取逻辑。
        let mut reader = Reader::new(data);
        let magic = reader.take(MAGIC.len()).ok_or(Error::SyncTruncated)?;
        if magic != MAGIC {
            return Err(Error::SyncBadMagic);
        }
        let version = reader.u8_bare().ok_or(Error::SyncTruncated)?;
        if version != FORMAT_VERSION {
            return Err(Error::SyncUnsupportedVersion { version });
        }
        let sync_id: SyncId = reader
            .take(SYNC_ID_LEN)
            .ok_or(Error::SyncTruncated)?
            .try_into()
            .map_err(|_| Error::SyncTruncated)?;
        let sender_bytes: [u8; EntryId::LEN] = reader
            .take(EntryId::LEN)
            .ok_or(Error::SyncTruncated)?
            .try_into()
            .map_err(|_| Error::SyncTruncated)?;
        let sender = EntryId::from_bytes(sender_bytes);
        let nonce: [u8; NONCE_LEN] = reader
            .take(NONCE_LEN)
            .ok_or(Error::SyncTruncated)?
            .try_into()
            .map_err(|_| Error::SyncTruncated)?;
        let ciphertext = reader.rest();
        // 密文至少要有认证标签，否则连尝试解密都不必。
        if ciphertext.len() < TAG_LEN {
            return Err(Error::SyncTruncated);
        }

        let aad = header_aad(version, &sync_id, &sender);
        let key = derive_envelope_key(master)?;
        let compressed = crypto::open_bytes(&key, &aad, &nonce, ciphertext)?;

        // ── 反向：解压 → 解析 ─────────────────────────────────────────────
        let plaintext = compress::decompress(&compressed)?;
        let mut reader = Reader::new(&plaintext);
        let declared = reader.u32_bare().ok_or(Error::SyncTruncated)? as usize;

        // 上限检查要在**循环之前**：否则一份声称有 40 亿条记录的载荷会让我们进入一个
        // 长期循环，每次迭代都读一个已经耗尽的游标并立刻返回 `SyncTruncated`——结果
        // 是对的，但代价由攻击者决定。
        if declared > MAX_RECORDS {
            return Err(Error::SyncTooManyRecords {
                count: declared,
                limit: MAX_RECORDS,
            });
        }

        let mut records = RecordSet::<Record>::new();
        for _ in 0..declared {
            let id_bytes: [u8; EntryId::LEN] = reader
                .take(EntryId::LEN)
                .ok_or(Error::SyncTruncated)?
                .try_into()
                .map_err(|_| Error::SyncTruncated)?;
            let nonce: [u8; NONCE_LEN] = reader
                .take(NONCE_LEN)
                .ok_or(Error::SyncTruncated)?
                .try_into()
                .map_err(|_| Error::SyncTruncated)?;
            let len = reader.u32_bare().ok_or(Error::SyncTruncated)? as usize;
            if len < TAG_LEN {
                return Err(Error::SyncMalformed {
                    reason: "记录密文短于认证标签",
                });
            }
            let ciphertext = reader.take(len).ok_or(Error::SyncTruncated)?.to_vec();
            // 同一个 ID 出现两次一律拒绝，而不是「取第一条」。
            //
            // 这与合并层的宽容不同，因为这里的问题不是「该听哪一边」而是「这份载荷
            // 自相矛盾」。外层已经认证，因此它不是伪造的——但它是**生成方写错了**，
            // 而我们最不希望的就是把这样的载荷静默收下一半。
            if !records.insert(Record {
                entry_id: EntryId::from_bytes(id_bytes),
                nonce,
                ciphertext,
            }) {
                return Err(Error::SyncMalformed {
                    reason: "载荷里同一个条目出现了两条记录",
                });
            }
        }

        if !reader.is_empty() {
            // 明文里多出的字节意味着载荷被重新拼装过。这与「外层认证通过」不矛盾：
            // 一份**合法**载荷的明文被追加内容后，压缩流会变，外层就认证不过了。能走到
            // 这里只可能是我们自己的生成逻辑写错了，因此这是内部错误而不是攻击信号
            // ——但仍然要拒绝，不能静默忽略。
            return Err(Error::SyncMalformed {
                reason: "载荷明文含超出声明记录数的内容",
            });
        }

        Ok(Self {
            sync_id,
            sender,
            records,
        })
    }

    /// 把载荷里的全部记录解开。
    ///
    /// # 一条失败就整份失败
    ///
    /// 不做「跳过解不开的、收下其余」：外层已认证，因此解不开只可能是生成方用错了
    /// 密钥（例如两台设备的保险库其实来自不同的主密钥），而**部分成功**会让这种故障
    /// 表现成「同步成功但少了几条」——最难定位的一类。
    ///
    /// # 错误
    ///
    /// - [`Error::SyncAuthenticationFailed`]：某条记录解不开。
    /// - 其余结构错误（见 [`record::open`]）。
    pub fn open_records(&self, master: &MasterKey) -> Result<Vec<OpenedRecord>> {
        let key = derive_record_key(master)?;
        let mut opened = Vec::with_capacity(self.records.len());
        for record in &self.records {
            opened.push(record::open(&key, record)?);
        }
        Ok(opened)
    }

    /// 外层 AEAD 的 AAD。
    fn aad(&self) -> [u8; AAD_LEN] {
        header_aad(FORMAT_VERSION, &self.sync_id, &self.sender)
    }
}

/// 一个边界检查的读取游标。
///
/// 与保险库那边的同名类型是**分开的两份**，因为两者读取的格式不同、上限不同，而共用
/// 一个会让任一处的改动影响另一处的安全性。代价是几十行重复代码——比一个跨格式共用
/// 的、需要同时满足两边约束的游标便宜得多。
struct Reader<'a> {
    /// 待读的字节。
    data: &'a [u8],
    /// 下一个要读的位置。
    ///
    /// 恒满足 `pos <= data.len()`：只有 [`Reader::take`] 会推进它，而 `take` 在越界
    /// 时**不**推进。
    pos: usize,
}

impl<'a> Reader<'a> {
    /// 从一段字节的开头处开始读。
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// 取走 `len` 字节并推进游标；取不到时返回 `None` 且**不**推进。
    ///
    /// 两道保证叠在一起：
    ///
    /// 1. `checked_add` 挡住 `pos + len` 的整数溢出。一个声称长度为 `usize::MAX` 的
    ///    记录字段能让朴素的加法回绕成一个小值，从而绕过边界检查——这是解析器最经典
    ///    的一类漏洞，而这里从类型层面就不可达。
    /// 2. `get(range)` 挡住越界。
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    /// 读一个字节，不做任何语义检查。
    ///
    /// 后缀 `_bare` 表示「裸读」：版本号与种类字节都可能是任意值，合法性由调用方判断。
    /// 刻意不叫 `u8`——本模块里到处都是整数类型名，那样读起来分不清是类型还是方法。
    fn u8_bare(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }

    /// 读一个**大端** 32 位整数。
    ///
    /// 大端是网络字节序，也是本格式所有长度字段的写法：小端在十六进制转储里读起来是
    /// 反的，而这个格式注定要被人盯着看。
    fn u32_bare(&mut self) -> Option<u32> {
        self.take(4)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_be_bytes)
    }

    /// 取走剩余的全部字节并把游标推到末尾。
    ///
    /// 已经在末尾时返回空切片而不是 `None`：外层密文的长度是可变的，因此「零长度」是
    /// 一个合法结果，交由后面的「至少要有认证标签」那条检查去拒绝。
    fn rest(&mut self) -> &'a [u8] {
        let rest = self.data.get(self.pos..).unwrap_or(&[]);
        self.pos = self.data.len();
        rest
    }

    /// 是否已经读到末尾。
    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
}

/// 外层 AAD 的长度：魔数 + 版本 + sync_id + 设备 ID。
const AAD_LEN: usize = MAGIC.len() + 1 + SYNC_ID_LEN + EntryId::LEN;

/// 构造外层 AEAD 的 AAD。
///
/// # 它认证了什么
///
/// 整个明文头。这是我们唯一能「绑定但不泄露」的写法：`sync_id` 与 `sender` 都必须被
/// 认证——前者挡住「把一份载荷的标识换掉以绕过重放防护」，后者挡住「把载荷说成别人
/// 发的」。
///
/// # 为什么是自由函数而不是 `Payload` 的方法
///
/// `open` 在**构造出 `Payload` 之前**就需要这个 AAD（要先认证才能知道里面的记录是
/// 什么）。写成方法就得先造一个字段全是占位值的 `Payload`，而那样的中间状态正是最
/// 容易被后续改动误用的东西。
///
/// # 为什么不需要防「版本号被改」
///
/// `version` 直接来自输入，而它在 AAD 里。改低版本号会让 `version != FORMAT_VERSION`
/// 在更早的地方就返回 `SyncUnsupportedVersion`，因此走不到这里；即使走到了，AAD 变了
/// 也会让认证失败。两道检查独立成立。
fn header_aad(version: u8, sync_id: &SyncId, sender: &EntryId) -> [u8; AAD_LEN] {
    let mut aad = [0_u8; AAD_LEN];
    aad[..MAGIC.len()].copy_from_slice(MAGIC);
    aad[MAGIC.len()] = version;
    let offset = MAGIC.len() + 1;
    aad[offset..offset + SYNC_ID_LEN].copy_from_slice(sync_id);
    aad[offset + SYNC_ID_LEN..].copy_from_slice(sender.as_bytes());
    aad
}

/// 内层记录里用的记录种类，供 [`record`] 与打包方共用。
pub(crate) use crate::vault::RecordKind as InnerRecordKind;

const _: () = {
    // 编译期确认内外层的种类字节不重叠。两者若撞上，AAD 就可能相同，而那是域分离
    // 失效——见 `HKDF_SALT_SYNC` 的说明。
    assert!(InnerRecordKind::SyncEntry.as_byte() != InnerRecordKind::Entry.as_byte());
    assert!(InnerRecordKind::SyncTombstone.as_byte() != InnerRecordKind::Tombstone.as_byte());
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::{Algorithm, Digits, OtpSecret};
    use crate::vault::{Entry as VaultEntry, RecordKind, Timestamp, Vault, master_key_to_bytes};

    /// 造一条合法条目。
    fn sample_entry(seed: u8) -> VaultEntry {
        VaultEntry::new(
            format!("服务 {seed}"),
            Some("组织".into()),
            format!("user{seed}@example.com"),
            OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("合法 Base32"),
            Algorithm::Sha1,
            Digits::Six,
            30,
            None,
            String::new(),
            Timestamp::from(1_700_000_000_u64),
            Timestamp::from(1_700_000_000_u64),
        )
        .expect("字段合法")
    }

    fn a_master_key() -> MasterKey {
        MasterKey::generate().expect("OS 随机源可用")
    }

    /// 逐条解开载荷，交出每条的 `(标识, 是否是活条目)`。
    ///
    /// # 为什么需要它
    ///
    /// [`Payload::records`] 是按标识索引的、**不区分种类**的容器：一条记录可能是活
    /// 条目，也可能是一条墓碑，而 `RecordSet::get` 两者都返回 `Some`。因此「这条活条目
    /// 有没有被发出去」这个问题**只能**靠解密看种类来回答。
    ///
    /// 返回值带上标识，测试才能断言「发出的是哪一条」，而不只是「发了几条」。
    fn opened_kinds(payload: &Payload, master: &MasterKey) -> Vec<(EntryId, bool)> {
        payload
            .open_records(master)
            .expect("逐条解密")
            .into_iter()
            .map(|record| match record {
                OpenedRecord::Entry { id, .. } => (id, true),
                OpenedRecord::Tombstone(tombstone) => (tombstone.entry_id, false),
            })
            .collect()
    }

    /// 把 `seal` 的输出拆开，交出**真实的明文段**。
    ///
    /// # 为什么测试需要它
    ///
    /// [`Payload::open`] 只交出 `Payload`（记录仍然是**加密**的），因此从公开 API 看
    /// 不到线格式的字节排布。而「记录长度常量算错了」这类 bug 恰恰只在字节层面可见
    /// ——它曾经真实存在（见 `RECORD_HEADER_LEN` 的说明），而且当时那条自以为在盯着
    /// 线格式的测试是恒等式，抓不到它。
    ///
    /// 这里按**格式文档**重做一遍解析，与 `Payload::open` 的实现是两份独立代码：
    /// 校验的是排布，而不是内部一致性。
    fn plaintext_of(sealed: &[u8], master: &MasterKey) -> Vec<u8> {
        let mut reader = Reader::new(sealed);
        assert_eq!(reader.take(MAGIC.len()), Some(&MAGIC[..]), "魔数");
        let version = reader.u8_bare().expect("版本");
        assert_eq!(version, FORMAT_VERSION, "版本");
        let sync_id = reader.take(SYNC_ID_LEN).expect("sync_id");
        let sender = reader.take(EntryId::LEN).expect("发送方");
        let nonce = reader.take(NONCE_LEN).expect("nonce");
        let ciphertext = reader.rest();
        assert!(reader.is_empty(), "密文之后还有多余字节");

        let sync_id = <[u8; SYNC_ID_LEN]>::try_from(sync_id).expect("长度正确");
        let sender = EntryId::from_bytes(<[u8; EntryId::LEN]>::try_from(sender).expect("长度"));
        let nonce = <[u8; NONCE_LEN]>::try_from(nonce).expect("长度正确");

        let aad = header_aad(version, &sync_id, &sender);
        let envelope_key = derive_envelope_key(master).expect("可派生");
        let compressed = crate::vault::crypto::open_bytes(&envelope_key, &aad, &nonce, ciphertext)
            .expect("外层应当解得开");
        compress::decompress(&compressed).expect("应当解得开")
    }

    /// 按字节读明文里的记录段，返回每条的 `(entry_id, nonce, 密文长度)`。
    fn parse_record_frames(plaintext: &[u8]) -> Vec<([u8; EntryId::LEN], [u8; NONCE_LEN], usize)> {
        let mut reader = Reader::new(plaintext);
        let count = reader.u32_bare().expect("记录数") as usize;
        let mut frames = Vec::with_capacity(count);
        for _ in 0..count {
            let id = reader.take(EntryId::LEN).expect("标识");
            let nonce = reader.take(NONCE_LEN).expect("nonce");
            let len = reader.u32_bare().expect("长度") as usize;
            reader.take(len).expect("密文");
            frames.push((
                <[u8; EntryId::LEN]>::try_from(id).expect("长度"),
                <[u8; NONCE_LEN]>::try_from(nonce).expect("长度"),
                len,
            ));
        }
        assert!(reader.is_empty(), "记录段之后还有多余字节");
        frames
    }

    /// **线格式的字节排布必须与 `encoded_len` 一致。**
    ///
    /// 这是唯一一条真正读字节的测试。它存在的理由是具体的：`RECORD_HEADER_LEN` 曾经
    /// 因为早先一版设计留下一个多余的 `+ 1`，而当时那条测试把同一个常量再加一遍，
    /// 于是「断言」与「被断言的东西」是同一个错误，绿了很久。
    #[test]
    fn the_plaintext_record_framing_matches_encoded_len() {
        let master = a_master_key();
        let sender = EntryId::from_bytes([7; EntryId::LEN]);

        // 三条条目 + 一条墓碑：两种记录都要出现在同一份载荷里。
        let mut vault = Vault::new();
        for seed in 0..3_u8 {
            vault.insert(sample_entry(seed)).expect("随机源可用");
        }
        let doomed = vault.insert(sample_entry(9)).expect("随机源可用");
        vault.remove(&doomed, Timestamp::from(1_700_000_100_u64));

        let payload = Payload::from_vault(&master, sender, &vault).expect("打包");
        let sealed = payload.seal(&master).expect("封装");

        let plaintext = plaintext_of(&sealed, &master);
        let frames = parse_record_frames(&plaintext);

        assert_eq!(frames.len(), payload.len(), "记录数不一致");
        assert_eq!(
            frames.len(),
            vault.len() + vault.tombstone_count(),
            "载荷里的记录数应当等于条目数加墓碑数"
        );

        // 每一条的字节数必须与 `encoded_len` 报的一致。把 frame 还原成 `Record` 再比，
        // 是为了走**同一个** `encoded_len`，而不是在测试里重算一遍公式。
        for (id_bytes, nonce, len) in &frames {
            let id = EntryId::from_bytes(*id_bytes);
            let record = payload.records.get(&id).expect("载荷里应当有这条记录");
            assert_eq!(record.nonce, *nonce, "nonce 对不上");
            assert_eq!(record.ciphertext.len(), *len, "密文长度对不上");
            assert_eq!(
                record.encoded_len(),
                EntryId::LEN + NONCE_LEN + 4 + len,
                "encoded_len 与线格式的实际字节数不一致"
            );
        }

        // 明文总长度 = 记录数 + 每条固定头 + 全部密文。这条把「常量算错」的误差按
        // 记录数放大，因此比逐条断言更容易在回归时看出来。
        let expected: usize = 4
            + frames.len() * (EntryId::LEN + NONCE_LEN + 4)
            + frames.iter().map(|f| f.2).sum::<usize>();
        assert_eq!(plaintext.len(), expected, "明文总长度与线格式不一致");
    }

    /// 明文里**没有**种类字节。
    ///
    /// 这是刻意的设计（让攻击者看不出这次带了几条删除），而它也是 `RECORD_HEADER_LEN`
    /// 那个多余 `+ 1` 的来源——所以值得有一条测试把它钉住，免得将来有人「顺手」
    /// 把种类写回明文以简化解密逻辑。
    #[test]
    fn the_record_kind_is_not_in_the_plaintext() {
        let master = a_master_key();
        let sender = EntryId::from_bytes([7; EntryId::LEN]);

        let mut vault = Vault::new();
        let id = vault.insert(sample_entry(1)).expect("随机源可用");
        vault.remove(&id, Timestamp::from(1_700_000_100_u64));

        let payload = Payload::from_vault(&master, sender, &vault).expect("打包");
        let sealed = payload.seal(&master).expect("封装");
        let plaintext = plaintext_of(&sealed, &master);

        // 明文 = 记录数(4) + 标识(16) + nonce(24) + 长度(4) + 墓碑密文。
        // 距离记录数之后第 4 个字节就是标识，中间**没有**种类字节。
        assert_eq!(
            plaintext.len(),
            4 + EntryId::LEN + NONCE_LEN + 4 + {
                let frames = parse_record_frames(&plaintext);
                frames[0].2
            }
        );
        assert_eq!(
            &plaintext[4..4 + EntryId::LEN],
            id.as_bytes(),
            "记录数之后紧接着的应当是标识，没有种类字节"
        );

        // 种类字节 0x82（SyncTombstone）不得出现在记录头的位置上。
        assert_ne!(
            RecordKind::SyncTombstone.as_byte(),
            plaintext[3],
            "第 4 字节是标识的一部分"
        );
    }

    /// 域分离常量必须稳定：改掉它们会让所有既有的载荷打不开。
    #[test]
    fn the_domain_separation_constants_are_stable() {
        assert_eq!(&HKDF_SALT_SYNC, b"Qualia2FA sync salt v1 (records)");
        assert_eq!(HKDF_SALT_SYNC.len(), 32);
        assert_eq!(MAGIC, b"Q2FASYNC");
        assert_eq!(FORMAT_VERSION, 1);
        // 载荷格式版本与文件格式版本是**两个**独立常量。
        assert_ne!(FORMAT_VERSION, crate::vault::FORMAT_VERSION);
    }

    /// 载荷与保险库的密钥必须真的不同。
    #[test]
    fn the_sync_and_vault_keys_are_different() {
        let master = a_master_key();
        let record = derive_record_key(&master).expect("可派生");
        let envelope = derive_envelope_key(&master).expect("可派生");
        let vault_key = crate::vault::crypto::entry_key(&master).expect("可派生");

        assert_ne!(record, envelope, "记录密钥与信封密钥撞上了");
        assert_ne!(record, vault_key, "同步记录密钥与保险库条目密钥撞上了");
        assert_ne!(envelope, vault_key, "信封密钥与保险库条目密钥撞上了");
    }

    /// 空保险库也能打包与拆包，且往返后仍是空的。
    #[test]
    fn an_empty_vault_roundtrips() {
        let master = a_master_key();
        let sender = EntryId::from_bytes([1; EntryId::LEN]);
        let payload = Payload::from_vault(&master, sender, &Vault::new()).expect("打包");

        assert!(payload.is_empty(), "空保险库不该产生记录");
        assert_eq!(payload.len(), 0);

        let sealed = payload.seal(&master).expect("封装");
        let opened = Payload::open(&master, &sealed).expect("拆包");
        assert!(opened.is_empty());
        assert_eq!(opened.sender, sender);
        assert_eq!(opened.sync_id, payload.sync_id);
        assert!(
            opened.open_records(&master).expect("逐条解密").is_empty(),
            "空载荷不该解开出任何记录"
        );
    }

    /// 每次打包都应当是一个**新的**载荷标识，否则重放防护无处落脚。
    #[test]
    fn every_payload_gets_a_fresh_sync_id() {
        let master = a_master_key();
        let sender = EntryId::from_bytes([1; EntryId::LEN]);
        let mut vault = Vault::new();
        vault.insert(sample_entry(1)).expect("随机源可用");

        let first = Payload::from_vault(&master, sender, &vault).expect("打包");
        let second = Payload::from_vault(&master, sender, &vault).expect("打包");
        assert_ne!(
            first.sync_id, second.sync_id,
            "两次打包拿到了同一个载荷标识"
        );
        assert_eq!(first.len(), second.len(), "两次打包的记录数应当相同");
    }

    /// 同一份保险库打包两次的密文必须不同（nonce 每次随机）。
    ///
    /// 若相同，说明 nonce 被复用了——那是 XChaCha20-Poly1305 最严重的一类误用，
    /// 而它在功能测试里完全看不出来（一切照常工作）。
    #[test]
    fn sealing_the_same_vault_twice_produces_different_bytes() {
        let master = a_master_key();
        let sender = EntryId::from_bytes([1; EntryId::LEN]);
        let mut vault = Vault::new();
        vault.insert(sample_entry(1)).expect("随机源可用");

        let first = Payload::from_vault(&master, sender, &vault).expect("打包");
        let second = Payload::from_vault(&master, sender, &vault).expect("打包");

        let a = first.seal(&master).expect("封装");
        let b = second.seal(&master).expect("封装");
        assert_ne!(a, b, "两次封装的字节完全相同，nonce 很可能被复用了");

        // 记录密钥相同，因此内层密文也必须因 nonce 不同而不同。
        let ra = plaintext_of(&a, &master);
        let rb = plaintext_of(&b, &master);
        let fa = parse_record_frames(&ra);
        let fb = parse_record_frames(&rb);
        assert_eq!(fa.len(), fb.len());
        for (x, y) in fa.iter().zip(fb.iter()) {
            assert_eq!(x.0, y.0, "同一条目");
            assert_ne!(x.1, y.1, "同一条记录的 nonce 被复用了");
        }
    }

    /// 保险库里同时有活条目与它的墓碑时，**只**发墓碑。
    ///
    /// # 这个状态是怎么出现的
    ///
    /// **不是** [`Vault::remove`] 造成的：它按设计既删条目也留墓碑，因此不会留下
    /// 「条目与墓碑并存」。并存只来自同步本身——[`crate::vault::Vault::record_tombstone`]
    /// 的文档写得很明确：「若该 ID 的活条目存在，**不会**被删除，调用方需要自己决定
    /// D2 的裁决结果」。也就是说，对端发来墓碑而本机不愿意自动采纳时，就会停在这个
    /// 状态上等用户裁决。
    ///
    /// 而这个状态是**真实且常见**的：两台设备各有一条同名同 ID 的条目、其中一台删了，
    /// 另一台在裁决界面弹出期间就是这个样子。广播那份活条目会让每次同步都在对端触发
    /// 同一个冲突，用户每同步一次就要看一次同样的裁决界面。
    #[test]
    fn an_entry_with_a_tombstone_is_not_sent() {
        let master = a_master_key();
        let sender = EntryId::from_bytes([1; EntryId::LEN]);

        let mut vault = Vault::new();
        let kept = vault.insert(sample_entry(1)).expect("随机源可用");
        let disputed = vault.insert(sample_entry(2)).expect("随机源可用");

        // 对端说这条被删了，本机先记下来但**不**采纳——裁决未完成。
        vault.record_tombstone(crate::vault::Tombstone {
            entry_id: disputed,
            deleted_at: Timestamp::from(1_700_000_100_u64),
            deleted_by: None,
        });

        // 前提：条目与墓碑并存。这才是本测试要覆盖的状态。
        assert_eq!(vault.len(), 2, "前提不成立：两条活条目都应当还在");
        assert_eq!(vault.tombstone_count(), 1, "前提不成立：应当有墓碑");
        assert!(
            vault.get(&disputed).is_some(),
            "前提不成立：`record_tombstone` 不该删掉活条目"
        );

        let payload = Payload::from_vault(&master, sender, &vault).expect("打包");
        assert_eq!(payload.len(), 2, "应当只有「保留的条目 + 墓碑」两条记录");
        assert!(payload.records.get(&kept).is_some(), "保留的条目应当被发出");

        // # 为什么不能靠 `records.get(&disputed).is_none()` 判断
        //
        // `RecordSet` 是按 `entry_id` 索引的，**不区分记录种类**——因此那条墓碑的
        // 记录用的正是 `disputed` 这个 ID。`get(&disputed)` 会返回 `Some`，而那是
        // 墓碑，不是被发出去了的活条目。（第一版测试就是这么写的，于是它错了。）
        //
        // 判断「发出去的是条目还是墓碑」只能靠逐条解开看种类。
        let records = opened_kinds(&payload, &master);
        let mut entries = Vec::new();
        let mut tombstones = Vec::new();
        for (id, is_entry) in records {
            if is_entry {
                entries.push(id);
            } else {
                tombstones.push(id);
            }
        }
        assert_eq!(
            entries,
            vec![kept],
            "应当只发出一条活条目，而且是保留的那条"
        );
        assert_eq!(tombstones, vec![disputed], "应当只发出一条墓碑");
        assert!(
            !entries.contains(&disputed),
            "有墓碑的活条目被当成条目发出了"
        );
    }

    /// 记录数上限在**循环之外**检查。
    ///
    /// 否则一个声称有 40 亿条记录的载荷能让我们先分配一个 40 亿项的容器再发现不对。
    /// 这里只能做结构性验证：构造一份声称超限的明文，确认它被拒绝而不是被分配。
    #[test]
    fn an_absurd_record_count_is_rejected_before_allocating() {
        let master = a_master_key();
        // 明文 = 一个声称有一条记录的载荷，但把记录数改成 u32::MAX。
        let mut vault = Vault::new();
        vault.insert(sample_entry(1)).expect("随机源可用");
        let payload = Payload::from_vault(&master, EntryId::from_bytes([1; EntryId::LEN]), &vault)
            .expect("打包");

        // 手工构造：记录数写成 u32::MAX，后面附上真实的记录字节（不压缩，直接进
        // 底层 AEAD——`decompress` 对未压缩输入会失败，因此这里改走 compress 之后
        // 再改字节不可行）。改为直接验证常量与解析顺序：构造一段「记录数超限」的
        // 明文，用 `compress` 压一下再封进信封。
        let mut plaintext = u32::MAX.to_be_bytes().to_vec();
        plaintext.extend_from_slice(&[0_u8; 64]);
        let compressed = compress::compress(&plaintext).expect("可压缩");

        let envelope_key = derive_envelope_key(&master).expect("可派生");
        let aad = header_aad(FORMAT_VERSION, &payload.sync_id, &payload.sender);
        let (nonce, ciphertext) =
            crate::vault::crypto::seal_bytes(&envelope_key, &aad, &compressed).expect("可加密");

        let mut sealed = Vec::new();
        sealed.extend_from_slice(MAGIC);
        sealed.push(FORMAT_VERSION);
        sealed.extend_from_slice(&payload.sync_id);
        sealed.extend_from_slice(payload.sender.as_bytes());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);

        let result = Payload::open(&master, &sealed);
        assert!(
            matches!(result, Err(Error::SyncTooManyRecords { .. })),
            "超限的记录数未被拒绝，实际 {result:?}"
        );
    }

    /// 主密钥的字节要走公开 API 拿，避免测试自己拼。
    #[test]
    fn the_master_key_roundtrips_through_bytes() {
        let master = a_master_key();
        let copy = MasterKey::from_bytes(master_key_to_bytes(&master)).expect("长度正确");
        assert_eq!(
            derive_record_key(&master).expect("可派生"),
            derive_record_key(&copy).expect("可派生"),
            "同一把主密钥的副本应当派生出同一把记录密钥"
        );
    }
}
