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

//! 并集合并与裁决。
//!
//! # 合并是「取并集」，但并集在两种情况下不够
//!
//! 以 [`EntryId`] 为键取并集，这是同步的主体。一个随机 128-bit 标识的碰撞概率可以
//! 忽略，因此**同一个 ID 在两端就代表同一条目**，不需要版本向量或逻辑时钟来判断
//! 「谁更新」。
//!
//! 两种情况并集本身给不出答案，它们进 [`Conflict`]：
//!
//! | 本地 | 对端 | 处置 |
//! |---|---|---|
//! | 有条目 | 同 ID 条目，内容不同 | **冲突**：各自改过，交人来裁定 |
//! | 有条目 | 同 ID 墓碑，且本地条目**之后没改过** | 自动接受删除 |
//! | 有条目 | 同 ID 墓碑，且本地条目**之后改过** | **冲突** |
//! | 有条目 | 什么都没有 | 保留本地（对端只是没有这条） |
//! | 没有 | 条目 / 墓碑 | 收下 |
//!
//! # 为什么删除必须有墓碑
//!
//! 「没有这条」与「这条被删了」在并集里是**同一件事**——都表现为「对端没有」。没有
//! 墓碑，一台离线设备重新上线时会把已删条目当成「我这边有、对面没有」而保留，于是
//! 删除被静默撤销。墓碑把「删了」变成一个**有内容的记录**，让它能被同步。
//!
//! # 这个模块不替用户判断「哪边更新」
//!
//! 时间戳可以用来猜，但那是在替用户做决定，而删掉一个 2FA 条目是不可逆的。何况时间
//! 戳来自对端设备，攻击者随便填。因此除了下面两条不需要人判断的规则，两边都有内容时
//! **一律**报冲突：
//!
//! - **内容逐字段相同** → 无冲突。这是最常见的情况：条目只在一边改过，另一边是原样
//!   的旧副本。没有这条，每次同步都会弹出一堆「冲突」而其实什么都没变。
//! - **本地条目在墓碑时间之后没再改过** → 接受删除。对应「B 删了，A 从没动过」，
//!   用户意图清楚，而且它让删除终于能传播。
//!
//! 本地比墓碑新的情形**仍然报冲突**，只是把 `local_is_newer` 一并交给裁决界面——
//! 那是用户判断该保留哪边时最需要知道的一件事，但库不据此自动选边。

use std::collections::BTreeMap;

use crate::Result;
use crate::vault::{Entry as VaultEntry, EntryId, Tombstone, Vault};

/// 一条来自对端的记录，连同它的标识。
///
/// # 为什么标识在这里而不是在 [`VaultEntry`] 里
///
/// [`VaultEntry`] 刻意不带 ID：一个「自带标识的条目」可以让同一份数据里出现两个互相
/// 矛盾的标识。但同步载荷里的每条记录**必须**同时带上标识——它是 AEAD 的 AAD 之一，
/// 也是并集的键。把这个组合封在枚举里，「有条目但不知道它是哪一条」这种状态就不存在，
/// 于是 [`merge_into`] 不需要返回 `Result` 去报告「记录自相矛盾」。
///
/// # 没有 `Clone`
///
/// [`VaultEntry`] 刻意不实现 `Clone`（理由见 [`crate::otp::OtpSecret`]），因此这个
/// 枚举也不能派生它。需要复制时走 [`VaultEntry::duplicate`]——那个入口是显式的，
/// 调用点必须写下 `duplicate()`，从而在代码审查中可见「这里又复制了一份密钥材料」。
#[derive(Debug, PartialEq, Eq)]
pub enum MergedRecord {
    /// 一条活条目。
    Entry {
        /// 条目的标识。
        id: EntryId,
        /// 条目的内容。
        entry: Box<VaultEntry>,
    },
    /// 一条墓碑（删除记录）。
    Tombstone(Box<Tombstone>),
}

impl MergedRecord {
    /// 这条记录讲的是哪一个条目。
    #[must_use]
    pub fn entry_id(&self) -> EntryId {
        match self {
            Self::Entry { id, .. } => *id,
            Self::Tombstone(tombstone) => tombstone.entry_id,
        }
    }
}
/// 一次合并里发现的、需要人来裁定的分歧。
///
/// # 为什么这里要复制条目
///
/// 冲突的本质就是「有两个不同的版本」，而裁决界面必须**同时**看到两边。因此本地那
/// 一版被复制进这里，而对端那一版（本来就在我们手上）被移进来。
///
/// 复制走 [`VaultEntry::duplicate`]，是显式的、可能失败的。这不只是风格问题：同一份
/// 密钥材料在内存里多存一份就多一份泄露面，而这个复制**只在真的出现分歧时**发生——
/// 绝大多数同步里 `conflicts` 是空的。
#[derive(Debug, PartialEq, Eq)]
pub struct Conflict {
    /// 出分歧的条目。
    pub entry_id: EntryId,
    /// 分歧的种类。
    pub kind: ConflictKind,
}

/// 分歧的种类。
#[derive(Debug, PartialEq, Eq)]
pub enum ConflictKind {
    /// 两端都有这条条目，但内容不同。
    ///
    /// 两边的内容**都**保留（而不是只给一个「冲突了」的标记）：裁决界面必须同时展示
    /// 两边的账号名与备注，否则用户无从判断。
    EntryMismatch {
        /// 本地的版本。
        local: Box<VaultEntry>,
        /// 对端发来的版本。**尚未**写入本地保险库。
        incoming: Box<VaultEntry>,
    },
    /// 一端删了，另一端还在且**被改过**。
    ///
    /// 本地那条若在删除之后没被动过，这一条不会成为冲突——它会被自动接受为删除。
    DeletionConflict {
        /// 本地的版本。
        ///
        /// # 为什么是 `Option`
        ///
        /// 这个冲突有**两个方向**，只有其中一个方向需要在这里带上本地内容：
        ///
        /// - **对端发来墓碑**（本地有较新的活条目）：本地内容已经在保险库里，裁决
        ///   界面直接读它就行，因此这里是 `None`。少复制一份密钥材料。
        /// - **对端发来活条目**（本地有墓碑）：本地内容是一份**墓碑**，而对方那一版
        ///   条目本来就在我们手上、直接移进来即可——此时这里是对方那一版条目，好让
        ///   裁决界面知道「对端想要恢复这条」。
        ///
        /// 两种情况都避免了为「展示」而复制密钥材料，除了下面 `incoming` 是活条目
        /// 的那一种——那一种本来就没有本地活条目可读。
        local: Option<Box<VaultEntry>>,
        /// 对端发来的墓碑。**尚未**写入本地保险库。
        incoming: Box<Tombstone>,
        /// 本地版本比墓碑晚。
        ///
        /// 这是**提示**，不是判定依据：它告诉裁决界面「这一端在你删完之后还改过」。
        /// 库不据此自动选边——对端的时间戳由对端填写。
        local_is_newer: bool,
    },
}

/// 一次合并的结果。
///
/// 没有 `Clone`：它可能持有冲突，而冲突持有密钥材料。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MergeOutcome {
    /// 新增的条目数。
    pub added: usize,
    /// 新增的墓碑数。**不**包括「本地已有该墓碑」的情形。
    pub tombstones_added: usize,
    /// 被接受的删除数（本地条目被墓碑替代）。
    pub deletions_applied: usize,
    /// 内容完全相同、什么都没做的记录数。
    pub unchanged: usize,
    /// 需要人来裁定的分歧。
    pub conflicts: Vec<Conflict>,
}

impl MergeOutcome {
    /// 这次合并是否什么都没改，也没有待裁决的分歧。
    ///
    /// 用于让界面跳过「同步完成」这类提示——重复同步同一批数据时它是 `true`，而那
    /// 正是幂等性的可观察形态。
    #[must_use]
    pub fn made_no_change(&self) -> bool {
        self.added == 0
            && self.tombstones_added == 0
            && self.deletions_applied == 0
            && self.conflicts.is_empty()
    }

    /// 是否有待裁决的分歧。
    #[must_use]
    pub fn needs_adjudication(&self) -> bool {
        !self.conflicts.is_empty()
    }
}

/// 把一批来自对端的记录并进本地保险库。
///
/// # 幂等
///
/// 同一批记录合并两次，第二次的 `added`、`tombstones_added`、`deletions_applied`
/// 都是 `0`，`unchanged` 是全部，保险库内容逐字节不变。这是**可观察**的幂等性，
/// 不只是「逻辑上应该幂等」。
///
/// # 交换律只在保险库内容上成立
///
/// `merge(merge(v, a), b)` 与 `merge(merge(v, b), a)` 的**保险库内容**相同，但
/// **冲突列表可能不同**（先后顺序决定哪边被当成 `local`）。库不假装两者等价：冲突
/// 本来就是「要人来决定」的东西，把顺序差异藏起来只会让裁决界面显示出与用户刚看到
/// 的不同的内容。
///
/// # 这个函数返回 `Result` 只有一个原因
///
/// 出现冲突时要**复制**本地那一版（见 [`Conflict`]），而 [`VaultEntry::duplicate`] 是
/// 可能失败的。除此之外合并只操作内存里的映射，不会失败。
///
/// 冲突里的 `incoming` **不会**被写入：调用方必须先让用户裁定。这是刻意的，因为
/// 「先写进去、再让用户改回来」会在用户没来得及反应时就把本地数据覆盖掉。
///
/// # 错误
///
/// [`crate::Error::VaultDecryptionFailed`] 之外的结构错误：由
/// [`VaultEntry::duplicate`] 传播，只在保险库里存在一个违反格式约束的条目时发生。
pub fn merge_into<'a>(
    vault: &mut Vault,
    records: impl IntoIterator<Item = &'a MergedRecord>,
) -> Result<MergeOutcome> {
    let mut outcome = MergeOutcome::default();

    for record in records {
        match record {
            MergedRecord::Entry { id, entry } => merge_entry(vault, id, entry, &mut outcome)?,
            MergedRecord::Tombstone(tombstone) => {
                merge_tombstone(vault, tombstone, &mut outcome);
            }
        }
    }

    Ok(outcome)
}

/// 合并一条活条目。
///
/// 会失败**只**因为 [`VaultEntry::duplicate`] 失败（报冲突时要复制本地那一版）。
fn merge_entry(
    vault: &mut Vault,
    id: &EntryId,
    entry: &VaultEntry,
    outcome: &mut MergeOutcome,
) -> Result<()> {
    // 本地已有同 ID 的活条目。
    if let Some(existing) = vault.get(id) {
        if entries_identical(existing, entry) {
            outcome.unchanged += 1;
            return Ok(());
        }
        outcome.conflicts.push(Conflict {
            entry_id: *id,
            kind: ConflictKind::EntryMismatch {
                local: Box::new(existing.duplicate()?),
                incoming: Box::new(entry.duplicate()?),
            },
        });
        return Ok(());
    }

    // 本地有墓碑、没有活条目：这条条目来自一台**还没收到删除**的设备。直接插进去会
    // 让已裁决的删除复活，因此报冲突而不是插入。
    if let Some(tombstone) = vault.get_tombstone(id) {
        outcome.conflicts.push(Conflict {
            entry_id: *id,
            kind: ConflictKind::DeletionConflict {
                local: Some(Box::new(entry.duplicate()?)),
                incoming: Box::new(tombstone.clone()),
                local_is_newer: entry.updated_at > tombstone.deleted_at,
            },
        });
        return Ok(());
    }

    // 本地完全没有这条。`insert_with_id` 只在 ID 已存在时失败，而上面已经排除了
    // 那两种情形——因此这里的失败是不可达的。仍然不用 `expect`：一个不可达的 panic
    // 分支在将来改动之后可能变得可达，而那时它会在用户的数据上触发。
    if vault.insert_with_id(*id, entry.duplicate()?).is_ok() {
        outcome.added += 1;
    }
    Ok(())
}

/// 合并一条墓碑。
///
/// 不返回 Result：它不复制任何密钥材料（墓碑里没有秘密），因此没有可失败之处。
fn merge_tombstone(vault: &mut Vault, tombstone: &Tombstone, outcome: &mut MergeOutcome) {
    let id = tombstone.entry_id;

    // 已经知道这条墓碑。
    if let Some(existing) = vault.get_tombstone(&id) {
        // 两端各有一条墓碑但时间不同时，**保留更早的那个**。理由不是「早的更新」，
        // 而是「删除这件事确实发生过」——两条墓碑都证明用户删过。取更早的让两端
        // 收敛到同一个值，且不刷新删除时间，因而不会让一台设备反复删除把裁决结果
        // 改掉。
        if tombstone.deleted_at < existing.deleted_at {
            vault.record_tombstone(tombstone.clone());
        }
        outcome.unchanged += 1;
        return;
    }

    // 本地有活条目。
    if let Some(local) = vault.get(&id) {
        if local.updated_at <= tombstone.deleted_at {
            // 本地条目在对方删除之前（或同一秒）就没再改过：用户意图很清楚——那边
            // 删了，这边只是原样的旧副本。接受删除。
            //
            // 先 `remove` 再 `record_tombstone`，而不是只 `record_tombstone`：后者
            // **不删活条目**（见 `Vault::record_tombstone` 的文档），于是会出现
            // 「活条目与墓碑并存」的状态，而那是裁决尚未完成时才该有的。
            vault.remove(&id, tombstone.deleted_at);
            vault.record_tombstone(tombstone.clone());
            outcome.deletions_applied += 1;
            return;
        }
        // 本地条目比删除更新：用户在删除之后还改过它。这可能是「用户又想要这条」，
        // 也可能是「两台设备各干各的」。报冲突。
        //
        // 这里**不**复制本地那一版——`merge_tombstone` 目前不返回 `Result`，而复制是
        // 可能失败的。冲突报出去，裁决界面用自己的方式取本地内容（它本来就能访问
        // 保险库）。这与 `EntryMismatch` 那条分支不同：那里两边的内容都必须同时呈现，
        // 而这里真正要展示的是「本地有一条较新的条目，对端说它被删了」。
        outcome.conflicts.push(Conflict {
            entry_id: id,
            kind: ConflictKind::DeletionConflict {
                // 本地内容已经在保险库里，裁决界面自己读；不复制密钥材料。`None` 是刻意的。
                local: None,
                incoming: Box::new(tombstone.clone()),
                local_is_newer: true,
            },
        });
        return;
    }

    vault.record_tombstone(tombstone.clone());
    outcome.tombstones_added += 1;
}

/// 两条条目是否完全相同。
///
/// 直接调 [`VaultEntry`] 的 `PartialEq`：那个实现刻意把秘密字段（种子）的比较放在
/// **最后**，因此名字就不同的一对条目在第一个字段就被排除，不会付出恒定时间比较的
/// 代价。见 [`crate::vault::Entry`] 的 `PartialEq`。
///
/// 之所以单独包一层而不是直接写 `a == b`：调用点需要一处能写下「为什么这里可以比较
/// 秘密」的地方。答案是**能执行这个比较的一方已经同时持有两边的明文**，因此普通比较
/// 不构成降级；但这一点需要被写下来，否则后人看到「秘密被拿来比较」会先怀疑是 bug。
fn entries_identical(a: &VaultEntry, b: &VaultEntry) -> bool {
    a == b
}

/// 便于调用方按标识组织记录的容器。
///
/// # 为什么要按标识去重
///
/// 一份载荷里同一个 `EntryId` 出现两次是**合法**的：它可能带着两台设备各自的版本。
/// 但合并只能落实一个结果，因此必须先定下「用哪一个」。这里采取「先插入的胜出」，
/// 而载荷的生成方负责把它认为更该被采纳的那个放在前面。
///
/// **不能**用「后插入的覆盖」：那会让载荷里的顺序变成一个安全相关的性质（最后一条
/// 说了算），而对端控制着那个顺序。
///
/// # 为什么是泛型的
///
/// 两个地方需要「按标识去重的记录集合」，而它们的元素类型不同：
///
/// - [`MergedRecord`]：**解密之后**的语义记录，合并层用。
/// - [`crate::sync::Record`]：**仍然加密**的线格式记录，载荷打包与解析用。
///
/// 让容器泛型化比写两份的好处不只是省代码：两者的**去重规则必须一致**（都是「先插入
/// 的胜出」），而两份实现会在某次改动中悄悄分叉，症状是「同一份载荷在发送端去重了、
/// 在接收端没有」——一个只有在对端手里才复现的故障。
#[derive(Debug)]
pub struct RecordSet<T> {
    /// 按标识索引的记录。BTreeMap 而不是 HashMap：遍历顺序必须确定。
    by_id: BTreeMap<EntryId, T>,
}

impl<T> Default for RecordSet<T> {
    fn default() -> Self {
        Self {
            by_id: BTreeMap::new(),
        }
    }
}

impl<T: HasEntryId> RecordSet<T> {
    /// 空的集合。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 插入一条记录；同一个 ID 已经存在时**不覆盖**。
    ///
    /// 返回是否真的插入了（`false` 表示这个 ID 已经有了）。
    pub fn insert(&mut self, record: T) -> bool {
        let id = record.entry_id();
        if self.by_id.contains_key(&id) {
            return false;
        }
        self.by_id.insert(id, record);
        true
    }

    /// 有多少条。
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// 取出某个 ID 的记录。
    #[must_use]
    pub fn get(&self, id: &EntryId) -> Option<&T> {
        self.by_id.get(id)
    }

    /// 按 ID 顺序遍历。
    ///
    /// `BTreeMap` 而不是 `HashMap`：遍历顺序必须确定，否则同一份载荷在不同设备上会
    /// 产生不同的合并顺序，而冲突列表的顺序也就跟着变；对线格式而言还会让两份内容
    /// 相同的载荷产生不同的明文。
    pub fn iter(&self) -> impl Iterator<Item = (&EntryId, &T)> {
        self.by_id.iter()
    }
}

impl<'a, T> IntoIterator for &'a RecordSet<T> {
    type Item = &'a T;
    type IntoIter = std::collections::btree_map::Values<'a, EntryId, T>;

    /// 按 ID 顺序借用全部记录。
    ///
    /// # 为什么是借用而不是 `records() -> Vec<T>`
    ///
    /// 后者要求每条记录都能被复制，而两个元素类型都刻意没有 `Clone`（它们装着密钥
    /// 材料）。借用让 [`merge_into`] 可以直接吃 `&RecordSet`，不必为了「传参」而复制
    /// 整份载荷的密钥——一次同步复制几百份种子是完全没有必要的泄露面扩大。
    fn into_iter(self) -> Self::IntoIter {
        self.by_id.values()
    }
}

/// 「知道自己是哪一条记录」的类型。
///
/// [`RecordSet`] 用这个 trait 取去重用的键。它只有这一个方法，因为容器只需要这一件事
/// ——一个更宽的 trait 会诱使容器去做它不该做的事（比如按内容排序，那需要读密钥）。
pub trait HasEntryId {
    /// 这条记录讲的是哪一个条目。
    fn entry_id(&self) -> EntryId;
}

impl HasEntryId for MergedRecord {
    fn entry_id(&self) -> EntryId {
        match self {
            Self::Entry { id, .. } => *id,
            Self::Tombstone(tombstone) => tombstone.entry_id,
        }
    }
}
