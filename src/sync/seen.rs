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

//! 已处理过的同步载荷标识的日志。
//!
//! # 它挡住的不是「数据被改坏」
//!
//! 合并是**幂等**的：同一份载荷合并两次，结果与合并一次相同。因此重放一份旧载荷
//! **不会破坏正确性**。它挡住的是另外两件事：
//!
//! 1. **白做一次完整的解密与合并。** 一份载荷要先过外层 AEAD、再解压、再逐条解密、
//!    再走合并。局域网里一台设备反复广播同一份载荷，接收方就会反复做这些事——这是
//!    一个不需要任何密码学突破的拒绝服务面。
//! 2. **界面上的「上次同步时间」变成攻击者可任意推动的值。** 用户看到「刚刚同步过」，
//!    而实际上什么都没发生。
//!
//! # 为什么是「拒绝」而不是「静默跳过」
//!
//! 静默成功会让调用方以为「刚刚完成了一次同步」，于是去更新那个时间戳——那正是上面
//! 第 2 条要防的。因此重复载荷返回 [`crate::Error::SyncAlreadyApplied`]，调用方据此
//! **不更新**同步时间，但仍可以告诉用户「这次的数据之前已经同步过了」。
//!
//! # 有界，且满了要显式失败
//!
//! 日志不能无限增长。到上限时返回 [`crate::Error::SyncIdLogFull`]，而**不是**静默
//! 丢弃最旧的那条：丢弃会让一份很旧的载荷重新变得可接受，而那正是本模块要防的。
//! 上限取 [`MAX_SEEN_SYNC_IDS`]，由调用方决定满了之后怎么办（提示用户、或者放弃
//! 重放防护并清空——那是上层策略，不是本模块能替用户做的决定）。

use std::collections::VecDeque;

use crate::sync::SyncId;
use crate::{Error, Result};

/// 日志的条目数上限。
///
/// 每条 32 字节，因此 4096 条约 128 KiB 内存。这个量级对桌面端与移动端都可以忽略，
/// 而 4096 次同步在真实使用下要很久才能填满（同步是用户手动触发的动作）。
///
/// 与 [`crate::vault::MAX_RECORDS`] 那种「防御恶意输入」的上限不同，这个上限**不是**
/// 安全边界：载荷标识是随机的，攻击者无法通过「故意发送新标识」来让日志被有用的旧
/// 标识挤出去——被他挤掉的只会是他自己发过的那些。
pub const MAX_SEEN_SYNC_IDS: usize = 4096;

/// 记住已处理的载荷标识。
///
/// # 容量满了之后的行为是显式的
///
/// [`SeenSyncIds::record`] 在已满时返回 [`Error::SyncIdLogFull`]，**不会**自动淘汰。
/// 需要继续工作时由调用方显式调用 [`SeenSyncIds::clear`]——那是一个「我愿意放弃重放
/// 防护」的决定，不该由库替用户做。
///
/// # 为什么用 `VecDeque` 而不是 `HashSet`
///
/// 需要「先进先出」这个顺序来支持将来的淘汰策略，而 `VecDeque` 在 4096 这个规模上
/// 的线性查找（每条 32 字节的比较）比 `HashSet` 的哈希开销还便宜，且不引入哈希的
/// 碰撞处理路径——碰撞在这里的后果是「一份新载荷被误判成重复」，那是一个静默的
/// 功能故障，而线性查找不可能产生它。
#[derive(Debug, Clone, Default)]
pub struct SeenSyncIds {
    /// 按处理顺序存放的载荷标识，最旧的在前。
    seen: VecDeque<SyncId>,
}

impl SeenSyncIds {
    /// 一个空的日志。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 已经记住多少条。
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// 是否一条都没记住。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// 这份载荷是否已经处理过。
    #[must_use]
    pub fn contains(&self, sync_id: &SyncId) -> bool {
        self.seen.contains(sync_id)
    }

    /// 记下一份载荷标识。
    ///
    /// # 错误
    ///
    /// 日志已满时返回 [`Error::SyncIdLogFull`]。**这个调用不会因为标识重复而失败**
    /// ——重复由调用方先用 [`SeenSyncIds::contains`] 判断，因为「重复」与「满了」需要
    /// 完全不同的界面动作。
    pub fn record(&mut self, sync_id: SyncId) -> Result<()> {
        if self.seen.len() >= MAX_SEEN_SYNC_IDS {
            return Err(Error::SyncIdLogFull {
                limit: MAX_SEEN_SYNC_IDS,
            });
        }
        self.seen.push_back(sync_id);
        Ok(())
    }

    /// 检查并记录，一步完成。
    ///
    /// # 错误
    ///
    /// - [`Error::SyncAlreadyApplied`]：这份载荷处理过了。**注意此时不会重复记录。**
    /// - [`Error::SyncIdLogFull`]：日志满了，且这份载荷是新的。
    ///
    /// 两件事合成一个调用，是因为调用方几乎总是要连着做——分开写容易出现「检查了但
    /// 忘了记」这种漏掉重放防护的写法，而那个错误在功能上完全看不出来。
    pub fn check_and_record(&mut self, sync_id: SyncId) -> Result<()> {
        if self.contains(&sync_id) {
            return Err(Error::SyncAlreadyApplied);
        }
        self.record(sync_id)
    }

    /// 清空日志。
    ///
    /// **这会放弃对旧载荷的重放防护**：清空之后，一份曾经处理过的载荷又会变得可以
    /// 接受。只在日志满了、且用户选择继续同步时调用。
    pub fn clear(&mut self) {
        self.seen.clear();
    }

    /// 按时间顺序遍历已记录的标识（最旧的在前）。
    pub fn iter(&self) -> impl Iterator<Item = &SyncId> {
        self.seen.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> SyncId {
        [seed; crate::sync::SYNC_ID_LEN]
    }

    #[test]
    fn a_new_id_is_accepted_and_then_recognized() {
        let mut log = SeenSyncIds::new();
        assert!(log.is_empty());
        assert!(!log.contains(&id(1)));

        log.check_and_record(id(1)).expect("第一次应当接受");
        assert_eq!(log.len(), 1);
        assert!(log.contains(&id(1)));
    }

    #[test]
    fn a_repeated_id_is_rejected() {
        let mut log = SeenSyncIds::new();
        log.check_and_record(id(1)).expect("第一次应当接受");
        let err = log.check_and_record(id(1));
        assert!(
            matches!(err, Err(Error::SyncAlreadyApplied)),
            "实际 {err:?}"
        );
        // 重复检查**不得**把日志撑大，否则一个反复重放的对端能靠重放把日志填满，
        // 从而让所有**新**载荷都被拒——那是一个不用密码学突破的拒绝服务。
        assert_eq!(log.len(), 1, "重复的标识不得被重复记录");
    }

    #[test]
    fn many_distinct_ids_are_all_remembered() {
        let mut log = SeenSyncIds::new();
        for seed in 0..200_u8 {
            log.check_and_record(id(seed)).expect("新标识应当接受");
        }
        assert_eq!(log.len(), 200);
        for seed in 0..200_u8 {
            assert!(log.contains(&id(seed)), "标识 {seed} 没被记住");
        }
    }

    /// 满了必须**显式失败**，不得静默丢弃最旧的那条。
    ///
    /// 静默丢弃会让一份很旧的载荷重新变得可接受，而那正是重放防护要挡的。这个测试
    /// 钉住的是一条安全性质，不是容量行为。
    #[test]
    fn a_full_log_fails_instead_of_evicting() {
        let mut log = SeenSyncIds::new();
        for i in 0..MAX_SEEN_SYNC_IDS {
            // 用能唯一区分的标识，避免把「重复」与「满了」混起来。
            let mut sync_id = [0_u8; crate::sync::SYNC_ID_LEN];
            sync_id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            log.record(sync_id).expect("未满时应当接受");
        }
        assert_eq!(log.len(), MAX_SEEN_SYNC_IDS);

        let mut fresh = [9_u8; crate::sync::SYNC_ID_LEN];
        fresh[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        let err = log.record(fresh);
        assert!(
            matches!(err, Err(Error::SyncIdLogFull { .. })),
            "实际 {err:?}"
        );

        // 最旧的那条必须还在：没有被淘汰。
        let mut oldest = [0_u8; crate::sync::SYNC_ID_LEN];
        oldest[..8].copy_from_slice(&0_u64.to_be_bytes());
        assert!(log.contains(&oldest), "最旧的标识被淘汰了");
    }

    #[test]
    fn clear_gives_up_protection_explicitly() {
        let mut log = SeenSyncIds::new();
        log.check_and_record(id(1)).expect("第一次应当接受");
        log.clear();
        assert!(log.is_empty());
        // 清空之后旧标识重新可接受——这是调用方的明确决定，不是意外。
        log.check_and_record(id(1)).expect("清空后应当重新接受");
    }

    #[test]
    fn iteration_is_oldest_first() {
        let mut log = SeenSyncIds::new();
        for seed in 1..=5_u8 {
            log.record(id(seed)).expect("应当接受");
        }
        let order: Vec<u8> = log.iter().map(|s| s[0]).collect();
        assert_eq!(order, vec![1, 2, 3, 4, 5]);
    }
}
