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

//! 单条记录的加解密：把保险库里的条目与墓碑变成载荷里的记录，以及反过来。
//!
//! # 与保险库文件的编码**共用同一套**
//!
//! 条目与墓碑的明文编码完全复用 [`crate::vault`] 里那份（[`crate::vault::Entry`] 与
//! [`crate::vault::Tombstone`] 的编解码）。这不是偷懒，而是刻意的：
//!
//! - **两份手写编码会漂移。** 新增一个字段时改了文件格式却忘了同步格式，症状是「同步
//!   之后新字段全空了」——一个不会让任何测试失败的静默数据损失。
//! - **同步本来就是「把同样的数据搬到另一台设备」**，两边语义完全相同，没有理由用
//!   两套表示。
//!
//! **域分离靠密钥，不靠编码**：同步记录用一把与保险库不同的子密钥
//! （[`crate::sync::derive_record_key`]），因此即使两边的 AAD 逐字节相同，密文也互不
//! 可解。见 [`crate::sync::HKDF_SALT_SYNC`] 的说明。
//!
//! # 种类在密文里，因此解密要试两次
//!
//! 记录的**种类**（活条目还是墓碑）是 AAD 的一部分，而 AAD 必须先于解密确定——于是
//! 「种类藏在密文里」这个目标带来一个鸡生蛋问题。
//!
//! 三条路：
//!
//! 1. 把种类明文写在记录头里。简单，但泄露「这次同步带了几条删除」。
//! 2. 用一把与种类无关的密钥，把种类放进明文**内部**，解密后再读。但这会让「把条目
//!    的密文搬到墓碑的位置」变成 AEAD 无法发现的事——内层逐条认证就白做了。
//! 3. **两种都试。** 顺序试 `SyncEntry` 与 `SyncTombstone`，取认证通过的那个。
//!
//! 这里选 3。理由是**它不引入任何歧义**：两个种类的 AAD 不同，同一段密文不可能同时
//! 通过两次认证（概率是 2⁻¹²⁸ 量级）。代价是认证失败时多算一次 Poly1305——而失败的
//! 情形本来就只有两种：密钥不对（整个载荷的第一条就会失败）或载荷被篡改（整个同步
//! 作废）。正常路径上每个种类只试一次。
//!
//! 换来的是：攻击者拿不到「这次带了几条删除」。这个信息本身价值有限，但**免费**——
//! 而它是一件只有一次机会去做对的事：一旦明文里写上了种类字节，将来想收回来就必须
//! 换载荷格式版本。

use crate::sync::{FORMAT_VERSION, InnerRecordKind, Record};
use crate::vault::crypto;
use crate::vault::{Entry as VaultEntry, EntryId, Tombstone};
use crate::{Error, Result};

/// 条目明文头的长度：魔数 4 + 标识 16 + 长度 2。
const ENTRY_HEADER_LEN: usize = 4 + EntryId::LEN + 2;

/// 条目明文头的魔数。
///
/// # 为什么密文里还要再放一个魔数
///
/// AAD 已经把「种类 + 条目 ID + 版本」绑进去了，因此**按正常路径**拿到一段明文就一定
/// 对得上。这个魔数是防**编码层被误用**：如果有人把条目的编码喂给墓碑的解码器（或者
/// 将来加了一种新记录、解码时选错了分支），第一个检查就能抓住，而不是让解析器在一个
/// 语义完全不同的字节流里挣扎，最后报一个指向错误方向的「字段标签不认识」。
const ENTRY_MAGIC: &[u8; 4] = b"Q2FE";

/// 一条解开并解析完成的记录。
///
/// # 为什么它不等于 [`crate::sync::Record`]
///
/// 两者刻意分开：`Record` 是**线格式**（只有字节和标识），`OpenedRecord` 是**语义**
/// （已经是一个能做合并的条目或墓碑）。同一条记录在解密前不知道自己是哪一种——种类在
/// 密文里，这正是「攻击者连这次同步带了几条删除都看不出来」的实现方式。
#[derive(Debug, PartialEq, Eq)]
pub enum OpenedRecord {
    /// 一条活条目。
    Entry {
        /// 条目的标识。同时是载荷里那条记录的标识（已核对一致）。
        id: EntryId,
        /// 条目内容。
        entry: Box<VaultEntry>,
    },
    /// 一条墓碑。
    Tombstone(Box<Tombstone>),
}

impl OpenedRecord {
    /// 这条记录讲的是哪一个条目。
    #[must_use]
    pub fn entry_id(&self) -> EntryId {
        match self {
            Self::Entry { id, .. } => *id,
            Self::Tombstone(tombstone) => tombstone.entry_id,
        }
    }

    /// 转成可以交给 [`crate::sync::merge_into`] 的形式。
    #[must_use]
    pub fn into_merged(self) -> crate::sync::MergedRecord {
        match self {
            Self::Entry { id, entry } => crate::sync::MergedRecord::Entry { id, entry },
            Self::Tombstone(tombstone) => crate::sync::MergedRecord::Tombstone(tombstone),
        }
    }
}

/// 把一条条目加密成载荷里的记录。
///
/// `id` 是这条条目在集合里的标识。条目本身不带标识（见 [`crate::vault::Entry`]），
/// 因此这个函数把它写进明文头，解密时再核对一次——见 [`open`] 的第 2 条。
///
/// # 错误
///
/// - [`Error::SyncMalformed`]：条目的编码超过 65535 字节。真实条目远小于此（最长字段
///   上限是 64 KiB），因此这只在编码逻辑出错时发生。
/// - [`Error::RandomnessUnavailable`]：随机源不可用。
pub fn seal_entry(key: &[u8; 32], id: &EntryId, entry: &VaultEntry) -> Result<Record> {
    let body = crate::vault::encode_entry(entry)?;
    let mut plaintext = Vec::with_capacity(ENTRY_HEADER_LEN + body.len());
    plaintext.extend_from_slice(ENTRY_MAGIC);
    plaintext.extend_from_slice(id.as_bytes());
    let len = u16::try_from(body.len()).map_err(|_| Error::SyncMalformed {
        reason: "单条条目的编码超过 65535 字节",
    })?;
    plaintext.extend_from_slice(&len.to_be_bytes());
    plaintext.extend_from_slice(&body);

    seal_plaintext(key, InnerRecordKind::SyncEntry, id, &plaintext)
}

/// 把一条墓碑加密成载荷里的记录。
///
/// # 错误
///
/// [`Error::RandomnessUnavailable`]：随机源不可用。
pub fn seal_tombstone(key: &[u8; 32], tombstone: &Tombstone) -> Result<Record> {
    let plaintext = crate::vault::encode_tombstone(tombstone);
    seal_plaintext(
        key,
        InnerRecordKind::SyncTombstone,
        &tombstone.entry_id,
        &plaintext,
    )
}

/// 用一把已派生好的子密钥把一段明文封成记录。
///
/// 是 [seal_entry] 与 [seal_tombstone] 的公共尾部：两者只差明文编码与种类字节。
fn seal_plaintext(
    key: &[u8; 32],
    kind: InnerRecordKind,
    id: &EntryId,
    plaintext: &[u8],
) -> Result<Record> {
    let (nonce, ciphertext) = crypto::seal_with_key(key, kind, id, FORMAT_VERSION, plaintext)?;
    Ok(Record {
        entry_id: *id,
        nonce,
        ciphertext,
    })
}

/// 解开并解析一条记录。
///
/// # 它核对什么
///
/// 1. **AAD**：种类、条目 ID、载荷格式版本。因此「把条目 A 的密文搬到条目 B 的位置」
///    会因为 AAD 里的 ID 对不上而认证失败，而不是被静默接受成 B 的内容。
/// 2. **明文头里的标识与 `record.entry_id` 一致**。这一条**不是**冗余：AAD 用的是
///    `record.entry_id`，而调用方可能从别处拿到一个不同的标识去查合并结果。让明文里
///    也带一份并核对，就堵住了「记录说自己是 A、内容其实来自 B」的那条缝。
/// 3. **条目明文头里的魔数与长度**：明文头以 `Q2FE` 起头，跟着标识与一个 u16 长度。
///    那 4 个字节不是冗余的——AAD 已经把种类与标识绑进去了，但**编码层被误用**
///    （把条目的编码喂给墓碑的解码器）时，第一道检查就能抓住，而不是让解析器在一个
///    语义完全不同的字节流里挣扎，最后报一个指向错误方向的「字段标签不认识」。
///
/// # 为什么两种种类都要试
///
/// 见模块文档。顺序是 `SyncEntry` 在前，因为条目在真实数据集里占绝大多数——省下的
/// 是失败路径的半次 Poly1305，而失败是罕见情况。
///
/// # 错误
///
/// - [`Error::SyncAuthenticationFailed`]：两种种类都认证失败。**不区分**「密钥不对」
///   「密文被篡改」「AAD 不匹配」——区分它们对攻击者有用，对使用者没有可操作价值。
///   之所以**不是** [`Error::VaultDecryptionFailed`]：那是「保险库文件打不开」，端侧
///   对它的处置（引导检查主密钥）与「这次同步的载荷不可信」完全不同。
/// - [`Error::SyncMalformed`]：明文结构自相矛盾。外层与 AAD 都已认证，因此走到这里
///   意味着**我们自己的编码逻辑写错了**，而不是受到了攻击。
/// - [`Error::VaultUnknownRecordKind`] 一族：条目明文的内部结构不合法。这是**真的**
///   可能来自一份合法载荷（旧版本写的编码、新版本读），因此保留具体诊断而不是并进
///   `SyncMalformed`。
pub fn open(key: &[u8; 32], record: &Record) -> Result<OpenedRecord> {
    let mut last_error = None;
    for kind in [InnerRecordKind::SyncEntry, InnerRecordKind::SyncTombstone] {
        match try_open_as(key, kind, record) {
            Ok(opened) => return Ok(opened),
            // 认证失败与结构错误都要继续试下一种。结构错误尤其要试：一段用墓碑种类
            // 加密的密文，在被当成条目解开后可能「认证通过」（不可能，AAD 不同）或者
            // 在解析时报结构错误。前者由密码学挡住，后者是这条分支存在的理由。
            Err(err) => last_error = Some(err),
        }
    }
    // 两种都失败。报「认证失败」而不是上一次的具体错误：上一次的错误可能是一个结构
    // 诊断，而它只是「用错了种类去解」的副产物，报出去会把人引向错误方向。
    Err(last_error.map_or(Error::SyncAuthenticationFailed, |_| {
        Error::SyncAuthenticationFailed
    }))
}

/// 按**指定**的种类试解一条记录。
///
/// 认证失败是这条路径的**正常**结果之一（种类猜错了），因此调用方必须继续试下一种，
/// 而不是把错误直接上抛。
fn try_open_as(key: &[u8; 32], kind: InnerRecordKind, record: &Record) -> Result<OpenedRecord> {
    let plaintext = crypto::open_with_key(
        key,
        kind,
        &record.entry_id,
        FORMAT_VERSION,
        &record.nonce,
        &record.ciphertext,
    )?;
    match kind {
        InnerRecordKind::SyncEntry => open_entry(&record.entry_id, &plaintext),
        InnerRecordKind::SyncTombstone => open_tombstone(&record.entry_id, &plaintext),
        _ => Err(Error::SyncMalformed {
            reason: "解码路径收到了非同步的记录种类",
        }),
    }
}

/// 解析一条已经解密并认证过的**条目**明文。
///
/// 明文已被 AEAD 认证，因此这里的检查针对的都是「我们自己的编码写错了」，而不是攻击。
fn open_entry(id: &EntryId, plaintext: &[u8]) -> Result<OpenedRecord> {
    if plaintext.len() < ENTRY_HEADER_LEN {
        return Err(Error::SyncTruncated);
    }
    if &plaintext[..4] != ENTRY_MAGIC {
        return Err(Error::SyncMalformed {
            reason: "条目明文缺少魔数",
        });
    }
    let embedded: [u8; EntryId::LEN] = plaintext[4..4 + EntryId::LEN]
        .try_into()
        .map_err(|_| Error::SyncTruncated)?;
    if &embedded != id.as_bytes() {
        return Err(Error::SyncMalformed {
            reason: "条目明文里的标识与记录标识不一致",
        });
    }
    let len_bytes: [u8; 2] = plaintext[4 + EntryId::LEN..ENTRY_HEADER_LEN]
        .try_into()
        .map_err(|_| Error::SyncTruncated)?;
    let declared = usize::from(u16::from_be_bytes(len_bytes));
    let body = plaintext
        .get(ENTRY_HEADER_LEN..ENTRY_HEADER_LEN + declared)
        .ok_or(Error::SyncTruncated)?;
    // 明文里多出的字节意味着编码逻辑写错了（外层已认证，所以不是攻击信号）。
    if plaintext.len() != ENTRY_HEADER_LEN + declared {
        return Err(Error::SyncMalformed {
            reason: "条目明文含超出声明长度的内容",
        });
    }
    Ok(OpenedRecord::Entry {
        id: *id,
        entry: Box::new(crate::vault::decode_entry(body)?),
    })
}

/// 解析一条已经解密并认证过的**墓碑**明文。
///
/// 直接复用保险库那一侧的墓碑解码：两者是同一套字节布局，见模块文档。
fn open_tombstone(id: &EntryId, plaintext: &[u8]) -> Result<OpenedRecord> {
    let tombstone = crate::vault::decode_tombstone(*id, plaintext)?;
    Ok(OpenedRecord::Tombstone(Box::new(tombstone)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Timestamp;
    use crate::vault::crypto::RecordKind;

    fn key() -> [u8; 32] {
        // 确定值而不是 `MasterKey::generate()`：测试要能复现，且这里不需要真主密钥——
        // 记录层只吃一把已派生好的子密钥。
        [0x5A; 32]
    }

    fn sample_entry() -> VaultEntry {
        VaultEntry::new(
            "ACME".to_owned(),
            Some("ACME 公司".to_owned()),
            "alice@example.com".to_owned(),
            crate::otp::OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("种子合法"),
            crate::otp::Algorithm::Sha1,
            crate::otp::Digits::Six,
            30,
            None,
            "工作账号".to_owned(),
            Timestamp::from(1_700_000_000_u64),
            Timestamp::from(1_700_000_100_u64),
        )
        .expect("条目合法")
    }

    #[test]
    fn an_entry_roundtrips() {
        let id = EntryId::from_bytes([1; EntryId::LEN]);
        let entry = sample_entry();
        let record = seal_entry(&key(), &id, &entry).expect("可加密");
        assert_eq!(record.entry_id, id);

        let opened = open(&key(), &record).expect("可解密");
        match opened {
            OpenedRecord::Entry {
                id: got_id,
                entry: got,
            } => {
                assert_eq!(got_id, id);
                assert_eq!(*got, entry, "往返后条目内容不一致");
            }
            other => panic!("期望是条目，实际 {other:?}"),
        }
    }

    #[test]
    fn a_tombstone_roundtrips() {
        let id = EntryId::from_bytes([2; EntryId::LEN]);
        let tombstone = Tombstone {
            entry_id: id,
            deleted_at: 1_700_000_200,
            deleted_by: Some(EntryId::from_bytes([3; EntryId::LEN])),
        };
        let record = seal_tombstone(&key(), &tombstone).expect("可加密");

        let opened = open(&key(), &record).expect("可解密");
        match opened {
            OpenedRecord::Tombstone(got) => assert_eq!(*got, tombstone, "往返后墓碑不一致"),
            other => panic!("期望是墓碑，实际 {other:?}"),
        }
    }

    /// 墓碑的三种 `deleted_by` 状态都要能往返。
    ///
    /// `deleted_by` 是 `Option`，而「有值」与「无值」在编码里只差一个标志字节——
    /// 正是最容易写错的那种。
    #[test]
    fn tombstone_deleted_by_states_roundtrip() {
        let id = EntryId::from_bytes([4; EntryId::LEN]);
        for deleted_by in [None, Some(EntryId::from_bytes([5; EntryId::LEN]))] {
            let tombstone = Tombstone {
                entry_id: id,
                deleted_at: 1,
                deleted_by,
            };
            let record = seal_tombstone(&key(), &tombstone).expect("可加密");
            let opened = open(&key(), &record).expect("可解密");
            match opened {
                OpenedRecord::Tombstone(got) => assert_eq!(got.deleted_by, deleted_by),
                other => panic!("期望是墓碑，实际 {other:?}"),
            }
        }
    }

    /// **错一把密钥必须认证失败，且不得被误判成另一种记录。**
    #[test]
    fn a_wrong_key_is_rejected() {
        let id = EntryId::from_bytes([6; EntryId::LEN]);
        let record = seal_entry(&key(), &id, &sample_entry()).expect("可加密");
        let err = open(&[0x5B; 32], &record);
        assert!(
            matches!(err, Err(Error::SyncAuthenticationFailed)),
            "实际 {err:?}"
        );
    }

    /// **把条目 A 的密文搬到条目 B 的位置必须失败。**
    ///
    /// 这是内层逐条认证存在的全部理由：没有它，一份**合法**载荷就能让接收方永久存下
    /// 一条内容与标识不匹配的记录。
    #[test]
    fn moving_a_ciphertext_to_another_id_is_rejected() {
        let id_a = EntryId::from_bytes([7; EntryId::LEN]);
        let id_b = EntryId::from_bytes([8; EntryId::LEN]);
        let mut record = seal_entry(&key(), &id_a, &sample_entry()).expect("可加密");

        record.entry_id = id_b;
        let err = open(&key(), &record);
        assert!(
            matches!(err, Err(Error::SyncAuthenticationFailed)),
            "条目密文被搬到另一个 ID 后仍被接受，实际 {err:?}"
        );
    }

    /// 把墓碑的密文当成条目来解必须失败。
    ///
    /// 这一条同时验证了「试两种种类」不会引入**误判**：墓碑的密文不能在条目那条路径上
    /// 认证通过。
    #[test]
    fn a_tombstone_cannot_be_read_as_an_entry() {
        let id = EntryId::from_bytes([9; EntryId::LEN]);
        let tombstone = Tombstone {
            entry_id: id,
            deleted_at: 1_700_000_300,
            deleted_by: None,
        };
        let record = seal_tombstone(&key(), &tombstone).expect("可加密");
        // 正常路径解出来必须是墓碑，不能是条目。
        match open(&key(), &record).expect("可解密") {
            OpenedRecord::Tombstone(_) => {}
            other => panic!("墓碑被误判成 {other:?}"),
        }
    }

    /// 单字节篡改必须被拒绝，且**每一个**字节位置都要试。
    #[test]
    fn flipping_any_ciphertext_byte_is_rejected() {
        let id = EntryId::from_bytes([10; EntryId::LEN]);
        let record = seal_entry(&key(), &id, &sample_entry()).expect("可加密");
        for index in 0..record.ciphertext.len() {
            let mut tampered = record.clone();
            tampered.ciphertext[index] ^= 0x01;
            let err = open(&key(), &tampered);
            assert!(
                matches!(err, Err(Error::SyncAuthenticationFailed)),
                "第 {index} 字节被翻转后仍被接受，实际 {err:?}"
            );
        }
    }

    /// 篡改 nonce 必须被拒绝。
    ///
    /// 单独测它：nonce 不在密文里，翻转密文的那条测试覆盖不到它。
    #[test]
    fn a_tampered_nonce_is_rejected() {
        let id = EntryId::from_bytes([11; EntryId::LEN]);
        let record = seal_entry(&key(), &id, &sample_entry()).expect("可加密");
        for index in 0..record.nonce.len() {
            let mut tampered = record.clone();
            tampered.nonce[index] ^= 0x80;
            let err = open(&key(), &tampered);
            assert!(
                matches!(err, Err(Error::SyncAuthenticationFailed)),
                "nonce 第 {index} 字节被翻转后仍被接受，实际 {err:?}"
            );
        }
    }

    /// 截断密文必须被拒绝。
    #[test]
    fn a_truncated_ciphertext_is_rejected() {
        let id = EntryId::from_bytes([12; EntryId::LEN]);
        let record = seal_entry(&key(), &id, &sample_entry()).expect("可加密");
        for cut in 1..record.ciphertext.len().min(8) {
            let mut short = record.clone();
            short.ciphertext.truncate(record.ciphertext.len() - cut);
            assert!(open(&key(), &short).is_err(), "截断 {cut} 字节后仍被接受");
        }
    }

    /// 每条记录的 nonce 必须不同。
    ///
    /// 192-bit 随机 nonce 在真实规模下不会撞，但「实现里把 nonce 写成了常量」这种错误
    /// 不会让任何其他测试失败——它只在两侧数据足够多时变成灾难性的密钥流复用。
    #[test]
    fn nonces_differ_across_records() {
        let id = EntryId::from_bytes([13; EntryId::LEN]);
        let entry = sample_entry();
        let first = seal_entry(&key(), &id, &entry).expect("可加密");
        let second = seal_entry(&key(), &id, &entry).expect("可加密");
        assert_ne!(first.nonce, second.nonce, "两次加密用了同一个 nonce");
        assert_ne!(
            first.ciphertext, second.ciphertext,
            "同一内容两次加密产生了相同密文，随机性有问题"
        );
    }

    /// **同步记录的密钥与保险库记录的密钥必须是两把。**
    ///
    /// 这是域分离的核心断言。若两者相同，一份同步载荷的密文可以被当成保险库文件的
    /// 记录喂进来（AAD 可能逐字节相同），而 AEAD 会认证通过。
    #[test]
    fn sync_and_vault_keys_are_different() {
        let master = crate::vault::MasterKey::generate().expect("随机源可用");

        let sync_key = crate::sync::derive_record_key(&master).expect("可派生");
        let vault_key = crypto::entry_key(&master).expect("可派生");

        assert_ne!(
            sync_key, vault_key,
            "同步记录与保险库记录派生了同一把子密钥，域分离失效"
        );

        // 信封密钥也必须是第三把。
        let envelope_key = crate::sync::derive_envelope_key(&master).expect("可派生");
        assert_ne!(sync_key, envelope_key, "记录密钥与信封密钥相同");
        assert_ne!(vault_key, envelope_key, "保险库密钥与信封密钥相同");

        // 派生必须是确定的，否则第二台设备解不开。
        let again = crate::sync::derive_record_key(&master).expect("可派生");
        assert_eq!(sync_key, again, "同一主密钥两次派生的结果不同");
    }

    /// 常量本身不能悄悄改掉。
    ///
    /// 它是对外契约：改了会让所有已发出去的同步载荷（含二维码里那些）解不开。
    #[test]
    fn the_domain_separation_constants_are_stable() {
        assert_eq!(
            crate::sync::HKDF_SALT_SYNC,
            *b"Qualia2FA sync salt v1 (records)",
            "同步的 HKDF salt 变了，既有载荷会全部解不开"
        );
        assert_eq!(
            RecordKind::SyncEntry.as_byte(),
            0x81,
            "同步条目的种类字节变了"
        );
        assert_eq!(
            RecordKind::SyncTombstone.as_byte(),
            0x82,
            "同步墓碑的种类字节变了"
        );
        assert_eq!(FORMAT_VERSION, 1, "载荷格式版本变了");
    }

    /// **两个域的记录种类字节必须不重叠，且解析器必须互不认账。**
    ///
    /// 这些是域分离的第二道防线（第一道是 HKDF 的 salt）。写成测试而不是只靠
    /// `sync.rs` 里的编译期断言，是因为「文件解析器不认同步种类」这件事是一个**行为**
    /// 断言，编译期断言表达不了。
    #[test]
    fn the_two_domains_kinds_do_not_overlap() {
        // 文件种类：只认 0x01 / 0x02。
        assert!(RecordKind::from_byte(0x01).is_some());
        assert!(RecordKind::from_byte(0x02).is_some());
        assert!(
            RecordKind::from_byte(0x81).is_none(),
            "文件解析器接受了同步条目种类——一份同步载荷会被当成保险库文件收下"
        );
        assert!(
            RecordKind::from_byte(0x82).is_none(),
            "文件解析器接受了同步墓碑种类"
        );

        // 同步种类：只认 0x81 / 0x82。
        assert!(RecordKind::from_sync_byte(0x81).is_some());
        assert!(RecordKind::from_sync_byte(0x82).is_some());
        assert!(
            RecordKind::from_sync_byte(0x01).is_none(),
            "同步解析器接受了文件条目种类"
        );
        assert!(RecordKind::from_sync_byte(0x02).is_none());
        assert!(RecordKind::from_sync_byte(0x00).is_none());
        assert!(RecordKind::from_sync_byte(0xFF).is_none());
    }

    /// 记录长度是「固定头 + 密文」，用于让上层预估载荷大小。
    #[test]
    fn encoded_len_matches_the_wire_format() {
        let id = EntryId::from_bytes([14; EntryId::LEN]);
        let record = seal_entry(&key(), &id, &sample_entry()).expect("可加密");
        // 固定头 = 种类 1 + 标识 16 + nonce 24 + 长度 4；密文已含认证标签。
        assert_eq!(
            record.encoded_len(),
            1 + 16 + 24 + 4 + record.ciphertext.len()
        );
    }

    #[test]
    fn entry_ids_survive_the_roundtrip_byte_for_byte() {
        // 标识是全零、全 FF 这类边界值时最容易在编码里被当成「缺失」。
        for pattern in [0x00_u8, 0xFF, 0x80] {
            for position in 0..EntryId::LEN {
                let mut bytes = [0_u8; EntryId::LEN];
                bytes[position] = pattern;
                let id = EntryId::from_bytes(bytes);
                let record = seal_entry(&key(), &id, &sample_entry()).expect("可加密");
                match open(&key(), &record).expect("可解密") {
                    OpenedRecord::Entry { id: got, .. } => {
                        assert_eq!(got.as_bytes(), &bytes, "标识 {bytes:?} 往返后不同");
                    }
                    other => panic!("期望是条目，实际 {other:?}"),
                }
            }
        }
    }

    #[test]
    fn timestamp_boundaries_survive_the_roundtrip() {
        let id = EntryId::from_bytes([15; EntryId::LEN]);
        for deleted_at in [1_u64, u32::MAX.into(), u64::MAX] {
            let tombstone = Tombstone {
                entry_id: id,
                deleted_at: Timestamp::from(deleted_at),
                deleted_by: None,
            };
            let record = seal_tombstone(&key(), &tombstone).expect("可加密");
            match open(&key(), &record).expect("可解密") {
                OpenedRecord::Tombstone(got) => assert_eq!(
                    got.deleted_at, deleted_at,
                    "删除时间 {deleted_at} 往返后不同"
                ),
                other => panic!("期望是墓碑，实际 {other:?}"),
            }
        }
    }
}
