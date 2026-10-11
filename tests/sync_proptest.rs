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

//! 同步载荷与并集合并的基于属性测试。
//!
//! # 这里的核心性质
//!
//! 1. **往返保真**：任意条目集合打包再解开，内容逐字段同值。
//! 2. **幂等**：同一份载荷合并两次，第二次什么都不改。
//! 3. **交换**：两台设备各自的载荷，以两种顺序合并，结果一致。
//! 4. **篡改必被发现**：改动载荷中任意一个字节，解析必须失败。
//! 5. **解析绝不 panic**：任意字节流都是可接受的输入。
//!
//! # 为什么「合并」是本文件的主角
//!
//! 打包与解包是单机性质，任何一台设备自己就能观察到；**合并**才是这个产品真正承诺
//! 的东西——多台设备各自离线改动，同步之后必须看到同一份条目集合。它也是唯一一条
//! 要在加入墓碑、冲突、乱序之后才可能被破坏的性质。
//!
//! 收敛的断言一律按**保险库内容**判等，而不是按冲突列表判等：冲突是「要人来决定」的
//! 东西，先后顺序会影响哪边被当成「本地」，因此它本来就不该是确定的。

use std::collections::BTreeMap;

use proptest::prelude::*;
use qualia_dik::device::{DEVICE_ID_LEN, DeviceId};
use qualia2fa_core::ExposeSecret as _;
use qualia2fa_core::otp::{Algorithm, Digits, OtpSecret};
use qualia2fa_core::sync::{self, MergedRecord, Payload, RecordSet, SeenSyncIds};
use qualia2fa_core::vault::{Entry, MasterKey, Timestamp, Vault};

/// 生成任意字节秘密。
fn arb_secret_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=64)
}

/// 生成任意文本字段，覆盖多字节字符。
///
/// 同步路径上字段要经过「编码 → 压缩 → 加密 → 解密 → 解压 → 解码」六个步骤，任何
/// 一步按**字符数**而不是字节数算长度都会在多字节输入上出错。每一步都只看字节，因此
/// 这条性质应当成立——但正是这种「显然成立」的东西值得随机化验证。
fn arb_text() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            0x20_u32..0x7F,
            // 多字节区间。排除代理对区，`char::from_u32` 会拒绝它们。
            0x80_u32..0xD800,
        ],
        0..=48,
    )
    .prop_map(|codepoints| {
        codepoints
            .into_iter()
            .filter_map(char::from_u32)
            .collect::<String>()
    })
}

/// 生成一条任意条目。
fn arb_entry() -> impl Strategy<Value = Entry> {
    (
        arb_text(),
        prop::option::of(arb_text()),
        arb_text(),
        arb_secret_bytes(),
        prop_oneof![
            Just(Algorithm::Sha1),
            Just(Algorithm::Sha256),
            Just(Algorithm::Sha512)
        ],
        prop_oneof![Just(Digits::Six), Just(Digits::Eight)],
        1_u64..=600,
        prop::option::of(any::<u64>()),
        arb_text(),
        1_u64..=2_000_000_000,
        1_u64..=2_000_000_000,
    )
        .prop_map(
            |(
                name,
                issuer,
                account,
                secret,
                algorithm,
                digits,
                period,
                counter,
                note,
                created_at,
                updated_at,
            )| {
                Entry::new(
                    name,
                    issuer,
                    account,
                    OtpSecret::from_bytes(secret).expect("生成器保证非空"),
                    algorithm,
                    digits,
                    period,
                    counter,
                    note,
                    Timestamp::from(created_at),
                    Timestamp::from(updated_at),
                )
                .expect("生成器保证各字段合法")
            },
        )
}

/// 生成一台设备的保险库：若干条目，其中一部分被删除（留下墓碑）。
fn arb_vault() -> impl Strategy<Value = Vault> {
    (
        prop::collection::vec(arb_entry(), 0..=10),
        prop::collection::vec(any::<bool>(), 0..=10),
    )
        .prop_map(|(entries, deletes)| {
            let mut vault = Vault::new();
            for (index, entry) in entries.into_iter().enumerate() {
                let id = vault.insert(entry).expect("OS 随机源可用");
                if deletes.get(index).copied().unwrap_or(false) {
                    vault.remove(&id, Timestamp::from(1_700_000_000_u64));
                }
            }
            vault
        })
}

/// 把保险库的**内容**抽成一个可比较的映射。
///
/// # 为什么不直接比 `Vault`
///
/// [`Vault`] 刻意不实现 `PartialEq`（比较它要遍历全部秘密材料，而那个操作没有生产
/// 用途）。更重要的是：这里要断言的是「**内容**一致」，而不是「内部表示一致」——后者
/// 会把纯粹的实现细节变成测试契约，让任何一次重构都要求改测试。
///
/// 秘密那部分用 Base32 表示比较：只用于测试，不参与任何认证判定。
fn vault_contents(vault: &Vault) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (id, entry) in vault.iter() {
        map.insert(
            format!("entry:{id}"),
            format!(
                "{}\u{1}{:?}\u{1}{}\u{1}{}\u{1}{:?}\u{1}{:?}\u{1}{}\u{1}{:?}\u{1}{}\u{1}{}\u{1}{}",
                entry.name,
                entry.issuer,
                entry.account,
                entry.secret.to_base32(),
                entry.algorithm,
                entry.digits,
                entry.period,
                entry.counter,
                entry.note,
                entry.created_at,
                entry.updated_at,
            ),
        );
    }
    for (id, tombstone) in vault.iter_tombstones() {
        map.insert(
            format!("tombstone:{id}"),
            format!("{}\u{1}{:?}", tombstone.deleted_at, tombstone.deleted_by),
        );
    }
    map
}

/// 把一台设备的保险库打包成载荷。
fn payload_of(vault: &Vault, master: &MasterKey, sender: DeviceId) -> Payload {
    Payload::from_vault(master, sender, vault).expect("打包应当成功")
}

/// 把一份载荷解成一组可以去重的语义记录。
fn records_of(payload: &Payload, master: &MasterKey) -> RecordSet<MergedRecord> {
    let opened = payload.open_records(master).expect("记录应当能解开");
    let mut set = RecordSet::new();
    for record in opened {
        set.insert(record.into_merged());
    }
    set
}

/// 把一份载荷并进一个保险库，返回结果。
///
/// # 冲突里的 `incoming` **不**会被写入
///
/// 那是调用方要按用户裁定去做的。因此这个辅助函数留下的保险库只包含「自动可决定」
/// 的那部分——而收敛断言针对的正是这部分：需要人来决定的条目不进保险库，于是同一批
/// 输入在不同顺序下到达同一个状态。
fn merge_payload(vault: &mut Vault, payload: &Payload, master: &MasterKey) -> sync::MergeOutcome {
    let set = records_of(payload, master);
    sync::merge_into(vault, &set).expect("合并不应当因复制失败而中止")
}

/// 生成一台「设备」：保险库 + 设备标识。主密钥另行生成，方便多台设备共用一把。
fn arb_vault_and_sender() -> impl Strategy<Value = (Vault, DeviceId)> {
    (arb_vault(), any::<[u8; DEVICE_ID_LEN]>())
        .prop_map(|(vault, sender)| (vault, DeviceId::from_bytes(sender)))
}

proptest! {
    #![proptest_config(ProptestConfig {
        // 每条用例要生成保险库、打包、加密、解密、合并，比纯字节级测试贵。
        // 64 轮足够覆盖结构性组合，同时让整个文件在十几秒内跑完。
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// **往返保真**：打包再解开，内容逐字段同值。
    ///
    /// 这是同步一切性质的基础。它失败意味着「发出去的东西与收到的不是一回事」，而
    /// 那种故障在真实使用里表现为「某台设备上的条目偶尔不一样」——极难复现。
    #[test]
    fn a_payload_roundtrips_every_entry(
        (vault, sender) in arb_vault_and_sender(),
    ) {
        let master = MasterKey::generate().expect("OS 随机源可用");
        let payload = payload_of(&vault, &master, sender);
        let sealed = payload.seal(&master).expect("打包应当成功");

        let opened = Payload::open(&master, &sealed).expect("拆包应当成功");
        prop_assert_eq!(opened.sync_id, payload.sync_id, "载荷标识变了");
        prop_assert_eq!(opened.sender, sender, "发送方变了");
        prop_assert_eq!(opened.len(), payload.len(), "记录数变了");

        let records = opened.open_records(&master).expect("记录应当能解开");

        let mut got_entries = BTreeMap::new();
        let mut got_tombstones = BTreeMap::new();
        for record in records {
            match record {
                sync::OpenedRecord::Entry { id, entry } => {
                    prop_assert!(
                        got_entries.insert(id, *entry).is_none(),
                        "同一个标识出现了两条条目"
                    );
                }
                sync::OpenedRecord::Tombstone(tombstone) => {
                    prop_assert!(
                        got_tombstones.insert(tombstone.entry_id, *tombstone).is_none(),
                        "同一个标识出现了两条墓碑"
                    );
                }
            }
        }

        prop_assert_eq!(got_entries.len(), vault.len(), "条目数不一致");
        prop_assert_eq!(
            got_tombstones.len(),
            vault.tombstone_count(),
            "墓碑数不一致"
        );

        for (id, original) in vault.iter() {
            let received = got_entries.get(id).expect("收到的条目里缺了这一条");
            prop_assert_eq!(&received.name, &original.name, "name");
            prop_assert_eq!(&received.issuer, &original.issuer, "issuer");
            prop_assert_eq!(&received.account, &original.account, "account");
            prop_assert_eq!(
                received.secret.to_base32(),
                original.secret.to_base32(),
                "secret"
            );
            prop_assert_eq!(received.algorithm, original.algorithm, "algorithm");
            prop_assert_eq!(received.digits, original.digits, "digits");
            prop_assert_eq!(received.period, original.period, "period");
            prop_assert_eq!(received.counter, original.counter, "counter");
            prop_assert_eq!(&received.note, &original.note, "note");
            prop_assert_eq!(received.created_at, original.created_at, "created_at");
            prop_assert_eq!(received.updated_at, original.updated_at, "updated_at");
        }

        for (id, original) in vault.iter_tombstones() {
            let received = got_tombstones.get(id).expect("收到的墓碑里缺了这一条");
            prop_assert_eq!(received.deleted_at, original.deleted_at, "deleted_at");
            prop_assert_eq!(received.deleted_by, original.deleted_by, "deleted_by");
        }
    }

    /// **幂等**：同一份载荷合并两次，第二次什么都不改。
    ///
    /// 「什么都不改」要按两个方向断言：计数为 0 **且**保险库内容逐项相同。只看计数的
    /// 话，一个「把条目替换成另一个同 ID 的内容」的实现也能通过——而那正是幂等性
    /// 要防的事。
    #[test]
    fn merging_the_same_payload_twice_changes_nothing(
        (source, sender) in arb_vault_and_sender(),
        (mut target, _) in arb_vault_and_sender(),
    ) {
        let master = MasterKey::generate().expect("OS 随机源可用");
        let payload = payload_of(&source, &master, sender);

        merge_payload(&mut target, &payload, &master);
        let after_first = vault_contents(&target);

        let second = merge_payload(&mut target, &payload, &master);
        let after_second = vault_contents(&target);

        prop_assert!(
            second.made_no_change(),
            "第二次合并报告有改动：added={} tombstones={} deletions={} conflicts={}",
            second.added,
            second.tombstones_added,
            second.deletions_applied,
            second.conflicts.len()
        );
        prop_assert_eq!(after_first, after_second, "第二次合并改变了保险库内容");
    }

    /// **交换**：两台设备各自的载荷，以两种顺序合并，结果一致。
    ///
    /// 真实场景里「先收到谁」由网络决定，因此这条性质是收敛的前提。注意它**只**对
    /// 保险库内容成立：冲突列表可能不同（哪边被当成「本地」取决于顺序），而那正是
    /// 「冲突要人来决定」的含义。
    #[test]
    fn merging_two_payloads_is_order_independent(
        (vault_a, sender_a) in arb_vault_and_sender(),
        (vault_b, sender_b) in arb_vault_and_sender(),
    ) {
        let master = MasterKey::generate().expect("OS 随机源可用");
        let payload_a = payload_of(&vault_a, &master, sender_a);
        let payload_b = payload_of(&vault_b, &master, sender_b);

        // 顺序一：先 A 后 B。
        let mut forward = Vault::new();
        merge_payload(&mut forward, &payload_a, &master);
        merge_payload(&mut forward, &payload_b, &master);

        // 顺序二：先 B 后 A。
        let mut backward = Vault::new();
        merge_payload(&mut backward, &payload_b, &master);
        merge_payload(&mut backward, &payload_a, &master);

        prop_assert_eq!(
            vault_contents(&forward),
            vault_contents(&backward),
            "两种合并顺序得到了不同的保险库内容"
        );
    }

    /// **收敛**：三台设备互相同步之后内容一致。
    ///
    /// 这是本文件最重要的性质，也是唯一一条把多台设备放在一起才能验证的。它覆盖
    /// 「新增」「删除」「两边都有」「只有一边有」四种组合在**任意**分布下的行为。
    #[test]
    fn three_devices_converge(
        (vault_a, sender_a) in arb_vault_and_sender(),
        (vault_b, sender_b) in arb_vault_and_sender(),
        (vault_c, sender_c) in arb_vault_and_sender(),
    ) {
        // 三台设备共用一把主密钥（真实场景里 B、C 是通过配对拿到它的）。
        let master = MasterKey::generate().expect("OS 随机源可用");

        let mut a = vault_a;
        let mut b = vault_b;
        let mut c = vault_c;

        // 两轮同步。为什么一轮不够：第一轮里每台设备收到的都是别人的**初始**载荷，
        // 因此「B 从 C 那里学到的、A 还不知道」这类二阶信息在第一轮结束时还没传播
        // 完。真实使用里就是「同步一次不够，要等大家都同步过一轮」。
        for _ in 0..2 {
            let payload_a = payload_of(&a, &master, sender_a);
            let payload_b = payload_of(&b, &master, sender_b);
            let payload_c = payload_of(&c, &master, sender_c);

            merge_payload(&mut a, &payload_b, &master);
            merge_payload(&mut a, &payload_c, &master);
            merge_payload(&mut b, &payload_a, &master);
            merge_payload(&mut b, &payload_c, &master);
            merge_payload(&mut c, &payload_a, &master);
            merge_payload(&mut c, &payload_b, &master);
        }

        prop_assert_eq!(vault_contents(&a), vault_contents(&b), "A 与 B 未收敛");
        prop_assert_eq!(vault_contents(&b), vault_contents(&c), "B 与 C 未收敛");
    }

    /// **任意字节流都不得 panic。**
    ///
    /// 输入完全来自攻击者可控的通道。这条性质是「不 panic」约定的随机化版本——单元
    /// 测试覆盖不了「某个长度的输入恰好走到某个 `unwrap`」这类路径。
    #[test]
    fn parsing_arbitrary_bytes_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..=512),
    ) {
        let master = MasterKey::generate().expect("OS 随机源可用");
        // 结果无论是 Ok 还是 Err 都算通过；这里只要求不 panic。
        let _ = Payload::open(&master, &data);
    }

    /// **载荷里任意一个字节被改动都必须被发现。**
    ///
    /// 与外层 AEAD 一起工作的是压缩层：如果压缩流有「尾部垃圾被忽略」这类性质，那么
    /// 追加在末尾的字节就可能被静默放过。逐字节翻转能同时覆盖这两条路径。
    #[test]
    fn any_single_byte_flip_in_a_payload_is_detected(
        (vault, sender) in arb_vault_and_sender(),
        flip in any::<prop::sample::Index>(),
    ) {
        let master = MasterKey::generate().expect("OS 随机源可用");
        let payload = payload_of(&vault, &master, sender);
        let sealed = payload.seal(&master).expect("打包应当成功");
        prop_assume!(!sealed.is_empty());

        let index = flip.index(sealed.len());
        let mut tampered = sealed.clone();
        tampered[index] ^= 0x01;

        prop_assert!(
            Payload::open(&master, &tampered).is_err(),
            "第 {} 字节被翻转后载荷仍被接受（共 {} 字节）",
            index,
            sealed.len()
        );
    }

    /// **不同的主密钥打不开载荷。**
    #[test]
    fn a_different_master_key_cannot_open_a_payload(
        (vault, sender) in arb_vault_and_sender(),
        other_seed in any::<[u8; DEVICE_ID_LEN]>(),
    ) {
        let master = MasterKey::generate().expect("OS 随机源可用");
        // 生成的种子恰好与随机输入相同（概率 2^-256）时跳过：那不是性质不成立，而是
        // 这一轮的输入没有区分力。
        prop_assume!(
            qualia2fa_core::vault::master_key_to_bytes(&master).expose_secret()
                != other_seed.as_slice()
        );

        let payload = payload_of(&vault, &master, sender);
        let sealed = payload.seal(&master).expect("打包应当成功");

        // 同一把密钥必须能打开，否则下面那条断言没有意义（可能是载荷本身坏了）。
        prop_assert!(Payload::open(&master, &sealed).is_ok(), "同一把密钥打不开");

        let wrong = MasterKey::from_bytes(qualia2fa_core::SecretBytes::from(
            other_seed.to_vec(),
        ))
        .expect("长度 32 正确");
        prop_assert!(
            Payload::open(&wrong, &sealed).is_err(),
            "另一把主密钥打开了载荷"
        );
    }

    /// **`SeenSyncIds` 记住的集合与放进去的完全一致。**
    ///
    /// 重放防护的全部内容就是这个集合，因此「记了但查不到」与「没记却查得到」两种
    /// 错误都要排除。
    #[test]
    fn the_seen_log_remembers_exactly_what_was_recorded(
        ids in prop::collection::vec(any::<[u8; DEVICE_ID_LEN]>(), 0..=64),
    ) {
        let mut log = SeenSyncIds::new();
        let mut expected: Vec<[u8; 32]> = Vec::new();
        for id in &ids {
            if log.check_and_record(*id).is_ok() && !expected.contains(id) {
                expected.push(*id);
            }
        }
        prop_assert_eq!(log.len(), expected.len(), "日志长度与预期不符");
        for id in &expected {
            prop_assert!(log.contains(id), "记过的标识找不到了");
        }
    }
}
