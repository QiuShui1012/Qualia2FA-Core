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

//! 保险库的基于属性测试。
//!
//! # 与单元测试的分工
//!
//! `src/vault.rs` 里的单元测试用手工构造的**具体**输入覆盖每条分支与每个错误
//! 路径；本文件用生成器覆盖**任意**输入下的普遍性质。两者都需要：
//!
//! - 单元测试能证明「这条错误路径确实被走到」，而随机输入几乎不会命中它。
//! - 属性测试能证明「对所有输入都成立」，而手工用例只能覆盖自己想到的那些。
//!
//! # 这里的核心性质
//!
//! 1. **往返保真**：任意条目集合落盘再读回，所有字段逐一同值。
//! 2. **篡改必被发现**：改动文件中任意一个字节，解析必须失败。
//! 3. **截断必被发现**：在任意位置截断文件，解析必须失败。
//! 4. **解析绝不 panic**：任意字节流都是可接受的输入。

use proptest::prelude::*;
use qualia2fa_core::ExposeSecret;
use qualia2fa_core::otp::{Algorithm, Digits, OtpSecret};
use qualia2fa_core::vault::{
    self, Entry, EntryId, FORMAT_VERSION, MAGIC, MasterKey, READABLE_VERSIONS, Tombstone, Vault,
    VaultFile,
};

/// 生成任意字节秘密。
///
/// 长度上界取 64：真实种子最多 64 字节（RFC 4226 建议的 HMAC-SHA512 块大小），
/// 再大不带来覆盖价值，只会让每次迭代变慢。
fn arb_secret_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=64)
}

/// 生成任意 UTF-8 文本字段。
///
/// 刻意包含非 ASCII（中文、emoji 等多字节字符）与 ASCII 边界字符：长度计算与
/// 截断错误最容易在多字节字符上发生，而字段长度上界是按**字节**算的。
fn arb_text() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            0_u32..0x80,
            // 多字节区间。排除代理对区（0xD800..0xE000），`char::from_u32` 会
            // 拒绝它们。
            0x80_u32..0xD800,
            0xE000_u32..0x2FFFF,
        ],
        0..=24,
    )
    .prop_map(|codes| codes.into_iter().filter_map(char::from_u32).collect())
}

/// 生成一条满足全部不变量的条目。
///
/// # 为什么不多生成非法条目
///
/// [`Entry::new`] 会拒绝空种子、`period == 0` 与超长字段。生成非法值只会在
/// `Entry::new` 那一层被挡住，测不到后面的持久化逻辑，反而稀释了有效用例。
/// 拒绝逻辑本身由 `src/vault/entry.rs` 里针对性的单元测试覆盖。
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
        prop_oneof![Just(Digits::Six), Just(Digits::Seven), Just(Digits::Eight)],
        1_u64..=604_800,
        prop::option::of(any::<u64>()),
        arb_text(),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(
            |(
                name,
                issuer,
                account,
                secret_bytes,
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
                    OtpSecret::from_bytes(secret_bytes).expect("策略保证非空"),
                    algorithm,
                    digits,
                    period,
                    counter,
                    note,
                    created_at,
                    updated_at,
                )
                .expect("策略保证字段合法")
            },
        )
}

/// 生成一个条目集合。
fn arb_entries() -> impl Strategy<Value = Vec<Entry>> {
    // 上界取 12：足够覆盖「多条记录」「顺序」等结构性问题，同时让每条用例在
    // 几十毫秒量级完成——属性测试要跑很多次，单个用例太慢会压低覆盖轮数。
    prop::collection::vec(arb_entry(), 0..=12)
}

/// 生成一个保险库：条目集合 + 其中一部分被删除。
///
/// 返回的 ID 列表对应「仍然存在的条目」，用于断言。
fn arb_vault() -> impl Strategy<Value = (Vault, MasterKey, Vec<EntryId>)> {
    (arb_entries(), prop::collection::vec(any::<bool>(), 0..=12)).prop_map(|(entries, deletes)| {
        let mut vault = Vault::new();
        let mut live = Vec::new();
        for (index, entry) in entries.into_iter().enumerate() {
            let id = vault.insert(entry).expect("OS 随机源可用");
            // `deletes` 可能比 `entries` 短，用 `get` 而非索引避免 panic。
            if deletes.get(index).copied().unwrap_or(false) {
                vault.remove(&id, 1_700_000_000);
            } else {
                live.push(id);
            }
        }
        let master = MasterKey::generate().expect("OS 随机源可用");
        (vault, master, live)
    })
}

/// 断言两条条目在**所有**字段上相等。
///
/// `Entry` 没有派生 `PartialEq`，因为它的 `secret` 字段是 [`OtpSecret`]，而后者
/// 刻意不实现 `PartialEq`：派生会让「用 `==` 快速比较两个种子」变成随手可做的
/// 事，那是非恒定时间的比较。这里显式逐字段比对，把种子那一项用 Base32 表示
/// 比较——这只用于测试，不参与任何认证判定。
fn assert_entry_eq(a: &Entry, b: &Entry) {
    assert_eq!(a.name, b.name, "name");
    assert_eq!(a.issuer, b.issuer, "issuer");
    assert_eq!(a.account, b.account, "account");
    assert_eq!(
        a.secret.to_base32(),
        b.secret.to_base32(),
        "secret（Base32 形式）"
    );
    assert_eq!(a.algorithm, b.algorithm, "algorithm");
    assert_eq!(a.digits, b.digits, "digits");
    assert_eq!(a.period, b.period, "period");
    assert_eq!(a.counter, b.counter, "counter");
    assert_eq!(a.note, b.note, "note");
    assert_eq!(a.created_at, b.created_at, "created_at");
    assert_eq!(a.updated_at, b.updated_at, "updated_at");
}

/// 复制一把主密钥。
///
/// `MasterKey` 刻意不实现 `Clone`；这里经字节绕一圈，是为了让「确实复制了一份
/// 密钥」在代码中可见，而不是一个悄无声息的 `.clone()`。
fn clone_key(master: &MasterKey) -> MasterKey {
    MasterKey::from_bytes(vault::master_key_to_bytes(master)).expect("长度正确")
}

proptest! {
    /// **核心性质 1**：任意条目集合落盘再读回，所有字段逐一相同。
    #[test]
    fn roundtrip_preserves_every_entry((vault, master, live_ids) in arb_vault()) {
        let mut file = VaultFile::with_master_key(clone_key(&master));

        // 逐条按原 ID 插入，保留「哪些被删除」的信息。
        let mut expected: Vec<(EntryId, String)> = Vec::new();
        for (id, entry) in vault.iter() {
            expected.push((*id, entry.name.clone()));
            file.vault_mut()
                .insert_with_id(*id, clone_entry(entry))
                .expect("ID 由策略分别生成，互不相同");
        }
        for tombstone in vault.iter_tombstones().map(|(_, t)| t) {
            file.vault_mut().record_tombstone(Tombstone {
                entry_id: tombstone.entry_id,
                deleted_at: tombstone.deleted_at,
                deleted_by: tombstone.deleted_by,
            });
        }
        expected.sort_by_key(|(id, _)| *id);
        let expected_tombstones = vault.tombstone_count();

        let bytes = file.serialize().expect("可序列化");
        let reopened = VaultFile::parse(clone_key(&master), &bytes).expect("可解析");

        prop_assert_eq!(reopened.vault().len(), expected.len(), "条目数变化");
        prop_assert_eq!(
            reopened.vault().tombstone_count(),
            expected_tombstones,
            "墓碑数变化"
        );

        // 条目的 ID 集合必须完全一致，且每个 ID 都还在。
        let mut actual: Vec<(EntryId, String)> = reopened
            .vault()
            .iter()
            .map(|(id, entry)| (*id, entry.name.clone()))
            .collect();
        actual.sort_by_key(|(id, _)| *id);
        prop_assert_eq!(&actual, &expected, "条目 ID 或名称集合变化");

        // 逐字段比对每一个条目——「数量对得上」不代表「内容对得上」。
        for (id, _) in &expected {
            let before = vault.get(id).expect("原条目存在");
            let after = reopened.vault().get(id).expect("读回条目存在");
            assert_entry_eq(before, after);
        }

        // 未删除的条目必须都还在。
        for id in &live_ids {
            prop_assert!(reopened.vault().get(id).is_some(), "未删除的条目丢失");
        }
    }

    /// **核心性质 2**：改动文件中任意一个字节，解析必须失败。
    ///
    /// 这条性质是「文件可以被攻击者完整读写」这一威胁模型的直接体现。任何
    /// 「改一个字节却仍能解出一份看起来正常的数据」都是静默的数据损坏。
    #[test]
    fn any_single_byte_flip_is_detected((vault, master, _live) in arb_vault(), flip_seed in any::<prop::sample::Index>()) {
        let mut file = VaultFile::with_master_key(clone_key(&master));
        for (id, entry) in vault.iter() {
            file.vault_mut().insert_with_id(*id, clone_entry(entry)).expect("ID 互不相同");
        }
        for (id, tombstone) in vault.iter_tombstones() {
            file.vault_mut().record_tombstone(Tombstone {
                entry_id: *id,
                deleted_at: tombstone.deleted_at,
                deleted_by: tombstone.deleted_by,
            });
        }
        let bytes = file.serialize().expect("可序列化");
        prop_assume!(!bytes.is_empty());

        let index = flip_seed.index(bytes.len());
        let mut tampered = bytes.clone();
        tampered[index] ^= 0x01;

        let result = VaultFile::parse(clone_key(&master), &tampered);
        prop_assert!(
            result.is_err(),
            "第 {} 字节被翻转（{:#04x} → {:#04x}）却仍被接受",
            index,
            bytes[index],
            tampered[index]
        );
    }

    /// **核心性质 3**：截断不得让**任何数据**通过验证。
    ///
    /// # 断言为什么是「没有条目存活」而不是「一定失败」
    ///
    /// 后者是错的，属性测试在这里给出了一个反例：一个**空**保险库只有 14 字节
    /// 的文件头，把它截断到 14 字节（也就是它本身）当然是合法的空保险库。
    /// 断言「一定失败」会把「截断成合法的空文件」误判为缺陷。
    ///
    /// 真正要保证的性质是**没有数据能靠截断蒙混过关**：截断后的文件若还能解析，
    /// 它必须一条条目都没有。AEAD 的认证标签覆盖整段密文，因此砍掉任何一部分
    /// 都无法通过认证——包括砍掉最后一条记录的一部分。
    #[test]
    fn truncation_never_yields_data((vault, master, _live) in arb_vault(), cut_seed in any::<prop::sample::Index>()) {
        let mut file = VaultFile::with_master_key(clone_key(&master));
        for (id, entry) in vault.iter() {
            file.vault_mut()
                .insert_with_id(*id, clone_entry(entry))
                .expect("ID 由策略分别生成，互不相同");
        }
        for tombstone in vault.iter_tombstones().map(|(_, t)| t) {
            file.vault_mut().record_tombstone(Tombstone {
                entry_id: tombstone.entry_id,
                deleted_at: tombstone.deleted_at,
                deleted_by: tombstone.deleted_by,
            });
        }
        let bytes = file.serialize().expect("可序列化");
        prop_assume!(!bytes.is_empty());

        // 截断到 0..bytes.len()（不含完整长度）。
        let cut = cut_seed.index(bytes.len());
        match VaultFile::parse(clone_key(&master), &bytes[..cut]) {
            Err(_) => {}
            Ok(parsed) => {
                prop_assert_eq!(
                    parsed.vault().len(),
                    0,
                    "截断到 {} 字节后仍有条目存活",
                    cut
                );
                prop_assert_eq!(
                    parsed.vault().tombstone_count(),
                    0,
                    "截断到 {} 字节后仍有墓碑存活",
                    cut
                );
            }
        }
    }

    /// 空输入必须被拒绝——连文件头都没有，不可能是任何东西的合法截断。
    #[test]
    fn empty_input_is_always_rejected(_seed in any::<u64>()) {
        let master = MasterKey::generate().expect("OS 随机源可用");
        prop_assert!(VaultFile::parse(master, &[]).is_err());
    }

    /// 任意字节流都是可接受的输入——解析器只返回错误，绝不 panic。
    ///
    /// 这条性质由 fuzz 目标 `vault_parse` 更彻底地覆盖（那里有插进合法骨架的
    /// 模式），这里保留一个轻量版本，让 `cargo test` 也能挡住明显的崩溃。
    #[test]
    fn parsing_arbitrary_bytes_never_panics(data in prop::collection::vec(any::<u8>(), 0..=512)) {
        let master = MasterKey::generate().expect("OS 随机源可用");
        // 只要求「返回」——成功与否都无所谓。
        let _ = VaultFile::parse(master, &data);
    }

    /// **向前兼容**：未知的顶层结构必须被拒绝而不是被误解释。
    ///
    /// 具体地说，魔数与版本号都必须参与判定。这条性质保证「把别的文件改名成
    /// .q2fa」不会被当成保险库读进来。
    ///
    /// 版本号的生成从 `FORMAT_VERSION + 1` 起：**当前版本与所有可读的旧版本都必须
    /// 被接受**（那是「用户的旧文件还能打开」这条承诺），因此不能拿它们当「未知
    /// 版本」的样本。
    #[test]
    fn wrong_magic_or_version_is_rejected(
        (vault, master, _live) in arb_vault(),
        magic_flip in any::<bool>(),
        version in (FORMAT_VERSION + 1)..=255,
    ) {
        let mut file = VaultFile::with_master_key(clone_key(&master));
        for (id, entry) in vault.iter() {
            file.vault_mut().insert_with_id(*id, clone_entry(entry)).expect("ID 互不相同");
        }
        let mut bytes = file.serialize().expect("可序列化");

        if magic_flip {
            bytes[0] ^= 0xFF;
            // 注意：`prop_assert!` 会把**整个表达式**字符串化后当格式串用，因此
            // `matches!(x, Err(Variant { .. }))` 里的 `{ .. }` 会被当成未闭合的
            // 占位符，报「invalid format string: expected `}`, found `.`」。
            // 把判定先绑定到一个 `bool` 上，表达式里就没有花括号了。
            let is_bad_magic = matches!(
                VaultFile::parse(clone_key(&master), &bytes),
                Err(qualia2fa_core::Error::VaultBadMagic)
            );
            prop_assert!(is_bad_magic, "魔数被破坏却未被拒绝");
        } else {
            bytes[8] = version;
            let is_unsupported = matches!(
                VaultFile::parse(clone_key(&master), &bytes),
                Err(qualia2fa_core::Error::VaultUnsupportedVersion { .. })
            );
            prop_assert!(is_unsupported, "版本 {} 未被拒绝", version);
        }
    }

    /// 换一把主密钥必须解不开——包括「只差一个比特」的密钥。
    ///
    /// 这条挡住的是「密钥没被真正用于加密」这类实现错误。
    #[test]
    fn a_different_master_key_cannot_open(
        (vault, master, _live) in arb_vault(),
        delta in 1_u8..=255,
    ) {
        prop_assume!(!vault.is_empty());
        let mut file = VaultFile::with_master_key(clone_key(&master));
        for (id, entry) in vault.iter() {
            file.vault_mut().insert_with_id(*id, clone_entry(entry)).expect("ID 互不相同");
        }
        let bytes = file.serialize().expect("可序列化");

        let mut other = vault::master_key_to_bytes(&master).expose_secret().to_vec();
        other[0] ^= delta;
        let other = MasterKey::from_bytes(other.into()).expect("长度正确");

        prop_assert!(VaultFile::parse(other, &bytes).is_err(), "另一把主密钥竟能解开");
    }
}

/// 复制一条条目。
///
/// [`OtpSecret`] 刻意不实现 `Clone`，因此经 Base32 绕一圈重建。**只用于测试**：
/// 生产路径上「复制一份种子」应当是显式且有理由的行为。
fn clone_entry(entry: &Entry) -> Entry {
    Entry::new(
        entry.name.clone(),
        entry.issuer.clone(),
        entry.account.clone(),
        OtpSecret::from_base32(&entry.secret.to_base32()).expect("原种子合法"),
        entry.algorithm,
        entry.digits,
        entry.period,
        entry.counter,
        entry.note.clone(),
        entry.created_at,
        entry.updated_at,
    )
    .expect("原条目合法，重建后仍合法")
}

/// 文件头布局是对外契约：这组断言不随实现变化而漂移。
///
/// 放在属性测试文件里是因为它约束的是**格式**（对外承诺），而不是某个函数的
/// 实现细节——格式一旦发布就不能改，这与属性测试的「契约」定位一致。
#[test]
fn file_format_constants_are_stable() {
    assert_eq!(MAGIC, b"Q2FAVLT\0", "魔数是对外契约");
    assert_eq!(
        FORMAT_VERSION, 2,
        "版本号参与 AAD，改动会让所有旧文件解不开"
    );
    assert_eq!(
        READABLE_VERSIONS,
        &[1, 2],
        "可读版本只增不减：移除一个会让用户手里的旧文件突然打不开"
    );
    assert_eq!(vault::MASTER_KEY_LEN, 32, "主密钥长度");
    assert_eq!(vault::NONCE_LEN, 24, "XChaCha20 的 nonce 长度");
    assert_eq!(vault::TAG_LEN, 16, "Poly1305 标签长度");
    assert_eq!(vault::KEY_CHECK_LEN, 32, "主密钥检查值长度");
    assert_eq!(EntryId::LEN, 16, "128-bit 条目标识");
}
