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

//! Property-based tests for sync payloads and union merge.
//!
//! Core properties:
//!
//! 1. **Round-trip fidelity**: any entry set packed and unpacked keeps every field.
//! 2. **Idempotence**: merging the same payload twice changes nothing the second time.
//! 3. **Commutativity**: two devices' payloads merged in either order give the same result.
//! 4. **Tampering is detected**: changing any byte of a payload makes parsing fail.
//! 5. **Parsing never panics**: any byte stream is acceptable input.
//!
//! Merge is what these tests are about: it is the only property that tombstones, conflicts
//! and out-of-order delivery can break, and it is what the product promises — several devices
//! that edit offline must see the same entry set after syncing.
//!
//! Convergence is asserted on **vault content**, never on the conflict list: a conflict is
//! something a human decides, and the order in which payloads arrive determines which side
//! counts as local, so the conflict list is not meant to be deterministic.

use std::collections::BTreeMap;

use proptest::prelude::*;
use qualia_dik::device::{DEVICE_ID_LEN, DeviceId};
use qualia2fa_core::ExposeSecret as _;
use qualia2fa_core::otp::{Algorithm, Digits, OtpSecret};
use qualia2fa_core::sync::{self, MergedRecord, Payload, RecordSet, SeenSyncIds};
use qualia2fa_core::vault::{Entry, MasterKey, Timestamp, Vault};

/// Generates an arbitrary byte secret.
fn arb_secret_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=64)
}

/// Generates an arbitrary text field, multi-byte characters included.
///
/// On the sync path a field passes through six steps — encode, compress, encrypt, decrypt,
/// decompress, decode — and a step that measured length in **characters** instead of bytes
/// would corrupt multi-byte input. Every step operates on bytes only, so the text must come
/// back identical.
///
/// Code points are drawn from `0x20..0x7F` and `0x80..0xD800`; the surrogate range
/// `0xD800..0xE000` is excluded because `char::from_u32` rejects it.
fn arb_text() -> impl Strategy<Value = String> {
    prop::collection::vec(prop_oneof![0x20_u32..0x7F, 0x80_u32..0xD800,], 0..=48).prop_map(
        |codepoints| {
            codepoints
                .into_iter()
                .filter_map(char::from_u32)
                .collect::<String>()
        },
    )
}

/// Generates an arbitrary entry.
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

/// Generates one device's vault: several entries, some of them deleted (leaving tombstones).
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

/// Extracts the **content** of a vault into a comparable map.
///
/// [`Vault`] deliberately does not implement `PartialEq`: comparing it would walk all secret
/// material, an operation with no production use. What is asserted here is content equality
/// rather than internal-representation equality — the latter would turn pure implementation
/// detail into a test contract.
///
/// Secrets are compared in their Base32 form: this is test-only and takes part in no
/// authentication decision.
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

/// Packs one device's vault into a payload.
fn payload_of(vault: &Vault, master: &MasterKey, sender: DeviceId) -> Payload {
    Payload::from_vault(master, sender, vault).expect("打包应当成功")
}

/// Opens a payload into a set of semantic records suitable for deduplication.
fn records_of(payload: &Payload, master: &MasterKey) -> RecordSet<MergedRecord> {
    let opened = payload.open_records(master).expect("记录应当能解开");
    let mut set = RecordSet::new();
    for record in opened {
        set.insert(record.into_merged());
    }
    set
}

/// Merges a payload into a vault and returns the outcome.
///
/// An `incoming` side of a conflict is **not** written: the caller does that once the user has
/// decided. The vault this helper leaves behind therefore holds only the automatically
/// decidable part, which is exactly what the convergence assertions cover — entries that need
/// a human decision stay out of the vault, so the same inputs reach the same state in any
/// order.
fn merge_payload(vault: &mut Vault, payload: &Payload, master: &MasterKey) -> sync::MergeOutcome {
    let set = records_of(payload, master);
    sync::merge_into(vault, &set).expect("合并不应当因复制失败而中止")
}

/// Generates a "device": a vault plus a device id. The master key is generated separately so
/// several devices can share one.
fn arb_vault_and_sender() -> impl Strategy<Value = (Vault, DeviceId)> {
    (arb_vault(), any::<[u8; DEVICE_ID_LEN]>())
        .prop_map(|(vault, sender)| (vault, DeviceId::from_bytes(sender)))
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// **Round-trip fidelity**: packing and unpacking keeps every field of every entry.
    ///
    /// This underpins every other sync property. A failure means what was sent and what was
    /// received differ, which in real use shows up as an entry that occasionally looks
    /// different on one device.
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

    /// **Idempotence**: merging the same payload twice changes nothing the second time.
    ///
    /// "Changes nothing" is asserted in two directions: the counters stay 0 **and** the vault
    /// content is item-for-item identical. Counters alone would let an implementation that
    /// replaces an entry with different content under the same id pass — exactly what
    /// idempotence has to rule out.
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

    /// **Commutativity**: two devices' payloads merged in either order give the same result.
    ///
    /// Which payload arrives first is decided by the network, so this property is the
    /// precondition for convergence. It holds **only** for vault content: the conflict list may
    /// differ, because which side counts as local depends on the order — that is what "a
    /// conflict is decided by a human" means.
    #[test]
    fn merging_two_payloads_is_order_independent(
        (vault_a, sender_a) in arb_vault_and_sender(),
        (vault_b, sender_b) in arb_vault_and_sender(),
    ) {
        let master = MasterKey::generate().expect("OS 随机源可用");
        let payload_a = payload_of(&vault_a, &master, sender_a);
        let payload_b = payload_of(&vault_b, &master, sender_b);

        let mut forward = Vault::new();
        merge_payload(&mut forward, &payload_a, &master);
        merge_payload(&mut forward, &payload_b, &master);

        let mut backward = Vault::new();
        merge_payload(&mut backward, &payload_b, &master);
        merge_payload(&mut backward, &payload_a, &master);

        prop_assert_eq!(
            vault_contents(&forward),
            vault_contents(&backward),
            "两种合并顺序得到了不同的保险库内容"
        );
    }

    /// **Convergence**: three devices that sync with each other end up with the same content.
    ///
    /// This is the property that needs several devices in one test. It covers the four
    /// combinations — added, deleted, present on both sides, present on one side only — in
    /// **any** distribution across the three vaults.
    ///
    /// Two rounds are required: the first round only exchanges each device's initial payload,
    /// so information one device learned from a third has not propagated yet.
    #[test]
    fn three_devices_converge(
        (vault_a, sender_a) in arb_vault_and_sender(),
        (vault_b, sender_b) in arb_vault_and_sender(),
        (vault_c, sender_c) in arb_vault_and_sender(),
    ) {
        let master = MasterKey::generate().expect("OS 随机源可用");

        let mut a = vault_a;
        let mut b = vault_b;
        let mut c = vault_c;

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

    /// **No byte stream may panic.**
    ///
    /// The input comes entirely from attacker-controlled channels. This is the randomized form
    /// of the no-panic contract: a unit test cannot cover the path where an input of a
    /// particular length happens to reach some `unwrap`.
    #[test]
    fn parsing_arbitrary_bytes_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..=512),
    ) {
        let master = MasterKey::generate().expect("OS 随机源可用");
        let _ = Payload::open(&master, &data);
    }

    /// **Any single flipped byte in a payload must be detected.**
    ///
    /// A compression layer works alongside the outer AEAD: if the compressed stream tolerated
    /// trailing garbage, bytes appended at the end could slip through silently. Flipping one
    /// byte at a time covers both paths.
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

    /// **A different master key cannot open a payload.**
    ///
    /// The same key must open it first, otherwise the negative assertion below would be
    /// vacuous. A round whose random seed happens to equal the generated key (probability
    /// 2^-256) is skipped: that input has no discriminating power.
    #[test]
    fn a_different_master_key_cannot_open_a_payload(
        (vault, sender) in arb_vault_and_sender(),
        other_seed in any::<[u8; DEVICE_ID_LEN]>(),
    ) {
        let master = MasterKey::generate().expect("OS 随机源可用");
        prop_assume!(
            qualia2fa_core::vault::master_key_to_bytes(&master).expose_secret()
                != other_seed.as_slice()
        );

        let payload = payload_of(&vault, &master, sender);
        let sealed = payload.seal(&master).expect("打包应当成功");

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

    /// **`SeenSyncIds` remembers exactly what was recorded.**
    ///
    /// This set is the whole of replay protection, so both errors are ruled out: recorded but
    /// not found, and not recorded but found.
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
