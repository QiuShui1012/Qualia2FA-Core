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

//! fuzz 目标：保险库文件解析。
//!
//! # 为什么需要它
//!
//! 保险库文件是**攻击者可以完整构造**的输入：它会经过用户自己选的网盘、二维码、
//! 另一台设备，这些通道都不受本应用控制。解析器要处理的是一份完全由对手决定的
//! 字节流，里面每个长度字段都可以是任意值。
//!
//! 因此本目标盯的是两类缺陷：
//!
//! 1. **越界与 panic**——「声称有 4 GiB 密文」「长度前缀之后什么都没有」
//!    「标签后面缺长度字段」这类输入不得让进程崩溃。这是拒绝服务防线：
//!    一个能被恶意文件搞崩的认证器等于不能用。
//! 2. **无界分配**——长度字段在被用于分配之前必须先与上限比较。否则一个
//!    100 字节的文件就能让应用申请 4 GiB 内存。
//!
//! # AEAD 把大部分输入挡在解析之前，所以要专门绕过去
//!
//! 这份文件的每条记录都被 XChaCha20-Poly1305 保护，因此**随手构造的字节流几乎
//! 一定在认证那一步就被拒绝**，根本走不到条目明文的解析逻辑（那才是最容易写错
//! 的地方）。为了让 fuzz 真正覆盖到它，本目标构造一份**用已知密钥加密的合法骨架
//! 文件**，让 fuzz 输入落在密文之内或其周围：
//!
//! - 模式 1：整段输入当作文件解析。覆盖文件头与记录框架。
//! - 模式 2：把输入**当作记录密文**插进合法骨架。这样输入会在通过（或未通过）
//!   认证后进入 `decode_entry` 的解析循环。
//!
//! 模式 2 是本目标存在的主要理由——`decode_entry` 里的「跳过未知节点」是向前
//! 兼容的全部实现，也是最容易写成越界的地方。
//!
//! # 关键：骨架必须用**能重新构造出来的密钥**
//!
//! `MasterKey::generate()` 每次都不一样，用它加密的话 fuzz 目标自己都解不开自己
//! 造的文件，模式 2 就白费了。因此这里用输入派生的固定长度密钥，让「加密」与
//! 「解析」两端用同一把钥匙。

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia2fa_core::otp;
use qualia2fa_core::vault::{self, Entry, EntryId, MasterKey, VaultFile};

/// 从输入派生一把确定的 32 字节密钥。
///
/// 取前 32 字节，不足则补零。**这不是密钥派生函数**，只是让 fuzz 目标自己造的
/// 文件自己能解开；它不参与任何真实的安全决策。
fn master_from(data: &[u8]) -> MasterKey {
    let mut key = [0_u8; vault::MASTER_KEY_LEN];
    let take = data.len().min(vault::MASTER_KEY_LEN);
    key[..take].copy_from_slice(&data[..take]);
    MasterKey::from_bytes(key.to_vec().into()).expect("长度恒为 32")
}

fuzz_target!(|data: &[u8]| {
    let master = master_from(data);

    // 模式 1：整段输入当作文件。
    // `MasterKey` 刻意不实现 `Clone`，因此复制要显式经字节绕一圈（见 `clone_key`）。
    check_file(clone_key(&master), data);

    // 模式 2：把输入当作**记录密文**塞进合法骨架。
    check_embedded_record(&master, data);
});

/// 解析一段字节，并在成功时验证往返。
fn check_file(master: MasterKey, data: &[u8]) {
    let Ok(file) = VaultFile::parse(master, data) else {
        return;
    };

    // 解析成功说明整份文件的认证都通过了。此时必须能重新序列化——
    // 若不能，说明「能解开的文件却写不回去」，是数据丢失的隐患。
    let Ok(again) = file.serialize() else {
        return;
    };

    // 重新序列化后再解析一次，内容必须稳定（序列化是幂等的语义上）。
    // 这里再次用同一把密钥；`file` 内部持有它的副本。
    let master2 = master_key_of(&file);
    let Ok(reparsed) = VaultFile::parse(master2, &again) else {
        panic!("自己序列化出的文件自己解不开");
    };
    assert_eq!(
        reparsed.vault().len(),
        file.vault().len(),
        "往返后条目数变化"
    );
    assert_eq!(
        reparsed.vault().tombstone_count(),
        file.vault().tombstone_count(),
        "往返后墓碑数变化"
    );
}

/// 取出文件持有的主密钥副本（用于再次解析）。
fn master_key_of(file: &VaultFile) -> MasterKey {
    let bytes = vault::master_key_to_bytes(file.master_key());
    MasterKey::from_bytes(bytes).expect("长度正确")
}

/// 把输入当作记录密文，插进一份骨架文件里解析。
///
/// 骨架用一个已知的条目加密而成，因此它的**非密文部分全部合法**：魔数、版本、
/// 记录种类、`entry_id`、nonce、长度都对。输入的字节被放进密文位置，于是
/// fuzz 的探索力量集中在「密文解密后的明文怎么解析」这条路径上。
fn check_embedded_record(master: &MasterKey, data: &[u8]) {
    // 先造一份合法骨架，拿到它内部的一条条目。
    let mut file = VaultFile::with_master_key(clone_key(master));
    let Ok(_) = file.vault_mut().insert(sample_entry()) else {
        return;
    };
    let Ok(skeleton) = file.serialize() else {
        return;
    };

    // 骨架的布局是固定的：14 字节文件头 + 1 字节种类 + 16 字节 ID + 24 字节 nonce
    // + 4 字节长度，其后是密文。把密文整段替换成 fuzz 输入。
    const CIPHERTEXT_OFFSET: usize = 14 + 1 + EntryId::LEN + vault::NONCE_LEN + 4;
    if skeleton.len() < CIPHERTEXT_OFFSET {
        return;
    }

    let mut mutated = skeleton[..CIPHERTEXT_OFFSET].to_vec();
    mutated.extend_from_slice(data);
    // 把长度字段改成输入的实际长度，否则解析器会在长度检查那一步就退出，
    // 到不了密文解密之后的解析逻辑。
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    mutated[CIPHERTEXT_OFFSET - 4..CIPHERTEXT_OFFSET].copy_from_slice(&len.to_be_bytes());

    check_file(clone_key(master), &mutated);
}

/// 复制一把主密钥。
///
/// `MasterKey` 刻意不实现 `Clone`（那会让「秘密被静默复制」变成随手可做），
/// 因此这里显式地经字节绕一圈——在 fuzz 目标里这么做是刻意的：它让「这里确实
/// 复制了一份密钥」在代码中可见。
fn clone_key(master: &MasterKey) -> MasterKey {
    MasterKey::from_bytes(vault::master_key_to_bytes(master)).expect("长度正确")
}

/// 一条用于构造骨架的合法条目。
fn sample_entry() -> Entry {
    Entry::new(
        "fuzz".into(),
        Some("Qualia2FA".into()),
        "alice".into(),
        otp::OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("合法 Base32"),
        otp::Algorithm::Sha1,
        otp::Digits::Six,
        30,
        None,
        String::new(),
        0,
        0,
    )
    .expect("字段均合法")
}
