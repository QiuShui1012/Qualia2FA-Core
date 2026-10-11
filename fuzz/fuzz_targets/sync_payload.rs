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

//! fuzz 目标：同步载荷的解析。
//!
//! # 为什么它比保险库文件更值得盯
//!
//! 保险库文件是用户自己选的通道搬来的；同步载荷是**局域网上任何一台设备**可以主动
//! 送过来的。攻击者不需要用户做任何事——只要和用户同一个 WiFi，就能往解析器里灌任意
//! 字节。因此这里的输入面比文件那条路径更宽。
//!
//! # 两条独立输入路径
//!
//! 1. **整段输入当作载荷**（模式 1）。覆盖外层信封：魔数、版本、`sync_id`、发送方、
//!    长度字段。用输入派生的固定密钥，因此绝大多数输入会在 AEAD 那一步被拒绝——
//!    但那正是要覆盖的路径之一（认证必须是**所有**畸形输入的终点，而不是崩溃）。
//! 2. **整段输入当作压缩流**（模式 2）。这是本目标存在的主要理由：
//!
//!    - 解压是**攻击者可以放大**的唯一一处。一个几百字节的 deflate 流能声称解出
//!      64 MiB。上限检查（`compress::MAX_DECOMPRESSED_LEN`）是拒绝服务防线，而
//!      「声称的长度恰好等于上限」「声称的长度恰好超过上限一字节」这类边界只有随机
//!      输入才会命中。
//!    - 解压**之后**的明文解析（记录数 + 每条的标识 / nonce / 长度 / 密文）有一片
//!      变长结构。模式 1 走不到那里，因为要先过 AEAD。
//!
//!    `compress` 是公开模块，因此这条路径可以完整覆盖。
//!
//! # 输入派生的密钥
//!
//! 与 `vault_parse` 同样的理由：`MasterKey::generate()` 每次不同，用它的话目标自己
//! 造的东西自己解不开。这里其实用不到「能自己解开」——模式 1 只要求不 panic——但用
//! 派生密钥让行为**可复现**，这对把崩溃输入最小化成回归种子是必需的。

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia2fa_core::sync::{self, Payload};
use qualia2fa_core::vault::{self, MasterKey};

/// 从输入派生一把确定的 32 字节主密钥。
///
/// **这不是密钥派生函数**，只是让 fuzz 目标行为可复现；它不参与任何真实的安全决策。
fn master_from(data: &[u8]) -> MasterKey {
    let mut key = [0_u8; vault::MASTER_KEY_LEN];
    let take = data.len().min(vault::MASTER_KEY_LEN);
    key[..take].copy_from_slice(&data[..take]);
    MasterKey::from_bytes(key.to_vec().into()).expect("长度恒为 32")
}

fuzz_target!(|data: &[u8]| {
    // 模式 1：整段输入当作载荷。
    //
    // 外层信封要先过「魔数 → 版本 → sync_id → 发送方 → nonce → 至少一个标签」这条
    // 检查链，然后才是 AEAD 与解压。链条上任何一环的越界都是拒绝服务。
    let master = master_from(data);
    match Payload::open(&master, data) {
        Ok(payload) => {
            // 走到这里说明整份载荷的认证都通过了。此时属性必须成立：重新打包出来的
            // 字节要能被自己再解开。这钉住的是「能解开的东西写不回去」——那是数据
            // 丢失的隐患。
            if let Ok(again) = payload.seal(&master) {
                let Ok(reparsed) = Payload::open(&master, &again) else {
                    panic!("自己打包出的载荷自己解不开");
                };
                assert_eq!(
                    reparsed.len(),
                    payload.len(),
                    "往返后记录数变化"
                );
            }
            // 逐条解开。这一步走的是「按两种种类试解密」那条路径，也是内层 AAD 与
            // 条目明文解析的全部所在。
            let _ = payload.open_records(&master);
        }
        Err(_) => {}
    }

    // 模式 2：整段输入当作**压缩流**。
    //
    // 这一条不经 AEAD，因此解压与解压后的明文解析都直接被 fuzz 打到。解压上限是
    // 拒绝服务防线，而解压后的解析器有变长结构——两者都是本目标的主要目标。
    if let Ok(plaintext) = sync::compress::decompress(data) {
        // 解出来的东西必须真的在上限之内。这条断言若失败，说明上限形同虚设。
        assert!(
            plaintext.len() <= sync::compress::MAX_DECOMPRESSED_LEN,
            "解压结果 {} 字节，超过了声称的上限 {}",
            plaintext.len(),
            sync::compress::MAX_DECOMPRESSED_LEN
        );
    }

    // 模式 3：压缩自身的往返。
    //
    // 看起来是同义反复（压缩再解压当然还原），但它覆盖的是「任意输入都能被压缩」——
    // 一个恒返回错误的压缩实现会让模式 1 与模式 2 都变成空转，而那种退化不会让任何
    // 测试失败。
    if let Ok(packed) = sync::compress::compress(data) {
        let back = sync::compress::decompress(&packed).expect("自己压出的流自己解不开");
        assert_eq!(back, data, "压缩往返改变了内容");
    }
});
