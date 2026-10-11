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

//! fuzz 目标：登录握手的两条消息解析路径。
//!
//! # 为什么需要它
//!
//! 登录过程中会对**来自另一台设备的两条消息**做解析，而这两条都可能来自攻击者：
//!
//! - `Msg1`（新设备 → 老设备）：`Login::authorize` 解析它。攻击者可以扫到二维码
//!   （二维码就贴在屏幕上）然后发任意字节过来。
//! - `Msg2`（老设备 → 新设备）：`Joiner::complete` 解析它。新设备无法分辨回话的是
//!   不是真的老设备，它只有字节。
//!
//! 两条路径都会先读定长头部（nonce、临时公钥）、把公钥喂给 P-256 的 SEC1 解码器、
//! 再做 AEAD。这三个动作都是「输入完全由对手决定」的典型场景：长度字段、曲外点、
//! 截断的密文。
//!
//! # 与 `vault_parse` 的区别
//!
//! `vault_parse` 盯的是文件格式的长生命周期解析（未知节点跳过、长度前缀）。本目标
//! 盯的是**协议消息**：长度必须是精确值（多一个字节就该拒绝）、公钥必须真的在曲线
//! 上、AEAD 标签必须过。这三条任何一条写成「大致检查一下」，都会让攻击者有机会把
//! 解析器推到它没设想过的状态。
//!
//! # 这里不需要「构造合法骨架」的手法
//!
//! `vault_parse` 必须绕开 AEAD，否则随手构造的字节流永远在认证那一步就被拒。这里
//! 不一样：**被拒绝正是我们要覆盖的路径**——拒绝逻辑本身（长度检查、曲线检查、
//! 常量时间比较）就写在解析器里，而它每次都会被走到。至于「认证通过之后的明文怎么
//! 解析」，两条消息的明文都只有定长字段的拷贝，没有变长结构，因此不存在那片攻击面。

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia_dik::{DevicePublicKey, DeviceSignature};
use qualia2fa_core::flow::{DeviceKeys, Joiner, Login};
use qualia2fa_core::vault::MasterKey;
use qualia2fa_core::{Error, Result};

/// 一条固定的设备身份，让 fuzz 输入之外的一切都是确定的。
///
/// 公钥从一块写死的字节里复制，签名返回固定值——本目标不验证签名的正确性（那由
/// `device::verify` 的单元测试与 `m3_flows` 覆盖），只需要一个能走完 `request` 的
/// 实现，好把 fuzz 力量全部留给消息解析。
struct FixedKeys {
    /// 一个合法的 P-256 公钥，来自固定标量 1（即生成元本身）。
    public: [u8; 65],
}

impl FixedKeys {
    /// 用生成元作为身份：`04 ‖ Gx ‖ Gy`。
    fn new() -> Self {
        // 生成元的 SEC1 未压缩编码是公开常量。
        let mut public = [0_u8; 65];
        public[0] = 0x04;
        // 为了方便，直接用一个已知合法的标量经 `p256` 算出来，而不是手抄坐标——
        // 手抄一旦错一位，本目标就会在「公钥不在曲线上」这一步静默退出，
        // 看起来仍然在跑，实际什么也没覆盖。
        let mut scalar = [0_u8; 32];
        scalar[31] = 1;
        let key = p256::ecdsa::SigningKey::from_bytes((&scalar).into())
            .expect("标量 1 必定合法");
        public.copy_from_slice(key.verifying_key().to_sec1_point(false).as_bytes());
        Self { public }
    }
}

impl DeviceKeys for FixedKeys {
    fn get_or_create(&mut self, _label: &str) -> Result<DevicePublicKey> {
        Ok(DevicePublicKey::from_sec1_bytes(&self.public)?)
    }

    fn sign(&mut self, _label: &str, message: &[u8]) -> Result<DeviceSignature> {
        let mut scalar = [0_u8; 32];
        scalar[31] = 1;
        let key = p256::ecdsa::SigningKey::from_bytes((&scalar).into())
            .expect("标量 1 必定合法");
        use p256::ecdsa::signature::Signer as _;
        let signature: p256::ecdsa::Signature = key.sign(message);
        Ok(DeviceSignature::from_bytes(&signature.to_bytes())?)
    }
}

/// 从输入派生一把确定的主密钥。
///
/// **不是密钥派生函数**，只是让 fuzz 目标自己造的东西自己能解开。取前 32 字节，
/// 不足补零——`MasterKey::from_bytes` 要求长度恰好是 32。
fn master_from(data: &[u8]) -> MasterKey {
    let mut key = [0_u8; 32];
    let take = data.len().min(32);
    key[..take].copy_from_slice(&data[..take]);
    MasterKey::from_bytes(key.to_vec().into()).expect("长度恒为 32")
}

fuzz_target!(|data: &[u8]| {
    let master = master_from(data);
    let mut keys = FixedKeys::new();

    // ── 方向一：老设备解析 Msg1 ──────────────────────────────────────────
    //
    // 这条路径上 `data` 就是 Msg1 的全部字节。任何长度、任何内容都不得 panic。
    if let Ok(mut login) = Login::new() {
        let _ = login.authorize(data, &master);
    }

    // ── 方向二：新设备解析 Msg2 ──────────────────────────────────────────
    //
    // 先用一个真实载荷建立会话并发出请求，再把 `data` 当作对方回话的 Msg2。
    // 这是「攻击者能构造整条消息」的精确模型。
    if let Ok(login) = Login::new() {
        if let Ok(mut joiner) = Joiner::new(login.payload(), "fuzz-device") {
            if joiner.request(&mut keys).is_ok() {
                // `complete` 收 `self`，因此每轮都要新建一个加入方。
                if let Ok(joiner2) = Joiner::new(login.payload(), "fuzz-device") {
                    let mut joiner2 = joiner2;
                    if joiner2.request(&mut keys).is_ok() {
                        // 存储用一个必然失败的实现：本目标只关心解析路径，
                        // 而真的写入会让每轮 fuzz 都做一次不必要的分配。
                        let mut store = NeverStores;
                        let _ = joiner2.complete(data, &mut keys, &mut store);
                    }
                }
            }
        }
    }

    // ── 方向三：二维码文本的解码 ─────────────────────────────────────────
    //
    // 用户扫到的可能是任意字符串（截图、损坏的二维码、别人贴的假码）。
    if let Ok(text) = core::str::from_utf8(data) {
        if let Ok(payload) = qualia2fa_core::pairing::QrPayload::from_base32(text) {
            let _ = Joiner::new(&payload, "fuzz-device").map(|mut j| j.request(&mut keys));
        }
    }
});

/// 一个从不真正存储的 [`qualia2fa_core::flow::SecureStore`]。
///
/// 失败是**诚实的**：它如实返回错误，而不是假装存住了。fuzz 目标关心的是解析路径
/// 是否 panic，不是存储语义。
struct NeverStores;

impl qualia2fa_core::flow::SecureStore for NeverStores {
    fn load_master_key(&self) -> Result<Option<MasterKey>> {
        Ok(None)
    }

    fn store_master_key(&mut self, _key: &MasterKey) -> Result<()> {
        Err(Error::SecureStoreWriteFailed {
            reason: "fuzz 目标不存储",
        })
    }

    fn delete_master_key(&mut self) -> Result<()> {
        Ok(())
    }

    fn is_hardware_backed(&self) -> bool {
        false
    }
}
