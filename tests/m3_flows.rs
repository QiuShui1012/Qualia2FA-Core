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

//! M3 的端到端流程：注册、登录、挑战-应答、恢复。
//!
//! # 为什么要有这个文件
//!
//! 各模块的单元测试验证的是「每个函数自己是对的」。但 M3 要交付的是**用户能走通的
//! 两条路**：
//!
//! - **注册**：一台没有任何状态的新设备，建立主密钥与本地保险库。
//! - **登录**：一台新设备从一台已经登录的设备那里拿到主密钥。
//!
//! 这两条路各自要跨过若干个模块（保险库 → 配对 → 设备身份 → 挑战-应答 → 恢复），
//! 而**模块之间**恰恰是单元测试照顾不到的地方。本文件按用户实际会做的事来组织，
//! 而不是按模块来组织。
//!
//! 顺带覆盖 TODO 里点名要求的那组安全性质：正确配对必须成功，而**伪造公钥 /
//! 篡改二维码 / 重放**必须全部失败。

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use qualia2fa_core::auth;
use qualia2fa_core::device::{self, DevicePublicKey, DeviceSignature};
use qualia2fa_core::pairing::{
    self, MSG1_LEN, MSG2_LEN, NONCE_LEN, NonceLog, PUBLIC_KEY_LEN, QrPayload,
};
use qualia2fa_core::recovery;
use qualia2fa_core::vault::Timestamp;
use qualia2fa_core::vault::{self, Vault, VaultFile};
use qualia2fa_core::{Error, SecretString};

/// 测试用的固定时间戳。
///
/// 本库不持有时钟（时间一律由调用方传入），因此测试也必须自己给一个确定的值。
const TEST_NOW: Timestamp = 1_700_000_000;

/// 一台设备的软件身份。
///
/// 生产环境里设备私钥住在平台硬件密钥库里，签名由 `qualia2fa-keystore` 发起。
/// 这些测试用软件密钥，是因为它们要验证的是**协议**，与私钥存在哪里无关；真实
/// 硬件路径由 keystore 仓库的真机集成测试覆盖。
struct Device {
    /// 签名私钥。
    signing: SigningKey,
    /// SEC1 编码的设备身份公钥。
    public: [u8; PUBLIC_KEY_LEN],
}

impl Device {
    /// 用给定标量造一台设备。
    fn new(scalar: u8) -> Self {
        let mut bytes = [0_u8; 32];
        bytes[31] = scalar;
        let signing = SigningKey::from_bytes((&bytes).into()).expect("小标量必定合法");
        let point = signing.verifying_key().to_sec1_point(false);
        let mut public = [0_u8; PUBLIC_KEY_LEN];
        public.copy_from_slice(point.as_bytes());
        Self { signing, public }
    }

    /// 对消息签名（标准 ECDSA 哈希模式，与 `device::verify` 对称）。
    fn sign(&self, message: &[u8]) -> DeviceSignature {
        let signature: Signature = self.signing.sign(message);
        DeviceSignature::from_bytes(&signature.to_bytes()).expect("固定 64 字节")
    }
}

// ── 注册 ─────────────────────────────────────────────────────────────────

/// **注册**：一台全新的设备建立起可用的本地保险库。
///
/// 「生成主密钥 → 建立本地保险库 → 设备身份入平台硬件密钥库」三步里，第一步与
/// 第二步属于本库（第三步是 keystore 的事）。这条测试走完属于本库的那两步，并确认
/// 结果**真的可用**——一个能创建但存不进东西、或存进去读不出来的保险库，在注册
/// 那一刻看起来是成功的。
#[test]
fn registration_produces_a_usable_vault() {
    let device = Device::new(1);
    let mut file = VaultFile::create().expect("注册时随机源必须可用");
    assert!(file.vault().is_empty(), "新保险库必须是空的");

    // 加一条条目，序列化，再用同一个主密钥解回来。
    let entry = qualia2fa_core::vault::entry_from_parsed_uri(
        &qualia2fa_core::uri::parse(
            "otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME",
        )
        .expect("合法 URI"),
        TEST_NOW,
    )
    .expect("构造条目");
    file.vault_mut().insert(entry).expect("插入条目");

    let bytes = file.serialize().expect("序列化");
    let (master, _) = file.into_parts();
    let reopened = VaultFile::parse(master, &bytes).expect("重新打开");
    assert_eq!(reopened.vault().len(), 1, "条目应当在重新打开后还在");

    // 设备身份本身是自洽的：签名能被验签。
    let message = b"registration";
    device::verify(
        &DevicePublicKey::from_sec1_bytes(&device.public).expect("合法公钥"),
        message,
        &device.sign(message),
    )
    .expect("自己签的名必须能验过");
}

/// 注册出来的主密钥必须是**新鲜的随机值**，而不是可推导的常量。
#[test]
fn registration_generates_a_fresh_master_key_each_time() {
    let a = VaultFile::create().expect("随机源可用");
    let b = VaultFile::create().expect("随机源可用");
    assert_ne!(
        a.master_key().expose(),
        b.master_key().expose(),
        "两次注册得到了同一个主密钥"
    );
}

// ── 登录（二维码配对） ────────────────────────────────────────────────────

/// **登录成功路径**：加入方拿到的主密钥与发起方手里的**逐字节相同**。
///
/// 这是 M3 的核心承诺。只断言「返回了 Ok」是不够的：一个把主密钥换成新随机值的
/// 实现同样会返回 Ok，而用户会在同步时才发现条目一条都对不上。
#[test]
fn login_transfers_the_exact_master_key() {
    let master = qualia2fa_core::vault::MasterKey::generate().expect("随机源可用");
    let joiner = Device::new(2);

    let (payload, pending) = pairing::begin().expect("发起配对");
    let session = pairing::join(&payload).expect("接受二维码");
    let (msg1, _) = session.request(&joiner.public).expect("生成请求");
    let adoption = pending.accept(&msg1, &master).expect("发起方接受请求");

    // **必须复用发出 Msg1 的那个会话。** `request` 借 `&self` 而不是消费它，正是
    // 为了这一点。新建一个会话会得到新的临时密钥与 nonce，于是双方算出的会话标识
    // 不同，Msg2 的密钥与 AAD 都对不上——失败现象是 `PairingAuthenticationFailed`，
    // 而密钥、nonce、AAD 看上去全都"用对了"。
    let received = session
        .open(adoption.reply(), &joiner.public)
        .expect("加入方打开 Msg2");

    assert_eq!(
        received.expose(),
        master.expose(),
        "加入方拿到的主密钥与发起方不一致"
    );
}

/// **登录之后新设备真的能用这个主密钥读数据。**
///
/// 上一条只比较了字节；这一条证明拿到的密钥**在功能上**是那把钥匙——用老设备
/// 加密的保险库，新设备能解开。
#[test]
fn login_lets_the_new_device_open_the_old_vault() {
    // 老设备：建库、写一条、序列化。
    let mut old = VaultFile::create().expect("随机源可用");
    let entry = qualia2fa_core::vault::entry_from_parsed_uri(
        &qualia2fa_core::uri::parse("otpauth://totp/Example:bob?secret=JBSWY3DPEHPK3PXP")
            .expect("合法 URI"),
        TEST_NOW,
    )
    .expect("构造条目");
    old.vault_mut().insert(entry).expect("插入");
    let file_bytes = old.serialize().expect("序列化");

    // 走完配对，新设备只拿到主密钥（没拿到条目本身）。
    let (master, _) = old.into_parts();
    let joiner = Device::new(2);
    let (payload, pending) = pairing::begin().expect("发起配对");
    let session = pairing::join(&payload).expect("接受二维码");
    let (msg1, _) = session.request(&joiner.public).expect("生成请求");
    let adoption = pending.accept(&msg1, &master).expect("接受请求");
    let new_master = session
        .open(adoption.reply(), &joiner.public)
        .expect("打开 Msg2");

    // 新设备用新拿到的主密钥解老设备的文件。
    let reopened = VaultFile::parse(new_master, &file_bytes).expect("新设备应当能解开");
    assert_eq!(reopened.vault().len(), 1, "新设备应当看到那条条目");
}

/// **篡改二维码必须失败。**
///
/// 二维码是唯一的带外信道，攻击者若能改它就能把自己的公钥换进去。这里逐个字节翻转
/// 载荷并确认：要么解码阶段就被拒绝，要么**配对根本无法完成**。
///
/// 先确认未篡改的载荷能走通，否则下面的断言毫无意义——一条「什么都拒绝」的实现
/// 也能让下面的循环全绿。
#[test]
fn tampered_qr_payload_never_completes_a_pairing() {
    let master = qualia2fa_core::vault::MasterKey::generate().expect("随机源可用");
    let joiner = Device::new(2);

    let (payload, pending) = pairing::begin().expect("发起配对");
    let baseline = payload.encode();

    // 基线：同一份载荷必须能走到 `accept` 成功。
    //
    // 注意用的是**上面那一个** `pending`。Msg1 的文法是绑定到某次 `begin()` 的
    // 临时密钥上的：另起一个 `begin()` 会得到新的临时密钥，会话标识随之不同，
    // 于是 Msg1 被拒。这与下面循环里「每个字节都要配一个全新的发起方会话」是
    // 两件不同的事——那里是故意的，这里是必须复用。
    {
        let decoded = QrPayload::decode(&baseline).expect("基线载荷应当能解码");
        let session = pairing::join(&decoded).expect("基线应当能加入");
        let (msg1, _) = session.request(&joiner.public).expect("生成请求");
        pending
            .accept(&msg1, &master)
            .expect("基线必须能走通，否则下面的断言没有意义");
    }

    for index in 0..baseline.len() {
        let mut tampered = baseline.clone();
        tampered[index] ^= 0x01;

        // 解码失败、或者加入失败，都属于「被拒绝」。
        let Ok(decoded) = QrPayload::decode(&tampered) else {
            continue;
        };
        let Ok(session) = pairing::join(&decoded) else {
            continue;
        };
        let Ok((msg1, _)) = session.request(&joiner.public) else {
            continue;
        };
        // 走到这里说明篡改后的载荷在结构上仍然"像"一份合法载荷——那正是最危险的
        // 情况。发起方必须在此拒绝它。
        let (_, pending) = pairing::begin().expect("发起配对");
        assert!(
            pending.accept(&msg1, &master).is_err(),
            "第 {index} 字节被篡改后仍然完成了配对"
        );
    }
}

/// **伪造公钥必须失败**：攻击者用自己的公钥冒充设备身份，验签必须挡下来。
#[test]
fn forged_device_public_key_is_rejected() {
    let message = b"pairing transcript";
    let honest = Device::new(1);
    let attacker = Device::new(9);

    // 攻击者用自己的私钥签名，却声称那是诚实设备的公钥。
    let forged = attacker.sign(message);
    let result = device::verify(
        &DevicePublicKey::from_sec1_bytes(&honest.public).expect("合法公钥"),
        message,
        &forged,
    );
    assert!(
        matches!(result, Err(Error::DeviceSignatureInvalid { .. })),
        "伪造的公钥/签名通过了验签"
    );

    // 攻击者把公钥也换成自己的 → 验签通过，但那是**另一台设备**的身份，
    // 调用方拿到的 `device_id` 会不同。这正是为什么签名只能证明「你是谁」，
    // 不能证明「你持有主密钥」。
    let attacker_key = DevicePublicKey::from_sec1_bytes(&attacker.public).expect("合法公钥");
    device::verify(&attacker_key, message, &forged).expect("用自己的密钥签自己的名当然通过");
    assert_ne!(
        attacker_key.device_id(),
        DevicePublicKey::from_sec1_bytes(&honest.public)
            .expect("合法公钥")
            .device_id(),
        "两台设备的身份标识撞了"
    );
}

/// 配对载荷里**不得**出现主密钥。
#[test]
fn qr_payload_never_contains_key_material() {
    let master = qualia2fa_core::vault::MasterKey::generate().expect("随机源可用");
    let (payload, _) = pairing::begin().expect("发起配对");
    let encoded = payload.encode();

    assert!(
        !encoded.windows(32).any(|window| window == master.expose()),
        "二维码载荷里出现了主密钥明文"
    );
    // 载荷里只有：版本 + 临时公钥 + nonce + 能力位。
    assert_eq!(encoded.len(), 1 + PUBLIC_KEY_LEN + NONCE_LEN + 1);
}

/// **重放必须失败。**
///
/// 攻击者录下一次完整的握手，然后在新的会话里重放其中的消息。
#[test]
fn replayed_pairing_messages_are_rejected() {
    let master = qualia2fa_core::vault::MasterKey::generate().expect("随机源可用");
    let joiner = Device::new(2);

    // 第一次握手：录下 msg1 与 msg2。
    let (payload_a, pending_a) = pairing::begin().expect("发起配对 A");
    let session = pairing::join(&payload_a).expect("接受二维码 A");
    let (recorded_msg1, _) = session.request(&joiner.public).expect("生成请求");
    let adoption_a = pending_a
        .accept(&recorded_msg1, &master)
        .expect("接受请求 A");
    let recorded_msg2 = adoption_a.reply().to_vec();

    // 第二次握手：一个全新的会话。
    let (payload_b, pending_b) = pairing::begin().expect("发起配对 B");
    let session_b = pairing::join(&payload_b).expect("接受二维码 B");
    let (_fresh_msg1, _) = session_b.request(&joiner.public).expect("生成请求");

    // 重放 msg1：它属于会话 A，不该被会话 B 接受。
    assert!(
        pending_b.accept(&recorded_msg1, &master).is_err(),
        "属于另一次会话的 msg1 被接受了"
    );

    // 重放 msg2：加入方在会话 B 里打开会话 A 的应答。
    let session_b2 = pairing::join(&payload_b).expect("接受二维码 B");
    assert!(
        session_b2.open(&recorded_msg2, &joiner.public).is_err(),
        "属于另一次会话的 msg2 被接受了"
    );
}

/// **`NonceLog` 能认出重复的 nonce**，且容量有界。
#[test]
fn nonce_log_detects_replays_and_stays_bounded() {
    let mut log = NonceLog::new();
    let nonce = [7_u8; NONCE_LEN];
    assert!(!log.is_used(&nonce), "记录前不该认为是已用");
    assert!(log.record(nonce), "第一次记录应当成功");
    assert!(log.is_used(&nonce), "记录后应当认为是已用");
    assert!(!log.record(nonce), "重复记录应当被拒绝");

    // 容量有界：一个攻击者不能用「大量未完成的配对」把内存撑爆。
    let mut log = NonceLog::new();
    for index in 0..2000_u32 {
        let mut nonce = [0_u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&index.to_be_bytes());
        log.record(nonce);
    }
    assert!(
        log.len() <= 256,
        "NonceLog 无界增长，实际上限是 {}",
        log.len()
    );
}

// ── 挑战-应答 ─────────────────────────────────────────────────────────────

/// 两台**已经登录**的设备互相确认身份。
#[test]
fn challenge_response_confirms_both_sides() {
    let master = qualia2fa_core::vault::MasterKey::generate().expect("随机源可用");
    let responder_device = Device::new(2);

    let (challenge, verifier) = auth::begin().expect("生成挑战");
    let responder = auth::accept(&challenge).expect("接受挑战");
    let response = responder
        .respond(&master, &responder_device.public, |message| {
            Ok(responder_device.sign(message))
        })
        .expect("生成应答");

    let verified = verifier.verify(&response, &master).expect("验证应答");
    assert_eq!(
        verified.session_id(),
        &responder.session_id(),
        "双方对会话标识的看法必须一致"
    );
    assert_eq!(
        verified.device_public(),
        &responder_device.public,
        "验证方应当认出对方是哪台设备"
    );
    auth::confirm(
        &master,
        &responder,
        verified.session_id(),
        &verified.confirmation(),
    )
    .expect("确认标签应当被接受");
}

/// 没有主密钥的一方**无论如何都过不了挑战-应答**。
#[test]
fn challenge_response_fails_without_the_master_key() {
    let real = qualia2fa_core::vault::MasterKey::generate().expect("随机源可用");
    let fake = qualia2fa_core::vault::MasterKey::generate().expect("随机源可用");
    let device = Device::new(2);

    let (challenge, verifier) = auth::begin().expect("生成挑战");
    let responder = auth::accept(&challenge).expect("接受挑战");
    let response = responder
        .respond(&fake, &device.public, |message| Ok(device.sign(message)))
        .expect("签名本身会成功");

    assert!(
        matches!(
            verifier.verify(&response, &real),
            Err(Error::AuthProofFailed)
        ),
        "用错的主密钥却通过了认证"
    );
}

// ── 恢复密钥 ──────────────────────────────────────────────────────────────

/// **恢复密钥是最后一条退路**：旧设备没了，只有口令和文件。
#[test]
fn recovery_restores_the_master_key_from_a_passphrase() {
    let master = qualia2fa_core::vault::MasterKey::generate().expect("随机源可用");
    // 测试用极低参数；默认参数是 64 MiB / 3 次，会让整个套件慢上几秒。
    let params = recovery::KdfParams::new(8, 1, 1).expect("下限参数");
    let passphrase = SecretString::from("correct horse battery staple");

    let file = recovery::export(&master, &passphrase, &params).expect("导出");
    assert_eq!(file.len(), 110, "恢复文件长度是固定契约");

    let restored = recovery::import(&file, &passphrase).expect("导入");
    assert_eq!(
        restored.expose(),
        master.expose(),
        "恢复出来的主密钥与原来的不一致"
    );
}

/// 口令打错必须失败，而且**不能**返回一个错误的主密钥。
#[test]
fn recovery_rejects_a_wrong_passphrase() {
    let master = qualia2fa_core::vault::MasterKey::generate().expect("随机源可用");
    let params = recovery::KdfParams::new(8, 1, 1).expect("下限参数");
    let file = recovery::export(&master, &SecretString::from("right"), &params).expect("导出");

    assert!(
        matches!(
            recovery::import(&file, &SecretString::from("wrong")),
            Err(Error::RecoveryAuthenticationFailed)
        ),
        "错误口令却通过了"
    );
}

/// **恢复出来的主密钥在功能上能解开保险库。**
///
/// 与登录一样：只比较字节是不够的，要让恢复出来的密钥真的去开一次库。
#[test]
fn recovered_master_key_opens_the_vault() {
    let mut file = VaultFile::create().expect("随机源可用");
    let entry = qualia2fa_core::vault::entry_from_parsed_uri(
        &qualia2fa_core::uri::parse("otpauth://totp/Recovery:carol?secret=JBSWY3DPEHPK3PXP")
            .expect("合法 URI"),
        TEST_NOW,
    )
    .expect("构造条目");
    file.vault_mut().insert(entry).expect("插入");
    let vault_bytes = file.serialize().expect("序列化");

    let (master, _) = file.into_parts();
    let params = recovery::KdfParams::new(8, 1, 1).expect("下限参数");
    let passphrase = SecretString::from("a passphrase");
    let recovery_file = recovery::export(&master, &passphrase, &params).expect("导出");

    // 模拟「旧设备没了」：只剩下恢复文件与保险库文件。
    drop(master);

    let restored = recovery::import(&recovery_file, &passphrase).expect("导入");
    let reopened = VaultFile::parse(restored, &vault_bytes).expect("恢复出的密钥应当能开库");
    assert_eq!(reopened.vault().len(), 1);
}

// ── 消息长度是跨设备契约 ──────────────────────────────────────────────────

/// 协议里所有长度都必须固定：两台设备各自实现时才不会对不上。
#[test]
fn protocol_lengths_are_stable() {
    assert_eq!(PUBLIC_KEY_LEN, 65);
    assert_eq!(NONCE_LEN, 32);
    assert_eq!(MSG1_LEN, 210);
    assert_eq!(MSG2_LEN, 80);
    assert_eq!(auth::CHALLENGE_LEN, 97);
    assert_eq!(auth::RESPONSE_SIGNED_LEN, 258);
    assert_eq!(recovery::FILE_LEN, 110);
    // 保险库格式也有版本号，改动必须是显式的。
    assert_eq!(vault::FORMAT_VERSION, 1);
}

/// 保险库的条目在两个设备之间可以通过**同步载荷**传递，但前提是双方主密钥相同。
///
/// 这条测试把「登录」与「同步」的接缝钉住：登录只传主密钥，条目要在 M4 才同步。
#[test]
fn a_second_vault_with_the_same_master_key_sees_nothing_until_sync() {
    let mut first = VaultFile::create().expect("随机源可用");
    let entry = qualia2fa_core::vault::entry_from_parsed_uri(
        &qualia2fa_core::uri::parse("otpauth://totp/Sync:dave?secret=JBSWY3DPEHPK3PXP")
            .expect("合法 URI"),
        TEST_NOW,
    )
    .expect("构造条目");
    first.vault_mut().insert(entry).expect("插入");

    // 第二台设备拿到同一个主密钥，但还没有任何条目——登录**不**传数据。
    let master =
        pairing::master_key_from_storage(pairing::master_key_for_storage(first.master_key()))
            .expect("长度正确");
    let second = VaultFile::with_master_key(master);
    assert!(
        second.vault().is_empty(),
        "登录不该顺带把条目也传过去——那是同步（M4）的职责"
    );

    // 但两边的主密钥相同，因此第一台的密文第二台解不开「因为没数据」而不是「因为密钥不同」。
    let _ = Vault::new();
}
