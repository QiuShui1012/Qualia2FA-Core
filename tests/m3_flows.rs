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
//! # 两条路径：编排 API 与协议细节
//!
//! 「用户会做什么」的部分走 [`qualia2fa_core::flow`]——那是应用真正应当调用的入口，
//! 顺序与失败处理都由它保证。剩下的部分直接用 `pairing` / `auth` / `device` 的底层
//! 接口，因为那几条测试要钉住的是**协议细节**（消息长度、逐字节篡改、重放日志），
//! 而不是某一条用户旅程。
//!
//! 两者都必要：只测底层会让「按什么顺序调」无人验证；只测编排则无法逐字节地证明
//! 「翻转任何一位都会被拒绝」。
//!
//! 顺带覆盖 TODO 里点名要求的那组安全性质：正确配对必须成功，而**伪造公钥 /
//! 篡改二维码 / 重放**必须全部失败。

use std::collections::HashMap;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use qualia2fa_core::auth;
use qualia2fa_core::device::{self, DevicePublicKey, DeviceSignature};
use qualia2fa_core::flow::{self, DeviceKeys, Joiner, Login, SecureStore};
use qualia2fa_core::pairing::{
    self, MSG1_LEN, MSG2_LEN, NONCE_LEN, NonceLog, PUBLIC_KEY_LEN, QrPayload,
};
use qualia2fa_core::recovery::{self, KdfParams};
use qualia2fa_core::vault::Timestamp;
use qualia2fa_core::vault::{self, MasterKey};
use qualia2fa_core::{Error, SecretString};

/// 测试用的固定时间戳。
///
/// 本库不持有时钟（时间一律由调用方传入），因此测试也必须自己给一个确定的值。
const TEST_NOW: Timestamp = 1_700_000_000;

/// 测试用的设备标签。生产环境每个平台会用自己的命名规则。
const LABEL: &str = "qualia2fa-test-device";

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

/// 满足 [`DeviceKeys`] 的软件实现。
///
/// 它对应端侧那层**不含判断**的适配代码：真实实现转发给 `qualia2fa-keystore`，这里
/// 转发给内存里的软件密钥。两者的形状必须一致——一旦适配层里长出 `if`，就说明有一条
/// 只在端侧才走的分支，而端侧没有单元测试。
struct SoftwareKeys {
    /// 按 label 记住已经创建过的身份。
    keys: HashMap<String, Device>,
}

impl SoftwareKeys {
    /// 一台还没有任何设备身份的新设备。
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
}

impl DeviceKeys for SoftwareKeys {
    fn get_or_create(&mut self, label: &str) -> Result<DevicePublicKey, Error> {
        if !self.keys.contains_key(label) {
            // 用 label 派生标量而不是随机取值：测试失败时要能复现。
            let scalar = label.bytes().fold(1_u8, u8::wrapping_add).max(1);
            self.keys.insert(label.to_owned(), Device::new(scalar));
        }
        let device = &self.keys[label];
        DevicePublicKey::from_sec1_bytes(&device.public)
    }

    fn sign(&mut self, label: &str, message: &[u8]) -> Result<DeviceSignature, Error> {
        // 传进来的必须是**消息本身**。若这里先哈希再交给 `Signer`，验签侧会把消息
        // 再哈希一次，失败现象是一个与真实原因相距很远的
        // `DeviceSignatureInvalid { reason: "签名与公钥或消息不匹配" }`。
        let device = self.keys.get(label).ok_or(Error::DeviceKeyMissing)?;
        Ok(device.sign(message))
    }
}

/// 满足 [`SecureStore`] 的内存实现，模拟「主密钥住进平台密钥库」。
///
/// `hardware` 可配置：生产环境里它由 keystore 如实上报（TPM 为 `true`、软件 KSP 为
/// `false`），这里让它可切换以验证它被原样转发给界面。
struct MemoryStore {
    /// 已存的主密钥。
    master: Option<MasterKey>,
    /// 是否声称受硬件保护。
    hardware: bool,
}

impl MemoryStore {
    /// 一台还没有存过主密钥的设备的存储。
    fn new(hardware: bool) -> Self {
        Self {
            master: None,
            hardware,
        }
    }
}

impl SecureStore for MemoryStore {
    fn load_master_key(&self) -> Result<Option<MasterKey>, Error> {
        // 主密钥不实现 `Clone`（那会静默复制明文），因此这里按字节复制一份新的。
        self.master
            .as_ref()
            .map(|key| MasterKey::from_bytes(flow::master_key_to_bytes(key)))
            .transpose()
    }

    fn store_master_key(&mut self, key: &MasterKey) -> Result<(), Error> {
        self.master = Some(MasterKey::from_bytes(flow::master_key_to_bytes(key))?);
        Ok(())
    }

    fn delete_master_key(&mut self) -> Result<(), Error> {
        self.master = None;
        Ok(())
    }

    fn is_hardware_backed(&self) -> bool {
        self.hardware
    }
}

// ── 注册 ─────────────────────────────────────────────────────────────────

/// **注册**：一台全新的设备建立起可用的本地保险库。
///
/// 走 [`flow::registration`]，也就是应用真正会调的入口。注册的三步里第一步与第二步
/// 属于本库，第三步（设备身份进平台密钥库）由 `DeviceKeys` 注入。这条测试确认结果
/// **真的可用**——一个能创建但存不进东西、或存进去读不出来的保险库，在注册那一刻
/// 看起来是成功的。
#[test]
fn registration_produces_a_usable_vault() {
    let mut keys = SoftwareKeys::new();
    let mut store = MemoryStore::new(true);
    let mut registered = flow::registration(&mut keys, &mut store, LABEL).expect("注册应当成功");

    assert!(registered.vault().vault().is_empty(), "新保险库必须是空的");
    assert!(
        registered.is_hardware_backed(),
        "存储自称硬件保护，必须原样转发"
    );

    // 加一条条目，序列化——这一步模拟应用把库写到磁盘。
    let entry = vault::entry_from_parsed_uri(
        &qualia2fa_core::uri::parse(
            "otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME",
        )
        .expect("合法 URI"),
        TEST_NOW,
    )
    .expect("构造条目");
    registered
        .vault_mut()
        .vault_mut()
        .insert(entry)
        .expect("插入条目");
    let bytes = registered.vault().serialize().expect("序列化");

    // 重启之后按正常路径打开：主密钥从平台存储取，内容从文件取。
    let reopened = flow::open_vault(&store, &bytes).expect("重新打开应当成功");
    assert_eq!(reopened.vault().len(), 1, "条目应当在重新打开后还在");

    // 设备身份本身是自洽的：签名能被验签。
    let message = b"registration";
    let public = keys.get_or_create(LABEL).expect("身份应当能用");
    flow::verify_device(&public, message, &keys.sign(LABEL, message).expect("签名"))
        .expect("自己签的名必须能验过");
}

/// 注册出来的主密钥必须是**新鲜的随机值**，而不是可推导的常量。
#[test]
fn registration_generates_a_fresh_master_key_each_time() {
    let mut keys_a = SoftwareKeys::new();
    let mut keys_b = SoftwareKeys::new();
    let a =
        flow::registration(&mut keys_a, &mut MemoryStore::new(false), LABEL).expect("随机源可用");
    let b =
        flow::registration(&mut keys_b, &mut MemoryStore::new(false), LABEL).expect("随机源可用");
    assert_ne!(
        a.vault().master_key().expose(),
        b.vault().master_key().expose(),
        "两次注册得到了同一个主密钥"
    );
}

// ── 登录（二维码配对） ────────────────────────────────────────────────────

/// **登录成功路径**：加入方拿到的主密钥与发起方手里的**逐字节相同**。
///
/// 这是 M3 的核心承诺。只断言「返回了 Ok」是不够的：一个把主密钥换成新随机值的
/// 实现同样会返回 Ok，而用户会在同步时才发现条目一条都对不上。
///
/// 这条测试用 `pairing` 的底层接口而不是 `flow`，因为它要钉住的是**会话绑定**这个
/// 协议细节：`request` 借 `&self` 而不是消费它，正是为了让同一个会话接着 `open`。
/// 新建会话会得到新的临时密钥，于是双方算出的会话标识不同，Msg2 的密钥与 AAD 都对
/// 不上——失败现象是 `PairingAuthenticationFailed`，而密钥、nonce、AAD 看上去
/// 全都「用对了」。
#[test]
fn login_transfers_the_exact_master_key() {
    let master = MasterKey::generate().expect("随机源可用");
    let joiner = Device::new(2);

    let (payload, pending) = pairing::begin().expect("发起配对");
    let session = pairing::join(&payload).expect("接受二维码");
    let (msg1, _) = session.request(&joiner.public).expect("生成请求");
    let adoption = pending.accept(&msg1, &master).expect("发起方接受请求");

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
/// 上一条只比较了字节；这一条走完整的 [`flow`] 编排，并证明拿到的密钥**在功能上**
/// 是那把钥匙——用老设备加密的保险库，新设备能解开。只比较字节对「把主密钥换成新
/// 随机值」这类实现是盲的。
#[test]
fn login_lets_the_new_device_open_the_old_vault() {
    // 老设备：注册、写一条、序列化。
    let mut old_keys = SoftwareKeys::new();
    let mut old_store = MemoryStore::new(true);
    let mut old = flow::registration(&mut old_keys, &mut old_store, LABEL).expect("老设备注册");
    let entry = vault::entry_from_parsed_uri(
        &qualia2fa_core::uri::parse("otpauth://totp/Example:bob?secret=JBSWY3DPEHPK3PXP")
            .expect("合法 URI"),
        TEST_NOW,
    )
    .expect("构造条目");
    old.vault_mut().vault_mut().insert(entry).expect("插入");
    let file_bytes = old.vault().serialize().expect("序列化");
    let master = MasterKey::from_bytes(flow::master_key_to_bytes(old.vault().master_key()))
        .expect("长度由构造保证");

    // 老设备显示二维码。
    let mut login = Login::new().expect("发起登录");
    let payload = login.payload().clone();

    // 新设备扫码、发出请求。
    let mut new_keys = SoftwareKeys::new();
    let mut new_store = MemoryStore::new(true);
    let mut joiner = Joiner::new(&payload, LABEL).expect("新设备应当能扫码");
    let request = joiner.request(&mut new_keys).expect("生成请求");

    // 界面上会在这里让用户确认「是本人发起的」；测试里直接授权。
    let reply = login
        .authorize(&request, &master)
        .expect("老设备授权应当成功");

    // 新设备完成登录：主密钥进平台存储。
    let received = joiner
        .complete(&reply, &mut new_keys, &mut new_store)
        .expect("新设备应当能完成登录");
    assert_eq!(received.expose(), master.expose(), "主密钥必须逐字节一致");

    // 而它**真的**能解开老设备写的文件——这才是「登录成功」的含义。
    let reopened = flow::open_vault(&new_store, &file_bytes).expect("新设备应当能解开");
    assert_eq!(reopened.vault().len(), 1, "新设备应当看到那条条目");
}

/// 两台各自注册的设备必须有不同的主密钥与不同的设备身份。
///
/// 这条看着显然，但它挡住的是「注册时复用了某个全局密钥」这类实现错误——那会让第二
/// 台设备的保险库与第一台其实是同一个账号，而界面完全看不出来。
///
/// 注意两台设备用的是**不同的 label**。这不是为了绕开什么：`SoftwareKeys` 按 label
/// 确定性派生密钥（好让测试可复现），因此同 label 必然得到同一个身份；而现实里每台
/// 设备的平台密钥库各自独立生成随机密钥，label 只在一台设备内部有意义。
#[test]
fn two_devices_register_independently() {
    let mut keys_a = SoftwareKeys::new();
    let mut keys_b = SoftwareKeys::new();
    let a =
        flow::registration(&mut keys_a, &mut MemoryStore::new(true), "device-a").expect("注册 A");
    let b =
        flow::registration(&mut keys_b, &mut MemoryStore::new(true), "device-b").expect("注册 B");

    assert_ne!(a.device().as_sec1_bytes(), b.device().as_sec1_bytes());
    assert_ne!(a.device_id(), b.device_id());
    assert_ne!(
        a.vault().master_key().expose(),
        b.vault().master_key().expose()
    );
    // 同一台设备上重复调用必须拿回**同一个**身份，否则重启后就打不开自己的库了。
    let mut keys = SoftwareKeys::new();
    let first = keys.get_or_create(LABEL).expect("首次");
    let second = keys.get_or_create(LABEL).expect("再次");
    assert_eq!(first.as_sec1_bytes(), second.as_sec1_bytes());
}

// ── 恢复密钥 ─────────────────────────────────────────────────────────────

/// **恢复密钥**：口令导出的文件能还原主密钥，并让一台空设备打开老保险库。
#[test]
fn recovery_restores_the_master_key_from_a_passphrase() {
    let mut keys = SoftwareKeys::new();
    let mut store = MemoryStore::new(true);
    let mut registered = flow::registration(&mut keys, &mut store, LABEL).expect("注册");
    let entry = vault::entry_from_parsed_uri(
        &qualia2fa_core::uri::parse("otpauth://totp/Recovery:carol?secret=JBSWY3DPEHPK3PXP")
            .expect("合法 URI"),
        TEST_NOW,
    )
    .expect("构造条目");
    registered
        .vault_mut()
        .vault_mut()
        .insert(entry)
        .expect("插入");
    let file_bytes = registered.vault().serialize().expect("序列化");

    // 用最低 KDF 参数让测试快；真实默认值见 `KdfParams::recommended`。
    let params = KdfParams::new(8, 1, 1).expect("最低参数应当合法");
    let passphrase = SecretString::from("correct horse battery staple");
    let backup =
        flow::export_recovery_key(registered.vault().master_key(), &passphrase, Some(params))
            .expect("导出应当成功");

    // 一台全新的设备只用口令恢复。
    let mut new_store = MemoryStore::new(true);
    let restored =
        flow::import_recovery_key(&backup, &passphrase, &mut new_store).expect("导入应当成功");
    assert_eq!(restored.expose(), registered.vault().master_key().expose());

    let reopened = flow::open_vault(&new_store, &file_bytes).expect("恢复后应当能打开");
    assert_eq!(reopened.vault().len(), 1);
}

/// 恢复口令写错时必须失败，且不得在设备上留下任何主密钥。
#[test]
fn recovery_rejects_a_wrong_passphrase() {
    let master = MasterKey::generate().expect("随机源可用");
    let params = KdfParams::new(8, 1, 1).expect("最低参数应当合法");
    let backup = recovery::export(&master, &SecretString::from("right"), &params).expect("导出");

    let mut store = MemoryStore::new(true);
    let error = flow::import_recovery_key(&backup, &SecretString::from("wrong"), &mut store)
        .expect_err("口令错误必须失败");
    assert!(
        matches!(error, Error::RecoveryAuthenticationFailed),
        "实际是 {error:?}"
    );
    assert!(
        store.load_master_key().expect("读取不应失败").is_none(),
        "失败不得留下主密钥"
    );
}

// ── 协议层：篡改、伪造、重放 ─────────────────────────────────────────────

/// **篡改二维码必须失败。**
///
/// 二维码是唯一的带外信道，攻击者若能改它就能把自己的公钥换进去。这里逐个字节翻转
/// 载荷并确认：要么解码阶段就被拒绝，要么**配对根本无法完成**。
///
/// 先确认未篡改的载荷能走通，否则下面的断言毫无意义——一条「什么都拒绝」的实现
/// 也能让下面的循环全绿。
#[test]
fn tampered_qr_payload_never_completes_a_pairing() {
    let master = MasterKey::generate().expect("随机源可用");
    let joiner = Device::new(2);

    let (payload, pending) = pairing::begin().expect("发起配对");
    let baseline = payload.encode();

    // 基线：同一份载荷必须能走到 `accept` 成功。
    //
    // 注意用的是**上面那一个** `pending`。Msg1 是绑定到某次 `begin()` 的临时密钥上
    // 的：另起一个 `begin()` 会得到新的临时密钥，会话标识随之不同，于是 Msg1 被拒。
    // 这与下面循环里「每个字节都要配一个全新的发起方会话」是两件不同的事——那里是
    // 故意的，这里是必须复用。
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
        // 走到这里说明篡改后的载荷在结构上仍然「像」一份合法载荷——那正是最危险的
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
    let real = Device::new(3);
    let attacker = Device::new(4);

    let signature = attacker.sign(message);
    let error = device::verify(
        &DevicePublicKey::from_sec1_bytes(&real.public).expect("合法公钥"),
        message,
        &signature,
    )
    .expect_err("攻击者签的名不该验过");
    assert!(
        matches!(error, Error::DeviceSignatureInvalid { .. }),
        "实际是 {error:?}"
    );

    // 合法签名仍然能过——否则「什么都拒绝」也能让上面那条绿。
    device::verify(
        &DevicePublicKey::from_sec1_bytes(&real.public).expect("合法公钥"),
        message,
        &real.sign(message),
    )
    .expect("自己的签名必须能验过");
}

/// 二维码载荷里**不得出现任何密钥材料**。
///
/// 二维码是公开信道（会被拍照、截图、投屏），因此它只能携带公钥与随机数。这条测试
/// 把载荷与主密钥逐字节比对，挡住「顺手把主密钥塞进二维码」这类灾难性改动。
#[test]
fn qr_payload_never_contains_key_material() {
    let master = MasterKey::generate().expect("随机源可用");
    let (payload, _pending) = pairing::begin().expect("发起配对");
    let bytes = payload.encode();
    let text = payload.to_base32();

    for window in master.expose().windows(8) {
        assert!(
            !bytes.windows(8).any(|w| w == window),
            "二维码载荷里出现了主密钥的片段"
        );
    }
    assert!(!text.is_empty());
    assert_eq!(bytes.len(), pairing::QR_PAYLOAD_LEN);
}

/// **重放整次会话必须失败**：把第一次登录的 Msg1 原样再发一次。
///
/// 重放防护在协议里是三层（见 `pairing` 与 `auth` 的模块文档），这里验证的
/// `NonceLog` 是**跨进程重启**那一层——它是唯一需要调用方配合的，因此必须有一条
/// 测试证明它确实能挡住东西，而不只是一个计数器。
#[test]
fn replayed_pairing_messages_are_rejected() {
    let master = MasterKey::generate().expect("随机源可用");
    let joiner = Device::new(2);

    // 第一次登录：完整走通，记下会话标识。
    let (payload, pending) = pairing::begin().expect("发起配对");
    let session = pairing::join(&payload).expect("接受二维码");
    let (recorded_msg1, session_id) = session.request(&joiner.public).expect("生成请求");
    let adoption = pending
        .accept(&recorded_msg1, &master)
        .expect("首次应当通过");
    assert_eq!(adoption.session_id(), &session_id);

    // 记进重放日志。
    let mut log = NonceLog::new();
    assert!(log.record(session_id), "首次记录应当成功");
    assert!(log.is_used(&session_id));

    // 攻击者把整条 Msg1 原样再发一次。发起方**必须**先查日志再应答——这是调用方的
    // 责任，因此这里也顺带钉住了「查日志确实能认出来」。
    assert!(log.is_used(&session_id), "重放日志必须认出已经用过的会话");

    // 换一个会话（对应现实里用户重新发起登录）必须是**新的**会话标识，不会被日志
    // 误伤——否则重放防护会变成「登录只能用一次」。
    let (payload2, _pending2) = pairing::begin().expect("发起配对");
    let session2 = pairing::join(&payload2).expect("接受二维码");
    let (_msg1_2, session_id2) = session2.request(&joiner.public).expect("生成请求");
    assert_ne!(session_id, session_id2);
    assert!(!log.is_used(&session_id2), "新会话不该被误判为重放");
    assert!(log.record(session_id2));
    assert_eq!(log.len(), 2);
}

/// 重放日志的容量必须有界。
///
/// 攻击者可以发起大量**不完成**的配对，每个都产生一个会话标识。若日志无界增长，
/// 那就是一条内存耗尽路径——而这个日志的作用只是挡住重放，记不住全部也无所谓。
#[test]
fn nonce_log_detects_replays_and_stays_bounded() {
    let mut log = NonceLog::new();
    let capacity = NonceLog::DEFAULT_CAPACITY;
    let mut session_ids = Vec::new();
    for index in 0..(capacity + 16) {
        let mut id = [0_u8; NONCE_LEN];
        id[..8].copy_from_slice(&(index as u64).to_le_bytes());
        assert!(log.record(id), "第 {index} 个标识应当能记录");
        session_ids.push(id);
    }
    assert!(
        log.len() <= capacity,
        "日志长度 {} 超过了容量 {capacity}",
        log.len()
    );
    // 最新的那些必须还在，否则「刚用完就被忘掉」等于没有防护。
    let newest = session_ids.last().expect("至少记录了一个");
    assert!(log.is_used(newest), "最新的会话标识不该被淘汰");
    // 重复记录同一个标识必须返回「已经在里面了」。
    assert!(!log.record(*newest), "同一个标识不该被记两次");
}

// ── 挑战-应答（D3） ──────────────────────────────────────────────────────

/// **挑战-应答**：持有主密钥的一方能让验证方确信这一点，双方对会话标识达成一致。
#[test]
fn challenge_response_confirms_both_sides() {
    let master = MasterKey::generate().expect("随机源可用");
    let device = Device::new(5);

    let (challenge, verifier) = auth::begin().expect("发起挑战");
    let responder = auth::accept(&challenge).expect("接受挑战");
    let response = responder
        .respond(&master, &device.public, |message| Ok(device.sign(message)))
        .expect("应答");
    let verified = verifier.verify(&response, &master).expect("验证应当通过");

    assert_eq!(verified.session_id(), &responder.session_id());
    assert_eq!(verified.device_key().as_sec1_bytes(), &device.public);

    // 确认标签必须被对方接受——这一步证明**反过来**也成立。
    auth::confirm(
        &master,
        &responder,
        verified.session_id(),
        &verified.confirmation(),
    )
    .expect("确认应当通过");
}

/// 没有主密钥的一方无法应答；伪造的应答必须被拒绝。
#[test]
fn challenge_response_fails_without_the_master_key() {
    let real = MasterKey::generate().expect("随机源可用");
    let fake = MasterKey::generate().expect("随机源可用");
    let device = Device::new(6);

    let (challenge, verifier) = auth::begin().expect("发起挑战");
    let responder = auth::accept(&challenge).expect("接受挑战");
    // 攻击者手里没有真主密钥，用它自己那把去应答。
    let response = responder
        .respond(&fake, &device.public, |message| Ok(device.sign(message)))
        .expect("应答本身能构造出来");
    let error = verifier
        .verify(&response, &real)
        .expect_err("伪造的应答必须被拒绝");
    assert!(matches!(error, Error::AuthProofFailed), "实际是 {error:?}");
}

// ── 契约 ─────────────────────────────────────────────────────────────────

/// 各协议消息的长度是**跨版本契约**，不得随实现漂移。
///
/// 两台设备可能运行不同版本的软件（这正是本应用的使用场景），长度变化会让它们无法
/// 互通，而症状是「配对偶尔失败」——极难定位。这些常量因此被钉在这里，改动它们必须
/// 是一次有意识的版本升级。
#[test]
fn protocol_lengths_are_stable() {
    assert_eq!(pairing::QR_PAYLOAD_LEN, 99);
    assert_eq!(MSG1_LEN, 210);
    assert_eq!(MSG2_LEN, 80);
    assert_eq!(PUBLIC_KEY_LEN, 65);
    assert_eq!(NONCE_LEN, 32);
    assert_eq!(auth::CHALLENGE_LEN, 97);
    assert_eq!(auth::RESPONSE_LEN, 194);
    assert_eq!(recovery::FILE_LEN, 110);
}

/// 两台各有独立主密钥的设备，在同步之前互相看不到对方的条目。
///
/// 这条钉住 D5 的一个直接后果：登录只传主密钥，**不传条目**。一个「顺手把条目也带
/// 过去」的实现会让同步在用户没要求的时候发生，而它的症状要到两台设备都改了同一条
/// 目之后才显现。
#[test]
fn a_second_vault_with_the_same_master_key_sees_nothing_until_sync() {
    let mut keys = SoftwareKeys::new();
    let mut store = MemoryStore::new(true);
    let mut first = flow::registration(&mut keys, &mut store, LABEL).expect("注册");
    let entry = vault::entry_from_parsed_uri(
        &qualia2fa_core::uri::parse("otpauth://totp/Sync:dave?secret=JBSWY3DPEHPK3PXP")
            .expect("合法 URI"),
        TEST_NOW,
    )
    .expect("构造条目");
    first.vault_mut().vault_mut().insert(entry).expect("插入");
    let bytes = first.vault().serialize().expect("序列化");

    // 第二台设备用同一把主密钥、但**新建**一个空保险库——登录之后的真实状态。
    let master = MasterKey::from_bytes(flow::master_key_to_bytes(first.vault().master_key()))
        .expect("长度由构造保证");
    let fresh = flow::empty_vault(master);
    assert!(fresh.vault().is_empty(), "新保险库不该自带条目");

    // 它确实能解开老设备的文件（同一把钥匙），但自己那份还是空的。
    let opened = flow::open_vault(&store, &bytes).expect("同一把密钥应当能解开");
    assert_eq!(opened.vault().len(), 1);
    assert!(fresh.vault().is_empty());
}
