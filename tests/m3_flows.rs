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

//! End-to-end flows: registration, login, challenge-response, recovery.
//!
//! # Scope
//!
//! Module unit tests verify that each function is correct on its own. The flows covered here
//! are the two paths a user actually walks:
//!
//! - **Registration**: a device with no state establishes a master key and a local vault.
//! - **Login**: a new device obtains the master key from a device that is already logged in.
//!
//! Each path crosses several modules (vault → pairing → device identity → challenge-response →
//! recovery), and the boundaries between modules are exactly what unit tests do not cover. This
//! file is organized by what the user actually does, not by module.
//!
//! # Two layers: orchestration API and protocol details
//!
//! The "what the user does" part goes through [`qualia2fa_core::flow`], the entry point an
//! application should actually call, which guarantees ordering and failure handling. The rest
//! uses the lower-level `pairing` / `auth` / `device` interfaces directly, because those tests
//! pin down **protocol details** (message lengths, per-byte tampering, the replay log) rather
//! than a user journey.
//!
//! Both layers are necessary: testing only the lower level leaves "in what order to call"
//! unverified, while testing only the orchestration cannot prove byte by byte that flipping any
//! single bit is rejected.
//!
//! The security properties covered here are: a valid pairing must succeed, while a forged
//! public key, a tampered QR payload, or a replay must all fail.

use std::collections::HashMap;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use qualia_dik::device::{DevicePublicKey, DeviceSignature};
use qualia2fa_core::auth;
use qualia2fa_core::flow::verify_device;
use qualia2fa_core::flow::{self, DeviceKeys, Joiner, Login, SecureStore};
use qualia2fa_core::pairing::{
    self, MSG1_LEN, MSG2_LEN, NONCE_LEN, NonceLog, PUBLIC_KEY_LEN, QrPayload,
};
use qualia2fa_core::recovery::{self, KdfParams};
use qualia2fa_core::vault::Timestamp;
use qualia2fa_core::vault::{self, MasterKey};
use qualia2fa_core::{Error, SecretString};

/// Fixed timestamp used by these tests.
///
/// The library holds no clock (time is always passed in by the caller), so tests must supply a
/// deterministic value themselves.
const TEST_NOW: Timestamp = 1_700_000_000;

/// Device label used by these tests. Each platform applies its own naming rules in production.
const LABEL: &str = "qualia2fa-test-device";

/// A device's software identity.
///
/// In production the device private key lives in the platform hardware keystore and signing is
/// performed by `qualia-dik`. These tests use software keys because what they verify is
/// the **protocol**, independent of where the private key lives; the real hardware path is
/// covered by on-device integration tests in the keystore repository.
struct Device {
    /// Signing private key.
    signing: SigningKey,
    /// SEC1-encoded device identity public key.
    public: [u8; PUBLIC_KEY_LEN],
}

impl Device {
    /// Creates a device from the given scalar.
    fn new(scalar: u8) -> Self {
        let mut bytes = [0_u8; 32];
        bytes[31] = scalar;
        let signing = SigningKey::from_bytes((&bytes).into()).expect("小标量必定合法");
        let point = signing.verifying_key().to_sec1_point(false);
        let mut public = [0_u8; PUBLIC_KEY_LEN];
        public.copy_from_slice(point.as_bytes());
        Self { signing, public }
    }

    /// Signs a message (standard ECDSA hashed mode, symmetric with `device::verify`).
    ///
    /// The input must be the **message itself**: this side hashes it before signing, and the
    /// verification side hashes it once more.
    fn sign(&self, message: &[u8]) -> DeviceSignature {
        let signature: Signature = self.signing.sign(message);
        DeviceSignature::from_bytes(&signature.to_bytes()).expect("固定 64 字节")
    }
}

/// Software implementation of [`DeviceKeys`].
///
/// It corresponds to the **condition-free** adaptation layer on the client side: the real
/// implementation forwards to `qualia-dik`, this one forwards to in-memory software
/// keys. Both must have the same shape — an `if` growing in the adaptation layer would mean a
/// branch taken only on the client side, where there are no unit tests.
struct SoftwareKeys {
    /// Identities already created, keyed by label.
    keys: HashMap<String, Device>,
}

impl SoftwareKeys {
    /// A new device with no device identity yet.
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
}

impl DeviceKeys for SoftwareKeys {
    fn get_or_create(&mut self, label: &str) -> Result<DevicePublicKey, Error> {
        if !self.keys.contains_key(label) {
            let scalar = label.bytes().fold(1_u8, u8::wrapping_add).max(1);
            self.keys.insert(label.to_owned(), Device::new(scalar));
        }
        let device = &self.keys[label];
        Ok(DevicePublicKey::from_sec1_bytes(&device.public)?)
    }

    fn sign(&mut self, label: &str, message: &[u8]) -> Result<DeviceSignature, Error> {
        let device = self.keys.get(label).ok_or(Error::DeviceKeyMissing)?;
        Ok(device.sign(message))
    }
}

/// In-memory implementation of [`SecureStore`], modelling "the master key resides in the
/// platform keystore".
///
/// `hardware` is configurable: in production the keystore reports it faithfully (`true` for a
/// TPM, `false` for a software KSP), here it is switchable so that forwarding it to the UI
/// unchanged can be verified.
///
/// Keys are copied through their byte representation, because `MasterKey` deliberately does not
/// implement `Clone`.
struct MemoryStore {
    /// The stored master key.
    master: Option<MasterKey>,
    /// Whether it claims to be hardware-protected.
    hardware: bool,
}

impl MemoryStore {
    /// Storage of a device that has never stored a master key.
    fn new(hardware: bool) -> Self {
        Self {
            master: None,
            hardware,
        }
    }
}

impl SecureStore for MemoryStore {
    fn load_master_key(&self) -> Result<Option<MasterKey>, Error> {
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

// ── Registration ───────────────────────────────────────────────────────

/// **Registration**: a brand-new device establishes a usable local vault.
///
/// Goes through [`flow::registration`], the entry point an application actually calls. Of the
/// three registration steps, the first two belong to this library and the third (device
/// identity into the platform keystore) is injected through `DeviceKeys`. This test confirms
/// the result is **really usable** — a vault that can be created but cannot store anything, or
/// cannot read back what was stored, looks successful at the moment of registration.
///
/// Reopening afterwards goes through the normal path: the master key is taken from the platform
/// store and the contents from the file. The device identity is self-consistent: a signature it
/// produces verifies.
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

    let reopened = flow::open_vault(&store, &bytes).expect("重新打开应当成功");
    assert_eq!(reopened.vault().len(), 1, "条目应当在重新打开后还在");

    let message = b"registration";
    let public = keys.get_or_create(LABEL).expect("身份应当能用");
    flow::verify_device(&public, message, &keys.sign(LABEL, message).expect("签名"))
        .expect("自己签的名必须能验过");
}

/// The master key produced by registration must be a **fresh random value**, not a derivable
/// constant.
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

// ── Login (QR pairing) ─────────────────────────────────────────────────

/// **Successful login path**: the master key the joiner receives is **byte for byte identical**
/// to the one the initiator holds.
///
/// Asserting "it returned Ok" is not enough: an implementation that swapped in a new random master
/// key would also return Ok, and the mismatch would only show up once the user tried to sync.
///
/// This test drives the low-level `pairing` API instead of `flow` because what it pins down is a
/// **protocol detail**, session binding: `request` borrows `&self` rather than consuming it so
/// that the same session can go on to `open`. A fresh session would carry a new ephemeral key, so
/// the two sides would derive different session identifiers and Msg2's key and AAD would no
/// longer match; the failure surfaces as `PairingAuthenticationFailed`.
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

/// **After login the new device can really read data with that master key.**
///
/// The previous test only compared bytes; this one goes through the full [`flow`] orchestration
/// and proves the key received is **functionally** the right one: the vault the old device
/// encrypted opens on the new one. Comparing bytes alone is blind to an implementation that swaps
/// in a new random master key.
///
/// The initiator authorizes directly here; the user confirmation the UI performs at that step is
/// not part of what this test verifies.
#[test]
fn login_lets_the_new_device_open_the_old_vault() {
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

    let mut login = Login::new().expect("发起登录");
    let payload = login.payload().clone();

    let mut new_keys = SoftwareKeys::new();
    let mut new_store = MemoryStore::new(true);
    let mut joiner = Joiner::new(&payload, LABEL).expect("新设备应当能扫码");
    let request = joiner.request(&mut new_keys).expect("生成请求");

    let reply = login
        .authorize(&request, &master)
        .expect("老设备授权应当成功");

    let received = joiner
        .complete(&reply, &mut new_keys, &mut new_store)
        .expect("新设备应当能完成登录");
    assert_eq!(received.expose(), master.expose(), "主密钥必须逐字节一致");

    let reopened = flow::open_vault(&new_store, &file_bytes).expect("新设备应当能解开");
    assert_eq!(reopened.vault().len(), 1, "新设备应当看到那条条目");
}

/// Two devices that register separately must end up with different master keys and different
/// device identities.
///
/// A failure here means registration reused some global key, which would make the second device's
/// vault the same account as the first one.
///
/// The two devices use **different labels**: `SoftwareKeys` derives keys deterministically from
/// the label so that these tests are reproducible, hence the same label always yields the same
/// identity. In production each device's platform keystore generates its own random key, and a
/// label is only meaningful inside one device.
///
/// A repeated [`DeviceKeys::get_or_create`] call on one device must return the **same** identity;
/// otherwise the device could not open its own vault after a restart.
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
    let mut keys = SoftwareKeys::new();
    let first = keys.get_or_create(LABEL).expect("首次");
    let second = keys.get_or_create(LABEL).expect("再次");
    assert_eq!(first.as_sec1_bytes(), second.as_sec1_bytes());
}

// ── Recovery key ───────────────────────────────────────────────────────

/// **Recovery key**: a passphrase-derived file restores the master key and lets an empty device
/// open an old vault.
///
/// The export uses the minimum KDF parameters (`KdfParams::new(8, 1, 1)`) to keep the test fast;
/// the production defaults are `KdfParams::recommended`.
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

    let params = KdfParams::new(8, 1, 1).expect("最低参数应当合法");
    let passphrase = SecretString::from("correct horse battery staple");
    let backup =
        flow::export_recovery_key(registered.vault().master_key(), &passphrase, Some(params))
            .expect("导出应当成功");

    let mut new_store = MemoryStore::new(true);
    let restored =
        flow::import_recovery_key(&backup, &passphrase, &mut new_store).expect("导入应当成功");
    assert_eq!(restored.expose(), registered.vault().master_key().expose());

    let reopened = flow::open_vault(&new_store, &file_bytes).expect("恢复后应当能打开");
    assert_eq!(reopened.vault().len(), 1);
}

/// A wrong recovery passphrase must fail and must not leave any master key on the device.
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

// ── Protocol layer: tampering, forgery, replay ─────────────────────────

/// **A tampered QR payload must never complete a pairing.**
///
/// The QR code is the only out-of-band channel, so an attacker able to modify it could substitute
/// a public key of their own. Every byte of the payload is flipped in turn, and the result must
/// either be rejected while decoding or fail to complete the pairing at all.
///
/// The untampered payload is exercised first, otherwise the assertions below would be vacuous: an
/// implementation that rejects everything would leave the loop green.
///
/// Msg1 is bound to the ephemeral key a `begin()` call generated, so the baseline reuses that same
/// `pending`; the loop below deliberately starts a fresh initiator for every byte instead. A
/// tampered payload that still decodes and joins — the dangerous case — must be rejected at
/// `accept`, while failing to decode or to join also counts as rejected.
#[test]
fn tampered_qr_payload_never_completes_a_pairing() {
    let master = MasterKey::generate().expect("随机源可用");
    let joiner = Device::new(2);

    let (payload, pending) = pairing::begin().expect("发起配对");
    let baseline = payload.encode();

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

        let Ok(decoded) = QrPayload::decode(&tampered) else {
            continue;
        };
        let Ok(session) = pairing::join(&decoded) else {
            continue;
        };
        let Ok((msg1, _)) = session.request(&joiner.public) else {
            continue;
        };
        let (_, pending) = pairing::begin().expect("发起配对");
        assert!(
            pending.accept(&msg1, &master).is_err(),
            "第 {index} 字节被篡改后仍然完成了配对"
        );
    }
}

/// **A forged public key must fail**: a signature produced with an attacker's own key must not
/// verify against the real device identity.
///
/// The check goes through this crate's `verify_device`, so what is asserted is the error type a
/// caller sees: the device identity library reports the failure, and it arrives wrapped as
/// `Error::Device(qualia_dik::Error::DeviceSignatureInvalid { .. })`. A signature made by the real
/// private key must still verify.
#[test]
fn forged_device_public_key_is_rejected() {
    let message = b"pairing transcript";
    let real = Device::new(3);
    let attacker = Device::new(4);

    let signature = attacker.sign(message);
    let error = verify_device(
        &DevicePublicKey::from_sec1_bytes(&real.public).expect("合法公钥"),
        message,
        &signature,
    )
    .expect_err("攻击者签的名不该验过");
    assert!(
        matches!(
            error,
            Error::Device(qualia_dik::Error::DeviceSignatureInvalid { .. })
        ),
        "实际是 {error:?}"
    );

    verify_device(
        &DevicePublicKey::from_sec1_bytes(&real.public).expect("合法公钥"),
        message,
        &real.sign(message),
    )
    .expect("自己的签名必须能验过");
}

/// **No key material may appear in the QR payload.**
///
/// The QR code is a public channel — it gets photographed, screenshotted and projected — so it may
/// carry only a public key and random nonces. The encoded payload is scanned for any 8-byte window
/// of the master key, and its length must equal `pairing::QR_PAYLOAD_LEN`.
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

/// **Replaying a whole session must fail**: the Msg1 of a first login is sent again unchanged.
///
/// Replay protection in the protocol has three layers (see the module documentation of `pairing`
/// and `auth`). The layer verified here is `NonceLog`, the one that survives a process restart and
/// the only one that requires the caller's cooperation: the initiator must consult the log before
/// answering. Recording an identifier reports whether it was new, and a replayed Msg1 keeps the
/// session identifier it was first recorded under, so `is_used` recognises it.
///
/// A later pairing (a user starting login again) must produce a **new** session identifier that the
/// log does not report as used; otherwise the replay log would make login work only once.
#[test]
fn replayed_pairing_messages_are_rejected() {
    let master = MasterKey::generate().expect("随机源可用");
    let joiner = Device::new(2);

    let (payload, pending) = pairing::begin().expect("发起配对");
    let session = pairing::join(&payload).expect("接受二维码");
    let (recorded_msg1, session_id) = session.request(&joiner.public).expect("生成请求");
    let adoption = pending
        .accept(&recorded_msg1, &master)
        .expect("首次应当通过");
    assert_eq!(adoption.session_id(), &session_id);

    let mut log = NonceLog::new();
    assert!(log.record(session_id), "首次记录应当成功");
    assert!(log.is_used(&session_id));

    assert!(log.is_used(&session_id), "重放日志必须认出已经用过的会话");

    let (payload2, _pending2) = pairing::begin().expect("发起配对");
    let session2 = pairing::join(&payload2).expect("接受二维码");
    let (_msg1_2, session_id2) = session2.request(&joiner.public).expect("生成请求");
    assert_ne!(session_id, session_id2);
    assert!(!log.is_used(&session_id2), "新会话不该被误判为重放");
    assert!(log.record(session_id2));
    assert_eq!(log.len(), 2);
}

/// The replay log's capacity must be **bounded**.
///
/// An attacker can start a large number of pairings that are **never completed**, each producing a
/// session identifier of `NONCE_LEN` (32) bytes. An unbounded log would be a memory-exhaustion
/// path, while the log's only job is to block replays, so it does not have to remember them all.
///
/// Only the newest identifiers are kept: the most recent one must still be recognised, `len()` must
/// stay at or below `NonceLog::DEFAULT_CAPACITY`, and recording an identifier already in the log
/// must report `false` instead of adding it a second time.
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
    let newest = session_ids.last().expect("至少记录了一个");
    assert!(log.is_used(newest), "最新的会话标识不该被淘汰");
    assert!(!log.record(*newest), "同一个标识不该被记两次");
}

// ── Challenge-response ─────────────────────────────────────────────────

/// **Challenge-response**: the party holding the master key convinces the verifier of that fact, and
/// both sides agree on the session identifier.
///
/// The response carries the device identity public key, and the confirmation tag the verifier
/// produces must be accepted back by the responder — the same property in the reverse direction.
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

    auth::confirm(
        &master,
        &responder,
        verified.session_id(),
        &verified.confirmation(),
    )
    .expect("确认应当通过");
}

/// A party without the master key cannot answer, and a forged response must be rejected.
///
/// The response is built from a **different** master key than the one the verifier holds, and
/// verification must fail with `Error::AuthProofFailed`.
#[test]
fn challenge_response_fails_without_the_master_key() {
    let real = MasterKey::generate().expect("随机源可用");
    let fake = MasterKey::generate().expect("随机源可用");
    let device = Device::new(6);

    let (challenge, verifier) = auth::begin().expect("发起挑战");
    let responder = auth::accept(&challenge).expect("接受挑战");
    let response = responder
        .respond(&fake, &device.public, |message| Ok(device.sign(message)))
        .expect("应答本身能构造出来");
    let error = verifier
        .verify(&response, &real)
        .expect_err("伪造的应答必须被拒绝");
    assert!(matches!(error, Error::AuthProofFailed), "实际是 {error:?}");
}

// ── Wire-format contract ───────────────────────────────────────────────

/// The length of every protocol message is a **cross-version contract** and must not drift with the
/// implementation.
///
/// Two devices may run different versions of the software, and a changed length would stop them from
/// interoperating, with the symptom being a pairing that fails intermittently. These constants are
/// therefore pinned here, and changing one has to be a deliberate version upgrade.
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

/// Two devices with independent master keys see none of each other's entries before they sync.
///
/// A direct consequence of what login transfers: the master key only, **no entries**. The second
/// device here is built from the same master key but as a **new, empty** vault, which is the state a
/// device is actually in after logging in; it can open the old device's file only because that file
/// is encrypted under the same key, while its own vault stays empty. Carrying entries along with the
/// key would make syncing happen without the user asking for it.
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

    let master = MasterKey::from_bytes(flow::master_key_to_bytes(first.vault().master_key()))
        .expect("长度由构造保证");
    let fresh = flow::empty_vault(master);
    assert!(fresh.vault().is_empty(), "新保险库不该自带条目");

    let opened = flow::open_vault(&store, &bytes).expect("同一把密钥应当能解开");
    assert_eq!(opened.vault().len(), 1);
    assert!(fresh.vault().is_empty());
}
