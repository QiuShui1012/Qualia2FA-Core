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

//! 设备登录配对：把主密钥交给一台新设备。
//!
//! # 要解决的问题
//!
//! 本应用没有中心服务器、没有账号密码。「登录」的含义是：一台**已经持有主密钥**
//! 的设备（**发起方** A）把主密钥交给一台新设备（**加入方** B）。B 拿到主密钥后，
//! 两台设备就能解开同一批条目。
//!
//! # 威胁模型
//!
//! 必须防住的攻击者：
//!
//! 1. **只看得到二维码照片**（隔窗拍摄、从相册翻出旧截图）。
//! 2. **看得到二维码、也能改动它**（用户被诱导扫了一张被替换过的二维码）。
//! 3. **能在 A 与 B 之间的信道上读、写、重放、删除任意消息**（中间人）。
//!
//! **不需要**防住的：已经控制住 A 或 B 之一的攻击者。那台设备本来就持有主密钥，
//! 配对协议无从提供额外保护。
//!
//! # 协议
//!
//! ```text
//!   A（已登录，持有主密钥 M）                    B（新设备，没有 M）
//!       │                                          │
//!       │ ① 生成临时密钥对 (a, A_pub) 与随机 nonce_A
//!       │    二维码 = { A_pub, nonce_A }            │
//!       │ ───────── 带外扫描（二维码）───────────► │
//!       │                                          │ ② 生成 (b, B_pub)
//!       │                                          │    S = ECDH(b, A_pub)
//!       │                                          │    由 S、A_pub、B_pub、
//!       │                                          │    nonce_A、nonce_B
//!       │                                          │    派生会话密钥
//!       │ ◄──── Msg1 = AEAD(K_ba, B 的身份公钥) ─── │ ③ 把自己的设备身份
//!       │         + 确认标签                         │    公钥发给 A
//!       │ ④ 验确认标签 → 确定对方持有会话密钥         │
//!       │    Msg2 = AEAD(K_ab, M ‖ 确认标签)       │
//!       │ ──────────────────────────────────────► │ ⑤ 解出 M，校验确认标签
//!       │                                          │
//! ```
//!
//! **主密钥只出现在 `Msg2` 里，且只以密文形式。** 加入方在收到之前完全没有 M。
//!
//! ## 为什么带外（二维码）是必需的
//!
//! 纯信道上的密钥协商无法抵抗中间人：攻击者分别与 A、B 各协商一份密钥，两人都
//! 察觉不到。要打破它只有两条路——带外认证，或者 PAKE。
//!
//! **本项目选带外认证，明确不用 PAKE**（TODO.md 的 D4）：RustCrypto/PAKEs 官方
//! 自述未经任何密码学或安全审查，`spake2` 稳定版三年未更新，`opaque-ke` 4.x
//! 未审计，CPace 在 Rust 生态**没有可用实现**。而本应用**没有账号密码**，
//! 本来也无从 PAKE——没有可用的低熵共享秘密。
//!
//! 二维码是天然的带外信道：A 的屏幕显示它、B 的摄像头读它。B 的用户**看着自己
//! 扫的那张码**，因此攻击者无法在不被察觉的情况下替换它。于是 `A_pub` 与
//! `nonce_A` 是经过带外认证的输入。
//!
//! ## 攻击者改动二维码会怎样
//!
//! 攻击者把 `A_pub` 换成自己的 `M_pub`。B 于是与 M 协商出 `S'`，用 `S'` 加密
//! `Msg1` 并发出。**M 能解开 `Msg1`，但里面只有 B 的设备身份公钥**——M 拿不到
//! 主密钥。而当 M 冒充 A 回一条「`Msg2`」给 B 时，那条消息必须用 `S'` 派生出的
//! `K_ab'` 加密，M 确实做得到……但 M 手里**没有主密钥**，装不进 `Msg2`。
//!
//! 因此这条攻击的收益为零：B 要么收到一条解不出主密钥的消息（M 伪造），要么
//! 配对超时。**攻击者改二维码无法得到主密钥**，这正是带外认证要保证的。
//!
//! 唯一真实的代价：攻击者可以**让配对失败**（拒绝服务）。这无法在协议层防住
//! ——任何改动信道的能力都能做到——但用户会看到「配对失败」并重试。
//!
//! # 协议不变量
//!
//! 1. **主密钥只从 A 流向 B，且只在 `Msg2` 里、只以密文形式。**
//! 2. **两个方向用两份不同的密钥。** 由同一 ECDH 秘密派生，用不同的 HKDF info
//!    串分离。
//! 3. **每个会话只用一次。** [`PendingSession::accept`] 收 `self`，类型系统保证
//!    它不可能被用第二次；临时私钥在 `Drop` 时擦除。
//! 4. **双向确认。** `Msg1` 里的标签证明 B 持有会话密钥；`Msg2` 里的标签证明 A
//!    持有会话密钥且**确实解开了 `Msg1`**（因此确认标签覆盖了 B 的身份公钥）。
//! 5. **一切都被认证。** 消息种类与整个 transcript 都进 AAD。
//!
//! # 本模块不做什么
//!
//! - **不传输。** 二维码怎么显示、消息怎么送达（M4 之前是二维码多帧，之后是
//!   iroh）由调用方决定。本模块只产生与消费字节。
//! - **不落盘。** 主密钥存哪里（平台硬件密钥库）由调用方决定。
//! - **不读时钟。** 核心库不读时钟。配对载荷的有效期靠「A 关闭配对界面就丢弃
//!   [`PendingSession`]」实现，而不是靠时间戳——时间戳既需要时钟，又挡不住
//!   「重放一个还没过期的载荷」。

use crate::vault::{MASTER_KEY_LEN, MasterKey, NONCE_LEN as AEAD_NONCE_LEN, master_key_to_bytes};
use crate::{Error, ExposeSecret, Result, SecretBytes};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::Generate;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use sha2::{Digest, Sha256};
// `zeroize` 不是本 crate 的直接依赖（`secrecy` 才是），因此从 `secrecy` 取用它
// 再导出的那一份——这保证擦除用的是**实际生效的那个版本**，而不是另指定的一份。
use secrecy::zeroize::Zeroize;

/// 配对协议版本，编码进二维码与两条消息。
///
/// 版本**必须**参与密钥派生（见 `transcript_hash`）：否则攻击者可以拿一个旧
/// 版本的 `Msg1` 去回应新版本的会话，而双方算出的 transcript 却是同一个。
pub const PROTOCOL_VERSION: u8 = 1;

/// P-256 SEC1 未压缩公钥的字节长度。
pub const PUBLIC_KEY_LEN: usize = 65;

/// 配对随机 nonce 的字节长度。
///
/// 256-bit。它保证**同一个二维码不会被用第二次**：A 每次打开配对界面都生成新的
/// 临时密钥与 nonce，因此上一轮抓到的 `Msg1` 在这一轮解不开。
pub const NONCE_LEN: usize = 32;

/// 确认标签的字节长度。
///
/// 256-bit。标签只是一次「我也有会话密钥」的证明，不承担长期认证，因此截断到
/// 128-bit 也够；这里保留完整的 HMAC-SHA256 输出，因为它本来就是这个长度，
/// 截断只会多一处需要解释的规则。
pub const CONFIRMATION_LEN: usize = 32;

/// 会话标识的字节长度。
pub const SESSION_ID_LEN: usize = 32;

/// AEAD 认证标签的字节长度（与保险库一致）。
pub const TAG_LEN: usize = 16;

/// 二维码载荷的字节长度：版本 + 临时公钥 + nonce + 能力标志。
pub const QR_PAYLOAD_LEN: usize = 1 + PUBLIC_KEY_LEN + NONCE_LEN + 1;

/// `Msg1` 明文头部的字节长度：B 的 nonce + B 的临时公钥。
///
/// **明文的，因为不可能是密文的。** 发起方需要 B 的临时公钥才能算出 ECDH 共享
/// 秘密，需要 B 的 nonce 才能算出 transcript；而这两者又都是解密其余部分的**前提**。
/// 把它们放进密文会形成一个解不开的循环。
///
/// 明文传输不构成弱点：它们本就相当于「加入方的临时公钥」这一个公开值。改它们
/// 只会让双方算出不同的 transcript，于是后续解密**必然失败**。
pub const MSG1_HEADER_LEN: usize = NONCE_LEN + PUBLIC_KEY_LEN;

/// `Msg1` 被加密部分的明文长度：B 的**设备身份**公钥 + 确认标签。
///
/// 设备身份放在密文里，而不是明文头里：它标识「是哪台设备加了进来」，属于配对
/// 双方之间的信息，不该出现在任何能读到配对流量的人手里。只有持有会话密钥的
/// 一方（即发起方）看得到。
pub const MSG1_BODY_PLAINTEXT_LEN: usize = PUBLIC_KEY_LEN + CONFIRMATION_LEN;

/// `Msg1` 的完整字节长度：明文头 + 密文体（含 AEAD 标签）。
pub const MSG1_LEN: usize = MSG1_HEADER_LEN + MSG1_BODY_PLAINTEXT_LEN + TAG_LEN;

/// `Msg2` 明文的字节长度：主密钥 + 确认标签。
pub const MSG2_PLAINTEXT_LEN: usize = MASTER_KEY_LEN + CONFIRMATION_LEN;

/// `Msg2` 密文的字节长度（含 AEAD 标签）。
pub const MSG2_LEN: usize = MSG2_PLAINTEXT_LEN + TAG_LEN;

/// 二维码里唯一的能力标志：本协议携带加入方的设备身份公钥。
///
/// 恒为 1。写进线格式而不是省略，是为了将来增加能力时，旧版本能用**明确的**
/// 错误拒绝，而不是把未知字节当已知含义解释。
const CAPABILITY_DEVICE_IDENTITY: u8 = 0x01;

/// HKDF 域分离串：加入方 → 发起方方向。
const HKDF_INFO_JOINER_TO_INITIATOR: &[u8] = b"Qualia2FA pairing v1 joiner-to-initiator";

/// HKDF 域分离串：发起方 → 加入方方向。
const HKDF_INFO_INITIATOR_TO_JOINER: &[u8] = b"Qualia2FA pairing v1 initiator-to-joiner";

/// 确认标签的域分离串。
const CONFIRMATION_LABEL: &[u8] = b"Qualia2FA pairing v1 confirmation";

/// AEAD nonce 的派生域分离串。
const NONCE_LABEL: &[u8] = b"Qualia2FA pairing v1 aead nonce";

/// 发起方通过二维码公布的临时公钥与 nonce。
///
/// # 生命周期
///
/// 由 [`begin`] 产生，扫进加入方后用于派生会话密钥。它**不是**秘密（会显示在
/// 屏幕上），但**短命**：一旦 [`PendingSession::accept`] 被调用，或用户关闭配对
/// 界面丢弃 [`PendingSession`]，对应的私钥就不存在了。
#[derive(Clone, PartialEq, Eq)]
pub struct QrPayload {
    /// 发起方的临时 ECDH 公钥（SEC1 未压缩点）。
    public_key: [u8; PUBLIC_KEY_LEN],
    /// 发起方的随机 nonce。
    nonce: [u8; NONCE_LEN],
    /// 能力标志位。
    capabilities: u8,
}

impl QrPayload {
    /// 发起方临时公钥的 SEC1 编码。
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// 随机 nonce。不是秘密，但**唯一**：同一个 nonce 不会被用第二次。
    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// 能力标志位。
    #[must_use]
    pub const fn capabilities(&self) -> u8 {
        self.capabilities
    }

    /// 编码成可直接放进二维码的字节串。
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(QR_PAYLOAD_LEN);
        out.push(PROTOCOL_VERSION);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.nonce);
        out.push(self.capabilities);
        out
    }

    /// 从扫到的字节还原。
    ///
    /// # 错误
    ///
    /// - 长度不对、或缺少必需能力位：[`Error::PairingPayloadMalformed`]
    /// - 版本不认识：[`Error::PairingUnsupportedVersion`]
    /// - 公钥不是合法的曲线点：[`Error::DevicePublicKeyInvalid`]
    ///
    /// **公钥的曲线成员检查是安全边界，不是格式检查**：把不属于曲线、而属于某个
    /// 小子群的点交给 ECDH，会有真实的密钥恢复风险。
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != QR_PAYLOAD_LEN {
            return Err(Error::PairingPayloadMalformed {
                reason: "长度不是 1 + 65 + 32 + 1 字节",
            });
        }
        if bytes[0] != PROTOCOL_VERSION {
            return Err(Error::PairingUnsupportedVersion { version: bytes[0] });
        }
        let mut public_key = [0_u8; PUBLIC_KEY_LEN];
        public_key.copy_from_slice(&bytes[1..1 + PUBLIC_KEY_LEN]);
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[1 + PUBLIC_KEY_LEN..1 + PUBLIC_KEY_LEN + NONCE_LEN]);
        let capabilities = bytes[QR_PAYLOAD_LEN - 1];

        PublicKey::from_sec1_bytes(&public_key).map_err(|_| Error::DevicePublicKeyInvalid {
            reason: "二维码里的临时公钥不是合法的 P-256 SEC1 点",
        })?;

        if capabilities & CAPABILITY_DEVICE_IDENTITY == 0 {
            return Err(Error::PairingPayloadMalformed {
                reason: "二维码缺少必需的能力位",
            });
        }

        Ok(Self {
            public_key,
            nonce,
            capabilities,
        })
    }

    /// 编码成 Base32 字符串，便于放进二维码的文本字段。
    ///
    /// 用 Base32 而不是十六进制：二维码的容量是最紧的约束（见 M4 的载荷分片），
    /// Base32 每字节只要 1.6 个字符，十六进制要 2 个。
    #[must_use]
    pub fn to_base32(&self) -> String {
        crate::base32::encode(&self.encode())
    }

    /// 从 Base32 字符串还原。
    ///
    /// # 错误
    ///
    /// Base32 解码失败时返回 Base32 系列错误，其余同 [`QrPayload::decode`]。
    pub fn from_base32(text: &str) -> Result<Self> {
        let bytes = crate::base32::decode(text)?;
        Self::decode(bytes.expose_secret())
    }
}

impl core::fmt::Debug for QrPayload {
    /// 打印公钥与能力位，**不打印 nonce**。
    ///
    /// nonce 不是秘密，但它足以让日志把「哪两次配对是同一轮」关联起来。配对是
    /// 敏感操作，日志里不留可关联标识更稳妥。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QrPayload")
            .field("version", &PROTOCOL_VERSION)
            .field("public_key", &"<65 bytes>")
            .field("nonce", &"<redacted>")
            .field("capabilities", &format_args!("0x{:02X}", self.capabilities))
            .finish()
    }
}

/// 发起方 A 的待处理会话：持有临时私钥，等待加入方的 `Msg1`。
///
/// # 一次性，由类型系统保证
///
/// [`PendingSession::accept`] 收 `self` 而不是 `&self`，因此**同一个会话不可能
/// 被接受两次**。这条约束不依赖调用方自觉：
///
/// - 攻击者重放同一个 `Msg1`，第二次会因为没有会话可传而编译不过。
/// - 用户重新打开配对界面会得到**新的** [`PendingSession`]，其 nonce 与临时公钥
///   都不同，因此上一轮抓到的 `Msg1` 解不开。
///
/// 临时私钥在 `Drop` 时由 `p256` 擦除（`EphemeralSecret` 实现 `ZeroizeOnDrop`）。
pub struct PendingSession {
    /// 本方的临时私钥。
    secret: EphemeralSecret,
    /// 与二维码内容一致的载荷。
    payload: QrPayload,
}

impl PendingSession {
    /// 二维码里应当显示的内容。
    #[must_use]
    pub const fn payload(&self) -> &QrPayload {
        &self.payload
    }

    /// 接受加入方的 `Msg1`，确认对方身份，并生成携带主密钥的 `Msg2`。
    ///
    /// # 参数
    ///
    /// - `msg1`: 加入方发来的完整 `Msg1` 密文（[`JoinerSession::request`] 的返回）。
    /// - `master`: 本是**发起方自己**的主密钥。它会以密文形式装进回执。
    ///
    /// # 返回
    ///
    /// [`Adoption`]：加入方的设备身份公钥、会话标识、以及要发回加入方的 `Msg2`。
    ///
    /// # 错误
    ///
    /// 认证失败一律返回 [`Error::PairingAuthenticationFailed`]，**不区分**
    /// 「密文被篡改」「消息来自另一个会话」「加入方用错了公钥」。区分它们对攻击者
    /// 有用，对使用者没有可操作价值——三种情况的应对都是「这次配对失败，请重新
    /// 扫码」。
    pub fn accept(self, msg1: &[u8], master: &MasterKey) -> Result<Adoption> {
        if msg1.len() != MSG1_LEN {
            return Err(Error::PairingAuthenticationFailed);
        }
        // `Msg1 = B_nonce ‖ B_eph_pub ‖ AEAD(B_identity_pub ‖ tag)`。
        //
        // 前两段是明文，因为发起方需要它们才能派生会话密钥（`B_eph_pub` 是 ECDH
        // 的另一半，`B_nonce` 参与 transcript），而派生密钥又是解密第三段的前提。
        // 把它们放进密文会形成死锁。
        //
        // **未认证就被读取不构成弱点**：改它们会让双方算出不同的 transcript，
        // 于是解密**必然失败**。攻击者顶多让这次配对失败（拒绝服务），而那本来
        // 就在任何能改动信道的攻击者能力范围内。真正需要保密的加入方**设备身份**
        // 在密文里，只有持有会话密钥的一方读得到。
        let mut joiner_nonce = [0_u8; NONCE_LEN];
        joiner_nonce.copy_from_slice(&msg1[..NONCE_LEN]);
        let mut joiner_ephemeral = [0_u8; PUBLIC_KEY_LEN];
        joiner_ephemeral.copy_from_slice(&msg1[NONCE_LEN..MSG1_HEADER_LEN]);
        let joiner_ephemeral = PublicKey::from_sec1_bytes(&joiner_ephemeral).map_err(|_| {
            Error::DevicePublicKeyInvalid {
                reason: "加入方的临时公钥不是合法的 P-256 SEC1 点",
            }
        })?;

        let transcript = transcript_hash(
            &self.payload.public_key,
            &self.payload.nonce,
            &msg1[NONCE_LEN..MSG1_HEADER_LEN],
            &joiner_nonce,
        );
        let shared = self.secret.diffie_hellman(&joiner_ephemeral);
        let keys = SessionKeys::derive(shared.raw_secret_bytes(), &transcript);

        // **整段密文体（含末尾的 AEAD 标签）一起交给 `decrypt_in_place`。**
        // 这个 API 自己会把末尾 `TAG_LEN` 字节当作标签剥出来，因此先切掉标签再
        // 调用，会让它把密文的最后 16 字节误当标签——症状是**认证永远失败**，
        // 而密钥、nonce、AAD 全都没错，极难定位。
        let mut plaintext = msg1[MSG1_HEADER_LEN..].to_vec();
        let aad = aad_for(&transcript, MessageKind::Request);
        let cipher = XChaCha20Poly1305::new(&Key::from(keys.joiner_to_initiator));
        cipher
            .decrypt_in_place(&XNonce::from(keys.nonce), &aad, &mut plaintext)
            .map_err(|_| Error::PairingAuthenticationFailed)?;
        debug_assert_eq!(plaintext.len(), MSG1_BODY_PLAINTEXT_LEN);

        let mut joiner_identity = [0_u8; PUBLIC_KEY_LEN];
        joiner_identity.copy_from_slice(&plaintext[..PUBLIC_KEY_LEN]);
        let expected = confirmation_tag(
            &keys.joiner_to_initiator,
            &transcript,
            MessageKind::Request,
            &joiner_identity,
        );
        if !constant_time_eq(&plaintext[PUBLIC_KEY_LEN..], &expected) {
            return Err(Error::PairingAuthenticationFailed);
        }
        // 身份公钥必须真的在曲线上：它会作为「本设备信任了哪台设备」被记录下来，
        // 一个曲外的点会让后续的签名验证总是失败，而症状离原因很远。
        PublicKey::from_sec1_bytes(&joiner_identity).map_err(|_| {
            Error::DevicePublicKeyInvalid {
                reason: "加入方的设备身份公钥不是合法的 P-256 SEC1 点",
            }
        })?;

        // 回执：主密钥 ‖ 确认标签。确认标签覆盖加入方的身份公钥——因此它同时
        // 证明「我解开了你的 Msg1」与「我看到的是这个身份」，而不是一条可以被
        // 移植到别的会话或别的身份上的通用「OK」。
        let mut reply = Vec::with_capacity(MSG2_PLAINTEXT_LEN);
        reply.extend_from_slice(master.expose());
        reply.extend_from_slice(&confirmation_tag(
            &keys.initiator_to_joiner,
            &transcript,
            MessageKind::Accept,
            &joiner_identity,
        ));
        let aad = aad_for(&transcript, MessageKind::Accept);
        let reply_cipher = XChaCha20Poly1305::new(&Key::from(keys.initiator_to_joiner));
        reply_cipher
            .encrypt_in_place(&XNonce::from(keys.nonce), &aad, &mut reply)
            .map_err(|_| Error::PairingAuthenticationFailed)?;

        Ok(Adoption {
            session_id: transcript,
            joiner_identity,
            reply,
        })
    }
}

impl core::fmt::Debug for PendingSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingSession")
            .field("payload", &self.payload)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// [`PendingSession::accept`] 的结果。
pub struct Adoption {
    /// 会话标识（双方一致，可用于日志关联）。
    session_id: [u8; SESSION_ID_LEN],
    /// 加入方的设备身份公钥（SEC1）。发起方据此知道加进来的是哪台设备。
    joiner_identity: [u8; PUBLIC_KEY_LEN],
    /// 要发回加入方的 `Msg2` 密文。
    reply: Vec<u8>,
}

impl Adoption {
    /// 会话标识。双方算出同一个值，可用于把两端的日志对起来。
    #[must_use]
    pub const fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// 加入方的设备身份公钥。
    ///
    /// 调用方应当用它构造 [`crate::DevicePublicKey`] 并**记录下来**——这是
    /// 「本设备信任了哪台设备」的唯一依据。注意它由配对信道保证真实性（只有
    /// 持有会话密钥的一方才能把它送到这里），但**配对之后**它只是一个记录的
    /// 身份，后续认证一律走签名验证。
    #[must_use]
    pub const fn joiner_identity(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.joiner_identity
    }

    /// 要发回加入方的 `Msg2` 密文。
    #[must_use]
    pub fn reply(&self) -> &[u8] {
        &self.reply
    }
}

impl core::fmt::Debug for Adoption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Adoption")
            .field("session_id", &&self.session_id[..8])
            .field("joiner_identity", &"<65 bytes>")
            .field("reply_len", &self.reply.len())
            .finish()
    }
}

/// 加入方 B 的会话：已扫到二维码，等待收下主密钥。
///
/// # 为什么 [`JoinerSession::request`] 借 `&self` 而 [`JoinerSession::open`] 收 `self`
///
/// `request` 必须能被重复调用吗？不需要——但**不能**收 `self`，因为调用方在发出
/// `Msg1` 之后还要拿同一个会话去 `open`。`open` 收 `self`：收到主密钥之后这次
/// 会话就结束了，临时私钥随即擦除。
///
/// 因此正确的调用顺序是 `join` → `request` → `open`，编译期就能保证不会漏掉
/// 其中任何一步。
pub struct JoinerSession {
    /// 本方的临时私钥。
    secret: EphemeralSecret,
    /// 本方生成的临时公钥（SEC1）。
    public_key: [u8; PUBLIC_KEY_LEN],
    /// 本方生成的 nonce。随 `Msg1` 明文发出，参与 transcript。
    nonce: [u8; NONCE_LEN],
    /// 从二维码解析出的载荷。
    payload: QrPayload,
}

impl JoinerSession {
    /// 本方临时公钥的 SEC1 编码。
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// 生成 `Msg1`：把自己的设备身份公钥交给发起方。
    ///
    /// # 参数
    ///
    /// - `device_identity`: 本方设备身份公钥的 SEC1 编码（由
    ///   `qualia2fa-keystore` 提供）。
    ///
    /// # 返回
    ///
    /// `Msg1` 的完整密文，以及本次会话标识。
    ///
    /// # 这条消息里没有主密钥
    ///
    /// 加入方此刻**还没有**主密钥（它正是为此而来）。`Msg1` 只携带加入方的身份
    /// 公钥与一个确认标签。主密钥在反方向的 [`JoinerSession::open`] 里收下。
    pub fn request(&self, device_identity: &[u8]) -> Result<(Vec<u8>, [u8; SESSION_ID_LEN])> {
        if device_identity.len() != PUBLIC_KEY_LEN {
            return Err(Error::DevicePublicKeyInvalid {
                reason: "设备身份公钥长度不是 65 字节",
            });
        }
        // 这里**主动多查一次**曲线成员资格，而不是把这件事留给发起方的 `accept`。
        //
        // 理由不是安全（发起方反正会拒），而是**可用性**：身份公钥来自本机的平台
        // 密钥库，若它不是合法的曲线点，那么这次配对**注定**失败——无论用户重试
        // 多少次、扫多少遍二维码。在发消息之前就报出来，错误才指向真正的故障点，
        // 而不是表现为「对方一直说配对失败」。
        PublicKey::from_sec1_bytes(device_identity).map_err(|_| Error::DevicePublicKeyInvalid {
            reason: "设备身份公钥不是合法的 P-256 SEC1 点",
        })?;
        let (transcript, keys) = self.derive()?;

        // 结构是 `header(明文) ‖ AEAD(身份公钥 ‖ 确认标签)`。分开拼装而不是先拼
        // 一整段再加密，是因为**头部不能进密文**——见 [`MSG1_HEADER_LEN`]。
        let mut body = Vec::with_capacity(MSG1_BODY_PLAINTEXT_LEN);
        body.extend_from_slice(device_identity);
        body.extend_from_slice(&confirmation_tag(
            &keys.joiner_to_initiator,
            &transcript,
            MessageKind::Request,
            device_identity,
        ));

        let aad = aad_for(&transcript, MessageKind::Request);
        let cipher = XChaCha20Poly1305::new(&Key::from(keys.joiner_to_initiator));
        cipher
            .encrypt_in_place(&XNonce::from(keys.nonce), &aad, &mut body)
            .map_err(|_| Error::PairingAuthenticationFailed)?;

        let mut msg = Vec::with_capacity(MSG1_LEN);
        msg.extend_from_slice(&self.nonce);
        msg.extend_from_slice(&self.public_key);
        msg.extend_from_slice(&body);

        Ok((msg, transcript))
    }

    /// 用发起方的 `Msg2` 收下主密钥。
    ///
    /// # 错误
    ///
    /// 认证失败一律返回 [`Error::PairingAuthenticationFailed`]。**长度不对、
    /// 标签不对、密文被篡改、来自另一个会话**都归到这一个变体。
    pub fn open(self, msg2: &[u8], device_identity: &[u8]) -> Result<MasterKey> {
        if msg2.len() != MSG2_LEN {
            return Err(Error::PairingAuthenticationFailed);
        }
        if device_identity.len() != PUBLIC_KEY_LEN {
            return Err(Error::DevicePublicKeyInvalid {
                reason: "设备身份公钥长度不是 65 字节",
            });
        }
        let (transcript, keys) = self.derive()?;

        // 同样：整段（含末尾标签）交给 `decrypt_in_place`，由它剥标签。
        let mut plaintext = msg2.to_vec();
        let aad = aad_for(&transcript, MessageKind::Accept);
        let cipher = XChaCha20Poly1305::new(&Key::from(keys.initiator_to_joiner));
        cipher
            .decrypt_in_place(&XNonce::from(keys.nonce), &aad, &mut plaintext)
            .map_err(|_| Error::PairingAuthenticationFailed)?;
        debug_assert_eq!(plaintext.len(), MSG2_PLAINTEXT_LEN);

        let expected = confirmation_tag(
            &keys.initiator_to_joiner,
            &transcript,
            MessageKind::Accept,
            device_identity,
        );
        if !constant_time_eq(&plaintext[MASTER_KEY_LEN..], &expected) {
            return Err(Error::PairingAuthenticationFailed);
        }

        // 只在这里把主密钥交给调用方。构造 `MasterKey` 时会校验长度，
        // 因此一个长度不对的载荷不可能变成「看起来能用」的主密钥。
        let mut raw = plaintext[..MASTER_KEY_LEN].to_vec();
        let secret: SecretBytes = core::mem::take(&mut raw).into();
        raw.zeroize();
        MasterKey::from_bytes(secret)
    }

    /// 本方派生会话材料（与发起方必须算出完全一致的结果）。
    fn derive(&self) -> Result<([u8; SESSION_ID_LEN], SessionKeys)> {
        let initiator_public =
            PublicKey::from_sec1_bytes(&self.payload.public_key).map_err(|_| {
                Error::DevicePublicKeyInvalid {
                    reason: "二维码里的临时公钥不是合法的 P-256 SEC1 点",
                }
            })?;
        let transcript = transcript_hash(
            &self.payload.public_key,
            &self.payload.nonce,
            &self.public_key,
            &self.nonce,
        );
        let shared = self.secret.diffie_hellman(&initiator_public);
        Ok((
            transcript,
            SessionKeys::derive(shared.raw_secret_bytes(), &transcript),
        ))
    }
}

impl core::fmt::Debug for JoinerSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JoinerSession")
            .field("payload", &self.payload)
            .field("public_key", &"<65 bytes>")
            .field("nonce", &"<redacted>")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// 消息种类，参与 AAD 与确认标签的构造。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageKind {
    /// 加入方 → 发起方。
    Request,
    /// 发起方 → 加入方。
    Accept,
}

impl MessageKind {
    /// 参与运算的字节值。
    const fn as_byte(self) -> u8 {
        match self {
            Self::Request => 0x01,
            Self::Accept => 0x02,
        }
    }
}

/// 一次配对派生出的会话密钥。
///
/// # 为什么两个方向用两份**不同的**密钥
///
/// 两个方向都由同一个 ECDH 秘密派生，但用不同的 HKDF info 串。这样即使两个方向
/// 用了同一个 AEAD nonce（本实现刻意让它们相同，省掉一个计数器），也不构成 nonce
/// 重用——密钥不同，两份密文之间没有可推导的关系。
///
/// 用两份密钥而不是「一份密钥 + 两个计数器」：计数器需要状态，而状态在多设备、
/// 无中心的场景里是最容易出错的东西。
struct SessionKeys {
    /// 加入方 → 发起方方向。
    joiner_to_initiator: [u8; 32],
    /// 发起方 → 加入方方向。
    initiator_to_joiner: [u8; 32],
    /// AEAD nonce（两个方向共用，密钥不同所以安全）。
    nonce: [u8; AEAD_NONCE_LEN],
}

impl SessionKeys {
    /// 从 ECDH 共享秘密与会话 transcript 派生。
    fn derive(shared: &[u8], transcript: &[u8; SESSION_ID_LEN]) -> Self {
        // transcript 作为 HKDF 的 salt：它包含双方公钥与 nonce，因此派生出的密钥
        // 与**这一次**配对绑定。换掉其中任何一个字节，双方派生出不同密钥，
        // 后续认证必然失败。
        let hkdf = Hkdf::<Sha256>::new(Some(transcript), shared);
        let mut joiner_to_initiator = [0_u8; 32];
        let mut initiator_to_joiner = [0_u8; 32];
        // `expand` 只在输出长度超过 255 * HashLen 时失败，32 字节不可能触发。
        // 仍然不 `unwrap`：库内「任何输入都不得 panic」的约定不允许例外。
        let failed = hkdf
            .expand(HKDF_INFO_JOINER_TO_INITIATOR, &mut joiner_to_initiator)
            .is_err()
            || hkdf
                .expand(HKDF_INFO_INITIATOR_TO_JOINER, &mut initiator_to_joiner)
                .is_err();
        if failed {
            // 走到这里说明输出长度参数被改坏了。用全零密钥会让后续认证必然失败，
            // 而不是悄悄用一个可预测的密钥。
            joiner_to_initiator.zeroize();
            initiator_to_joiner.zeroize();
        }

        // AEAD nonce 由 transcript 派生：同一个 transcript 必然得到同一个 nonce，
        // 这正是双方需要的一致性；不同会话得到不同 nonce，因此不会跨会话重用。
        let mut hasher = Sha256::new();
        hasher.update(NONCE_LABEL);
        hasher.update(transcript);
        let digest = hasher.finalize();
        let mut nonce = [0_u8; AEAD_NONCE_LEN];
        nonce.copy_from_slice(&digest[..AEAD_NONCE_LEN]);

        Self {
            joiner_to_initiator,
            initiator_to_joiner,
            nonce,
        }
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.joiner_to_initiator.zeroize();
        self.initiator_to_joiner.zeroize();
        self.nonce.zeroize();
    }
}

/// 计算会话 transcript 的 SHA-256。
///
/// 输入：版本 + 发起方临时公钥 + 发起方 nonce + 加入方临时公钥 + 加入方 nonce。
///
/// # 为什么双方必须算出一模一样的字节
///
/// 这个值同时充当 HKDF 的 salt、AAD 的一部分与会话标识。任何不一致都会表现为
/// 「认证失败」——一个几乎无法定位的方向。因此拼装顺序写死在**这一个**函数里，
/// 两个方向都调用它，不允许任何一方自己拼。
fn transcript_hash(
    initiator_public_key: &[u8; PUBLIC_KEY_LEN],
    initiator_nonce: &[u8; NONCE_LEN],
    joiner_public_key: &[u8],
    joiner_nonce: &[u8; NONCE_LEN],
) -> [u8; SESSION_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update([PROTOCOL_VERSION]);
    hasher.update(initiator_public_key);
    hasher.update(initiator_nonce);
    hasher.update(joiner_public_key);
    hasher.update(joiner_nonce);
    let digest = hasher.finalize();
    let mut out = [0_u8; SESSION_ID_LEN];
    out.copy_from_slice(&digest);
    out
}

/// 构造 AAD：会话标识 + 消息种类。
///
/// 消息种类必须进 AAD：否则攻击者可以把 `Msg2` 的密文当作 `Msg1` 回放给发起方
/// （或反过来）。两者用的是**不同方向的密钥**，所以这在当前设计下已经不可能；
/// 但把种类写进 AAD 使这条性质不依赖于「两个方向密钥不同」这个容易在重构中被
/// 破坏的实现细节。
fn aad_for(transcript: &[u8; SESSION_ID_LEN], kind: MessageKind) -> [u8; SESSION_ID_LEN + 1] {
    let mut aad = [0_u8; SESSION_ID_LEN + 1];
    aad[..SESSION_ID_LEN].copy_from_slice(transcript);
    aad[SESSION_ID_LEN] = kind.as_byte();
    aad
}

/// 计算确认标签：`HMAC-SHA256(key, label ‖ kind ‖ transcript ‖ peer_identity)`。
///
/// # 为什么要带上对端身份
///
/// 标签的语义是「我看到了**这个**对端，并且我们有共同的会话密钥」。若不含身份，
/// 标签就成了一条与身份无关的通用「OK」，可以被移植到另一个身份上。带上它之后，
/// 两条消息各自绑定到具体的一方。
///
/// 用 HMAC 而不是直接比较会话密钥：比较密钥会泄露两段密钥之间的相等关系，而
/// HMAC 的输出不泄露关于密钥的任何信息。
fn confirmation_tag(
    key: &[u8; 32],
    transcript: &[u8; SESSION_ID_LEN],
    kind: MessageKind,
    peer_identity: &[u8],
) -> [u8; CONFIRMATION_LEN] {
    // `Hmac::new_from_slice` 对 HMAC-SHA256 接受任意长度密钥，不会失败。
    // 仍然不 `unwrap`。
    let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(key) else {
        return [0_u8; CONFIRMATION_LEN];
    };
    mac.update(CONFIRMATION_LABEL);
    mac.update(&[kind.as_byte()]);
    mac.update(transcript);
    mac.update(peer_identity);
    let digest = mac.finalize().into_bytes();
    let mut out = [0_u8; CONFIRMATION_LEN];
    out.copy_from_slice(&digest);
    out
}

/// 常量时间比较两个字节串。
///
/// 长度不同时立即返回 `false`：长度不是秘密（它由协议固定），泄露它没有意义。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// 发起方开始一次配对，得到要显示成二维码的载荷。
///
/// # 错误
///
/// 只在 OS 随机源不可用时失败（[`Error::RandomnessUnavailable`]）。
///
/// # 为什么同时返回载荷与会话
///
/// 载荷是**给别人看**的（二维码），会话是**自己拿着**的（临时私钥）。两者必须
/// 成对产生：先看二维码再生成私钥（或反过来）都会让「二维码里的公钥」与「手上的
/// 私钥」不匹配，而那会表现为所有配对都失败。
#[must_use = "配对会话必须被保留，否则二维码里的公钥就没有对应的私钥了"]
pub fn begin() -> Result<(QrPayload, PendingSession)> {
    let secret = EphemeralSecret::generate();
    let public_key = secret.public_key().to_sec1_point(false);
    let mut public_key_bytes = [0_u8; PUBLIC_KEY_LEN];
    public_key_bytes.copy_from_slice(public_key.as_bytes());

    let mut nonce = [0_u8; NONCE_LEN];
    crate::getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;

    let payload = QrPayload {
        public_key: public_key_bytes,
        nonce,
        capabilities: CAPABILITY_DEVICE_IDENTITY,
    };
    let session = PendingSession {
        secret,
        payload: payload.clone(),
    };
    Ok((payload, session))
}

/// 加入方从扫到的二维码开始一次配对。
///
/// # 错误
///
/// - 二维码里的公钥不在曲线上：[`Error::DevicePublicKeyInvalid`]
/// - OS 随机源不可用：[`Error::RandomnessUnavailable`]
pub fn join(payload: &QrPayload) -> Result<JoinerSession> {
    // 二维码里的公钥在 `decode` 时已经验证过，这里**再验证一次**：
    // `JoinerSession` 也可能由调用方手工构造载荷后创建，不能假设它来自
    // `QrPayload::decode`。
    PublicKey::from_sec1_bytes(&payload.public_key).map_err(|_| Error::DevicePublicKeyInvalid {
        reason: "二维码里的临时公钥不是合法的 P-256 SEC1 点",
    })?;

    let secret = EphemeralSecret::generate();
    let public_key = secret.public_key().to_sec1_point(false);
    let mut public_key_bytes = [0_u8; PUBLIC_KEY_LEN];
    public_key_bytes.copy_from_slice(public_key.as_bytes());

    let mut nonce = [0_u8; NONCE_LEN];
    crate::getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;

    Ok(JoinerSession {
        secret,
        public_key: public_key_bytes,
        nonce,
        payload: payload.clone(),
    })
}

/// 把主密钥包成可交给平台密钥库的字节。
///
/// 只是 [`master_key_to_bytes`] 的转发；提供它是为了让调用方不必同时 import
/// `vault` 与 `pairing` 两个模块。
#[must_use]
pub fn master_key_for_storage(master: &MasterKey) -> SecretBytes {
    master_key_to_bytes(master)
}

/// 从平台密钥库取回的字节重建主密钥。
///
/// # 错误
///
/// 长度不是 [`MASTER_KEY_LEN`] 时返回 [`Error::MasterKeyWrongLength`]。
pub fn master_key_from_storage(bytes: SecretBytes) -> Result<MasterKey> {
    MasterKey::from_bytes(bytes)
}

/// 已用过的配对 nonce 记录，用于拒绝重放。
///
/// # 它防的是什么
///
/// 配对协议本身已经做到「每个会话只用一次」（[`PendingSession::accept`] 收
/// `self`，且每次 [`begin`] 都生成新的临时密钥与 nonce）。这个记录防的是更上一
/// 层：调用方如果把 nonce 持久化了，就能在**重启之后**仍然认出「这个二维码/这次
/// 会话我已经处理过」，而不是因为内存里的状态丢了就重新接受一次。
///
/// # 容量有界
///
/// 配对的频率是「用户手动操作」，几百条足够。而**无界**的记录会变成一个可以被
/// 撑爆的消耗点：攻击者不断发起半途而废的配对就能让它无限增长。满了之后淘汰
/// 最旧的一条——被淘汰的 nonce 对应的会话早已结束，重放它也不可能成功。
#[derive(Debug, Clone, Default)]
pub struct NonceLog {
    /// 已用过的 nonce，按插入顺序。
    used: std::collections::VecDeque<[u8; NONCE_LEN]>,
}

impl NonceLog {
    /// 默认保留的 nonce 条数。
    pub const DEFAULT_CAPACITY: usize = 256;

    /// 新建一个空记录。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录条数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.used.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.used.is_empty()
    }

    /// 该 nonce 是否已经用过。
    #[must_use]
    pub fn is_used(&self, nonce: &[u8; NONCE_LEN]) -> bool {
        self.used.contains(nonce)
    }

    /// 记录一个 nonce。
    ///
    /// 返回 `false` 表示这个 nonce **之前已经记录过**（即这是一次重放），调用方
    /// 应当拒绝本次操作。返回 `true` 表示记录成功。
    pub fn record(&mut self, nonce: [u8; NONCE_LEN]) -> bool {
        if self.is_used(&nonce) {
            return false;
        }
        if self.used.len() >= Self::DEFAULT_CAPACITY {
            self.used.pop_front();
        }
        self.used.push_back(nonce);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;

    /// 造一个**真实合法**的设备身份公钥（曲线上的点、65 字节 SEC1）。
    ///
    /// 不能随便填字节：`from_sec1_bytes` 会做完整的曲线成员检查，而那是安全边界。
    /// 用 P-256 生成元作为身份，够本测试用——配对协议只把它当**不透明**的字节搬运。
    fn fake_identity() -> [u8; PUBLIC_KEY_LEN] {
        public_key_of(&SecretKey::from_bytes(&[1_u8; 32].into()).expect("标量 1 合法"))
    }

    /// 另一个合法但不同的身份。
    fn other_identity() -> [u8; PUBLIC_KEY_LEN] {
        public_key_of(&SecretKey::from_bytes(&[2_u8; 32].into()).expect("标量 2 合法"))
    }

    /// 取一个私钥对应的 SEC1 未压缩公钥。
    fn public_key_of(secret: &SecretKey) -> [u8; PUBLIC_KEY_LEN] {
        let point = secret.public_key().to_sec1_point(false);
        let mut out = [0_u8; PUBLIC_KEY_LEN];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// 跑一次完整配对，返回两端各自看到的东西。
    fn run_pairing() -> (
        MasterKey,
        MasterKey,
        [u8; SESSION_ID_LEN],
        [u8; SESSION_ID_LEN],
    ) {
        let initiator_master = MasterKey::generate().expect("随机源可用");
        let identity = fake_identity();

        let (payload, pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let (msg1, joiner_sid) = joiner.request(&identity).expect("可生成 Msg1");

        let adoption = pending
            .accept(&msg1, &initiator_master)
            .expect("Msg1 应通过认证");
        assert_eq!(
            adoption.joiner_identity(),
            &identity,
            "发起方应看到加入方的设备身份"
        );

        let joiner_master = joiner
            .open(adoption.reply(), &identity)
            .expect("Msg2 应通过认证");
        (
            initiator_master,
            joiner_master,
            *adoption.session_id(),
            joiner_sid,
        )
    }

    /// 端到端的正确路径：双方拿到**同一个**主密钥。
    #[test]
    fn happy_path_transfers_the_master_key() {
        let (a, b, sid_a, sid_b) = run_pairing();
        assert_eq!(a.expose(), b.expose(), "双方主密钥必须一致");
        assert_eq!(sid_a, sid_b, "双方会话标识必须一致");
    }

    /// 二维码必须能 Base32 往返。
    #[test]
    fn qr_payload_roundtrips_through_base32() {
        let (payload, _pending) = begin().expect("随机源可用");
        let text = payload.to_base32();
        let decoded = QrPayload::from_base32(&text).expect("应能解码");
        assert_eq!(decoded, payload);
    }

    /// 二维码字节布局是对外契约，锁住它。
    #[test]
    fn qr_payload_layout_is_stable() {
        let (payload, _pending) = begin().expect("随机源可用");
        let bytes = payload.encode();
        assert_eq!(bytes.len(), QR_PAYLOAD_LEN);
        assert_eq!(bytes[0], PROTOCOL_VERSION);
        assert_eq!(&bytes[1..66], payload.public_key());
        assert_eq!(&bytes[66..98], payload.nonce());
        assert_eq!(bytes[98], CAPABILITY_DEVICE_IDENTITY);
    }

    /// 长度不对的二维码必须被拒绝。
    #[test]
    fn qr_payload_rejects_wrong_length() {
        let (payload, _pending) = begin().expect("随机源可用");
        let bytes = payload.encode();
        for cut in [0_usize, 1, QR_PAYLOAD_LEN - 1] {
            assert!(
                matches!(
                    QrPayload::decode(&bytes[..cut]),
                    Err(Error::PairingPayloadMalformed { .. })
                ),
                "长度 {cut} 应被拒绝"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(QrPayload::decode(&longer).is_err());
    }

    /// 版本不认识时必须**明确**拒绝，而不是当成本版本解释。
    #[test]
    fn qr_payload_rejects_unknown_version() {
        let (payload, _pending) = begin().expect("随机源可用");
        let mut bytes = payload.encode();
        bytes[0] = 0x7F;
        match QrPayload::decode(&bytes) {
            Err(Error::PairingUnsupportedVersion { version }) => assert_eq!(version, 0x7F),
            other => panic!("应报版本不支持，实际 is_ok={}", other.is_ok()),
        }
    }

    /// **曲外公钥必须被拒绝。** 这是安全边界，不是格式检查。
    ///
    /// 构造方式是把公钥坐标的最后一个字节翻转——几乎必然离开曲线。
    #[test]
    fn qr_payload_rejects_off_curve_public_key() {
        let (payload, _pending) = begin().expect("随机源可用");
        let mut bytes = payload.encode();
        bytes[PUBLIC_KEY_LEN] ^= 0x01;
        assert!(
            matches!(
                QrPayload::decode(&bytes),
                Err(Error::DevicePublicKeyInvalid { .. })
            ),
            "曲外公钥应被拒绝"
        );
    }

    /// 缺少必需能力位时必须拒绝。
    #[test]
    fn qr_payload_rejects_missing_capability() {
        let (payload, _pending) = begin().expect("随机源可用");
        let mut bytes = payload.encode();
        bytes[QR_PAYLOAD_LEN - 1] = 0x00;
        assert!(matches!(
            QrPayload::decode(&bytes),
            Err(Error::PairingPayloadMalformed { .. })
        ));
    }

    /// 每次会话都必须得到全新的临时公钥与 nonce。
    #[test]
    fn each_session_gets_a_fresh_payload() {
        let (a, _pa) = begin().expect("随机源可用");
        let (b, _pb) = begin().expect("随机源可用");
        assert_ne!(a.nonce(), b.nonce(), "nonce 被复用");
        assert_ne!(a.public_key(), b.public_key(), "临时公钥被复用");
    }

    /// **篡改 Msg1 的任意一个字节都必须失败。**
    #[test]
    fn tampering_with_msg1_fails() {
        let master = MasterKey::generate().expect("随机源可用");
        let identity = fake_identity();
        // 先取一份基准密文，再逐个字节翻转。每个翻转都在**新的**会话上测，
        // 因为 `accept` 会消费会话。
        let (payload, pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let (baseline, _) = joiner.request(&identity).expect("可生成 Msg1");
        assert_eq!(baseline.len(), MSG1_LEN);

        for index in 0..baseline.len() {
            let (payload_i, pending_i) = begin().expect("随机源可用");
            let joiner_i = join(&payload_i).expect("随机源可用");
            let (mut tampered, _) = joiner_i.request(&identity).expect("可生成 Msg1");
            tampered[index] ^= 0x01;
            assert!(
                pending_i.accept(&tampered, &master).is_err(),
                "Msg1 第 {index} 字节被翻转却通过了认证"
            );
        }
        // 基准那一份必须能通过（证明上面的失败确实来自篡改）。
        assert!(pending.accept(&baseline, &master).is_ok());
    }

    /// **篡改 Msg2 的任意一个字节都必须失败**，包括主密钥本体。
    #[test]
    fn tampering_with_msg2_fails() {
        let master = MasterKey::generate().expect("随机源可用");
        let identity = fake_identity();
        let (payload, pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let (msg1, _) = joiner.request(&identity).expect("可生成 Msg1");
        let adoption = pending.accept(&msg1, &master).expect("应通过认证");
        assert_eq!(adoption.reply().len(), MSG2_LEN);

        // 翻转主密钥区的第一个字节：它同时破坏 AEAD 认证，因此必须失败。
        let mut tampered = adoption.reply().to_vec();
        tampered[0] ^= 0x01;
        assert!(
            joiner.open(&tampered, &identity).is_err(),
            "被改动的主密钥却通过了认证"
        );
    }

    /// 用**另一个会话**的 Msg1 去回应本会话必须失败。
    #[test]
    fn msg1_from_another_session_fails() {
        let master = MasterKey::generate().expect("随机源可用");
        let identity = fake_identity();
        let (_payload_a, pending_a) = begin().expect("随机源可用");
        let (payload_b, _pending_b) = begin().expect("随机源可用");
        let joiner_b = join(&payload_b).expect("随机源可用");
        let (msg1_b, _) = joiner_b.request(&identity).expect("可生成 Msg1");

        assert!(
            pending_a.accept(&msg1_b, &master).is_err(),
            "跨会话 Msg1 应被拒绝"
        );
    }

    /// 长度不对的消息必须被拒绝（且不得 panic）。
    ///
    /// 长度检查必须**先于**任何认证运算：否则一个极长的输入会让攻击者用很小的
    /// 代价换到大计算量。
    #[test]
    fn wrong_length_messages_fail() {
        let master = MasterKey::generate().expect("随机源可用");
        let identity = fake_identity();

        // Msg1 的长度检查：会话每次都要新的（`accept` 收 `self`）。
        let (payload, _pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let (msg1, _) = joiner.request(&identity).expect("可生成 Msg1");
        for cut in [0_usize, 1, MSG1_LEN - 1] {
            let (p, pend) = begin().expect("随机源可用");
            drop(join(&p).expect("随机源可用"));
            assert!(
                pend.accept(&msg1[..cut], &master).is_err(),
                "长度 {cut} 应被拒绝"
            );
        }
        // 过长的输入同样必须被拒绝。
        let mut too_long = msg1.clone();
        too_long.push(0);
        let (p, pend) = begin().expect("随机源可用");
        drop(join(&p).expect("随机源可用"));
        assert!(
            pend.accept(&too_long, &master).is_err(),
            "过长的 Msg1 应被拒绝"
        );

        // Msg2 的长度检查。`open` 收 `self`，因此每个长度都要一套新会话。
        for cut in [0_usize, 1, MSG2_LEN - 1] {
            let (p, pend) = begin().expect("随机源可用");
            let j = join(&p).expect("随机源可用");
            let (m1, _) = j.request(&identity).expect("可生成 Msg1");
            let ad = pend.accept(&m1, &master).expect("应通过认证");
            assert!(
                j.open(&ad.reply()[..cut], &identity).is_err(),
                "长度 {cut} 应被拒绝"
            );
        }
    }

    /// 设备身份公钥长度不对时必须在**发消息之前**就拒绝。
    #[test]
    fn request_rejects_wrong_identity_length() {
        let (payload, _pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        for bad in [&[][..], &[0_u8; 64][..], &[0_u8; 66][..]] {
            assert!(
                matches!(
                    joiner.request(bad),
                    Err(Error::DevicePublicKeyInvalid { .. })
                ),
                "长度 {} 应被拒绝",
                bad.len()
            );
        }
    }

    /// 曲外的「设备身份公钥」必须被拒绝。
    #[test]
    fn request_rejects_off_curve_identity() {
        let (payload, _pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let mut bad = fake_identity();
        bad[0] = 0x03; // 改成压缩前缀，长度仍对但不是未压缩点
        assert!(joiner.request(&bad).is_err(), "非法前缀应被拒绝");
    }

    /// **换一个身份公钥去开 Msg2 必须失败。**
    ///
    /// 这条锁住「确认标签绑定对端身份」：标签不是一条与身份无关的通用 OK。
    #[test]
    fn msg2_cannot_be_opened_with_a_different_identity() {
        let master = MasterKey::generate().expect("随机源可用");
        let identity = fake_identity();
        let (payload, pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let (msg1, _) = joiner.request(&identity).expect("可生成 Msg1");
        let adoption = pending.accept(&msg1, &master).expect("应通过认证");

        assert!(
            joiner.open(adoption.reply(), &other_identity()).is_err(),
            "用另一个身份却能打开 Msg2"
        );
    }

    /// nonce 记录必须能识别重放。
    #[test]
    fn nonce_log_detects_replay() {
        let mut log = NonceLog::new();
        let nonce = [7_u8; NONCE_LEN];
        assert!(!log.is_used(&nonce));
        assert!(log.record(nonce), "首次记录应成功");
        assert!(log.is_used(&nonce));
        assert!(!log.record(nonce), "重复记录应被识别为重放");
        assert_eq!(log.len(), 1);
    }

    /// nonce 记录的容量必须有界——否则攻击者可以用半途而废的配对把它撑爆。
    #[test]
    fn nonce_log_is_bounded() {
        let mut log = NonceLog::new();
        for i in 0..(NonceLog::DEFAULT_CAPACITY + 50) {
            let mut nonce = [0_u8; NONCE_LEN];
            nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
            assert!(log.record(nonce), "第 {i} 条应记录成功");
        }
        assert_eq!(log.len(), NonceLog::DEFAULT_CAPACITY);
    }

    /// 两次配对的 transcript 必须不同（因此会话密钥也不同）。
    #[test]
    fn transcripts_differ_per_session() {
        let identity = fake_identity();
        let (payload_a, _pa) = begin().expect("随机源可用");
        let (payload_b, _pb) = begin().expect("随机源可用");
        let joiner_a = join(&payload_a).expect("随机源可用");
        let joiner_b = join(&payload_b).expect("随机源可用");
        let (_, sid_a) = joiner_a.request(&identity).expect("可生成");
        let (_, sid_b) = joiner_b.request(&identity).expect("可生成");
        assert_ne!(sid_a, sid_b, "两次会话的 transcript 相同");
    }

    /// 主密钥存取的往返。
    #[test]
    fn master_key_storage_roundtrip() {
        let master = MasterKey::generate().expect("随机源可用");
        let bytes = master_key_for_storage(&master);
        let rebuilt = master_key_from_storage(bytes).expect("长度正确");
        assert_eq!(master.expose(), rebuilt.expose());
    }

    /// `Msg1` 的字节布局是对外契约，锁住它。
    ///
    /// 关键性质：**明文头里只有 nonce 与临时公钥，而没有设备身份公钥**。设备身份
    /// 是配对双方之间的信息，不该出现在任何读得到配对流量的人手里。
    #[test]
    fn msg1_layout_keeps_device_identity_encrypted() {
        let identity = fake_identity();
        let (payload, _pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let (msg1, _) = joiner.request(&identity).expect("可生成 Msg1");

        assert_eq!(msg1.len(), MSG1_LEN);
        assert_eq!(MSG1_LEN, 32 + 65 + (65 + 32) + 16);
        assert_eq!(
            &msg1[..NONCE_LEN],
            &joiner_nonce_of(&msg1),
            "nonce 应在最前"
        );
        assert_eq!(
            &msg1[NONCE_LEN..MSG1_HEADER_LEN],
            joiner.public_key(),
            "明文头应携带加入方的临时公钥"
        );
        // 设备身份**不得**在明文里出现。
        assert!(
            !msg1.windows(PUBLIC_KEY_LEN).any(|w| w == identity),
            "设备身份公钥出现在了 Msg1 的明文部分"
        );
    }

    /// 从 `Msg1` 里取 nonce（仅测试用，避免测试自己重复偏移量计算）。
    fn joiner_nonce_of(msg1: &[u8]) -> [u8; NONCE_LEN] {
        let mut out = [0_u8; NONCE_LEN];
        out.copy_from_slice(&msg1[..NONCE_LEN]);
        out
    }

    #[test]
    fn probe_divergence() {
        let identity = fake_identity();
        let (payload, pending) = begin().expect("rng");
        let joiner = join(&payload).expect("rng");
        let (msg1, sid_j) = joiner.request(&identity).expect("req");

        // 加入方侧重算
        let (sid_j2, keys_j) = joiner.derive().expect("derive");
        println!(
            "joiner sid  request={} derive={}",
            hex(&sid_j),
            hex(&sid_j2)
        );
        println!("joiner k_ba  = {}", hex(&keys_j.joiner_to_initiator[..8]));
        println!("joiner nonce = {}", hex(&keys_j.nonce));

        // 发起方侧
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&msg1[..NONCE_LEN]);
        let mut eph = [0u8; PUBLIC_KEY_LEN];
        eph.copy_from_slice(&msg1[NONCE_LEN..MSG1_HEADER_LEN]);
        let eph_pub = PublicKey::from_sec1_bytes(&eph).expect("曲线上");
        let sid_i = transcript_hash(
            &pending.payload.public_key,
            &pending.payload.nonce,
            &msg1[NONCE_LEN..MSG1_HEADER_LEN],
            &nonce,
        );
        println!("initiator sid = {}", hex(&sid_i));
        println!(
            "payload.pub == msg1 header eph? {}",
            pending.payload.public_key[..] == eph[..]
        );
        println!(
            "eph_pub == from header? {}",
            eph_pub.to_sec1_point(false).as_bytes() == &eph[..]
        );
        let shared = pending.secret.diffie_hellman(&eph_pub);
        let keys_i = SessionKeys::derive(shared.raw_secret_bytes(), &sid_i);
        println!("initiator k_ba = {}", hex(&keys_i.joiner_to_initiator[..8]));
        println!("initiator nonce = {}", hex(&keys_i.nonce));
        println!(
            "accept err = {:?}",
            pending.accept(&msg1, &MasterKey::generate().unwrap()).err()
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// 长度不对的存储字节必须被拒绝。
    #[test]
    fn master_key_storage_rejects_wrong_length() {
        for len in [0_usize, 31, 33] {
            let bytes: SecretBytes = vec![0_u8; len].into();
            assert!(
                master_key_from_storage(bytes).is_err(),
                "长度 {len} 应被拒绝"
            );
        }
    }

    /// **调试输出不得泄露主密钥。**
    #[test]
    fn debug_output_is_redacted() {
        let master = MasterKey::generate().expect("随机源可用");
        let identity = fake_identity();
        let (payload, pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let (msg1, _) = joiner.request(&identity).expect("可生成 Msg1");
        // 先把 `joiner` 的 Debug 输出取出来，再把它交给 `open`（`open` 收 `self`）。
        let joiner_debug = format!("{joiner:?}");
        let adoption = pending.accept(&msg1, &master).expect("应通过认证");
        let _ = joiner.open(adoption.reply(), &identity).expect("应能解开");

        let texts = [
            format!("{payload:?}"),
            joiner_debug,
            format!("{adoption:?}"),
        ];
        for text in &texts {
            assert!(!text.contains("XChaCha"), "不该出现内部类型名");
        }
        // 主密钥的字节序列（十六进制）不得出现。
        let hex: String = master.expose().iter().map(|b| format!("{b:02x}")).collect();
        for text in &texts {
            assert!(!text.contains(&hex), "Debug 泄露了主密钥十六进制：{text}");
        }
    }

    /// `Adoption::reply` 里**确实装着**主密钥——这条测试防止「忘了加密载荷」
    /// 这类改动悄悄地让配对成功但什么也没传过去。
    #[test]
    fn reply_actually_carries_the_master_key() {
        let (a, b, _, _) = run_pairing();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), &[0_u8; MASTER_KEY_LEN], "主密钥不该是全零");
    }
}
