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

//! 挑战-应答：向对方证明「我持有主密钥」，而不把主密钥交出去。
//!
//! # 为什么需要它
//!
//! [`crate::pairing`] 解决「怎么把主密钥交给一台新设备」。但两台**已经配对过**的
//! 设备之后要反复通信（M4 的同步就是），每次重新扫二维码显然不可接受，而直接互发
//! 主密钥更不行——那等于把主密钥撒在信道上。
//!
//! 本模块给出这一层的答案：**持有**主密钥本身就可以作为身份凭证，只要能在不泄露
//! 它的前提下证明这一点。做法是标准的挑战-应答。
//!
//! # 与配对协议的分工
//!
//! | | 配对（[`crate::pairing`]） | 挑战-应答（本模块） |
//! |---|---|---|
//! | 前提 | 双方**没有**共同的秘密 | 双方**已经**有共同的主密钥 |
//! | 目的 | 建立共同秘密 | 确认对方仍然持有它 |
//! | 是否传主密钥 | 是（加密后） | **否** |
//! | 抗中间人 | 靠二维码带外认证 | **不提供**（见下） |
//!
//! ## 本模块不抗中间人，这是刻意的
//!
//! 中间人能否冒充，取决于它能不能通过应答。攻击者没有主密钥，就算不出 tag，
//! 于是冒充失败——**这一点是成立的**。但主动中间人可以**转发**双方的消息，让两端
//! 都以为在与对方通话。这是所有非信道绑定协议的共同限制。
//!
//! 不在这里解决它的理由：本项目的通信目标是「同一 WiFi / 热点 / 二维码」，而
//! M4.5 会用 iroh 建连，那里有基于 `EndpointId` 的信道绑定。把抗中间人压进这一层
//! 会让它依赖具体传输方式，而本层刻意做成**传输无关**的。
//!
//! 需要抗中间人时，调用方应当把本层的会话标识与传输层的对端身份**绑定起来**校验
//! ——[`Verified::session_id`] 与 [`Responder::session_id`] 存在的意义就是提供这个
//! 双方一致、且由双方输入共同决定的锚点。
//!
//! 另外，**应答方（`Responder`）不知道自己面对的临时公钥属于谁**时也可能被中间人
//! 牵着走：验证方一侧在 [`Verifier::verify`] 成功后才拿到会话标识，因此调用方应当
//! 等认证完成后、在开始交换任何数据之前，拿这个标识去核对传输层。
//!
//! # 协议
//!
//! ```text
//!   A（验证方）                                B（应答方）
//!       │                                          │
//!       │ ① 生成临时密钥对 (a, A_pub) 与随机 nonce_A
//!       │ ──────── 挑战 = { A_pub, nonce_A } ─────► │
//!       │                                          │ ② S = ECDH(b, A_pub)
//!       │                                          │    从主密钥派生 K_proof
//!       │                                          │    tag = HMAC(K_proof, sid)
//!       │ ◄── 应答 = { B_pub, nonce_B, 设备公钥, ─── │    sid = H(A_pub‖n_A‖B_pub‖n_B)
//!       │        tag, 设备签名 } ────────────────── │
//!       │ ③ 复算 tag，比对                           │
//!       │    验证设备签名（证明是哪台设备）            │
//!       │ ──────── 确认 = HMAC(K_confirm, sid) ───► │ ④ 校验确认
//!       │                                          │
//! ```
//!
//! ## 为什么 tag 还要绑 ECDH
//!
//! tag 的密钥来自**主密钥**（这是「证明持有它」的唯一来源），但它的输入里必须有
//! **只有 A 与 B 能算出的**东西。
//!
//! 否则会这样：攻击者录下一条 `tag = HMAC(K_proof, nonce_A)`，然后自己扮演 B，
//! 等 A 发来**新的**挑战、把抢到的 `nonce_A` 冒充成自己的 `nonce_B` 回过去。A 复算
//! `HMAC(K_proof, 它自己刚生成的 nonce_A)`——对不上。**关键在于 A 必须把对方声称的
//! nonce 纳入自己的 transcript**，而不是只用自己的那个。
//!
//! 本实现的做法是让 `sid` 同时包含**双方**的临时公钥与 nonce，并由 ECDH 的共享
//! 秘密作为 HKDF 的 salt 参与派生。于是：
//!
//! - 攻击者改任何一个字段 → 双方算出不同的 `sid` → tag 不匹配。
//! - 攻击者重放整条应答到新会话 → 新的 `A_pub`/`nonce_A` 让 `sid` 不同 → 不匹配。
//! - 攻击者没有主密钥 → 算不出 tag。
//!
//! ## 为什么还要设备签名
//!
//! tag 证明的是「对方持有主密钥」——但**任何**持有主密钥的设备都能算出它。若调用方
//! 需要知道「现在回答的是哪一台设备」，就必须叠加设备身份签名（ECDSA P-256，见
//! [`qualia_dik::device`]）。两者证明的事情不同，因此都要有：
//!
//! - tag → 「你确实有主密钥」（**不可伪造**，即使攻击者控制了信道）
//! - 签名 → 「你是设备 X」（可由持有 X 私钥的一方伪造，而那正是 X 的定义）
//!
//! 签名覆盖 `sid` 与双方的公开值，因此**不能**把某台设备的签名移植到别的会话上。
//!
//! # 重放防护
//!
//! 三层，缺一不可：
//!
//! 1. **输入层**：`sid` 由双方的临时公钥与 nonce 共同决定，每次会话都不同。
//! 2. **会话层**：[`Verifier::verify`] 收 `self`，类型系统保证同一个挑战不会被
//!    验证两次。
//! 3. **跨重启**：调用方可以把用过的 `sid` 记进 [`crate::pairing::NonceLog`]，
//!    从而在进程重启后仍然认出「这次会话我处理过」。

use crate::pairing::{CONFIRMATION_LEN, NONCE_LEN, PUBLIC_KEY_LEN, SESSION_ID_LEN};
use crate::vault::MasterKey;
use crate::{Error, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::Generate;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use qualia_dik::{DevicePublicKey, DeviceSignature};
use secrecy::zeroize::Zeroize;
use sha2::{Digest, Sha256};

/// 挑战的字节长度：`A_pub ‖ nonce_A`。
pub const CHALLENGE_LEN: usize = PUBLIC_KEY_LEN + NONCE_LEN;

/// 应答**不含签名**部分的字节长度：`B_pub ‖ nonce_B ‖ 设备公钥 ‖ tag`。
pub const RESPONSE_LEN: usize = PUBLIC_KEY_LEN + NONCE_LEN + PUBLIC_KEY_LEN + CONFIRMATION_LEN;

/// 应答的完整字节长度（含设备签名）。
pub const RESPONSE_SIGNED_LEN: usize = RESPONSE_LEN + qualia_dik::device::SIGNATURE_LEN;

/// 确认标签的字节长度。
pub const CONFIRM_LEN: usize = CONFIRMATION_LEN;

/// 从主密钥派生证明密钥的域分离串。
const HKDF_INFO_PROOF: &[u8] = b"Qualia2FA auth v1 proof key";

/// 从主密钥派生确认密钥的域分离串。
const HKDF_INFO_CONFIRM: &[u8] = b"Qualia2FA auth v1 confirm key";

/// 证明标签的域分离串。
const PROOF_LABEL: &[u8] = b"Qualia2FA auth v1 proof";

/// 确认标签的域分离串。
const CONFIRM_LABEL: &[u8] = b"Qualia2FA auth v1 confirm";

/// 会话标识的域分离串。
const SESSION_LABEL: &[u8] = b"Qualia2FA auth v1 session";

/// 设备签名覆盖消息的域分离串。
const SIGNATURE_LABEL: &[u8] = b"Qualia2FA auth v1 device signature";

/// 验证方 A：已发出挑战，等待应答。
///
/// # 一次性
///
/// [`Verifier::verify`] 收 `self`。同一个挑战不可能被验证两次——这条约束由类型系统
/// 保证，因此「攻击者重放应答」在会话层面直接不成立：没有会话可以传进去。
///
/// 临时私钥在 `Drop` 时由 `p256` 擦除（`EphemeralSecret` 实现 `ZeroizeOnDrop`）。
pub struct Verifier {
    /// 本方的临时私钥。
    secret: EphemeralSecret,
    /// 本方生成的 nonce。
    nonce: [u8; NONCE_LEN],
    /// 本方临时公钥的 SEC1 编码。
    public_key: [u8; PUBLIC_KEY_LEN],
}

impl Verifier {
    /// 要发给应答方的挑战字节。
    #[must_use]
    pub fn challenge(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHALLENGE_LEN);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.nonce);
        out
    }

    /// 本方（验证方）的临时公钥。
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// 本方 nonce。
    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// 校验应答，并生成要发回的确认标签。
    ///
    /// # 参数
    ///
    /// - `response`: 应答方给出的完整应答（含签名）。
    /// - `master`: 本方持有的主密钥。**它只用于复算 tag，不会出现在任何输出里。**
    ///
    /// # 返回
    ///
    /// [`Verified`]：对方的设备身份、会话标识、以及要发回的确认标签。
    ///
    /// # 错误
    ///
    /// - 长度不对、或其中的公钥不是合法曲线点：[`Error::AuthMessageMalformed`]
    /// - **tag 不匹配**（对方没有主密钥）：[`Error::AuthProofFailed`]
    /// - **设备签名不通过**：[`Error::DeviceSignatureInvalid`]
    ///
    /// 后两者**刻意分开**：tag 失败意味着「对方没有主密钥」，签名失败意味着「对方
    /// 有主密钥，但不是它声称的那台设备」。这两种情况对使用者的含义完全不同（前者
    /// 危险，后者通常只是设备身份换了），而且都不涉及秘密值——攻击者从一个失败结果
    /// 里能学到的，只有它已经知道的事情。
    pub fn verify(self, response: &[u8], master: &MasterKey) -> Result<Verified> {
        if response.len() != RESPONSE_SIGNED_LEN {
            return Err(Error::AuthMessageMalformed {
                reason: "应答长度不对",
            });
        }
        let body = &response[..RESPONSE_LEN];
        let mut responder_public = [0_u8; PUBLIC_KEY_LEN];
        responder_public.copy_from_slice(&body[..PUBLIC_KEY_LEN]);
        let mut responder_nonce = [0_u8; NONCE_LEN];
        responder_nonce.copy_from_slice(&body[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + NONCE_LEN]);
        let mut device_public = [0_u8; PUBLIC_KEY_LEN];
        device_public.copy_from_slice(
            &body[PUBLIC_KEY_LEN + NONCE_LEN..PUBLIC_KEY_LEN + NONCE_LEN + PUBLIC_KEY_LEN],
        );
        let mut tag = [0_u8; CONFIRMATION_LEN];
        tag.copy_from_slice(&body[PUBLIC_KEY_LEN + NONCE_LEN + PUBLIC_KEY_LEN..]);

        let responder_public = PublicKey::from_sec1_bytes(&responder_public).map_err(|_| {
            Error::AuthMessageMalformed {
                reason: "应答里的临时公钥不是合法的 P-256 SEC1 点",
            }
        })?;
        // 设备公钥必须验证：它会被交给调用方当作「对方是谁」的结论。
        let device_key = DevicePublicKey::from_sec1_bytes(&device_public).map_err(|_| {
            Error::AuthMessageMalformed {
                reason: "应答里的设备公钥不是合法的 P-256 SEC1 点",
            }
        })?;

        let session_id = session_id_of(
            &self.public_key,
            &self.nonce,
            &body[..PUBLIC_KEY_LEN],
            &responder_nonce,
        );
        let shared = self.secret.diffie_hellman(&responder_public);
        let keys = AuthKeys::derive(master, shared.raw_secret_bytes(), &session_id);

        if !constant_time_eq(&tag, &proof_tag(&keys.proof, &session_id)) {
            return Err(Error::AuthProofFailed);
        }

        // 设备签名：覆盖会话标识 + 双方的临时公钥与 nonce + tag。因此签名不能从
        // 别的会话搬过来，也不能配在别的 tag 上。
        let message = signature_message(
            &session_id,
            &self.public_key,
            &self.nonce,
            &body[..PUBLIC_KEY_LEN],
            &responder_nonce,
            &tag,
        );
        qualia_dik::device::verify(
            &device_key,
            &message,
            &signature_of(&response[RESPONSE_LEN..])?,
        )?;

        Ok(Verified {
            session_id,
            device_key,
            device_public,
            confirm: keys.confirm,
        })
    }
}

impl core::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Verifier")
            .field("public_key", &"<65 bytes>")
            .field("nonce", &"<redacted>")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// [`Verifier::verify`] 的结果。
pub struct Verified {
    /// 本次会话的标识（双方一致）。
    session_id: [u8; SESSION_ID_LEN],
    /// 对方的设备身份公钥（强类型）。
    device_key: DevicePublicKey,
    /// 对方的设备身份公钥（SEC1 原始字节，供调用方自行解释／落库）。
    device_public: [u8; PUBLIC_KEY_LEN],
    /// 派生出的确认密钥。
    confirm: [u8; 32],
}

impl Verified {
    /// 会话标识。
    ///
    /// 调用方应当把它与传输层的对端身份绑定校验，否则中间人可以转发消息（见模块
    /// 文档「不抗中间人」一节）。
    #[must_use]
    pub const fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// 对方的设备身份公钥。
    #[must_use]
    pub const fn device_key(&self) -> &DevicePublicKey {
        &self.device_key
    }

    /// 对方的设备身份公钥的 SEC1 编码。
    #[must_use]
    pub const fn device_public(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.device_public
    }

    /// 要发回应答方的确认标签。
    ///
    /// 应答方据此确认「对面确实有主密钥」。**单向认证是不够的**：只验证应答方时，
    /// 攻击者可以冒充验证方去骗取一次成功的应答——虽然拿不到主密钥，但能让应答方
    /// 误以为自己在与合法设备通信，从而愿意继续交换数据。
    #[must_use]
    pub fn confirmation(&self) -> [u8; CONFIRM_LEN] {
        confirm_tag(&self.confirm, &self.session_id)
    }
}

impl core::fmt::Debug for Verified {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Verified")
            .field("session_id", &&self.session_id[..8])
            .field("device_id", &self.device_key.device_id())
            .field("confirm", &"<redacted>")
            .finish()
    }
}

/// 应答方 B：已收到挑战。
pub struct Responder {
    /// 本方的临时私钥。
    secret: EphemeralSecret,
    /// 本方临时公钥的 SEC1 编码。
    public_key: [u8; PUBLIC_KEY_LEN],
    /// 本方的 nonce。
    nonce: [u8; NONCE_LEN],
    /// 验证方的临时公钥。
    verifier_public: [u8; PUBLIC_KEY_LEN],
    /// 验证方的 nonce。
    verifier_nonce: [u8; NONCE_LEN],
}

impl Responder {
    /// 会话标识。
    #[must_use]
    pub fn session_id(&self) -> [u8; SESSION_ID_LEN] {
        session_id_of(
            &self.verifier_public,
            &self.verifier_nonce,
            &self.public_key,
            &self.nonce,
        )
    }

    /// 本方临时公钥的 SEC1 编码。
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// 本方 nonce。不是秘密，但**唯一**。
    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// 生成应答。
    ///
    /// # 参数
    ///
    /// - `master`: 本方持有的主密钥。**它不会出现在应答里**——只用于派生 tag。
    /// - `device_public`: 本方设备身份公钥的 SEC1 编码。
    /// - `sign`: 用设备私钥对**原始消息**签名的回调。
    ///
    ///   之所以是回调而不是直接传 `DeviceSigner`：签名是平台代码（`qualia2fa-keystore`
    ///   的 `DeviceSigner`），而**核心库不能依赖 keystore**——依赖方向是
    ///   keystore → core。回调让这一层保持无平台依赖，也让它能在任何平台上测试。
    ///
    ///   回调收到的是**消息本身**，不是摘要。因此平台实现若要对接只吃摘要的硬件
    ///   API（Windows CNG 的 `NCryptSignHash` 形参就叫 `pbHashValue`），应当自己
    ///   做一次 SHA-256 再走 `sign_digest`。哈希次数只能有一处归属：
    ///   验证侧固定走 [`qualia_dik::device::verify`]，它在标准 ECDSA 模式下**自己哈希
    ///   一次**。签名侧若再多哈希一次，表现为每次握手都失败，而错误信息
    ///   （"签名与公钥或消息不匹配"）完全不指向真正的原因。
    ///
    /// # 错误
    ///
    /// - 设备公钥长度或曲线成员资格不对：[`Error::AuthMessageMalformed`]
    /// - `sign` 返回错误时原样透传
    pub fn respond(
        &self,
        master: &MasterKey,
        device_public: &[u8],
        sign: impl FnOnce(&[u8]) -> Result<DeviceSignature>,
    ) -> Result<Vec<u8>> {
        if device_public.len() != PUBLIC_KEY_LEN {
            return Err(Error::AuthMessageMalformed {
                reason: "设备身份公钥长度不是 65 字节",
            });
        }
        DevicePublicKey::from_sec1_bytes(device_public).map_err(|_| {
            Error::AuthMessageMalformed {
                reason: "设备身份公钥不是合法的 P-256 SEC1 点",
            }
        })?;

        let verifier_public = PublicKey::from_sec1_bytes(&self.verifier_public).map_err(|_| {
            Error::AuthMessageMalformed {
                reason: "挑战里的临时公钥不是合法的 P-256 SEC1 点",
            }
        })?;
        let session_id = self.session_id();
        let shared = self.secret.diffie_hellman(&verifier_public);
        let keys = AuthKeys::derive(master, shared.raw_secret_bytes(), &session_id);

        let tag = proof_tag(&keys.proof, &session_id);
        let message = signature_message(
            &session_id,
            &self.verifier_public,
            &self.verifier_nonce,
            &self.public_key,
            &self.nonce,
            &tag,
        );
        // 把**原始消息**交给回调，由调用方决定怎么签。
        //
        // 早期版本在这里先算好 SHA-256 摘要再传出去，结果测试里 `p256` 又在摘要上
        // 哈希了一次——变成 `Sign(SHA256(SHA256(message)))`，而验证侧走
        // `qualia_dik::device::verify` 只哈希一次，于是每一次握手都以
        // `DeviceSignatureInvalid { reason: "签名与公钥或消息不匹配" }` 失败。
        // 传消息而不是摘要，让「哈希几次」这件事只有一个归属方。
        let signature = sign(&message)?;

        let mut out = Vec::with_capacity(RESPONSE_SIGNED_LEN);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(device_public);
        out.extend_from_slice(&tag);
        out.extend_from_slice(signature.as_bytes());
        Ok(out)
    }
}

impl core::fmt::Debug for Responder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Responder")
            .field("public_key", &"<65 bytes>")
            .field("nonce", &"<redacted>")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// 验证方开始一次认证，得到要发给应答方的挑战。
///
/// # 错误
///
/// 只在 OS 随机源不可用时失败（[`Error::RandomnessUnavailable`]）。
#[must_use = "挑战必须被发出去，否则这次认证无法开始"]
pub fn begin() -> Result<(Vec<u8>, Verifier)> {
    let secret = EphemeralSecret::generate();
    let point = secret.public_key().to_sec1_point(false);
    let mut public_key = [0_u8; PUBLIC_KEY_LEN];
    public_key.copy_from_slice(point.as_bytes());

    let mut nonce = [0_u8; NONCE_LEN];
    crate::getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;

    let mut challenge = Vec::with_capacity(CHALLENGE_LEN);
    challenge.extend_from_slice(&public_key);
    challenge.extend_from_slice(&nonce);
    Ok((
        challenge,
        Verifier {
            secret,
            nonce,
            public_key,
        },
    ))
}

/// 应答方接收挑战。
///
/// # 错误
///
/// - 挑战长度不对、或其中的公钥不在曲线上：[`Error::AuthMessageMalformed`]
/// - OS 随机源不可用：[`Error::RandomnessUnavailable`]
pub fn accept(challenge: &[u8]) -> Result<Responder> {
    if challenge.len() != CHALLENGE_LEN {
        return Err(Error::AuthMessageMalformed {
            reason: "挑战长度不对",
        });
    }
    let mut verifier_public = [0_u8; PUBLIC_KEY_LEN];
    verifier_public.copy_from_slice(&challenge[..PUBLIC_KEY_LEN]);
    let mut verifier_nonce = [0_u8; NONCE_LEN];
    verifier_nonce.copy_from_slice(&challenge[PUBLIC_KEY_LEN..]);

    // 曲外点必须在这里就拒绝：它会被送进 ECDH。
    PublicKey::from_sec1_bytes(&verifier_public).map_err(|_| Error::AuthMessageMalformed {
        reason: "挑战里的临时公钥不是合法的 P-256 SEC1 点",
    })?;

    let secret = EphemeralSecret::generate();
    let point = secret.public_key().to_sec1_point(false);
    let mut public_key = [0_u8; PUBLIC_KEY_LEN];
    public_key.copy_from_slice(point.as_bytes());
    let mut nonce = [0_u8; NONCE_LEN];
    crate::getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;

    Ok(Responder {
        secret,
        public_key,
        nonce,
        verifier_public,
        verifier_nonce,
    })
}

/// 应答方校验验证方发来的确认标签。
///
/// # 参数
///
/// `session_id` 与 `confirmation` 来自 [`Verified`] 经由通信信道传回的内容；其余由
/// 调用方从自己的 [`Responder`] 与 `master` 提供。
///
/// # 错误
///
/// 标签不匹配时返回 [`Error::AuthProofFailed`]。
pub fn confirm(
    master: &MasterKey,
    responder: &Responder,
    session_id: &[u8; SESSION_ID_LEN],
    confirmation: &[u8],
) -> Result<()> {
    if confirmation.len() != CONFIRM_LEN {
        return Err(Error::AuthMessageMalformed {
            reason: "确认标签长度不对",
        });
    }
    // 校验对方回传的 session_id 与自己算出的一致：不一致说明双方对这次会话的理解
    // 不同（可能是被换了消息），此时**不能**继续。
    if *session_id != responder.session_id() {
        return Err(Error::AuthProofFailed);
    }
    let verifier_public = PublicKey::from_sec1_bytes(&responder.verifier_public).map_err(|_| {
        Error::AuthMessageMalformed {
            reason: "挑战里的临时公钥不是合法的 P-256 SEC1 点",
        }
    })?;
    let shared = responder.secret.diffie_hellman(&verifier_public);
    let keys = AuthKeys::derive(master, shared.raw_secret_bytes(), session_id);
    if !constant_time_eq(confirmation, &confirm_tag(&keys.confirm, session_id)) {
        return Err(Error::AuthProofFailed);
    }
    Ok(())
}

/// 从主密钥与 ECDH 共享秘密派生出的两份密钥。
///
/// # 为什么要主密钥**和** ECDH，两个都要
///
/// - **主密钥**提供「只有持有它的一方能算出」这条性质。没有它，任何截获信道的人
///   都能回答挑战。
/// - **ECDH 共享秘密**（作为 HKDF 的 salt）把结果绑定到**这一次**会话。没有它，
///   tag 就只是 `f(主密钥, sid)`，而 `sid` 完全由信道上可见的字节构成——攻击者
///   可以照抄一次录下的会话，把它重放成一次「看起来全新」的会话。
///
/// 两者缺一不可。这也解释了为什么本模块需要 ECDH，而不只是 HMAC。
struct AuthKeys {
    /// 应答方用来证明持有主密钥的密钥。
    proof: [u8; 32],
    /// 验证方用来确认的密钥。
    confirm: [u8; 32],
}

impl AuthKeys {
    /// 派生。
    fn derive(master: &MasterKey, shared: &[u8], session_id: &[u8; SESSION_ID_LEN]) -> Self {
        // 主密钥当作 HKDF 的输入密钥材料，ECDH 共享秘密当作 salt。
        //
        // 反过来（共享秘密当 ikm、主密钥当 salt）也可以，但这里的选择让
        // 「主密钥是**唯一**的秘密来源」这件事在代码上更显眼：proof 与 confirm
        // 都是从它展开出来的，而共享秘密只负责把这次展开锚定到本会话。
        let hkdf = Hkdf::<Sha256>::new(Some(shared), master.expose());
        let mut proof = [0_u8; 32];
        let mut confirm = [0_u8; 32];
        // `expand` 只在输出长度超过 255 * HashLen 时失败，32 字节不可能触发。
        // 仍然不 `unwrap`：库内「任何输入都不得 panic」的约定不允许例外。
        let failed = hkdf.expand(HKDF_INFO_PROOF, &mut proof).is_err()
            || hkdf.expand(HKDF_INFO_CONFIRM, &mut confirm).is_err();
        if failed {
            // 走到这里说明输出长度参数被改坏了。全零密钥会让后续认证必然失败，
            // 而不是悄悄用一个可预测的密钥。
            proof.zeroize();
            confirm.zeroize();
        }
        let _ = session_id;
        Self { proof, confirm }
    }
}

impl Drop for AuthKeys {
    fn drop(&mut self) {
        self.proof.zeroize();
        self.confirm.zeroize();
    }
}

/// 计算会话标识。
///
/// 输入顺序写死在**这一个**函数里，两个方向都调用它。
fn session_id_of(
    verifier_public: &[u8; PUBLIC_KEY_LEN],
    verifier_nonce: &[u8; NONCE_LEN],
    responder_public: &[u8],
    responder_nonce: &[u8; NONCE_LEN],
) -> [u8; SESSION_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_LABEL);
    hasher.update(verifier_public);
    hasher.update(verifier_nonce);
    hasher.update(responder_public);
    hasher.update(responder_nonce);
    let digest = hasher.finalize();
    let mut out = [0_u8; SESSION_ID_LEN];
    out.copy_from_slice(&digest);
    out
}

/// 设备签名覆盖的消息。
///
/// 覆盖会话标识、双方的公开值与 tag，因此**一条签名只对一次会话有效**。少了任何
/// 一项，攻击者就能把某台设备的一次签名搬到别的会话里——那会让「签名证明是哪台
/// 设备」这条性质失效。
fn signature_message(
    session_id: &[u8; SESSION_ID_LEN],
    verifier_public: &[u8; PUBLIC_KEY_LEN],
    verifier_nonce: &[u8; NONCE_LEN],
    responder_public: &[u8],
    responder_nonce: &[u8; NONCE_LEN],
    tag: &[u8; CONFIRMATION_LEN],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        SIGNATURE_LABEL.len()
            + SESSION_ID_LEN
            + PUBLIC_KEY_LEN
            + NONCE_LEN
            + responder_public.len()
            + NONCE_LEN
            + CONFIRMATION_LEN,
    );
    message.extend_from_slice(SIGNATURE_LABEL);
    message.extend_from_slice(session_id);
    message.extend_from_slice(verifier_public);
    message.extend_from_slice(verifier_nonce);
    message.extend_from_slice(responder_public);
    message.extend_from_slice(responder_nonce);
    message.extend_from_slice(tag);
    message
}

/// 从字节切片构造设备签名。
///
/// 走 [`DeviceSignature::from_bytes`] 而不是自己拼数组：长度校验只应有一处。
fn signature_of(bytes: &[u8]) -> Result<DeviceSignature> {
    // `?` 把 `qualia_dik::Error` 经 `Error::Device` 转换过来——那一步由 `#[from]`
    // 提供；不能直接返回 `Ok(..)` 之外的表达式，因为 `Ok` 的类型不会自动转换。
    Ok(DeviceSignature::from_bytes(bytes)?)
}

/// 计算证明标签。
fn proof_tag(key: &[u8; 32], session_id: &[u8; SESSION_ID_LEN]) -> [u8; CONFIRMATION_LEN] {
    tag(key, PROOF_LABEL, session_id)
}

/// 计算确认标签。
fn confirm_tag(key: &[u8; 32], session_id: &[u8; SESSION_ID_LEN]) -> [u8; CONFIRM_LEN] {
    tag(key, CONFIRM_LABEL, session_id)
}

/// 通用标签计算。
fn tag(key: &[u8; 32], label: &[u8], session_id: &[u8; SESSION_ID_LEN]) -> [u8; CONFIRMATION_LEN] {
    // `new_from_slice` 对 HMAC-SHA256 接受任意长度密钥，不会失败。仍然不 `unwrap`。
    let Ok(mut mac) = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key) else {
        return [0_u8; CONFIRMATION_LEN];
    };
    mac.update(label);
    mac.update(session_id);
    let digest = mac.finalize().into_bytes();
    let mut out = [0_u8; CONFIRMATION_LEN];
    out.copy_from_slice(&digest);
    out
}

/// 常量时间比较。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer as _};

    /// 生成一台"设备"：软件保存的 P-256 私钥 + 对应的公开信息。
    ///
    /// # 为什么测试里可以用软件密钥
    ///
    /// 生产环境里设备私钥住在平台硬件里，签名由 `qualia2fa-keystore` 发起。但**本模块
    /// 不关心私钥存在哪里**——它只通过回调要一段签名。测试里用软件密钥构造回调，
    /// 验证的是本模块的协议性质，与密钥保管无关。真实硬件路径由 keystore 仓库的
    /// 集成测试覆盖。
    ///
    /// 标量固定为 `n`（而不是随机）时更方便调试；这里用随机值，因为"两台不同的
    /// 设备"是本模块大部分测试的前提。
    fn device(scalar: u8) -> (SigningKey, [u8; PUBLIC_KEY_LEN]) {
        // 用一个确定的小标量：1、2、3……远小于曲线阶，必定是合法私钥。
        let mut bytes = [0_u8; 32];
        bytes[31] = scalar;
        let signing = SigningKey::from_bytes((&bytes).into()).expect("合法标量");
        let public = signing.verifying_key().to_sec1_point(false);
        let mut out = [0_u8; PUBLIC_KEY_LEN];
        out.copy_from_slice(public.as_bytes());
        (signing, out)
    }

    /// 造一个主密钥。
    fn new_master() -> MasterKey {
        MasterKey::generate().expect("随机源可用")
    }

    /// 跑完一次完整握手，返回各方的中间结果。
    ///
    /// 返回 `Responder` 而非只返回确认结果，是为了让"确认标签是对的还是错的"能被
    /// 分开检验。**`Responder` 不能被复制**，所以每条测试各自跑一次握手。
    fn handshake(master: &MasterKey) -> (Verified, Responder, [u8; PUBLIC_KEY_LEN], Vec<u8>) {
        let (signing, device_public) = device(7);
        let (challenge, verifier) = begin().expect("生成挑战");
        let responder = accept(&challenge).expect("接受挑战");
        let response = responder
            .respond(master, &device_public, |message| {
                let signature: p256::ecdsa::Signature = signing.sign(message);
                signature_of(&signature.to_bytes())
            })
            .expect("生成应答");
        let verified = verifier.verify(&response, master).expect("验证应答");
        (verified, responder, device_public, response)
    }

    /// 正常握手必须成功，且双方对会话标识的看法一致。
    #[test]
    fn handshake_succeeds_and_both_sides_agree_on_the_session() {
        let master = new_master();
        let (verified, responder, device_public, _) = handshake(&master);

        assert_eq!(
            verified.session_id(),
            &responder.session_id(),
            "双方算出的会话标识必须一致"
        );
        assert_eq!(verified.device_public(), &device_public);

        // 确认标签必须被应答方接受。
        confirm(
            &master,
            &responder,
            verified.session_id(),
            &verified.confirmation(),
        )
        .expect("确认标签应当被接受");
    }

    /// **攻击者没有主密钥时必须失败。**
    ///
    /// 这是本模块存在的理由：攻击者能看见挑战，也能看见应答，但它算不出 tag。
    #[test]
    fn responder_without_the_master_key_cannot_answer() {
        let real = new_master();
        let wrong = new_master();
        let (_, device_public) = device(7);
        let (challenge, verifier) = begin().expect("生成挑战");
        let responder = accept(&challenge).expect("接受挑战");

        // 应答方拿的是**另一个**主密钥。
        let response = responder
            .respond(&wrong, &device_public, |digest| {
                let (signing, _) = device(7);
                let signature: p256::ecdsa::Signature = signing.sign(digest);
                signature_of(&signature.to_bytes())
            })
            .expect("签名本身会成功");

        assert!(
            matches!(
                verifier.verify(&response, &real),
                Err(Error::AuthProofFailed)
            ),
            "用错的主密钥却通过了认证"
        );
    }

    /// 没有私钥的攻击者无法伪造签名——**即使它把 tag 那一关过了**。
    ///
    /// 这条测试说明「tag」与「签名」各自挡住什么。攻击者能拿到正确的 tag（它看得见
    /// 信道），但它没有设备私钥，因此签名这一关仍然挡着。
    ///
    /// 做法是让应答**由攻击者的密钥签名**，但 tag 是合法的：把合法应答的签名段
    /// 换成另一个密钥对同一消息的签名。
    #[test]
    fn forged_signature_is_rejected_even_with_a_valid_tag() {
        let master = new_master();

        let (challenge, verifier) = begin().expect("生成挑战");
        let responder = accept(&challenge).expect("接受挑战");
        // 真正的设备。
        let (real_signing, real_device) = device(7);
        let response = responder
            .respond(&master, &real_device, |message| {
                let signature: p256::ecdsa::Signature = real_signing.sign(message);
                signature_of(&signature.to_bytes())
            })
            .expect("生成应答");

        // 攻击者只知道消息的一部分：它无法重算 message（需要 responder 的临时私钥
        // 才能完成 ECDH），因此这里只能换一个「签名不对」的版本。
        //
        // 这正是要害：**签名覆盖的消息里含有 ECDH 派生的会话标识**，攻击者既算不出
        // 正确的 tag，也算不出签名要覆盖的消息。
        let (_attacker_signing, attacker_device) = device(9);
        let mut forged = response.clone();
        // 让签名段变成全零：一定不合法。
        for byte in &mut forged[RESPONSE_LEN..] {
            *byte = 0;
        }
        assert_ne!(attacker_device, real_device);

        // 验签失败由设备身份库报出，经 `Error::Device` 包装上来。断言内层变体：
        // 「是验签不过」这个事实属于设备身份库，包装只是把它带上来。
        assert!(
            matches!(
                verifier.verify(&forged, &master),
                Err(Error::Device(
                    qualia_dik::Error::DeviceSignatureInvalid { .. }
                ))
            ),
            "被换成无效签名的应答却通过了"
        );
    }

    /// **篡改应答里除签名外的任意一个字节都必须被发现。**
    #[test]
    fn tampering_with_the_response_is_detected() {
        let master = new_master();
        let (signing, device_public) = device(7);

        for index in 0..RESPONSE_SIGNED_LEN {
            let (challenge, verifier) = begin().expect("生成挑战");
            let responder = accept(&challenge).expect("接受挑战");
            let mut response = responder
                .respond(&master, &device_public, |digest| {
                    let signature: p256::ecdsa::Signature = signing.sign(digest);
                    signature_of(&signature.to_bytes())
                })
                .expect("生成应答");
            response[index] ^= 0x01;

            assert!(
                verifier.verify(&response, &master).is_err(),
                "第 {index} 字节被翻转却通过了认证"
            );
        }
    }

    /// 挑战长度不对必须被拒绝。
    #[test]
    fn challenge_with_wrong_length_is_rejected() {
        for length in [0_usize, 1, CHALLENGE_LEN - 1, CHALLENGE_LEN + 1] {
            let mut challenge = vec![0_u8; length];
            if length > 0 {
                challenge[0] = 0x04;
            }
            assert!(
                matches!(accept(&challenge), Err(Error::AuthMessageMalformed { .. })),
                "长度 {length} 的挑战应被拒绝"
            );
        }
    }

    /// 挑战里的公钥不在曲线上必须被拒绝。
    #[test]
    fn challenge_with_off_curve_key_is_rejected() {
        let (challenge, _) = begin().expect("生成挑战");
        let mut broken = challenge.clone();
        // 改掉公钥的最后一个字节：前缀仍是 0x04，但坐标不再满足曲线方程。
        broken[PUBLIC_KEY_LEN - 1] ^= 0x01;

        assert!(matches!(
            accept(&broken),
            Err(Error::AuthMessageMalformed { .. })
        ));
    }

    /// 应答里的公钥不在曲线上必须被拒绝（**在算 tag 之前**）。
    #[test]
    fn response_with_off_curve_key_is_rejected() {
        let master = new_master();
        let (challenge, verifier) = begin().expect("生成挑战");
        let responder = accept(&challenge).expect("接受挑战");
        let (signing, device_public) = device(7);
        let mut response = responder
            .respond(&master, &device_public, |message| {
                let signature: p256::ecdsa::Signature = signing.sign(message);
                signature_of(&signature.to_bytes())
            })
            .expect("生成应答");
        response[PUBLIC_KEY_LEN - 1] ^= 0x01;

        assert!(matches!(
            verifier.verify(&response, &master),
            Err(Error::AuthMessageMalformed { .. })
        ));
    }

    /// 确认标签错误必须被拒绝。
    #[test]
    fn wrong_confirmation_is_rejected() {
        let master = new_master();
        let (verified, responder, _, _) = handshake(&master);
        let mut confirmation = verified.confirmation();
        confirmation[0] ^= 0x01;

        assert!(matches!(
            confirm(&master, &responder, verified.session_id(), &confirmation),
            Err(Error::AuthProofFailed)
        ));

        // 长度不对同样必须被拒绝。
        assert!(matches!(
            confirm(
                &master,
                &responder,
                verified.session_id(),
                &confirmation[..1]
            ),
            Err(Error::AuthMessageMalformed { .. })
        ));
    }

    /// **会话标识不一致时必须拒绝**，即使标签本身是对的。
    ///
    /// 这挡住的是「把一次会话的确认标签搬到另一次会话上」。
    #[test]
    fn confirmation_with_a_mismatched_session_id_is_rejected() {
        let master = new_master();
        let (verified, responder, _, _) = handshake(&master);
        let mut wrong_session = *verified.session_id();
        wrong_session[0] ^= 0x01;

        assert!(matches!(
            confirm(
                &master,
                &responder,
                &wrong_session,
                &verified.confirmation()
            ),
            Err(Error::AuthProofFailed)
        ));
    }

    /// 用错误的 master 做确认校验必须失败。
    #[test]
    fn confirmation_with_the_wrong_master_key_is_rejected() {
        let master = new_master();
        let (verified, responder, _, _) = handshake(&master);
        let other = new_master();

        assert!(matches!(
            confirm(
                &other,
                &responder,
                verified.session_id(),
                &verified.confirmation()
            ),
            Err(Error::AuthProofFailed)
        ));
    }

    /// **两次会话的会话标识与 tag 必须都不同。**
    ///
    /// 否则攻击者可以重放整条应答。
    #[test]
    fn two_sessions_never_share_a_session_id_or_tag() {
        let master = new_master();
        let mut sessions = Vec::new();
        let mut tags = Vec::new();
        for _ in 0..8 {
            let (_, _, _, response) = handshake(&master);
            let (challenge, verifier) = begin().expect("生成挑战");
            let responder = accept(&challenge).expect("接受挑战");
            sessions.push(responder.session_id());
            tags.push(response[PUBLIC_KEY_LEN + NONCE_LEN + PUBLIC_KEY_LEN..].to_vec());
            drop(verifier);
        }

        for i in 0..sessions.len() {
            for j in (i + 1)..sessions.len() {
                assert_ne!(sessions[i], sessions[j], "两次会话出现了相同的会话标识");
                assert_ne!(tags[i], tags[j], "两次会话出现了相同的证明标签");
            }
        }
    }

    /// 应答的**长度**是固定契约。
    #[test]
    fn message_lengths_are_stable() {
        assert_eq!(CHALLENGE_LEN, 65 + 32);
        assert_eq!(RESPONSE_LEN, 65 + 32 + 65 + 32);
        assert_eq!(RESPONSE_SIGNED_LEN, RESPONSE_LEN + 64);
        assert_eq!(CONFIRM_LEN, 32);
    }

    /// 应答里**不得**出现主密钥明文。
    #[test]
    fn response_never_contains_the_master_key() {
        let master = new_master();
        let (_, _, _, response) = handshake(&master);
        assert!(
            !response
                .windows(crate::vault::MASTER_KEY_LEN)
                .any(|w| w == master.expose()),
            "应答里出现了主密钥明文"
        );
    }

    /// `Debug` 输出必须被脱敏。
    ///
    /// 秘密材料不得进入日志、错误消息或 `Debug`——这是本仓库的不可协商约束之一。
    /// 这里检查的是本模块的三个类型：临时私钥、nonce、以及派生出的确认密钥。
    #[test]
    fn debug_output_is_redacted() {
        let master = new_master();
        let (challenge, verifier) = begin().expect("生成挑战");
        let responder = accept(&challenge).expect("接受挑战");
        let (signing, device_public) = device(7);
        let response = responder
            .respond(&master, &device_public, |message| {
                let signature: p256::ecdsa::Signature = signing.sign(message);
                signature_of(&signature.to_bytes())
            })
            .expect("生成应答");
        // `Debug` 字符串必须在 `verify` 之前取：`verify` 收 `self`，会消耗 `verifier`。
        let verifier_text = format!("{verifier:?}");
        let responder_text = format!("{responder:?}");
        let verified = verifier.verify(&response, &master).expect("验证");
        let verified_text = format!("{verified:?}");

        // 主密钥的十六进制形式不得出现在任何 Debug 输出里。
        let master_hex: String = master.expose().iter().map(|b| format!("{b:02x}")).collect();
        // 双方的 nonce 也不得出现（它们是会话相关的秘密材料）。
        let responder_nonce_hex: String = responder_side_nonce(&response)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        for (what, text) in [
            ("Verifier", &verifier_text),
            ("Responder", &responder_text),
            ("Verified", &verified_text),
        ] {
            assert!(
                !text.contains(&master_hex),
                "{what} 的 Debug 输出泄露了主密钥"
            );
            assert!(
                !text.contains(&responder_nonce_hex),
                "{what} 的 Debug 输出泄露了 nonce"
            );
            // 被脱敏的字段必须是显式的占位符，而不是「碰巧没打印」。
            assert!(
                text.contains("redacted") || text.contains("bytes"),
                "{what} 的 Debug 输出没有出现脱敏占位符：{text}"
            );
        }
    }

    /// 取应答里携带的应答方 nonce（应答体的 `PUBLIC_KEY_LEN..PUBLIC_KEY_LEN+NONCE_LEN`）。
    fn responder_side_nonce(response: &[u8]) -> [u8; NONCE_LEN] {
        let mut out = [0_u8; NONCE_LEN];
        out.copy_from_slice(&response[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + NONCE_LEN]);
        out
    }

    /// 常量时间比较的行为必须正确。
    #[test]
    fn constant_time_eq_behaves() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 3]), "长度不同必须为假");
        assert!(constant_time_eq(&[], &[]));
    }
}
