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

//! 设备身份：一台设备用来向其它设备证明「我是我」的长期密钥。
//!
//! # 它解决什么问题
//!
//! 本应用没有中心服务器，也没有账号密码（见 `README`）。所以「这台设备是可信的」
//! 这件事不能靠任何第三方断言，只能靠**它自己持有的密钥**。设备身份就是那对密钥：
//! 私钥在本机硬件里生成、永不导出；公钥可以在设备之间自由传播。
//!
//! 于是「认证」有了一个具体的、可验证的含义：**对方能对一段它事先没见过的数据
//! 产出一个用某个公钥能验证通过的签名，且那个公钥的指纹与我们要找的设备一致。**
//!
//! # 为什么是 ECDSA P-256，而不是 Ed25519
//!
//! 这是一个**强约束，不是偏好**，因为私钥要放进平台硬件：
//!
//! - **Android**：KeyMint HAL 的 `Algorithm.aidl` 里只有 `RSA=1, EC=3, AES=32,
//!   TRIPLE_DES=33, HMAC=128`——**没有 EdDSA**。`KeyProperties.java` 里也没有
//!   Ed25519 常量。注意 `CURVE_25519` 确实存在，但它是 **XDH 密钥协商曲线，不是
//!   签名算法**——这是二手资料里最常见的错误。
//! - **iOS**：Apple 文档明确写着 Secure Enclave 只用 NIST P-256。
//!
//! 所以 P-256/ECDSA 是**两个移动平台上唯一能进硬件的签名算法**。选 Ed25519 就
//! 等于接受「移动端身份密钥只能软件持有」——那必须是一个显式决定，不能是事故。
//!
//! # 本模块不做什么
//!
//! 不持有私钥，也不做签名。私钥住在硬件里，签名由 `qualia2fa-keystore` 发起。
//! 本模块只负责**身份的公钥侧**：表示、指纹、以及**验签**——因为验证签名必须能被
//! 任何一台设备执行，包括那些自己根本不持有任何硬件密钥的设备。
//!
//! # 本模块不做 I/O，也不读时钟
//!
//! 时间一律由调用方传入，与库内其它模块一致。

use crate::error::{Error, Result};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

/// SEC1 未压缩点编码的固定长度：`0x04 || X(32) || Y(32)`。
///
/// 为什么固定成未压缩形式而不是压缩形式（33 字节）：未压缩形式是 Windows CNG
/// (`BCRYPT_ECCPUBLICBLOB`)、Android Keystore 与 Secure Enclave 共同的自然输出，
/// 直接取用不需要实现点压缩。省下的 32 字节在二维码里毫无意义。
pub const PUBLIC_KEY_LEN: usize = 65;

/// ECDSA P-256 原始签名的固定长度：`r(32) || s(32)`。
///
/// # 为什么线上格式用原始 `r||s` 而不是 DER
///
/// DER 编码是**变长**的：`r` 或 `s` 的最高位为 1 时前面要补一个 `0x00`，于是同一
/// 个签名的 DER 长度在 70–72 字节之间浮动。这带来两个麻烦：
///
/// 1. 长度泄漏：观察者能从签名长度反推出 `r`/`s` 的最高字节，虽然对 ECDSA 的
///    安全性没有已知影响，但这是一条没有必要的旁路。
/// 2. **可塑性**：DER 有冗余表示，同一个数学签名可以有多种合法编码，于是「签名
///    唯一」这件事需要额外论证。
///
/// 原始 `r||s` 是定长的、每个签名只有一种表示。DER 只在两个平台的边界上出现，
/// **不进协议**（Windows CNG 的 `NCryptSignHash` 恰好也直接返回 `r||s`）。
pub const SIGNATURE_LEN: usize = 64;

/// 设备身份公钥的指纹长度。
pub const DEVICE_ID_LEN: usize = 32;

/// 一台设备的身份标识：设备身份公钥的 SHA-256 指纹。
///
/// # 为什么是公钥的哈希，而不是随机数或自增计数
///
/// 设备身份是**密码学**身份：两台设备没有任何共享状态就可以各自动算出同一个
/// `DeviceId`。如果改用随机数，设备就需要一个注册表来记住「哪个 ID 对应哪把公钥」；
/// 而在一个没有中心服务器的系统里，那份注册表本身就是需要同步、需要认证、也最难
/// 保证一致的东西。
///
/// 用哈希则把「ID 与公钥必须一致」变成**结构性事实**：拿到 ID 就能从公钥重算出来
/// 并比对，无法伪造，也不需要维护。
///
/// SHA-256 在这里只用于**标识**，不承担抗碰撞以外的密码学职责——设备身份的真实性
/// 由签名保证，指纹只是一个便于比较的短名字。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId([u8; DEVICE_ID_LEN]);

impl DeviceId {
    /// 从设备身份公钥计算指纹。
    #[must_use]
    pub fn from_public_key(public_key: &DevicePublicKey) -> Self {
        let digest = Sha256::digest(public_key.as_sec1_bytes());
        let mut bytes = [0_u8; DEVICE_ID_LEN];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    /// 从 32 字节原始指纹构造。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DEVICE_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// 取原始指纹字节。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DEVICE_ID_LEN] {
        &self.0
    }

    /// 转为小写十六进制。
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(DEVICE_ID_LEN * 2);
        for byte in self.0 {
            // 手工格式化，避免为这一个用途引入 hex 依赖。
            out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            out.push(char::from_digit(u32::from(byte & 0x0F), 16).unwrap_or('0'));
        }
        out
    }
}

impl core::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl core::fmt::Debug for DeviceId {
    /// 十六进制显示，便于在日志与测试失败信息里比对。
    ///
    /// 设备身份**不是秘密**——它本来就要印在二维码上给对方看——所以这里不需要
    /// 脱敏。这是与 `OtpSecret` 一类类型的关键区别。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DeviceId({})", self.to_hex())
    }
}

/// 设备身份公钥（SEC1 未压缩点，65 字节）。
///
/// 公钥不是秘密：它会被放进二维码、写进日志、在设备之间传播。所以这个类型
/// **实现 `Debug` 的完整输出**，也**可以 `Clone`**，与秘密类型相反。
#[derive(Clone, PartialEq, Eq)]
pub struct DevicePublicKey {
    /// `0x04 || X || Y`。构造时已验证是曲线上的合法点。
    sec1: [u8; PUBLIC_KEY_LEN],
}

impl DevicePublicKey {
    /// 从 SEC1 未压缩点构造，并**验证它确实是 P-256 曲线上的点**。
    ///
    /// # 为什么必须验证
    ///
    /// 公钥来自外部输入（二维码、网络）。P-256 上存在**非法曲线攻击**：把一个
    /// 不属于曲线、而属于某个小子群的点交给对方，可以从对方的运算结果里反推出
    /// 私钥信息。虽然 ECDSA 验签本身不像 ECDH 那样直接暴露私钥，但让一个非法点
    /// 进入后续任何运算都是不必要的风险。
    ///
    /// 这里用 `p256` 的完整解析（而不是只检查长度与前缀），它内部会做曲线方程
    /// 校验。因此**非法点根本无法构造出本类型的值**。
    ///
    /// # 错误
    ///
    /// 若长度不对、前缀不是 `0x04`、或该点不在 P-256 上，返回
    /// [`Error::DevicePublicKeyInvalid`]。
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(Error::DevicePublicKeyInvalid {
                reason: "长度不是 65 字节的 SEC1 未压缩点",
            });
        }
        if bytes[0] != 0x04 {
            return Err(Error::DevicePublicKeyInvalid {
                reason: "SEC1 前缀不是 0x04（未压缩形式）",
            });
        }
        // 这一步做真正的曲线校验：点不在曲线上就会失败。
        if VerifyingKey::from_sec1_bytes(bytes).is_err() {
            return Err(Error::DevicePublicKeyInvalid {
                reason: "该点不在 P-256 曲线上",
            });
        }

        let mut sec1 = [0_u8; PUBLIC_KEY_LEN];
        sec1.copy_from_slice(bytes);
        Ok(Self { sec1 })
    }

    /// 取 SEC1 未压缩点字节。
    #[must_use]
    pub const fn as_sec1_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.sec1
    }

    /// 这台设备的身份标识。
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        DeviceId::from_public_key(self)
    }
}

impl core::fmt::Debug for DevicePublicKey {
    /// 输出为十六进制。公钥不是秘密，不需要脱敏。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DevicePublicKey(")?;
        for byte in self.sec1 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// 设备身份签名（ECDSA P-256 原始 `r||s`，64 字节）。
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceSignature([u8; SIGNATURE_LEN]);

impl DeviceSignature {
    /// 从原始 `r||s` 构造。
    ///
    /// 不在这里做范围校验：`r`/`s` 必须是 `[1, n-1]` 内的整数这一约束由
    /// **验签**负责，而验签本来就要重新计算并比对，重复一次没有意义。构造这个
    /// 类型只是说「这 64 个字节声称是一个签名」。
    ///
    /// # 错误
    ///
    /// 长度不是 64 字节时返回 [`Error::DeviceSignatureInvalid`]。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let raw: [u8; SIGNATURE_LEN] =
            bytes
                .try_into()
                .map_err(|_| Error::DeviceSignatureInvalid {
                    reason: "长度不是 64 字节的原始 r||s",
                })?;
        Ok(Self(raw))
    }

    /// 取原始 `r||s` 字节。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for DeviceSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DeviceSignature(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// 用某个设备公钥验证它对 `message` 的签名。
///
/// # 验证的是消息，不是摘要
///
/// 平台硬件只接受**摘要**（Windows CNG 的 `NCryptSignHash` 形参就叫
/// `pbHashValue`），所以签名侧必须先做一次 SHA-256。本函数接收**原始消息**并
/// 自己做同样的哈希，这样调用方不需要在两处保持哈希算法一致——那是很容易写错的
/// 地方，而且错了以后表现为「签名验证莫名失败」。
///
/// 需要明确：这里用的是 ECDSA 的**标准哈希模式**（`Signer`/`Verifier`），它内部
/// 完成哈希。**不要**把已经算好的摘要再传进来。
///
/// # 错误
///
/// 签名格式非法或验证不通过，都返回 [`Error::DeviceSignatureInvalid`]。
/// **两者刻意不区分**：调用方能做的应对完全相同（拒绝这次认证），而区分它们
/// 只会给攻击者一个微小的预言机。
#[must_use = "验证结果必须被检查，丢弃它等于没有验证"]
pub fn verify(
    public_key: &DevicePublicKey,
    message: &[u8],
    signature: &DeviceSignature,
) -> Result<()> {
    // 公钥在 `from_sec1_bytes` 时已验证过是曲线上的点，这里的失败属于内部矛盾，
    // 但仍然返回错误而不是 panic——库内任何路径都不得 panic。
    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key.as_sec1_bytes()).map_err(|_| {
            Error::DeviceSignatureInvalid {
                reason: "公钥无法解析（不应发生：构造时已验证）",
            }
        })?;

    let signature =
        Signature::from_slice(signature.as_bytes()).map_err(|_| Error::DeviceSignatureInvalid {
            reason: "签名不是合法的 P-256 r||s",
        })?;

    verifying_key
        .verify(message, &signature)
        .map_err(|_| Error::DeviceSignatureInvalid {
            reason: "签名与公钥或消息不匹配",
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    /// 造一对测试用密钥（软件生成，只用于测试）。
    fn test_key() -> (SigningKey, DevicePublicKey) {
        // 固定标量，保证测试可复现。
        let signing = SigningKey::from_slice(&[7_u8; 32]).expect("合法标量");
        let sec1 = signing.verifying_key().to_sec1_point(false);
        let public = DevicePublicKey::from_sec1_bytes(sec1.as_bytes()).expect("合法点");
        (signing, public)
    }

    /// 用软件密钥对消息签名，产出我们的线格式。
    fn sign(signing: &SigningKey, message: &[u8]) -> DeviceSignature {
        let sig: Signature = signing.sign(message);
        DeviceSignature::from_bytes(&sig.to_bytes()).expect("64 字节")
    }

    /// 完整往返：签了就能验过。
    #[test]
    fn valid_signature_verifies() {
        let (signing, public) = test_key();
        let message = b"\x01Qualia2FA test message";
        let signature = sign(&signing, message);
        assert!(verify(&public, message, &signature).is_ok());
    }

    /// 改一个 bit 的消息必须验不过。
    #[test]
    fn modified_message_fails() {
        let (signing, public) = test_key();
        let mut message = *b"hello qualia2fa!";
        let signature = sign(&signing, &message);
        message[0] ^= 0x01;
        assert!(verify(&public, &message, &signature).is_err());
    }

    /// 改一个 bit 的签名必须验不过。
    #[test]
    fn modified_signature_fails() {
        let (signing, public) = test_key();
        let message = b"hello qualia2fa!";
        let signature = sign(&signing, message);
        for index in [0_usize, 31, 32, 63] {
            let mut raw = *signature.as_bytes();
            raw[index] ^= 0x01;
            let tampered = DeviceSignature::from_bytes(&raw).expect("仍是 64 字节");
            assert!(
                verify(&public, message, &tampered).is_err(),
                "第 {index} 字节被改动却通过了验证"
            );
        }
    }

    /// 用另一把密钥的公钥验证必须失败。
    #[test]
    fn wrong_public_key_fails() {
        let (signing, _) = test_key();
        let other = SigningKey::from_slice(&[9_u8; 32]).expect("合法标量");
        let other_sec1 = other.verifying_key().to_sec1_point(false);
        let other_public = DevicePublicKey::from_sec1_bytes(other_sec1.as_bytes()).expect("合法点");

        let message = b"hello qualia2fa!";
        let signature = sign(&signing, message);
        assert!(verify(&other_public, message, &signature).is_err());
    }

    /// **非法曲线攻击**：不在 P-256 上的点必须被拒绝，而不是被接受。
    #[test]
    fn off_curve_point_is_rejected() {
        // 取一个几乎肯定不在曲线上的点：X 为 1，Y 为 1。
        let mut bytes = [0_u8; PUBLIC_KEY_LEN];
        bytes[0] = 0x04;
        bytes[32] = 1;
        bytes[64] = 1;
        assert!(
            DevicePublicKey::from_sec1_bytes(&bytes).is_err(),
            "不在曲线上的点被接受了——这会导致非法曲线攻击"
        );
    }

    /// 长度与前缀都要检查。
    #[test]
    fn malformed_public_key_is_rejected() {
        assert!(DevicePublicKey::from_sec1_bytes(&[]).is_err());
        assert!(DevicePublicKey::from_sec1_bytes(&[0x04; 64]).is_err());
        assert!(DevicePublicKey::from_sec1_bytes(&[0x04; 66]).is_err());

        // 压缩形式（0x02/0x03 前缀）不被接受：我们的线格式是未压缩点。
        let (_, public) = test_key();
        let mut compressed = *public.as_sec1_bytes();
        compressed[0] = 0x02;
        assert!(
            DevicePublicKey::from_sec1_bytes(&compressed).is_err(),
            "压缩形式不应被接受"
        );
    }

    /// 签名的长度必须严格是 64。
    #[test]
    fn malformed_signature_is_rejected() {
        assert!(DeviceSignature::from_bytes(&[]).is_err());
        assert!(DeviceSignature::from_bytes(&[0_u8; 63]).is_err());
        assert!(DeviceSignature::from_bytes(&[0_u8; 65]).is_err());
    }

    /// `DeviceId` 必须由公钥唯一决定，且与公钥一致。
    #[test]
    fn device_id_is_derived_from_public_key() {
        let (_, public) = test_key();
        let id = public.device_id();
        assert_eq!(id, DeviceId::from_public_key(&public));
        assert_eq!(id.as_bytes().len(), DEVICE_ID_LEN);
        assert_eq!(id.to_hex().len(), DEVICE_ID_LEN * 2);

        // 另一把密钥必须给出不同的 ID。
        let (_, other) = {
            let signing = SigningKey::from_slice(&[9_u8; 32]).expect("合法标量");
            let sec1 = signing.verifying_key().to_sec1_point(false);
            let public = DevicePublicKey::from_sec1_bytes(sec1.as_bytes()).expect("合法点");
            (signing, public)
        };
        assert_ne!(id, other.device_id());
    }

    /// `Debug` 输出包含完整的十六进制，用于日志与测试失败信息。
    #[test]
    fn debug_shows_hex() {
        let (_, public) = test_key();
        let text = format!("{public:?}");
        assert!(text.starts_with("DevicePublicKey(04"), "实际: {text}");
        assert_eq!(
            text.len(),
            "DevicePublicKey(".len() + PUBLIC_KEY_LEN * 2 + 1
        );
        assert_eq!(public.device_id().to_string().len(), DEVICE_ID_LEN * 2);
    }
}
