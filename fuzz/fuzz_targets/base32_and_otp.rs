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

//! fuzz 目标：Base32 编解码与 OTP 计算。
//!
//! # 为什么要单独 fuzz Base32
//!
//! Base32 是**所有种子进入系统的必经之路**——它把一个长度任意的字符串映射成
//! 长度不同的字节序列，涉及位对齐、尾部余数处理与填充校验。这类「位级搬运」
//! 代码是越界和差一错误的经典温床，而它的输入直接来自二维码。
//!
//! # 覆盖的性质
//!
//! 1. **绝不 panic**——`decode` 与 `decode_strict` 对任意字符串都必须返回。
//! 2. **往返精确**——`decode(encode(bytes)) == bytes`，对任意字节序列成立。
//! 3. **两种模式的关系**——严格模式接受的输入，宽容模式也必须接受
//!    （严格是宽容的子集）。反向不成立，但这不构成缺陷：宽容模式的存在
//!    意义就是接受其它认证器产出的非规范编码。
//! 4. **OTP 输出形状**——任意种子、任意计数器下，码必须恒为定宽十进制。
//!    这是「把码当整数处理就会丢前导零」这类 bug 的防线。

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia2fa_core::base32;
use qualia2fa_core::otp::{self, Algorithm, Digits, OtpSecret};
use qualia2fa_core::ExposeSecret;

fuzz_target!(|data: &[u8]| {
    // ── 0. 空输入是**明确拒绝**的（空种子无意义）──────────────────────
    // 这条必须单独处理：`encode([])` 合法地返回空串，而解码端会正确拒绝它。
    // 最初把「往返必须成功」写成无条件断言，于是 fuzz 一启动就在 `data` 为空时
    // 报假阳性。库的行为是对的，错的是断言。
    if data.is_empty() {
        assert!(
            base32::decode("").is_err(),
            "空输入必须被拒绝（空种子无意义）"
        );
        assert!(
            base32::decode_strict("").is_err(),
            "空输入必须被严格模式拒绝"
        );
        return;
    }

    // ── 1. 任意字节序列 → Base32 → 解码，必须精确还原 ──────────────────
    let encoded = base32::encode(data);
    let decoded = base32::decode_strict(&encoded)
        .expect("自己编码出的规范形式必须能被严格模式解码");
    assert_eq!(
        decoded.expose_secret(),
        data,
        "Base32 往返不精确：原文 {} 字节，编码 {encoded}",
        data.len()
    );

    // 无填充形式同样必须可解码（真实世界绝大多数种子无填充）。
    let unpadded = encoded.trim_end_matches('=');
    let decoded_unpadded = base32::decode(unpadded).expect("无填充形式必须可解码");
    assert_eq!(
        decoded_unpadded.expose_secret(),
        data,
        "无填充往返不精确：{unpadded}"
    );

    // 两处编码必须一致——`decode_strict` 的输入是规范形式。
    assert_eq!(
        base32::encode(decoded_unpadded.expose_secret()),
        encoded,
        "重新编码的结果与首次编码不一致"
    );

    // ── 2. 任意文本 → 两种解码模式，均不得 panic ────────────────────────
    // fuzz 输入不保证是合法 UTF-8，用 lossy 转换保留信息。
    let text = String::from_utf8_lossy(data);

    let lenient = base32::decode(&text);
    let strict = base32::decode_strict(&text);

    // 严格模式接受的，宽容模式也必须接受（含错误类型也应一致地成功）。
    // 注意：这里比较的是「都成功」这一事实，而不是错误内容——两种模式在
    // 非规范填充上的错误类型本就不同。
    if let Ok(from_strict) = &strict {
        assert!(
            lenient.is_ok(),
            "严格模式接受了 {text:?}，宽容模式却拒绝"
        );
        assert_eq!(
            from_strict.expose_secret(),
            lenient.expect("已确认成功").expose_secret(),
            "两种模式对同一输入给出不同结果：{text:?}"
        );
    }

    // ── 3. 用解码出的种子算 OTP，验证输出形状 ──────────────────────────
    // 只在解码成功且非空时继续；空种子会被 `OtpSecret` 拒绝（这是设计如此）。
    if let Ok(bytes) = strict
        && !bytes.expose_secret().is_empty()
    {
        let secret = OtpSecret::from_bytes(bytes.expose_secret().to_vec())
            .expect("已确认非空");

        // 用输入的字节派生计数器，使 fuzzer 能同时变异种子与计数器。
        let counter = u64::from_le_bytes([
            data.first().copied().unwrap_or(0),
            data.get(1).copied().unwrap_or(0),
            data.get(2).copied().unwrap_or(0),
            data.get(3).copied().unwrap_or(0),
            data.get(4).copied().unwrap_or(0),
            data.get(5).copied().unwrap_or(0),
            data.get(6).copied().unwrap_or(0),
            data.get(7).copied().unwrap_or(0),
        ]);

        for algorithm in [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512] {
            for digits in [Digits::Six, Digits::Seven, Digits::Eight] {
                let code = otp::hotp_code(&secret, counter, algorithm, digits);
                assert_eq!(
                    code.len(),
                    digits.count() as usize,
                    "码长不符：{code}（{algorithm:?}/{digits:?}）"
                );
                assert!(
                    code.bytes().all(|b| b.is_ascii_digit()),
                    "码含非数字字符：{code}"
                );
                // 数值必须落在 [0, 10^digits)。
                let numeric: u64 = code.parse().expect("码应可解析为数字");
                assert!(
                    numeric < 10_u64.pow(digits.count()),
                    "码超出位数范围：{code}"
                );
                // `format_code` 与 `hotp` 必须一致。
                assert_eq!(
                    otp::format_code(otp::hotp(&secret, counter, algorithm, digits), digits),
                    code
                );
            }
        }

        // TOTP 与 Steam：周期非零时必须成功，且形状固定。
        let time = counter;
        let totp_code = otp::totp_code(&secret, time, 30, Algorithm::Sha1, Digits::Six)
            .expect("周期非零");
        assert_eq!(totp_code.len(), 6);

        let steam = otp::steam_guard_code(&secret, time, 30, Algorithm::Sha1)
            .expect("周期非零");
        assert_eq!(steam.chars().count(), otp::STEAM_DIGITS);
        const STEAM_ALPHABET: &str = "23456789BCDFGHJKMNPQRTVWXY";
        assert!(
            steam.chars().all(|c| STEAM_ALPHABET.contains(c)),
            "Steam 码含字母表外字符：{steam}"
        );

        // 校验函数自反。
        assert!(otp::verify_code(&totp_code, &totp_code));
    }
});
