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

//! Fuzz target: Base32 encoding/decoding and OTP computation.
//!
//! # Input surface
//!
//! Base32 is the path every seed takes to enter the system: it maps a string of
//! arbitrary length to a byte sequence of a different length, involving bit
//! alignment, trailing-remainder handling and padding validation. This input is
//! untrusted and comes directly from a QR code.
//!
//! # Properties covered
//!
//! 1. **Never panics** — `decode` and `decode_strict` must return for any string.
//! 2. **Exact round-trip** — `decode(encode(bytes)) == bytes` for any byte
//!    sequence.
//! 3. **Relation between the two modes** — whatever the strict mode accepts, the
//!    lenient mode must accept as well (strict is a subset of lenient). The
//!    converse does not hold, and that is not a defect: the lenient mode exists
//!    to accept the non-canonical encodings produced by other authenticators.
//! 4. **OTP output shape** — for any seed and any counter the code must always be
//!    fixed-width decimal. This guards against bugs such as dropping leading
//!    zeros by treating the code as an integer.
//!
//! Preconditions: no feature flags, and no valid skeleton has to be built to
//! bypass AEAD — the target consumes arbitrary bytes as they are.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia2fa_core::base32;
use qualia2fa_core::otp::{self, Algorithm, Digits, OtpSecret};
use qualia2fa_core::ExposeSecret;

fuzz_target!(|data: &[u8]| {
    // ── 0. Empty input is explicitly rejected (an empty seed is meaningless) ──
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

    // ── 1. Arbitrary bytes → Base32 → decode must round-trip exactly ────────
    let encoded = base32::encode(data);
    let decoded = base32::decode_strict(&encoded)
        .expect("自己编码出的规范形式必须能被严格模式解码");
    assert_eq!(
        decoded.expose_secret(),
        data,
        "Base32 往返不精确：原文 {} 字节，编码 {encoded}",
        data.len()
    );

    let unpadded = encoded.trim_end_matches('=');
    let decoded_unpadded = base32::decode(unpadded).expect("无填充形式必须可解码");
    assert_eq!(
        decoded_unpadded.expose_secret(),
        data,
        "无填充往返不精确：{unpadded}"
    );

    assert_eq!(
        base32::encode(decoded_unpadded.expose_secret()),
        encoded,
        "重新编码的结果与首次编码不一致"
    );

    // ── 2. Arbitrary text → both decode modes, neither may panic ────────────
    let text = String::from_utf8_lossy(data);

    let lenient = base32::decode(&text);
    let strict = base32::decode_strict(&text);

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

    // ── 3. Compute OTP from the decoded seed and verify the output shape ────
    if let Ok(bytes) = strict
        && !bytes.expose_secret().is_empty()
    {
        let secret = OtpSecret::from_bytes(bytes.expose_secret().to_vec())
            .expect("已确认非空");

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
                let numeric: u64 = code.parse().expect("码应可解析为数字");
                assert!(
                    numeric < 10_u64.pow(digits.count()),
                    "码超出位数范围：{code}"
                );
                assert_eq!(
                    otp::format_code(otp::hotp(&secret, counter, algorithm, digits), digits),
                    code
                );
            }
        }

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

        assert!(otp::verify_code(&totp_code, &totp_code));
    }
});
