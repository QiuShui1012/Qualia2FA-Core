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

//! RFC 官方测试向量——**这是 M1 的验收标准**。
//!
//! 这些向量来自规范正文，不是本仓库自己生成的。任何一条失败都意味着实现不符合
//! 标准，也就意味着真实用户会拿到错误的验证码。
//!
//! | 规范 | 出处 | 覆盖 |
//! |---|---|---|
//! | RFC 4226 | 附录 D | HMAC-SHA-1 HOTP 的 10 组向量 |
//! | RFC 6238 | 附录 B | SHA-1 / SHA-256 / SHA-512 三套 TOTP 向量 |
//! | RFC 6238 | 附录 A | 种子构造方式（用于复现附录 B） |
//! | RFC 4648 | §10 | Base32 编解码向量（见 `src/base32.rs` 单元测试） |
//!
//! # 为什么单独放一个文件
//!
//! 这些向量是**对外承诺**，不是实现细节。作为独立集成测试文件，审阅者可以一眼
//! 看到覆盖全貌，而不必在实现代码里翻找。修改它们必须同时修改规范依据。

use qualia2fa_core::otp::{self, Algorithm, Digits, OtpSecret};

/// RFC 4226 与 RFC 6238 使用的 ASCII 种子 `"12345678901234567890"`。
///
/// 这不是随机种子，而是规范为了便于复现而选的固定值，**绝不可**在生产中使用。
const RFC_SECRET_ASCII: &[u8] = b"12345678901234567890";

/// RFC 6228 附录 A 说明：SHA-256 与 SHA-512 的种子分别是 SHA-1 种子的重复延伸。
///
/// 原文（RFC 6238 §Appendix A）写明 SHA-1 用 20 字节、SHA-256 用 32 字节、
/// SHA-512 用 64 字节，且后两者由前者重复填充而成。这里按规范构造。
fn seed_of_len(len: usize) -> Vec<u8> {
    let mut seed = Vec::with_capacity(len);
    while seed.len() < len {
        seed.extend_from_slice(RFC_SECRET_ASCII);
    }
    seed.truncate(len);
    seed
}

/// RFC 4226 附录 D —— HOTP 全部 10 组向量。
///
/// 附录 D 的表格给出 `Count` 从 0 到 9 对应的 6 位十进制 HOTP 值。
#[test]
fn rfc4226_appendix_d_all_ten_vectors() {
    /// 附录 D 表格的逐行抄录（计数器, 期望的 6 位码）。
    const VECTORS: [(u64, &str); 10] = [
        (0, "755224"),
        (1, "287082"),
        (2, "359152"),
        (3, "969429"),
        (4, "338314"),
        (5, "254676"),
        (6, "287922"),
        (7, "162583"),
        (8, "399871"),
        (9, "520489"),
    ];

    let secret = OtpSecret::from_bytes(RFC_SECRET_ASCII.to_vec()).expect("种子非空");

    for (counter, expected) in VECTORS {
        let got = otp::hotp_code(&secret, counter, Algorithm::Sha1, Digits::Six);
        assert_eq!(
            got, expected,
            "RFC 4226 附录 D 计数器 {counter} 不符：期望 {expected}，实际 {got}"
        );
    }
}

/// RFC 6238 附录 B —— TOTP 三套向量。
///
/// 附录 B 给出 6 个时间点（T = 59、1111111109、1111111111、1234567890、
/// 2000000000、20000000000），每个时间点在三种算法下各有一个 8 位期望值。
///
/// 注意**位数是 8**——这是附录 B 表格的形式，与附录 D 的 6 位不同。
#[test]
fn rfc6238_appendix_b_sha1_vectors() {
    const VECTORS: [(u64, &str); 6] = [
        (59, "94287082"),
        (1_111_111_109, "07081804"),
        (1_111_111_111, "14050471"),
        (1_234_567_890, "89005924"),
        (2_000_000_000, "69279037"),
        (20_000_000_000, "65353130"),
    ];

    let secret = OtpSecret::from_bytes(seed_of_len(20)).expect("种子非空");

    for (time, expected) in VECTORS {
        let got =
            otp::totp_code(&secret, time, 30, Algorithm::Sha1, Digits::Eight).expect("period 非零");
        assert_eq!(
            got, expected,
            "RFC 6238 附录 B (SHA-1) T={time} 不符：期望 {expected}，实际 {got}"
        );
    }
}

#[test]
fn rfc6238_appendix_b_sha256_vectors() {
    const VECTORS: [(u64, &str); 6] = [
        (59, "46119246"),
        (1_111_111_109, "68084774"),
        (1_111_111_111, "67062674"),
        (1_234_567_890, "91819424"),
        (2_000_000_000, "90698825"),
        (20_000_000_000, "77737706"),
    ];

    let secret = OtpSecret::from_bytes(seed_of_len(32)).expect("种子非空");

    for (time, expected) in VECTORS {
        let got = otp::totp_code(&secret, time, 30, Algorithm::Sha256, Digits::Eight)
            .expect("period 非零");
        assert_eq!(
            got, expected,
            "RFC 6238 附录 B (SHA-256) T={time} 不符：期望 {expected}，实际 {got}"
        );
    }
}

#[test]
fn rfc6238_appendix_b_sha512_vectors() {
    const VECTORS: [(u64, &str); 6] = [
        (59, "90693936"),
        (1_111_111_109, "25091201"),
        (1_111_111_111, "99943326"),
        (1_234_567_890, "93441116"),
        (2_000_000_000, "38618901"),
        (20_000_000_000, "47863826"),
    ];

    let secret = OtpSecret::from_bytes(seed_of_len(64)).expect("种子非空");

    for (time, expected) in VECTORS {
        let got = otp::totp_code(&secret, time, 30, Algorithm::Sha512, Digits::Eight)
            .expect("period 非零");
        assert_eq!(
            got, expected,
            "RFC 6238 附录 B (SHA-512) T={time} 不符：期望 {expected}，实际 {got}"
        );
    }
}

/// 交叉验证：用手写 HMAC-SHA-1 独立复现 RFC 4226 附录 D 的第一组。
///
/// # 为什么需要这条
///
/// 上面的向量测试验证的是 `hmac_truncate` + `hotp` 的**整体**结果。若动态截断
/// 与 HMAC 调用**同时**出错，整体结果可能碰巧吻合（虽然概率极低）。
/// 这里用 `hmac`/`sha1` 直接算一遍，并手写截断与取模，从另一条路径得到同一个值。
///
/// 这条同时是对「改用 `SimpleHmac` 不影响结果」的验证——它走的是同一 API，
/// 但绕开了本模块的分派与截断代码。
#[test]
fn cross_check_hotp_counter_zero_against_manual_hmac() {
    use hmac::digest::{Digest, KeyInit, Mac};

    let mut mac = <hmac::SimpleHmac<sha1::Sha1> as KeyInit>::new_from_slice(RFC_SECRET_ASCII)
        .expect("HMAC 接受任意长度密钥");
    Mac::update(&mut mac, &0_u64.to_be_bytes());
    let digest = Mac::finalize(mac).into_bytes();

    // 手写动态截断。
    let offset = usize::from(digest[19] & 0x0f);
    let bin = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    let manual = format!("{:06}", bin % 1_000_000);

    assert_eq!(manual, "755224", "手写实现应与 RFC 4226 附录 D 一致");

    // 本模块的结果必须与手写一致。
    let secret = OtpSecret::from_bytes(RFC_SECRET_ASCII.to_vec()).expect("种子非空");
    assert_eq!(
        otp::hotp_code(&secret, 0, Algorithm::Sha1, Digits::Six),
        manual
    );

    // 顺带确认 SHA-1 摘要就是 20 字节（下面用到 `digest[19]`）。
    let sha1_len = <sha1::Sha1 as Digest>::output_size();
    assert_eq!(sha1_len, 20, "SHA-1 输出长度应为 20 字节");
}

/// 8 位与 6 位的期望值必须自洽。
///
/// RFC 6238 附录 B 用 8 位，RFC 4226 附录 D 用 6 位；两者是同一个截断值对
/// 不同模数取模的结果。验证这一点可以抓住「位数没有真正生效」这类 bug。
#[test]
fn digit_count_actually_changes_the_modulus() {
    let secret = OtpSecret::from_bytes(RFC_SECRET_ASCII.to_vec()).expect("种子非空");
    let counter = 1_u64;

    // 同一个计数器、同一个算法，只有位数不同。
    let six = otp::hotp_code(&secret, counter, Algorithm::Sha1, Digits::Six);
    let eight = otp::hotp_code(&secret, counter, Algorithm::Sha1, Digits::Eight);

    assert_eq!(six.len(), 6);
    assert_eq!(eight.len(), 8);
    // 6 位码应是 8 位码的后 6 位（对同一个二进制值取不同模数）。
    assert_eq!(
        &eight[eight.len() - 6..],
        six,
        "6 位码应是 8 位码对 10^6 取模的结果"
    );

    // RFC 4226 附录 D 计数器 1 的期望值。
    assert_eq!(six, "287082");
}

/// 7 位在 RFC 里没有向量，但必须在数学上与 6/8 位自洽。
#[test]
fn seven_digits_is_self_consistent() {
    let secret = OtpSecret::from_bytes(RFC_SECRET_ASCII.to_vec()).expect("种子非空");
    let seven = otp::hotp_code(&secret, 1, Algorithm::Sha1, Digits::Seven);
    let eight = otp::hotp_code(&secret, 1, Algorithm::Sha1, Digits::Eight);

    assert_eq!(seven.len(), 7);
    assert_eq!(
        &eight[eight.len() - 7..],
        seven,
        "7 位码应是 8 位码对 10^7 取模的结果"
    );
}

/// 前导零必须保留——这是最容易被「数值化」实现弄丢的细节。
///
/// 用 Base32 种子 `"JBSWY3DPEHPK3PXP"` 在一个固定时间点得到一个带前导零的码，
/// 若实现把结果当整数显示，就会漏掉前导零而给出错误的验证码。
#[test]
fn leading_zeros_are_preserved_in_output() {
    // 先找出一个确实带前导零的时间点，避免硬编码一个可能变化的期望值。
    let secret = OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("合法 Base32 种子");

    let mut found_leading_zero = false;
    for step in 0_u64..200 {
        let code = otp::totp_code(&secret, step * 30, 30, Algorithm::Sha1, Digits::Six)
            .expect("period 非零");
        assert_eq!(code.len(), 6, "任何情况下都必须是 6 位：{code}");
        assert!(
            code.chars().all(|c| c.is_ascii_digit()),
            "必须全是 ASCII 数字：{code}"
        );
        if code.starts_with('0') {
            found_leading_zero = true;
            // 数值本身应小于 10^5，且格式化后仍补齐到 6 位。
            let numeric: u32 = code.parse().expect("应可解析为数字");
            assert!(numeric < 100_000, "带前导零的码应小于 100000：{code}");
            assert_eq!(otp::format_code(numeric, Digits::Six), code);
        }
    }
    assert!(
        found_leading_zero,
        "200 个时间步内未出现前导零案例，本测试未能覆盖目标场景"
    );
}
