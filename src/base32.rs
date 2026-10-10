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

//! Base32 编解码（RFC 4648 §6）。
//!
//! 这是**攻击者可控的输入面**（二维码内容、用户手输的种子），因此实现取向是
//! 「宁可拒绝，不可猜测」：任何歧义输入都返回错误，绝不静默修正。
//!
//! # 刻意支持的宽容度
//!
//! 真实世界的 `otpauth://` 种子并非都严格规范，以下宽容是必要的，否则用户会
//! 遇到「扫码失败但别的应用能扫」的困惑：
//!
//! - **大小写不敏感**：RFC 4648 规定编码用大写，但小写同样接受。
//! - **容忍缺失 `=` 填充**：大量生成器省略填充。
//! - **容忍 ASCII 空白**：用户从网页复制种子时常带空格或换行。
//!
//! # 刻意拒绝的输入
//!
//! - **非字母表字符**（含 `0`、`1`、`8`、`9` 这类易与字母混淆的数字）——
//!   拒绝而非猜测，因为猜错会得到一个「看起来能用的错误密钥」，
//!   用户直到收不到验证码才会发现。
//! - **非法长度**：合法 Base32 长度模 8 只能是 `0, 2, 4, 5, 7`。
//!   其余长度（1、3、6）意味着输入被截断或损坏。
//! - **非零填充位**（仅 [`decode_strict`] 拒绝，[`decode`] 接受）——见下。
//!
//! # 关于填充比特：宽容模式与严格模式
//!
//! RFC 4648 允许最后一个字符携带**未使用**的填充比特。需要说清楚的是：
//! **RFC 的官方测试向量全部恰好为零填充比特**，但那是所选用例的巧合，不是保证。
//! 因此「拒绝非零填充位」会误拒大量**完全合法**的编码。
//!
//! 本模块因此分成两个入口：
//!
//! | 函数 | 非零填充位 | 用途 |
//! |---|---|---|
//! | [`decode`] | **接受**（与各家认证器一致） | 接受用户/二维码导入的种子 |
//! | [`decode_strict`] | **拒绝** | 校验我们自己 [`encode`] 的输出是否规范 |
//!
//! 宽容不构成安全弱点：解码结果由**有效**比特唯一决定，填充比特无法改变它，
//! 所以非规范编码不会解出「另一个密钥」。
//!
//! # 为什么不用现成的 `base32` crate
//!
//! 查证时其最新版本是 **1.0.0-rc.1（预发布）**，且无法满足上述「精确拒绝规则」
//! 与自定义错误类型的需要。本实现约 100 行且被 RFC 向量与 fuzz 覆盖，
//! 少一个依赖更可控。

use crate::{Error, Result, SecretBytes};

/// Base32 字母表（RFC 4648 §6，标准大写形式）。
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 单个 Base32 字符承载 5 比特。
const BITS_PER_CHAR: usize = 5;

/// 把单个 ASCII 字符映射为 5 比特值。
///
/// 大小写等价；空白字符被调用方先行剔除，故此处遇到空白返回 `None`。
const fn decode_char(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a'),
        b'2'..=b'7' => Some(byte - b'2' + 26),
        _ => None,
    }
}

/// 剔除 ASCII 空白与 `=` 填充后，返回有效字符数所需的输出字节数。
///
/// `count` 是去掉填充后的有效字符数。用整数运算而非浮点，避免精度问题。
const fn output_len_for(count: usize) -> Option<usize> {
    match count % 8 {
        0 => Some(count / 8 * 5),
        2 => Some(count / 8 * 5 + 1),
        4 => Some(count / 8 * 5 + 2),
        5 => Some(count / 8 * 5 + 3),
        7 => Some(count / 8 * 5 + 4),
        // 1、3、6 不是合法余数：输入被截断或损坏。
        _ => None,
    }
}

/// 解码 Base32 字符串为秘密字节（**宽容**模式，用于接受外部输入）。
///
/// 返回值是 [`SecretBytes`]，因为解码结果在 2FA 场景下几乎总是 OTP 种子。
///
/// # 错误
///
/// - [`Error::Base32InvalidCharacter`]：出现字母表之外的字符，或填充 `=` 之后又出现数据。
///   `index` 是它在**剔除空白后**的字符序列中的位置，便于定位。
/// - [`Error::Base32InvalidLength`]：有效字符数模 8 不是 `0/2/4/5/7`。
/// - [`Error::SecretTooShort`]：解码结果为空。
///
/// # 为什么不检查尾部填充比特
///
/// RFC 4648 允许最后一个字符携带**未使用**的填充比特，其值不参与解码结果。
/// 成熟实现（含各家认证器）普遍**忽略**这些比特，因此本函数也忽略，以保证
/// 「别的应用能导入的种子我们也能导入」。
///
/// 这不构成安全弱点：解码结果由**有效**比特唯一决定，填充比特无法改变它，
/// 所以非规范编码不会解出「另一个密钥」。若需要确认编码本身是否规范
/// （例如校验我们自己 `encode` 的输出），用 [`decode_strict`]。
///
/// # 示例
///
/// ```
/// use qualia2fa_core::{base32, ExposeSecret};
///
/// // RFC 4648 §10 的 "foobar" 测试向量
/// let decoded = base32::decode("MZXW6YTBOI======").expect("向量应能解码");
/// assert_eq!(decoded.expose_secret(), b"foobar");
/// ```
pub fn decode(input: &str) -> Result<SecretBytes> {
    decode_inner(input, false)
}

/// 解码 Base32 字符串，并**额外**要求尾部填充比特为零（规范形式）。
///
/// 仅用于确认编码是 RFC 4648 的规范形式，例如验证本模块 [`encode`] 的输出、
/// 或校验我们自己生成的恢复材料。
///
/// **不要**用它对用户导入的种子做校验——许多合法生成器会产出非规范但完全
/// 有效的编码，用本函数会误拒（见 [`decode`] 的说明）。
///
/// # 错误
///
/// 在 [`decode`] 的全部错误之外，追加 [`Error::Base32InvalidPadding`]：
/// 最后一个字符的未使用比特非零。
pub fn decode_strict(input: &str) -> Result<SecretBytes> {
    decode_inner(input, true)
}

/// [`decode`] 与 [`decode_strict`] 的共同实现。
///
/// `require_canonical` 为真时额外检查尾部填充比特。
fn decode_inner(input: &str, require_canonical: bool) -> Result<SecretBytes> {
    // 第一遍：剔除空白与填充，同时校验字母表。
    // 手写循环而非 iterator chain，是为了让 `index` 指向剔除后的位置——错误信息
    // 里给出「第几个有效字符」比给出原始字节偏移更有用。
    let mut valid = 0_usize;
    let mut seen_padding = false;
    for (index, &byte) in input.as_bytes().iter().enumerate() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            seen_padding = true;
            continue;
        }
        if seen_padding {
            // 填充之后又出现有效字符，说明输入形如 "AB=CD"，是损坏的。
            return Err(Error::Base32InvalidCharacter { index });
        }
        if decode_char(byte).is_none() {
            return Err(Error::Base32InvalidCharacter { index });
        }
        valid += 1;
    }

    let Some(byte_len) = output_len_for(valid) else {
        return Err(Error::Base32InvalidLength { length: valid });
    };
    if byte_len == 0 {
        return Err(Error::SecretTooShort {
            required: 1,
            actual: 0,
        });
    }

    // 第二遍：逐字符累积比特。用 u64 缓冲避免为少量比特分配 Vec。
    let mut out = Vec::with_capacity(byte_len);
    let mut buffer: u64 = 0;
    let mut buffered_bits = 0_u32;

    for &byte in input.as_bytes() {
        if byte.is_ascii_whitespace() || byte == b'=' {
            continue;
        }
        // 已在第一遍校验过，这里不可能失败；用 let-else 而非 unwrap 以满足
        // 「库内禁 panic」的约定。
        let Some(value) = decode_char(byte) else {
            return Err(Error::Base32InvalidCharacter { index: 0 });
        };
        buffer = (buffer << BITS_PER_CHAR) | u64::from(value);
        buffered_bits += BITS_PER_CHAR as u32;
        if buffered_bits >= 8 {
            buffered_bits -= 8;
            out.push((buffer >> buffered_bits) as u8);
        }
    }

    // 仅在严格模式下检查尾部填充比特。
    //
    // 注意 `buffer` 里的高位可能残留**已输出**的比特，所以必须只取最低
    // `buffered_bits` 位来判定——这正是下面掩码的作用，漏掉它会误判。
    if require_canonical && buffered_bits > 0 {
        let residual_mask = (1_u64 << buffered_bits) - 1;
        if buffer & residual_mask != 0 {
            return Err(Error::Base32InvalidPadding);
        }
    }

    debug_assert_eq!(out.len(), byte_len, "容量计算与实际写入不一致");
    Ok(out.into())
}

/// 把秘密字节编码为 Base32 字符串（**带** `=` 填充，标准形式）。
///
/// 本项目主要用于测试往返性质与生成给用户抄写的恢复材料；
/// 解析方向才是攻击者可控的入口。
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u64 = 0;
    let mut buffered_bits = 0_u32;

    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        buffered_bits += 8;
        while buffered_bits >= BITS_PER_CHAR as u32 {
            buffered_bits -= BITS_PER_CHAR as u32;
            let index = ((buffer >> buffered_bits) & 0x1f) as usize;
            // ALPHABET 固定 32 项，索引来自 5 比特掩码，恒在范围内。
            out.push(char::from(ALPHABET[index]));
        }
    }

    // 不足 5 比特的尾部左移补零成为最后一个字符。
    if buffered_bits > 0 {
        let index = ((buffer << (BITS_PER_CHAR as u32 - buffered_bits)) & 0x1f) as usize;
        out.push(char::from(ALPHABET[index]));
    }

    // 补齐到 8 的倍数（RFC 4648 §6 规定填充）。
    while !out.len().is_multiple_of(8) {
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExposeSecret;

    /// RFC 4648 §10 的官方测试向量。
    ///
    /// 注意 RFC 给的是 `""`、`"f"`、`"fo"`… 逐步加长，覆盖了全部 5 种合法余数。
    #[test]
    fn rfc4648_test_vectors() {
        let vectors: &[(&str, &[u8])] = &[
            ("", b""),
            ("MY======", b"f"),
            ("MZXQ====", b"fo"),
            ("MZXW6===", b"foo"),
            ("MZXW6YQ=", b"foob"),
            ("MZXW6YTB", b"fooba"),
            ("MZXW6YTBOI======", b"foobar"),
        ];
        for (encoded, expected) in vectors {
            // 空串在本实现里因 SecretTooShort 被拒（种子不可能为空），单独跳过。
            if expected.is_empty() {
                assert!(
                    matches!(decode(encoded), Err(Error::SecretTooShort { .. })),
                    "空输入应被拒绝"
                );
                continue;
            }
            let decoded = decode(encoded).unwrap_or_else(|e| panic!("{encoded:?} 解码失败: {e}"));
            assert_eq!(
                decoded.expose_secret(),
                *expected,
                "{encoded:?} 解码结果不符"
            );
        }
    }

    /// 编码方向必须产出 RFC 4648 的标准形式（含填充）。
    #[test]
    fn encode_matches_rfc4648_vectors() {
        assert_eq!(encode(b"f"), "MY======");
        assert_eq!(encode(b"fo"), "MZXQ====");
        assert_eq!(encode(b"foo"), "MZXW6===");
        assert_eq!(encode(b"foob"), "MZXW6YQ=");
        assert_eq!(encode(b"fooba"), "MZXW6YTB");
        assert_eq!(encode(b"foobar"), "MZXW6YTBOI======");
    }

    #[test]
    fn accepts_lowercase() {
        let upper = decode("MZXW6YTBOI======").expect("大写应可解码");
        let lower = decode("mzxw6ytboi======").expect("小写应可解码");
        assert_eq!(upper.expose_secret(), lower.expose_secret());
    }

    #[test]
    fn tolerates_missing_padding() {
        let padded = decode("MZXW6YTBOI======").expect("带填充应可解码");
        let unpadded = decode("MZXW6YTBOI").expect("无填充应可解码");
        assert_eq!(padded.expose_secret(), unpadded.expose_secret());
    }

    #[test]
    fn tolerates_ascii_whitespace() {
        let expected = decode("MZXW6YTBOI").expect("基准应可解码");
        for variant in [
            " MZXW6YTBOI ",
            "MZXW 6YTBOI",
            "MZXW6YTB\nOI",
            "MZ\tXW6YTBOI",
            "MZ XW 6Y TB OI ",
        ] {
            let got = decode(variant).unwrap_or_else(|e| panic!("{variant:?} 应可解码: {e}"));
            assert_eq!(got.expose_secret(), expected.expose_secret(), "{variant:?}");
        }
    }

    #[test]
    fn rejects_characters_outside_alphabet() {
        // `0`、`1`、`8`、`9` 是最常见的误输入（与 O、I、B、G 混淆）。
        for bad in [
            "MZXW6YTBO0======",
            "MZXW6YTBO1======",
            "MZXW6YTBO8======",
            "MZXW6YTBO9======",
            "MZXW6YTB-=",
            "MZXW6YTB!",
            "MZXW6YTBO\u{4e2d}",
        ] {
            let result = decode(bad);
            assert!(
                matches!(result, Err(Error::Base32InvalidCharacter { .. })),
                "{bad:?} 应因非法字符被拒，实际: {result:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_lengths() {
        // 有效字符数模 8 为 1、3、6 时无合法字节数。
        for bad in ["M", "MZX", "MZXW6Y"] {
            let result = decode(bad);
            assert!(
                matches!(result, Err(Error::Base32InvalidLength { .. })),
                "{bad:?} 应因长度非法被拒，实际: {result:?}"
            );
        }
    }

    #[test]
    fn rejects_data_after_padding() {
        let result = decode("MZXW6YTB=OI");
        assert!(
            matches!(result, Err(Error::Base32InvalidCharacter { .. })),
            "填充后出现数据应被拒，实际: {result:?}"
        );
    }

    /// 非规范填充比特：宽容模式接受，严格模式拒绝。
    ///
    /// `"MZ"` = 2 个有效字符 → 1 字节。`'Z'` 的 5 个比特里只有高 3 位进入结果，
    /// 低 2 位（`10`）是未使用的填充比特。
    ///
    /// 这两个断言一起构成对「宽容/严格」分工的**活文档**：任何一边被误改都会
    /// 立刻失败。
    #[test]
    fn padding_bits_are_accepted_leniently_but_rejected_strictly() {
        // 宽容：与各家认证器行为一致，必须接受。
        let lenient = decode("MZ").expect("宽容模式应接受非规范填充比特");
        assert_eq!(lenient.expose_secret(), &[0x66]);

        // 严格：同一输入应被拒。
        let strict = decode_strict("MZ");
        assert!(
            matches!(strict, Err(Error::Base32InvalidPadding)),
            "严格模式应拒绝非零填充比特，实际: {strict:?}"
        );
    }

    /// 零填充比特的编码在两种模式下都必须成功。
    ///
    /// 2 个有效字符 → 1 字节，尾部残留 **2** 比特，故最后一个字符的值必须
    /// **模 4 余 0** 才是零填充。字母表里满足的有 `A`(0)、`E`(4)、`I`(8)、
    /// `M`(12)、`Q`(16)、`U`(20)、`Y`(24)、`4`(28)。
    ///
    /// 注意 `B`(1) **不满足**——它的残留比特是 `01`。这是一个容易写错的点，
    /// 故在此显式记录。
    #[test]
    fn zero_padding_bits_accepted_in_both_modes() {
        for input in ["MA", "ME", "MI", "MM", "MQ", "MU", "MY", "M4"] {
            assert!(decode(input).is_ok(), "{input:?} 宽容模式应可解码");
            assert!(
                decode_strict(input).is_ok(),
                "{input:?} 严格模式应可解码（残留比特为零）"
            );
        }

        // 反例：`ML`(11) 的残留比特是 `11`，非零。
        assert!(decode("ML").is_ok(), "宽容模式仍应接受");
        assert!(
            matches!(decode_strict("ML"), Err(Error::Base32InvalidPadding)),
            "严格模式应拒绝 ML"
        );
    }

    /// 本模块 `encode` 的输出必须是规范形式，即严格模式必须接受。
    ///
    /// 这条把编码器与严格解码器绑在一起：任何一边破坏规范性都会失败。
    #[test]
    fn our_own_encoding_is_canonical() {
        for len in 1_usize..=70 {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
            let encoded = encode(&data);
            let decoded = decode_strict(&encoded)
                .unwrap_or_else(|e| panic!("长度 {len} 的自产编码不满足规范形式: {e}"));
            assert_eq!(decoded.expose_secret(), data.as_slice(), "长度 {len}");
        }
    }

    #[test]
    fn rejects_empty_and_padding_only() {
        for bad in ["", "   ", "========", "="] {
            let result = decode(bad);
            assert!(
                matches!(result, Err(Error::SecretTooShort { .. })),
                "{bad:?} 应被拒为空秘密，实际: {result:?}"
            );
        }
    }

    /// 真实场景：一个 32 字节（256 比特）的 TOTP 种子。
    ///
    /// 这是最常见的种子长度，务必确认往返正确。
    #[test]
    fn roundtrip_realistic_seed_lengths() {
        for len in [10_usize, 16, 20, 32, 64] {
            let original: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let encoded = encode(&original);
            let decoded = decode(&encoded).unwrap_or_else(|e| panic!("长度 {len} 往返失败: {e}"));
            assert_eq!(decoded.expose_secret(), original.as_slice(), "长度 {len}");
        }
    }

    /// 错误信息**不得**泄露输入内容——种子可能就藏在里面。
    #[test]
    fn errors_do_not_embed_input() {
        let secret_like = "JBSWY3DPEHPK3PXP0"; // 末尾故意放非法字符 '0'
        let Err(error) = decode(secret_like) else {
            panic!("应解码失败");
        };
        let text = format!("{error}");
        assert!(
            !text.contains("JBSWY3DPEHPK3PXP"),
            "错误信息泄露了种子内容：{text}"
        );
    }
}
