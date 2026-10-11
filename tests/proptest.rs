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

//! 基于属性的测试。
//!
//! 与 `fuzz/` 下的 libFuzzer 目标分工：
//!
//! - **proptest（本文件）**：验证「对所有输入都应成立的**性质**」，用收缩
//!   （shrinking）给出最小反例。跑在 `cargo test` 里，CI 必然执行。
//! - **fuzz**：极大量随机输入 + 变异，找 panic、越界、挂起。需要显式触发。
//!
//! # 为什么这一层测的不是「显然成立」的东西
//!
//! 秘密类型的失败模式不是「算错」而是**泄露**：`Debug` 一旦把明文带出来，就可能
//! 落进日志、崩溃转储或遥测。这类 bug 不会被固定样例的单元测试发现，
//! 必须用「任意输入」来保证。
//!
//! 另外，这些性质同时是**对上游 `secrecy` 的回归防线**：将来升级 `secrecy` 时，
//! 若其脱敏行为发生变化，这里会直接失败。

use proptest::prelude::*;
use qualia2fa_core::base32;
use qualia2fa_core::otp::{self, Algorithm, Digits, OtpSecret};
use qualia2fa_core::uri::{self, OtpAuth, UriType};
use qualia2fa_core::{ExposeSecret, SecretBytes, SecretString};

/// 生成任意字节序列。
///
/// 上限取 2048 字节：既覆盖真实种子/密钥量级（20–64 字节），又给到手写
/// Base32 串、二维码载荷这类较长的输入，同时避免超长输入拖慢测试。
fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=2048)
}

/// 生成**非空**字节串，用于「编码 → 解码」这类往返性质。
///
/// # 为什么不能复用 `arb_bytes`
///
/// `arb_bytes` 允许空串，而**空输入不是合法的 Base32**：`base32::decode("")`
/// 会返回 [`Error::SecretTooShort`]（见 `src/base32.rs` 的
/// `rejects_empty_and_padding_only`，那是刻意的行为——空种子会让所有验证码
/// 相同，必须拒绝）。
///
/// 于是「编码再解码必须还原」这条性质对空输入**本来就不成立**，而 `arb_bytes`
/// 迟早会生成它。这是个潜伏的测试缺陷：它一直在随机地等着被触发，一旦触发，
/// proptest 会把 `data = []` 写进 `proptest-regressions` 文件，此后每次运行都
/// 稳定失败。
///
/// 「空输入被拒绝」这件事由上面的单元测试覆盖，往返性质只需要管非空输入。
fn arb_nonempty_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=2048)
}

proptest! {
    /// 性质：从 `Vec<u8>` 构造后取用，必须原样返回，不截断、不填充、不改写。
    #[test]
    fn expose_is_transparent(data in arb_bytes()) {
        let secret: SecretBytes = data.clone().into();
        prop_assert_eq!(secret.expose_secret(), data.as_slice());
    }

    /// 性质：`Clone` 必须逐字节一致。
    #[test]
    fn clone_is_exact(data in arb_bytes()) {
        let secret: SecretBytes = data.clone().into();
        let copy = secret.clone();
        prop_assert_eq!(copy.expose_secret(), secret.expose_secret());
    }

    /// 性质：`SecretString` 的构造与取用同样透明。
    ///
    /// 用 Rust 的 `String`（保证 UTF-8）作为输入，覆盖文本秘密路径。
    #[test]
    fn secret_string_is_transparent(text in ".*") {
        let secret = SecretString::from(text.clone());
        prop_assert_eq!(secret.expose_secret(), text.as_str());
    }

    /// **核心性质**：`Debug` 输出绝不含明文。
    ///
    /// 检查明文的十六进制与十进制两种表示。上游 `secrecy` 的 `Debug` 连长度都
    /// 不打印，因此这里**不**断言长度可读——只断言不泄露。
    ///
    /// 仅当长度 ≥ 4 时才做子串检查：更短的十进制串（如 2 字节的 "12"）会与
    /// `Debug` 里的类型名、数字等产生偶然碰撞，导致误报。
    #[test]
    fn debug_never_contains_plaintext(data in arb_bytes()) {
        let secret: SecretBytes = data.clone().into();
        let debug = format!("{secret:?}");
        let lower = debug.to_lowercase();

        // 必须标注脱敏。
        prop_assert!(
            lower.contains("redacted"),
            "Debug 未标注脱敏（长度 {}）：{}",
            data.len(),
            debug
        );

        if data.len() >= 4 {
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            prop_assert!(!lower.contains(&hex), "泄露十六进制明文：{}", debug);

            let decimal = data
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join("");
            prop_assert!(!debug.contains(&decimal), "泄露十进制明文：{}", debug);
        }
    }

    /// 性质：嵌套在 `#[derive(Debug)]` 结构里的秘密，同样不得泄露。
    #[test]
    fn debug_never_leaks_when_nested(data in arb_bytes()) {
        // 字段只用于构造 `Debug` 输出，不参与读取；`expect` 比 `allow` 严格：
        // 一旦这些字段真被读到，它会反过来报错提醒删除本属性。
        #[expect(
            dead_code,
            reason = "字段仅用于构造 Debug 输出；这是本测试的全部意图"
        )]
        #[derive(Debug)]
        struct Holder {
            /// 非秘密字段，用于确认 Debug 确实在输出内容。
            tag: u8,
            /// 秘密字段。
            secret: SecretBytes,
        }

        let holder = Holder { tag: 1, secret: data.clone().into() };
        let debug = format!("{holder:?}");

        if data.len() >= 4 {
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            prop_assert!(
                !debug.to_lowercase().contains(&hex),
                "嵌套 Debug 泄露十六进制明文：{}",
                debug
            );
        }
    }
}

// ─────────────────────────── Base32 与 OTP 的性质 ───────────────────────────

proptest! {
    /// **核心性质**：Base32 编码再解码必须逐字节还原。
    ///
    /// 这条覆盖全部 5 种合法尾部余数（0/2/4/5/7 位）。随机字节长度会均匀
    /// 命中它们，因此不需要为每种余数单独写测试。
    ///
    /// 输入限定非空——空输入不是合法 Base32，见 [`arb_nonempty_bytes`]。
    #[test]
    fn base32_encode_decode_roundtrips(data in arb_nonempty_bytes()) {
        let encoded = base32::encode(&data);
        // 编码结果只能是字母表内字符与填充符。
        prop_assert!(
            encoded.bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b) || b == b'='),
            "编码含字母表外字符：{}",
            encoded
        );
        // 我们自己的编码必须是规范形式，因此严格模式也必须接受。
        let decoded = base32::decode_strict(&encoded)
            .map_err(|e| TestCaseError::fail(format!("严格解码自己的编码失败：{e}（原文 {}）", encoded)))?;
        prop_assert_eq!(decoded.expose_secret(), data.as_slice());
    }

    /// 性质：无填充形式的编码同样可解码（真实世界绝大多数种子无填充）。
    ///
    /// 输入同样限定非空：空串去掉填充还是空串，仍然非法。
    #[test]
    fn base32_unpadded_encoding_also_decodes(data in arb_nonempty_bytes()) {
        let padded = base32::encode(&data);
        let unpadded = padded.trim_end_matches('=');
        let decoded = base32::decode(unpadded)
            .map_err(|e| TestCaseError::fail(format!("无填充解码失败：{e}")))?;
        prop_assert_eq!(decoded.expose_secret(), data.as_slice());
    }

    /// 性质：任意字符串都不得让解码器 panic——只能返回 `Ok` 或 `Err`。
    ///
    /// 这条是「库内禁 panic」契约在 Base32 上的体现。解码器接受的输入直接来自
    /// 二维码与用户手输，必须有界且不崩。
    #[test]
    fn base32_never_panics_on_arbitrary_text(text in "\\PC*") {
        // 只要求调用返回，不关心成功与否。
        let _ = base32::decode(&text);
        let _ = base32::decode_strict(&text);
    }

    /// 性质：OTP 码必须**恒为**定宽十进制字符串。
    ///
    /// 这是最容易出错的地方：把结果当整数处理就会丢掉前导零，
    /// 而当结果恰好是 0 时会输出空串或 "0"。
    #[test]
    fn otp_code_is_always_exact_width_digits(
        data in prop::collection::vec(any::<u8>(), 1..=64),
        counter in any::<u64>(),
        algorithm in prop_oneof![
            Just(Algorithm::Sha1),
            Just(Algorithm::Sha256),
            Just(Algorithm::Sha512)
        ],
        digits in prop_oneof![Just(Digits::Six), Just(Digits::Seven), Just(Digits::Eight)],
    ) {
        let secret = OtpSecret::from_bytes(data)
            .map_err(|e| TestCaseError::fail(format!("非空种子应被接受：{e}")))?;
        let code = otp::hotp_code(&secret, counter, algorithm, digits);
        prop_assert_eq!(code.len(), digits.count() as usize);
        prop_assert!(
            code.bytes().all(|b| b.is_ascii_digit()),
            "含非数字字符：{}",
            code
        );
        // 数值必须落在 [0, 10^digits)。
        let numeric: u64 = code.parse().expect("应可解析为数字");
        prop_assert!(numeric < 10_u64.pow(digits.count()));
    }

    /// 性质：`format_code` 与 `hotp` 必须一致（格式化不改变数值）。
    #[test]
    fn format_code_agrees_with_numeric_value(
        data in prop::collection::vec(any::<u8>(), 1..=64),
        counter in any::<u64>(),
        digits in prop_oneof![Just(Digits::Six), Just(Digits::Seven), Just(Digits::Eight)],
    ) {
        let secret = OtpSecret::from_bytes(data).expect("非空");
        let numeric = otp::hotp(&secret, counter, Algorithm::Sha1, digits);
        let formatted = otp::format_code(numeric, digits);
        // 先解析再断言：`prop_assert_eq!` 会消费其参数。且 proptest 的宏不支持
        // 内联命名格式化参数（`{name}` 捕获）——所有格式化参数必须预先算好，
        // 并按位置显式传入。这两点都在此前踩过。
        let reparsed: u64 = formatted.parse().expect("应可解析");
        let expected = otp::hotp_code(&secret, counter, Algorithm::Sha1, digits);
        prop_assert_eq!(formatted, expected);
        prop_assert_eq!(reparsed, u64::from(numeric));
    }

    /// 性质：TOTP 只依赖 `unix_time / period`，同一时间步内的不同时刻必须同码。
    #[test]
    fn totp_is_constant_within_a_time_step(
        data in prop::collection::vec(any::<u8>(), 1..=64),
        time in 0_u64..1_000_000_000_000,
        period in 1_u64..=86_400,
        offset in 0_u64..86_400,
    ) {
        let secret = OtpSecret::from_bytes(data).expect("非空");
        let base = time - (time % period);
        // 落在同一个时间步内的另一个时刻。
        let same_step = base + (offset % period);
        prop_assert_eq!(base / period, same_step / period, "构造应落在同一时间步");

        let a = otp::totp_code(&secret, base, period, Algorithm::Sha1, Digits::Six)
            .expect("period 非零");
        let b = otp::totp_code(&secret, same_step, period, Algorithm::Sha1, Digits::Six)
            .expect("period 非零");
        prop_assert_eq!(a, b);
    }

    /// 性质：`verify_code` 自反，且对不同长度的输入恒为 `false`。
    #[test]
    fn verify_code_is_reflexive(
        data in prop::collection::vec(any::<u8>(), 1..=64),
        counter in any::<u64>(),
    ) {
        let secret = OtpSecret::from_bytes(data).expect("非空");
        let code = otp::hotp_code(&secret, counter, Algorithm::Sha1, Digits::Six);
        prop_assert!(otp::verify_code(&code, &code), "自反性失败：{}", code);
        // 长度不同时必须为 false（长度不是秘密，可立即返回）。
        // 变体必须先在宏外算好：宏内部会把 `{code}` 当成内联命名捕获参数。
        let too_long = format!("{code}0");
        let one_shorter = code[1..].to_owned();
        prop_assert!(!otp::verify_code(&code, &too_long));
        prop_assert!(!otp::verify_code(&code, &one_shorter));
    }

    /// 性质：Steam 码恒为 5 个字符，且全部来自 Steam 字母表。
    #[test]
    fn steam_code_shape_is_constant(
        data in prop::collection::vec(any::<u8>(), 1..=64),
        time in 0_u64..1_000_000_000_000,
    ) {
        let secret = OtpSecret::from_bytes(data).expect("非空");
        let code = otp::steam_guard_code(&secret, time, 30, Algorithm::Sha1)
            .expect("period 非零");
        prop_assert_eq!(code.chars().count(), otp::STEAM_DIGITS);
        const ALPHABET: &str = "23456789BCDFGHJKMNPQRTVWXY";
        // 先把结果算成 `bool`：proptest 的宏不支持内联命名格式化参数。
        let all_in_alphabet = code.chars().all(|c| ALPHABET.contains(c));
        prop_assert!(all_in_alphabet, "含字母表外字符：{}", code);
    }
}

// ────────────────────────── `otpauth://` 解析的性质 ──────────────────────────

/// 生成可安全放进 `otpauth://` 各字段的文本。
///
/// # 为什么必须限制字符集
///
/// 这不是为了让测试好写，而是因为**有些字符在格式里是不可往返的**：
///
/// - **冒号 `:`**：label 用第一个 `:` 分隔 issuer 与 account，因此账号名里的 `:`
///   无法与分隔符区分。这是**格式本身的歧义**，不是实现缺陷——解析与序列化
///   两端都已显式拒绝（`Error::UriAccountContainsColon`）。既然合法值域里不含
///   冒号，策略就不该生成它，否则测的是不可达状态。
/// - **空白**：query 解码把 `+` 视为空格，前导/尾随空白在多数实现里会被裁剪。
/// - **控制字符**：本格式不定义其语义。
///
/// 因此这里用「字母数字 + 少量格式里有明确含义的 ASCII + 任意非 ASCII」，
/// 让性质测试聚焦在**编解码正确性**上，而不是去断言规范未定义的边角行为。
fn arb_label_text() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            // 非 ASCII（含中文、emoji 等多字节字符），覆盖百分号编解码路径。
            0x80_u32..0x2FFFF,
            // 格式里有明确含义、且应能往返的 ASCII。
            prop::sample::select(vec![
                'a', 'Z', '0', '9', ' ', '+', '-', '_', '.', '%', '&', '=', '?', '#', '@', '/',
            ])
            .prop_map(|c| c as u32),
        ],
        1..=12,
    )
    .prop_map(|codes| codes.into_iter().filter_map(char::from_u32).collect())
}

/// 生成 TOTP 或 HOTP 的完整配置，保证字段组合自洽。
fn arb_otp_auth() -> impl Strategy<Value = OtpAuth> {
    (
        prop::collection::vec(any::<u8>(), 1..=64),
        arb_label_text(),
        prop::option::of(arb_label_text()),
        prop_oneof![
            Just(Algorithm::Sha1),
            Just(Algorithm::Sha256),
            Just(Algorithm::Sha512)
        ],
        prop_oneof![Just(Digits::Six), Just(Digits::Seven), Just(Digits::Eight)],
        1_u64..=604_800,
        any::<bool>(),
        any::<u64>(),
    )
        .prop_map(
            |(secret_bytes, account, issuer, algorithm, digits, period, is_hotp, counter)| {
                OtpAuth {
                    uri_type: if is_hotp {
                        UriType::Hotp
                    } else {
                        UriType::Totp
                    },
                    secret: OtpSecret::from_bytes(secret_bytes).expect("非空"),
                    issuer,
                    account,
                    algorithm,
                    digits,
                    // `OtpAuth` 的不变量：`period` 只在 TOTP 下有含义，HOTP 恒为
                    // `DEFAULT_PERIOD`。策略必须生成满足不变量的值，否则测的是
                    // 不可达状态——这个坑已经踩过一次（最小反例：HOTP + period=1）。
                    period: if is_hotp { uri::DEFAULT_PERIOD } else { period },
                    counter: is_hotp.then_some(counter),
                }
            },
        )
}

proptest! {
    /// **核心性质**：`parse(serialize(auth)?)` 必须还原出等价的配置。
    ///
    /// 序列化会做规范化（省略默认值、种子转为无填充 Base32），所以断言的是
    /// **语义等价**而不是逐字节相同。这条性质覆盖了百分号编解码、默认值省略、
    /// 以及 issuer 在两个位置（label 前缀与 query 参数）的一致性校验。
    ///
    /// 这条性质曾经抓到两个真实缺陷：scheme 前缀剥离在非字符边界上 panic，
    /// 以及 HOTP 的 `period` 往返丢失。
    #[test]
    fn otpauth_uri_roundtrips(auth in arb_otp_auth()) {
        let text = uri::serialize(&auth)
            .map_err(|e| TestCaseError::fail(format!("序列化失败：{e}")))?;
        let parsed = uri::parse(&text)
            .map_err(|e| TestCaseError::fail(format!("解析自己的输出失败：{e}\nURI: {text}")))?;

        prop_assert_eq!(parsed.uri_type, auth.uri_type, "类型不同");
        prop_assert_eq!(parsed.account.clone(), auth.account.clone(), "账号不同");
        prop_assert_eq!(parsed.issuer.clone(), auth.issuer.clone(), "issuer 不同");
        prop_assert_eq!(parsed.algorithm, auth.algorithm, "算法不同");
        prop_assert_eq!(parsed.digits, auth.digits, "位数不同");
        prop_assert_eq!(parsed.period, auth.period, "周期不同");
        prop_assert_eq!(parsed.counter, auth.counter, "计数器不同");
        // 种子必须逐字节还原——这是最重要的一条。
        prop_assert_eq!(
            parsed.secret.to_base32(),
            auth.secret.to_base32(),
            "种子不同"
        );
    }

    /// 性质：序列化两次必须得到相同结果（规范化是幂等的）。
    #[test]
    fn otpauth_serialization_is_idempotent(auth in arb_otp_auth()) {
        let once = uri::serialize(&auth).expect("应可序列化");
        let parsed = uri::parse(&once).expect("自己的输出应可解析");
        let twice = uri::serialize(&parsed).expect("应可序列化");
        prop_assert_eq!(once, twice);
    }

    /// 性质：任意字符串都不得让 URI 解析器 panic。
    ///
    /// 这是**最主要的攻击者可控输入面**（二维码内容、剪贴板、手输链接），
    /// 因此「有界且不崩」是硬契约。
    #[test]
    fn uri_parser_never_panics(text in "\\PC*") {
        let _ = uri::parse(&text);
    }

    /// 性质：在合法 URI 前缀后拼接任意文本，同样不得 panic。
    ///
    /// 纯随机字符串几乎永远不会命中 `otpauth://` 前缀，从而走不到深层解析逻辑。
    /// 这条把随机性注入到真正的解析路径里。
    #[test]
    fn uri_parser_never_panics_with_valid_prefix(suffix in "\\PC*") {
        for prefix in [
            "otpauth://totp/",
            "otpauth://hotp/",
            "otpauth://totp/a:b?secret=",
            "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer=",
        ] {
            let _ = uri::parse(&format!("{prefix}{suffix}"));
        }
    }

    /// 性质：Base32 解码结果作为种子时，长度必须与原字节数一致。
    ///
    /// 这条把 Base32 与 OTP 两个模块接起来：若 Base32 在多字节边界上少算/多算
    /// 一个字节，这里会立刻失败。
    #[test]
    fn secret_length_survives_base32_roundtrip(data in prop::collection::vec(any::<u8>(), 1..=64)) {
        let encoded = base32::encode(&data);
        let secret = OtpSecret::from_base32(&encoded)
            .map_err(|e| TestCaseError::fail(format!("从 Base32 构造种子失败：{e}")))?;
        prop_assert_eq!(secret.len(), data.len());
        prop_assert_eq!(secret.to_base32(), encoded.trim_end_matches('='));
    }
}

/// **回归**：账号名里的 `:` 造成往返歧义。
///
/// # 原缺陷
///
/// 最初 `split_label` 允许账号名含 `:`（当时按「账号名可能是
/// `john@example.com:8080` 这种带端口的形式」考虑）。但 label 用第一个 `:`
/// 分隔 issuer 与 account，账号名里的 `:` 因此**无法与分隔符区分**：
///
/// ```text
/// 输入:       otpauth://totp/:a::a?secret=AA
/// 首次解析:   account = "a::a",  issuer = None
/// 序列化后:   otpauth://totp/a%3A%3Aa?secret=AA
/// 再次解析:   account = ":a",    issuer = Some("a")   ← 静默改变了归属
/// ```
///
/// 后果是用户可能把一个条目的验证码错配到另一个服务上——对 2FA 来说这是
/// 安全事故，不是显示问题。百分号编码救不了它：`%3A` 与字面 `:` 在解码后
/// 无从区分。
///
/// # 修法
///
/// 把这个不变量强制在**两端**：`split_label` 拒绝含 `:` 的账号名，
/// `serialize` 也拒绝（改为返回 `Result`）。这样合法值域里不存在歧义状态。
///
/// 该缺陷由穷举诊断程序发现（`fuzz` 里的往返断言是同一性质的更强形式）。
#[test]
fn regression_account_with_colon_is_rejected_on_both_ends() {
    // 解析端：这些 URI 都必须被拒绝，而不是解析出一个会变形的账号名。
    for bad in [
        "otpauth://totp/:a::a?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/ACME:john:8080?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/:a:?secret=JBSWY3DPEHPK3PXP",
        // 百分号编码的冒号同样必须被拒绝——解码后与字面冒号无从区分。
        "otpauth://totp/ACME:john%3A8080?secret=JBSWY3DPEHPK3PXP",
    ] {
        assert!(
            matches!(
                uri::parse(bad),
                Err(qualia2fa_core::Error::UriAccountContainsColon { .. })
            ),
            "{bad:?} 应因账号名含冒号被拒绝"
        );
    }

    // 序列化端：同样拒绝，避免产出一个「解析回来不同」的 URI。
    let auth = OtpAuth {
        uri_type: UriType::Totp,
        secret: OtpSecret::from_bytes(vec![1, 2, 3, 4]).expect("非空"),
        issuer: Some("ACME".to_owned()),
        account: "john:8080".to_owned(),
        algorithm: Algorithm::Sha1,
        digits: Digits::Six,
        period: uri::DEFAULT_PERIOD,
        counter: None,
    };
    assert!(
        uri::serialize(&auth).is_err(),
        "serialize 应拒绝含冒号的账号名"
    );

    // 不含冒号的账号名不受影响（确认拒绝范围没有过度扩大）。
    let ok = OtpAuth {
        account: "john@example.com".to_owned(),
        ..auth
    };
    let text = uri::serialize(&ok).expect("不含冒号应可序列化");
    let parsed = uri::parse(&text).expect("应可解析");
    assert_eq!(parsed.account, "john@example.com");
    assert_eq!(parsed.issuer.as_deref(), Some("ACME"));
}

// ─────────────────────────────── 回归测试 ───────────────────────────────
//
// 下面两条来自 proptest 找到的真实缺陷，固化为具名测试，使失败信息直接说明
// 问题所在（而不是只留下一个最小化的随机输入）。

/// **回归**：scheme 前缀剥离曾在非字符边界上 panic。
///
/// # 原缺陷
///
/// `strip_prefix_ignore_ascii_case` 最初写成 `input.split_at(prefix.len())`。
/// `str::split_at` 要求索引落在**字符边界**上，否则 panic。`"otpauth://"` 是
/// 10 字节，当输入的前 10 字节切在一个多字节字符中间时就崩。
///
/// # 为什么这条重要
///
/// 这是**攻击者可控输入导致的拒绝服务**：输入来自二维码、剪贴板、用户手输。
/// 一个远程攻击者只要能让你扫一个二维码，就能让应用崩溃。
///
/// # 最小反例
///
/// proptest 收缩出的账号名是 `"\u{80}"`，其百分号编码是 `%C2%80`——共 6 字节，
/// 而它紧跟在 `otpauth://hotp/` 之后，使第 10 字节落在 `C2` 上。
///
/// 下面覆盖多种「前缀长度切进多字节序列」的输入，包括中文（3 字节/字符）、
/// emoji（4 字节/字符）与 U+0080（2 字节/字符）。
#[test]
fn regression_scheme_stripping_never_panics_on_multibyte_boundary() {
    // 直接测底层函数：各种长度都会让 `prefix.len()` 落在字符中间。
    for text in [
        "otpauth:\u{4e2d}",
        "otpauth\u{1f600}",
        "otpau\u{4e2d}\u{6587}",
        "\u{4e2d}\u{6587}\u{5b57}\u{7b26}",
        "otpauth:/\u{80}",
        "\u{80}\u{80}\u{80}\u{80}\u{80}",
        "",
        "otp",
    ] {
        // 不关心返回什么，只要求不 panic。
        let _ = uri::parse(text);
        let _ = uri::parse(&format!("otpauth://totp/{text}?secret=AA"));
    }

    // 前缀确实是 `otpauth://` 时，余下部分应被正确剥离。
    let parsed = uri::parse("OTPAUTH://totp/a?secret=AA").expect("大小写不敏感的 scheme 应被接受");
    assert_eq!(parsed.account, "a");
}

/// **回归**：HOTP 的 `period` 曾导致序列化/解析往返丢数据。
///
/// # 原缺陷
///
/// `serialize` 只在 TOTP 时写出 `period`，而 `parse` 无条件读取它并赋给
/// `OtpAuth::period`。于是 `HOTP + period=1` 这样的条目序列化后再解析，
/// `period` 会从 1 变成默认的 30——往返不保持等价。
///
/// # 修法
///
/// 不是「把 period 也写出来」，而是**把它固定为不变量**：HOTP 按计数器推进，
/// `period` 对它没有意义，因此解析时一律归一为 [`uri::DEFAULT_PERIOD`]。
/// 这样 `OtpAuth` 的状态空间里就不存在「HOTP 带非默认 period」这种值。
#[test]
fn regression_hotp_period_is_normalized_to_default() {
    // URI 里显式写了 period=1，但因为是 HOTP，必须被归一。
    let parsed = uri::parse("otpauth://hotp/acct?secret=JBSWY3DPEHPK3PXP&counter=0&period=1")
        .expect("应可解析");
    assert_eq!(parsed.uri_type, UriType::Hotp);
    assert_eq!(
        parsed.period,
        uri::DEFAULT_PERIOD,
        "HOTP 的 period 应被归一为默认值"
    );

    // 序列化后不含 period，再次解析仍等价——往返稳定。
    let text = uri::serialize(&parsed).expect("应可序列化");
    assert!(
        !text.contains("period="),
        "HOTP 的序列化不应写出 period：{text}"
    );
    let reparsed = uri::parse(&text).expect("应可解析");
    assert_eq!(reparsed.period, uri::DEFAULT_PERIOD);

    // TOTP 不受影响：非默认 period 必须被保留。
    let totp =
        uri::parse("otpauth://totp/acct?secret=JBSWY3DPEHPK3PXP&period=60").expect("应可解析");
    assert_eq!(totp.period, 60, "TOTP 的非默认 period 应被保留");
    let totp_text = uri::serialize(&totp).expect("应可序列化");
    assert!(
        totp_text.contains("period=60"),
        "TOTP 应写出 period：{totp_text}"
    );
    assert_eq!(
        uri::parse(&totp_text).expect("应可解析").period,
        60,
        "TOTP period 往返应保持"
    );
}
