#![no_main]

//! fuzz 目标：`secrecy` 包装的秘密类型在**任意输入**下的脱敏与透明性契约。
//!
//! 本目标检查三条必须永远成立的性质：
//!
//! 1. **不 panic**：任意字节输入都不得让构造、借用或格式化 panic。
//! 2. **透明性**：构造 → `expose_secret` 必须原样返回，不得截断、填充或改写。
//! 3. **不泄露**：`Debug` 输出只含类型名与脱敏标记，绝不出现明文内容。
//!
//! 性质 3 的检查方式经过一次修正，值得记录：**用 fuzz 的任意输入去做
//! 「Debug 里是否含明文」的子串比对是不可靠的**——`Debug` 输出本身含有
//! `[REDACTED]` 这类固定字面量，短输入会与它们的子串偶然碰撞，产生假阳性。
//! 因此性质 3 改用**固定哨兵值**做精确检查；任意输入只用于性质 1 与 2。
//!
//! 该目标同时是对上游 `secrecy` 的**回归防线**。若将来升级 `secrecy` 后其脱敏
//! 行为退化，哨兵检查会立刻失败。
//!
//! TODO(M1)：待 `otpauth://` URI 解析器与 Base32 解码实现后，**新增**
//! `uri_parse` 与 `base32_decode` 两个目标——那才是真正攻击者可控的输入面。
//! 本目标保留，因为它是秘密处理路径唯一的自动化防线。

use libfuzzer_sys::fuzz_target;
use qualia2fa_core::{ExposeSecret, SecretBytes, SecretString};

/// 哨兵：一段在任何编码下都不可能与 `Debug` 的类型名或脱敏标记碰撞的字节。
///
/// 刻意选非 ASCII 的大值字节，使十六进制（`f0f1f2f3f4f5f6f7`）、十进制
/// （`240241242...`）以及 UTF-8 文本形态都不会偶然出现在输出里。
const SENTINEL_BYTES: [u8; 8] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7];

/// 哨兵文本：含非 ASCII 字符，确保不会被类型名或标记意外包含。
const SENTINEL_TEXT: &str = "\u{4f60}\u{597d}\u{ff0c}\u{4e16}\u{754c}\u{ff01}";

fuzz_target!(|data: &[u8]| {
    // ── 性质 1 与 2：用任意输入，只验证不 panic 与透明性 ──────────────────
    let secret: SecretBytes = data.to_vec().into();
    assert_eq!(
        secret.expose_secret(),
        data,
        "SecretBytes 改变了字节内容"
    );

    let copy = secret.clone();
    assert_eq!(
        copy.expose_secret(),
        secret.expose_secret(),
        "Clone 改变了内容"
    );

    // 格式化任意内容都不得 panic。
    let arbitrary_debug = format!("{secret:?}");
    assert!(
        arbitrary_debug.to_lowercase().contains("redacted"),
        "Debug 输出未标注脱敏：{arbitrary_debug}"
    );

    // ── 性质 3：用固定哨兵做精确泄露检查 ────────────────────────────────
    let sentinel: SecretBytes = SENTINEL_BYTES.to_vec().into();
    let sentinel_debug = format!("{sentinel:?}");
    let sentinel_lower = sentinel_debug.to_lowercase();

    assert!(
        sentinel_lower.contains("redacted"),
        "哨兵 Debug 未标注脱敏：{sentinel_debug}"
    );

    let hex: String = SENTINEL_BYTES.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !sentinel_lower.contains(&hex),
        "Debug 泄露了哨兵的十六进制表示：{sentinel_debug}"
    );

    let decimal = SENTINEL_BYTES
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join("");
    assert!(
        !sentinel_debug.contains(&decimal),
        "Debug 泄露了哨兵的十进制表示：{sentinel_debug}"
    );

    // ── 文本路径的哨兵检查 ──────────────────────────────────────────────
    let text_secret = SecretString::from(SENTINEL_TEXT);
    let text_debug = format!("{text_secret:?}");

    assert!(
        text_debug.to_lowercase().contains("redacted"),
        "SecretString 的 Debug 未标注脱敏：{text_debug}"
    );
    assert!(
        !text_debug.contains(SENTINEL_TEXT),
        "SecretString 的 Debug 泄露了哨兵文本：{text_debug}"
    );

    // 合法 UTF-8 的任意输入仍要覆盖 `SecretString` 的透明性。
    if let Ok(text) = core::str::from_utf8(data) {
        let string_secret = SecretString::from(text);
        assert_eq!(
            string_secret.expose_secret(),
            text,
            "SecretString 改变了文本内容"
        );
    }
});
