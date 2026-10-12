#![no_main]

//! Fuzz target: the redaction and transparency contract of the secret types
//! wrapped by `secrecy`, under arbitrary input.
//!
//! # Input surface
//!
//! The bytes are the arbitrary string produced by the fuzzer, and whoever supplies
//! them controls them entirely. Properties 1 and 2 are checked on those bytes;
//! property 3 is checked with a fixed sentinel instead, because a substring
//! comparison for "does the `Debug` output contain the plaintext" is unreliable
//! with arbitrary input: the `Debug` output itself contains fixed literals such as
//! `[REDACTED]`, and short inputs collide with them by accident, producing false
//! positives.
//!
//! # Properties covered
//!
//! 1. **No panics**: no byte input may make construction, borrowing or formatting
//!    panic.
//! 2. **Transparency**: construction → `expose_secret` must return the input
//!    unchanged, without truncation, padding or rewriting.
//! 3. **No leakage**: the `Debug` output contains only the type name and the
//!    redaction marker, never the plaintext.
//!
//! This target is also a regression guard on the upstream `secrecy` crate: if a
//! future upgrade degrades its redaction behavior, the sentinel checks fail
//! immediately. It is the only automated guard over the secret-handling path.
//!
//! Preconditions: no feature flags, and no valid skeleton has to be built — the
//! target consumes arbitrary bytes directly.

use libfuzzer_sys::fuzz_target;
use qualia2fa_core::{ExposeSecret, SecretBytes, SecretString};

/// Sentinel: bytes that cannot collide with the type name or the redaction marker
/// of `Debug` under any encoding.
///
/// The non-ASCII, large-value bytes are deliberate, so that neither the hexadecimal
/// form (`f0f1f2f3f4f5f6f7`), the decimal form (`240241242...`) nor the UTF-8 text
/// form appears in the output by accident.
const SENTINEL_BYTES: [u8; 8] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7];

/// Sentinel text: contains non-ASCII characters, so that neither a type name nor a
/// marker can contain it by accident.
const SENTINEL_TEXT: &str = "\u{4f60}\u{597d}\u{ff0c}\u{4e16}\u{754c}\u{ff01}";

fuzz_target!(|data: &[u8]| {
    // ── Properties 1 and 2: arbitrary input, no-panic and transparency only ──
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

    let arbitrary_debug = format!("{secret:?}");
    assert!(
        arbitrary_debug.to_lowercase().contains("redacted"),
        "Debug 输出未标注脱敏：{arbitrary_debug}"
    );

    // ── Property 3: exact leak check with a fixed sentinel ──────────────────
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

    // ── Sentinel check on the text path ─────────────────────────────────────
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

    if let Ok(text) = core::str::from_utf8(data) {
        let string_secret = SecretString::from(text);
        assert_eq!(
            string_secret.expose_secret(),
            text,
            "SecretString 改变了文本内容"
        );
    }
});
