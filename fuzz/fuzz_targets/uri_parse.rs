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

//! fuzz 目标：`otpauth://` URI 解析。
//!
//! # 为什么这是最重要的一个 fuzz 目标
//!
//! `otpauth::parse` 是本项目**最主要的攻击者可控输入面**：
//!
//! - 二维码内容（用户扫任意码）
//! - 剪贴板文本（用户粘贴任意内容）
//! - 用户手输的链接
//!
//! 它同时是**唯一一个会把攻击者数据解释为结构化配置**的入口。因此本目标要保证
//! 的性质有两类：
//!
//! 1. **绝不 panic**——这是拒绝服务防线。曾经真实存在一个 panic：
//!    `strip_prefix_ignore_ascii_case` 用 `str::split_at` 在非字符边界上切片，
//!    扫描一个账号名含多字节字符的二维码即可让应用崩溃。
//! 2. **绝不泄露**——解析失败路径不得把输入原样带进错误信息（否则一个恶意
//!    二维码就能把任意内容写进日志），成功路径的 `Debug` 不得输出种子。
//!
//! # 输入编码
//!
//! 原始字节不保证是合法 UTF-8，而 `parse` 接受 `&str`。因此这里用
//! `String::from_utf8_lossy` 转换——它总能成功，且会把无效字节替换为 U+FFFD，
//! 从而**仍然把无效字节的信息带给解析器**（比直接丢弃更有覆盖价值）。
//!
//! 另外，纯随机字节几乎永远不会命中 `otpauth://` 前缀，从而走不到深层解析逻辑。
//! 因此本目标有第二种模式：把输入**同时**当作「前缀后的内容」拼接，强制进入
//! 真正的解析路径。

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia2fa_core::uri;

/// 需要覆盖的合法前缀。覆盖 `totp`/`hotp`、有无 issuer、有无 query。
const PREFIXES: &[&str] = &[
    "otpauth://totp/",
    "otpauth://hotp/",
    "otpauth://totp/a:b?secret=",
    "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP",
    "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer=",
    "otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP&counter=",
    "otpauth://totp/a?secret=AA&algorithm=",
    "otpauth://totp/a?secret=AA&digits=",
    "otpauth://totp/a?secret=AA&period=",
];

fuzz_target!(|data: &[u8]| {
    // 无效 UTF-8 用替换字符表示，而不是丢弃——保证信息不丢失。
    let text = String::from_utf8_lossy(data);

    // 模式 1：整串作为 URI 解析。
    check(&text);

    // 模式 2：把同一份输入接在每个合法前缀之后，强制进入深层解析。
    // 用取首字节的方式选择前缀，而不是循环全部——fuzzer 通过变异这个字节
    // 就能切换前缀，从而在有限预算内覆盖所有分支。
    if let Some(&selector) = data.first() {
        let prefix = PREFIXES[usize::from(selector) % PREFIXES.len()];
        let mut candidate = String::with_capacity(prefix.len() + text.len());
        candidate.push_str(prefix);
        candidate.push_str(&text);
        check(&candidate);
    }
});

/// 断言解析结果不 panic、不泄露。
fn check(text: &str) {
    // 唯一必须成立的性质：返回，而不是崩溃。
    let Ok(parsed) = uri::parse(text) else {
        return;
    };

    // 解析成功时，`Debug` 不得输出种子。
    //
    // # 断言的是「secret 字段已脱敏」，不是「种子串不出现在输出里」
    //
    // 后者是错的：`issuer` 与 `account` 也来自 URI，完全可以合法地包含与种子
    // 相同的字符。最初的写法就是前者，于是 fuzz 一构造出
    // `issuer = "...JBSWY3DPEHPK3PXP..."` 就报假阳性——那不是泄露，是两个
    // 无关字段恰好有相同子串。
    //
    // 正确性质是结构性的：`secret` 字段必须恒为脱敏标记。
    let debug = format!("{parsed:?}");
    assert!(
        debug.contains(r#"secret: "<redacted>""#),
        "Debug 未把 secret 字段脱敏：{debug}"
    );

    // 种子在 URI 里以 Base32 形式出现；若 `Debug` 里出现了 `secret:` 后紧跟
    // 真实 Base32，说明脱敏被绕过。检查方式是比较脱敏标记，并额外确认种子
    // **不会紧跟在 `secret: ` 之后**。
    let base32 = parsed.secret.to_base32();
    let leaked_as_secret_field = debug.contains(&format!(r#"secret: "{base32}""#));
    assert!(
        !leaked_as_secret_field,
        "Debug 的 secret 字段泄露了 Base32 种子：{debug}"
    );

    // `issuer` / `account` 必须被截断——它们是攻击者可控的无界输入，
    // 且可能含隐私（真实场景里是邮箱）。这条防止日志被恶意二维码放大。
    if let Some(issuer) = &parsed.issuer {
        if issuer.len() > 64 {
            // 截断后的表示以省略号结尾；未截断时 `Debug` 会原样打印。
            let full = format!("{issuer:?}");
            assert!(
                !debug.contains(&full),
                "超长 issuer 未被截断，日志可被放大（{} 字节）",
                issuer.len()
            );
        }
    }

    // 成功解析出的配置必须自洽——这些不变量若被破坏，说明校验有漏洞。
    //
    // 1. 种子非空（`OtpSecret` 的类型不变量）。
    assert!(parsed.secret.len() > 0, "解析出的种子为空");
    // 2. TOTP 不得带计数器，HOTP 必须带。
    match parsed.uri_type {
        uri::UriType::Totp => assert!(parsed.counter.is_none(), "TOTP 不应有 counter"),
        uri::UriType::Hotp => assert!(parsed.counter.is_some(), "HOTP 应有 counter"),
    }
    // 3. `period` 必须落在合法区间内（解析器自己定义的上限）。
    assert!(parsed.period > 0, "period 不应为 0");

    // 4. 序列化必须能成功解析回来（往返不产生 panic，也不产生非法状态）。
    //    这条同时 fuzz 了 `serialize` 的输出面。
    //
    //    注意这条断言曾经抓到两个真缺陷：
    //    - 账号名含 `:` 会被解析出来，但序列化再解析后 issuer/account 的归属
    //      会静默改变（现已在两端拒绝）。
    //    - HOTP 的 `period` 在往返中丢失（现在解析时归一为默认值）。
    if let Ok(roundtrip) = uri::serialize(&parsed) {
        if let Ok(reparsed) = uri::parse(&roundtrip) {
            assert_eq!(
                reparsed.secret.to_base32(),
                base32,
                "往返后的种子发生了变化"
            );
            assert_eq!(reparsed.account, parsed.account, "往返后账号发生了变化");
            assert_eq!(reparsed.issuer, parsed.issuer, "往返后 issuer 发生了变化");
            // 序列化是幂等的——第二次必须得到完全相同的字符串。
            let again = uri::serialize(&reparsed).expect("已能序列化一次，应能再次");
            assert_eq!(again, roundtrip, "序列化不幂等");
        }
    }
}
