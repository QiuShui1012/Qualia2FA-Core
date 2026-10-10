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

//! `otpauth://` URI 解析（Google Authenticator Key URI Format）。
//!
//! 这是本项目**最主要的攻击者可控输入面**：二维码内容、用户手输的链接、剪贴板
//! 文本都会进到这里。因此本模块的取向是「严格拒绝」而非「尽力理解」——解析出
//! 一个语义错误但结构合法的配置，比直接报错危险得多。
//!
//! # URI 结构
//!
//! ```text
//! otpauth://TYPE/LABEL?PARAMETERS
//! ```
//!
//! - `TYPE` 是 `totp` 或 `hotp`。
//! - `LABEL` 是 `accountname` 或 `issuer:accountname`，两部分都做百分号解码。
//!   **账号名本身不得含 `:`**（见下方拒绝规则）。
//! - `PARAMETERS` 是 `key=value&...`，按 `application/x-www-form-urlencoded` 解码。
//!
//! # 支持的参数
//!
//! | 参数 | 必需性 | 取值 | 默认 |
//! |---|---|---|---|
//! | `secret` | **必需** | Base32 | — |
//! | `issuer` | 可选 | 文本 | — |
//! | `algorithm` | 可选 | `SHA1` / `SHA256` / `SHA512` | `SHA1` |
//! | `digits` | 可选 | `6` / `7` / `8` | `6` |
//! | `period` | 可选 | 秒数，非零 | `30` |
//! | `counter` | **HOTP 必需** | 整数 | — |
//!
//! # 拒绝规则（全部有测试覆盖）
//!
//! - scheme 不是 `otpauth`，或 type 不是 `totp`/`hotp`
//! - 缺失 `secret`，或 `secret` 无法 Base32 解码
//! - `algorithm` 无法识别——**拒绝而非回退到 SHA-1**，因为静默回退会让用户拿到
//!   一个恒定错误的验证码，且错误信息无从查起
//! - `digits` 不在 {6,7,8}——必须严格校验，否则 `10^digits` 会溢出
//! - `period` 为 0 或无法解析
//! - `totp` 带了 `counter`，或 `hotp` 缺 `counter`
//! - `counter` 无法解析为整数
//! - **重复参数**（同一 key 出现两次）——不同实现取「第一个」还是「最后一个」
//!   并不一致，是经典的解析歧义，故直接拒绝
//! - label 里的 issuer 与 `issuer` 参数**同时存在但不一致**
//! - **账号名含 `:`**——它与 issuer 分隔符不可区分，会造成往返歧义
//!   （百分号编码也救不了它）。`serialize` 同样拒绝，两端一致。

use crate::otp::{Algorithm, Digits, OtpSecret};
use crate::{Error, Result};

/// URI 声明的类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriType {
    /// 基于时间的一次性密码（RFC 6238）。
    Totp,
    /// 基于计数器的一次性密码（RFC 4226）。
    Hotp,
}

impl UriType {
    /// 从 URI 的 authority 部分解析。
    ///
    /// 大小写不敏感（规范写 `totp`/`hotp`，但部分生成器会写大写）。
    fn parse(value: &str) -> Result<Self> {
        if value.eq_ignore_ascii_case("totp") {
            Ok(Self::Totp)
        } else if value.eq_ignore_ascii_case("hotp") {
            Ok(Self::Hotp)
        } else {
            Err(Error::UriUnsupportedType {
                name: truncate(value, 16),
            })
        }
    }
}

/// 解析后的 `otpauth://` 配置。
///
/// `Debug` 是**手写**的，因为其中含种子（[`OtpSecret`]）——派生 `Debug` 会调用
/// 各字段的 `Debug`，虽然 `OtpSecret` 自身已脱敏，但手写实现能让审阅者一眼确认
/// 没有任何字段可能泄露。
pub struct OtpAuth {
    /// 该条目是 TOTP 还是 HOTP。
    pub uri_type: UriType,
    /// OTP 种子。已校验非空。
    pub secret: OtpSecret,
    /// 发行方（服务名）。来自 `issuer` 参数或 label 前缀。
    pub issuer: Option<String>,
    /// 账号名（label 中 issuer 之后的部分，或整个 label）。
    pub account: String,
    /// 哈希算法。
    pub algorithm: Algorithm,
    /// 位数。
    pub digits: Digits,
    /// TOTP 时间步（秒）。
    ///
    /// **不变量**：只在 [`UriType::Totp`] 下有含义。HOTP 按计数器推进、不按时间，
    /// 因此 HOTP 条目的该字段恒为 [`DEFAULT_PERIOD`]。解析时会强制归一，不信任
    /// URI 里写的值。
    pub period: u64,
    /// HOTP 计数器。TOTP 时为 `None`。
    pub counter: Option<u64>,
}

/// `Debug` 中 `issuer` / `account` 字段的最大打印长度（字节）。
///
/// 见 [`OtpAuth`] 的 `Debug` 实现说明。
const DEBUG_MAX_FIELD: usize = 64;

impl core::fmt::Debug for OtpAuth {
    /// 手写实现，出于两个考虑：
    ///
    /// 1. **不打印种子**。`OtpSecret` 自身的 `Debug` 已脱敏，但手写能让审阅者
    ///    一眼确认没有任何路径可能把种子带出来。
    /// 2. **截断 `issuer` / `account`**。这两个字段来自攻击者可控的 URI，
    ///    长度无界；而且它们**不是秘密但可能是隐私**（真实场景里常见
    ///    `issuer = "GitHub"`、`account = "alice@example.com"`）。无界打印会让
    ///    一个恶意二维码把任意长度的内容灌进日志，而这类日志常被上传到问题
    ///    追踪系统。截断是「够用来调试」与「不成为放大器」之间的折中。
    ///
    /// 注意截断**不是**为了防种子泄露——种子在 `secret` 字段里且从不打印。
    /// 它防的是日志放大与隐私外溢。
    ///
    /// 该截断由 fuzz 目标 `uri_parse` 的前身发现：当时它无条件打印 `issuer`，
    /// 一个构造出的超长 issuer 就让 `Debug` 输出膨胀到数十字节以上。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OtpAuth")
            .field("uri_type", &self.uri_type)
            // 只说明「已脱敏」，连种子的长度都不给——与 `OtpSecret` 的 Debug 一致。
            .field("secret", &"<redacted>")
            .field(
                "issuer",
                &self.issuer.as_deref().map(|s| truncate(s, DEBUG_MAX_FIELD)),
            )
            .field("account", &truncate(&self.account, DEBUG_MAX_FIELD))
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("counter", &self.counter)
            .finish()
    }
}

/// 把可能超长的输入截断后再放进错误，避免把攻击者可控的任意长度文本带进日志。
fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    // 必须在字符边界截断，否则会在多字节字符中间切开而 panic。
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::from(&value[..end]);
    out.push('…');
    out
}

/// 解析 `otpauth://` URI。
///
/// 规则与拒绝条件见[模块文档](self)。
///
/// # 示例
///
/// ```
/// use qualia2fa_core::uri;
/// use qualia2fa_core::otp::{Algorithm, Digits};
///
/// let uri = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8";
/// let parsed = uri::parse(uri).expect("合法 URI");
/// assert_eq!(parsed.issuer.as_deref(), Some("GitHub"));
/// assert_eq!(parsed.account, "alice");
/// assert_eq!(parsed.digits, Digits::Eight);
/// assert_eq!(parsed.algorithm, Algorithm::Sha1);
/// ```
pub fn parse(input: &str) -> Result<OtpAuth> {
    // ── 1. 拆分 scheme ──────────────────────────────────────────────────
    // 刻意不引入通用 URL 解析库：`otpauth` 不是 WHATWG 的 special scheme，
    // 用通用解析器反而要处理一堆与本格式无关的规则（如 host 大小写归一、
    // 默认端口、路径规范化），且得不到更好的正确性保证。
    let after_scheme =
        strip_prefix_ignore_ascii_case(input, "otpauth://").ok_or(Error::UriUnsupportedScheme)?;

    // ── 2. 拆分 query ───────────────────────────────────────────────────
    // 用 `split_once` 找第一个 `?`。`#`（fragment）按规范不存在于本格式，
    // 若出现则视为 query 的一部分后在参数解析阶段被拒（无法构成合法 key=value）。
    let (path_and_authority, query) = match after_scheme.split_once('?') {
        Some((left, right)) => (left, Some(right)),
        None => (after_scheme, None),
    };

    // ── 3. 拆分 type 与 label ───────────────────────────────────────────
    let (type_part, label_part) = path_and_authority.split_once('/').ok_or(
        // 没有 `/` 说明既没有 type 也没有 label。
        Error::UriMissingType,
    )?;
    let uri_type = UriType::parse(type_part)?;

    // label 做百分号解码。`form_urlencoded` 的 parse 接受 `+` 作为空格，
    // 但路径段里 `+` 应是字面加号——这是本格式常见的实现分歧点。
    // 规范要求对 label 做百分号解码，故此处只解 `%XX`，不把 `+` 当空格。
    let label = percent_decode_path(label_part)?;

    // ── 4. 解析 query 参数 ──────────────────────────────────────────────
    let params = parse_params(query)?;

    // ── 5. 组装并校验 ───────────────────────────────────────────────────
    let secret_raw = params.secret.ok_or(Error::UriMissingSecret)?;
    let secret = OtpSecret::from_base32(&secret_raw)?;

    let algorithm = match &params.algorithm {
        Some(name) => Algorithm::parse(name)?,
        None => Algorithm::default(),
    };

    let digits = match &params.digits {
        Some(value) => Digits::parse(value)?,
        None => Digits::default(),
    };

    let period = match &params.period {
        Some(value) => parse_period(value)?,
        None => DEFAULT_PERIOD,
    };

    // HOTP 必须有 counter；TOTP 必须没有——两者都严格，因为放错类型会让用户
    // 拿到一个恒定错误的验证码。
    //
    // 另：**HOTP 的 `period` 字段无意义**（HOTP 按计数器推进，不按时间），因此
    // 无论 URI 里写了什么 `period`，一律归一为默认值。这不是「忽略用户的输入」，
    // 而是让 `OtpAuth` 的不变量成为「`period` 只在 TOTP 下有含义」——否则
    // `serialize` 不写 `period`、`parse` 却又读进来，往返就会丢数据。
    // 该问题由 proptest 的 `otpauth_uri_roundtrips` 抓到（最小反例：HOTP + period=1）。
    let counter = match uri_type {
        UriType::Hotp => Some(parse_counter(
            params.counter.as_deref().ok_or(Error::UriMissingCounter)?,
        )?),
        UriType::Totp => {
            if params.counter.is_some() {
                return Err(Error::UriUnexpectedCounter);
            }
            None
        }
    };
    let period = if uri_type == UriType::Hotp {
        DEFAULT_PERIOD
    } else {
        period
    };

    // label 里的 issuer 与 issuer 参数必须一致（若两者都存在）。
    let (label_issuer, account) = split_label(&label)?;
    let issuer = resolve_issuer(label_issuer, params.issuer)?;

    Ok(OtpAuth {
        uri_type,
        secret,
        issuer,
        account,
        algorithm,
        digits,
        period,
        counter,
    })
}

/// TOTP 的默认时间步（秒），RFC 6238 §4.1 的建议值。
pub const DEFAULT_PERIOD: u64 = 30;

/// `period` 的合理上限：一年。
///
/// 该值不是规范要求，而是防止明显错误的输入（例如把毫秒当秒写进来）产生
/// 「永远不变」的验证码——那种配置看起来能用，实则已失去第二因子的意义。
const MAX_PERIOD: u64 = 366 * 24 * 60 * 60;

/// 解析 `period` 参数。
fn parse_period(value: &str) -> Result<u64> {
    let Ok(period) = value.parse::<u64>() else {
        return Err(Error::UriInvalidParameter {
            name: "period".to_owned(),
            reason: format!("不是合法整数：{}", truncate(value, 16)),
        });
    };
    if period == 0 {
        return Err(Error::InvalidPeriod);
    }
    if period > MAX_PERIOD {
        return Err(Error::UriInvalidParameter {
            name: "period".to_owned(),
            reason: format!("超出上限 {MAX_PERIOD} 秒"),
        });
    }
    Ok(period)
}

/// 解析 `counter` 参数。
fn parse_counter(value: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|_| Error::UriInvalidParameter {
            name: "counter".to_owned(),
            reason: format!("不是合法无符号整数：{}", truncate(value, 16)),
        })
}

/// 把 label 拆成 `(issuer, account)`。
///
/// 按规范只在**第一个** `:` 处分割。
///
/// # 为什么账号名里不允许出现 `:`
///
/// label 用 `:` 分隔 issuer 与 account，所以账号名里的 `:` **无法与分隔符区分**。
/// 这会造成真实的往返歧义。实测反例（由穷举诊断程序找到）：
///
/// ```text
/// 输入:       otpauth://totp/:a::a?secret=AA
/// 首次解析:   account = "a::a",  issuer = None
/// 序列化后:   otpauth://totp/a%3A%3Aa?secret=AA
/// 再次解析:   account = ":a",    issuer = Some("a")   ← 静默改变了归属
/// ```
///
/// 注意**百分号编码救不了它**：解析时先把 `%3A` 解码成 `:`，之后就再也无法区分
/// 这个 `:` 原本就在账号名里、还是被用来分隔 issuer。
///
/// 三种处理方式里：
///
/// - **保留**（原实现）：往返静默改变 issuer/account 归属 —— 最危险，用户会把
///   一个条目的验证码错配到另一个服务上。
/// - **只在序列化时编码**：解析回来依旧歧义，没解决问题。
/// - **拒绝**（本实现）：把不变量强制在两端，违规立刻可见。
///
/// 选拒绝。这也与规范一致：Google Authenticator Key URI Format 的 label 是
/// `issuer:accountname`，账号名本身不含 `:`。
///
/// # 错误
///
/// 账号名（第一个 `:` 之后的部分）含 `:` 时返回 [`Error::UriAccountContainsColon`]。
fn split_label(label: &str) -> Result<(Option<&str>, String)> {
    let (prefix, account) = match label.split_once(':') {
        // 前缀为空的 `:account` 视为「没有 issuer」，而不是 issuer 为空串。
        Some((prefix, rest)) if !prefix.is_empty() => (Some(prefix), rest),
        Some((_, rest)) => (None, rest),
        None => (None, label),
    };

    // 此处的 `account` 是**已解码**的文本，因此 `%3A` 形式的冒号同样在此被拦下。
    if account.contains(':') {
        return Err(Error::UriAccountContainsColon {
            account: truncate(account, 32),
        });
    }
    Ok((prefix, account.to_owned()))
}

/// 合并 label 前缀与 `issuer` 参数，冲突时报错。
fn resolve_issuer(
    label_issuer: Option<&str>,
    param_issuer: Option<String>,
) -> Result<Option<String>> {
    match (label_issuer, param_issuer) {
        (Some(from_label), Some(from_param)) => {
            if from_label == from_param {
                Ok(Some(from_param))
            } else {
                Err(Error::UriIssuerMismatch {
                    in_label: truncate(from_label, 32),
                    in_parameter: truncate(&from_param, 32),
                })
            }
        }
        (Some(from_label), None) => Ok(Some(from_label.to_owned())),
        (None, from_param) => Ok(from_param),
    }
}

/// 忽略 ASCII 大小写地剥离前缀。
///
/// scheme 按 RFC 3986 是大小写不敏感的，故 `OTPAUTH://` 也接受。
///
/// # 为什么不能用 `split_at`
///
/// 最初实现写成 `input.split_at(prefix.len())`，这在**非字符边界**上会 panic。
/// `"otpauth://"` 是 10 字节，而 `input` 的第 10 字节完全可能落在一个多字节字符
/// 中间——例如 `"otpauth://"` 后紧跟 `%C2%80`（U+0080 的百分号编码）时，
/// 第 10 字节是 `%`……但若前缀长度恰好切在别的输入的多字节序列里就会崩。
///
/// 这是**攻击者可控输入导致的 panic**（本模块的输入来自二维码与剪贴板），
/// 所以必须用 `str::get` 做边界检查。该 bug 由 proptest 的
/// `uri_parser_never_panics` 抓到，最小反例的账号名是 `"\u{80}"`。
fn strip_prefix_ignore_ascii_case<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    // `get` 在越界或非字符边界时返回 `None`，不会 panic。
    // 长度不足时同样返回 `None`，故无需单独做长度检查。
    let head = input.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| input.get(prefix.len()..).unwrap_or_default())
}

/// 对 URI 路径段做百分号解码。
///
/// **与 query 的解码规则不同**：路径段里 `+` 是字面加号，不是空格。若把 label
/// 交给 `form_urlencoded` 处理，`issuer` 里的 `+` 会被错误地变成空格。
///
/// # 为什么必须先收集字节再整体转字符串
///
/// 一个多字节 UTF-8 字符会被编码成多个连续的 `%XX`（例如「中」是
/// `%E4%B8%AD`）。若对每个 `%XX` 单独调用 `char::from`，得到的是三个
/// Latin-1 字符 `ä¸` 而不是一个「中」——这是本函数最初的真实 bug，由
/// `path_decoding_handles_multibyte_utf8` 测试抓到。
///
/// 正确做法是先解成字节序列，最后一次性做 UTF-8 校验。这同时带来一个额外好处：
/// 非法的字节序列（例如 `%FF`）会被拒绝，而不是被静默接受成一个错误字符。
fn percent_decode_path(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    // 解码后长度不会超过原串（`%XX` 三字节变一字节），故按原长度预分配即可。
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // 需要后面恰好两个十六进制数字。
            if i + 2 >= bytes.len() {
                return Err(Error::UriInvalidPercentEncoding);
            }
            let hi = hex_value(bytes[i + 1]).ok_or(Error::UriInvalidPercentEncoding)?;
            let lo = hex_value(bytes[i + 2]).ok_or(Error::UriInvalidPercentEncoding)?;
            decoded.push(hi << 4 | lo);
            i += 3;
        } else {
            // 非 `%` 字节原样透传。找到下一个 `%` 或结尾，一次追加一整段，
            // 避免逐字节处理。
            let start = i;
            while i < bytes.len() && bytes[i] != b'%' {
                i += 1;
            }
            decoded.extend_from_slice(&bytes[start..i]);
        }
    }
    // 整体校验 UTF-8：解码结果必须是合法文本，否则说明 URI 被损坏或伪造。
    String::from_utf8(decoded).map_err(|_| Error::UriInvalidPercentEncoding)
}

/// 十六进制数字的数值。
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// query 参数集合。用具名字段而非 `HashMap`，以便编译器检查「哪些参数被读取」。
#[derive(Default)]
struct Params {
    /// `secret`：Base32 种子（必需）。
    secret: Option<String>,
    /// `issuer`：发行方。
    issuer: Option<String>,
    /// `algorithm`：哈希算法名。
    algorithm: Option<String>,
    /// `digits`：位数。
    digits: Option<String>,
    /// `period`：TOTP 时间步。
    period: Option<String>,
    /// `counter`：HOTP 计数器。
    counter: Option<String>,
}

/// 解析 query 字符串。
///
/// **重复参数直接拒绝**：不同实现取「第一个」还是「最后一个」并不一致，
/// 是经典的解析歧义（也是攻击面——攻击者可以构造出两个应用理解不同的 URI）。
fn parse_params(query: Option<&str>) -> Result<Params> {
    let mut params = Params::default();
    let Some(query) = query else {
        return Ok(params);
    };

    // 空 query（`?` 后面什么都没有）是合法的，视为无参数。
    if query.is_empty() {
        return Ok(params);
    }

    // 用 `form_urlencoded` 做 query 解码：这正是该 crate 的标准用途
    // （`application/x-www-form-urlencoded`），且它把 `+` 正确解为空格——
    // 这对 `issuer=ACME+Co` 这类写法是必要的。
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        // 未知参数按规范应忽略（生成器会加 `image=` 等扩展），但**已知参数**
        // 的重复必须拒绝。
        let slot = match key.as_ref() {
            "secret" => &mut params.secret,
            "issuer" => &mut params.issuer,
            "algorithm" => &mut params.algorithm,
            "digits" => &mut params.digits,
            "period" => &mut params.period,
            "counter" => &mut params.counter,
            _ => continue,
        };
        if slot.is_some() {
            return Err(Error::UriDuplicateParameter {
                name: truncate(&key, 16),
            });
        }
        *slot = Some(value.into_owned());
    }
    Ok(params)
}

/// 把解析结果序列化回 `otpauth://` URI。
///
/// 用于导出与二维码生成。**不保证与输入逐字节相同**（参数顺序、默认值是否省略
/// 都会规范化），但保证 `parse(serialize(x)?)` 与原值等价。
///
/// `secret` 会用 Base32 重新编码为**无填充大写**形式——这是各认证器最普遍的写法，
/// 也避免二维码里出现 `=` 带来的转义问题。
///
/// # 错误
///
/// `auth.account` 含 `:` 时返回 [`Error::UriAccountContainsColon`]。
///
/// # 为什么返回 `Result` 而不是直接编码冒号
///
/// 因为**编码冒号并不解决问题**：解析端把 `%3A` 解码回 `:` 后，同样无法区分
/// 它是账号名的一部分还是 issuer 分隔符。若这里悄悄编码，就会产出一个
/// 「解析回来与预期不同的」URI——静默的数据损坏。返回错误让调用方立刻知道
/// 该配置无法表示。
///
/// 同样地，`auth.period` 对 HOTP 无意义，本函数不会写出它（见 [`OtpAuth::period`]
/// 的不变量说明）。
pub fn serialize(auth: &OtpAuth) -> Result<String> {
    // 强制与 `split_label` 相同的不变量：两端一致，才能保证往返等价。
    if auth.account.contains(':') {
        return Err(Error::UriAccountContainsColon {
            account: truncate(&auth.account, 32),
        });
    }

    let mut out = String::from("otpauth://");
    out.push_str(match auth.uri_type {
        UriType::Totp => "totp",
        UriType::Hotp => "hotp",
    });
    out.push('/');

    // label：`issuer:account`，两部分都做百分号编码。
    if let Some(issuer) = &auth.issuer {
        out.push_str(&percent_encode_path(issuer));
        out.push(':');
    }
    out.push_str(&percent_encode_path(&auth.account));

    out.push('?');
    // 种子的 Base32 无填充形式由 `OtpSecret::to_base32` 提供，本模块不接触裸字节。
    out.push_str("secret=");
    out.push_str(&auth.secret.to_base32());

    if let Some(issuer) = &auth.issuer {
        out.push_str("&issuer=");
        out.push_str(&percent_encode_query(issuer));
    }
    // 只在非默认值时写出，使输出的 URI 更短，也更接近各生成器的习惯。
    if auth.algorithm != Algorithm::default() {
        out.push_str("&algorithm=");
        out.push_str(match auth.algorithm {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        });
    }
    if auth.digits != Digits::default() {
        out.push_str("&digits=");
        out.push_str(&auth.digits.count().to_string());
    }
    if auth.uri_type == UriType::Totp && auth.period != DEFAULT_PERIOD {
        out.push_str("&period=");
        out.push_str(&auth.period.to_string());
    }
    if let Some(counter) = auth.counter {
        out.push_str("&counter=");
        out.push_str(&counter.to_string());
    }
    Ok(out)
}

/// 对 URI **路径段**做百分号编码。
///
/// 保留 RFC 3986 的 `pchar` 中无需转义的字符，其余（含 `:`、`/`、`?`、`#`、`%`
/// 与所有非 ASCII 字节）编码为 `%XX`。`+` 在此处**必须**编码，否则会被
/// query 解码规则误解为空格。
fn percent_encode_path(input: &str) -> String {
    /// 路径段中无需编码的字符（RFC 3986 `unreserved` 与部分 `sub-delims`）。
    const SAFE: &[u8] = b"-._~!$&'()*+,;=@";

    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        if byte.is_ascii_alphanumeric() || SAFE.contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

/// 对 query 的**值**做百分号编码（空格用 `+` 以外的 `%20`，更无歧义）。
fn percent_encode_query(input: &str) -> String {
    /// query 值中无需编码的字符。
    const SAFE: &[u8] = b"-._~";

    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        if byte.is_ascii_alphanumeric() || SAFE.contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

// 说明：本模块的详细测试放在 `tests/uri_parsing.rs`（集成测试），因为拒绝规则
// 是**对外契约**，值得作为独立文件审阅。此处只留少量实现细节测试。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_value_accepts_both_cases() {
        assert_eq!(hex_value(b'0'), Some(0));
        assert_eq!(hex_value(b'9'), Some(9));
        assert_eq!(hex_value(b'a'), Some(10));
        assert_eq!(hex_value(b'F'), Some(15));
        // 用字节串字面量而非 `[b'g', b'G', ...]` 数组：迭代的是 `&u8`，
        // 与 `hex_value(u8)` 的签名配合只需解引用。
        for &bad in b"gG/: " {
            assert_eq!(hex_value(bad), None, "{bad:?} 不应被接受");
        }
    }

    #[test]
    fn path_decoding_does_not_treat_plus_as_space() {
        // 这是与 query 解码的关键差别。
        assert_eq!(percent_decode_path("a+b").expect("应可解码"), "a+b");
        assert_eq!(percent_decode_path("a%2Bb").expect("应可解码"), "a+b");
        assert_eq!(percent_decode_path("a%20b").expect("应可解码"), "a b");
    }

    #[test]
    fn path_decoding_handles_multibyte_utf8() {
        // "中" 的 UTF-8 是 E4 B8 AD。
        assert_eq!(percent_decode_path("%E4%B8%AD").expect("应可解码"), "中");
        // 裸多字节字符应原样保留。
        assert_eq!(percent_decode_path("中").expect("应可解码"), "中");
        // 混合。
        assert_eq!(
            percent_decode_path("a%E4%B8%ADb").expect("应可解码"),
            "a中b"
        );
    }

    #[test]
    fn path_decoding_rejects_malformed_escapes() {
        // 三类问题：缺十六进制数字、非法十六进制字符、`%` 在结尾。
        for bad in ["%", "%A", "%GG", "abc%", "abc%A"] {
            assert!(
                matches!(
                    percent_decode_path(bad),
                    Err(Error::UriInvalidPercentEncoding)
                ),
                "{bad:?} 应因编码格式被拒绝"
            );
        }
    }

    /// 解码结果必须是合法 UTF-8——非法字节序列应被拒绝，而不是被静默接受。
    ///
    /// 这条测试同时锁住「先收集字节再整体校验」的实现方式：若改回逐字节
    /// `char::from`，`path_decoding_handles_multibyte_utf8` 会先失败。
    #[test]
    fn path_decoding_rejects_invalid_utf8() {
        for bad in [
            "%FF",    // 单字节 0xFF 在 UTF-8 中永不合法
            "%80",    // 孤立的续接字节
            "%E4%B8", // 被截断的三字节序列（"中" 少最后一字节）
            "%C0%80", // 过长编码（overlong）表示 NUL
            "ok%FE",  // 前面合法、后面非法
        ] {
            assert!(
                matches!(
                    percent_decode_path(bad),
                    Err(Error::UriInvalidPercentEncoding)
                ),
                "{bad:?} 应因非法 UTF-8 被拒绝"
            );
        }
    }

    #[test]
    fn strip_prefix_is_case_insensitive() {
        assert_eq!(
            strip_prefix_ignore_ascii_case("OTPAUTH://x", "otpauth://"),
            Some("x")
        );
        assert_eq!(
            strip_prefix_ignore_ascii_case("otpauth://x", "otpauth://"),
            Some("x")
        );
        assert_eq!(
            strip_prefix_ignore_ascii_case("http://x", "otpauth://"),
            None
        );
        assert_eq!(strip_prefix_ignore_ascii_case("otp", "otpauth://"), None);
    }

    #[test]
    fn label_splits_on_first_colon_only() {
        assert_eq!(
            split_label("ACME:john@example.com").expect("合法"),
            (Some("ACME"), "john@example.com".to_owned())
        );
        assert_eq!(
            split_label("justaccount").expect("合法"),
            (None, "justaccount".to_owned())
        );
        // 空前缀视为无 issuer。
        assert_eq!(
            split_label(":acct").expect("合法"),
            (None, "acct".to_owned())
        );
    }

    /// 账号名里的 `:` 必须被拒绝——它与 issuer 分隔符不可区分。
    ///
    /// 本测试只覆盖 `split_label` 这一层，因此只用**字面**冒号。百分号编码的
    /// 冒号（`%3A`）要等 `percent_decode_path` 解码之后才变成冒号，属于端到端
    /// 行为，由 `tests/proptest.rs` 的 `regression_account_with_colon_is_rejected_on_both_ends`
    /// 覆盖。
    #[test]
    fn label_rejects_colon_in_account() {
        for bad in ["ACME:john:8080", ":a::a", "a::b", "x:y:z"] {
            assert!(
                matches!(split_label(bad), Err(Error::UriAccountContainsColon { .. })),
                "{bad:?} 应被拒绝"
            );
        }

        // 空账号名是合法的：`"a:"` 在第一个冒号处分割后账号为空串，其中不含冒号，
        // 不应被这条规则误伤。
        assert_eq!(
            split_label("a:").expect("空账号名应被接受"),
            (Some("a"), String::new())
        );

        // 但 `"::"` 必须被拒绝：第一个冒号之前是空串（视为无 issuer），
        // 之后剩下的账号名是 `":"`，仍然含冒号。
        // 注意这与「空账号名合法」并不矛盾——前者账号是空串，后者账号是冒号。
        assert!(
            matches!(
                split_label("::"),
                Err(Error::UriAccountContainsColon { .. })
            ),
            "\"::\" 的账号名是 \":\"，应被拒绝"
        );
    }

    /// `serialize` 必须拒绝含冒号的账号名，而不是悄悄产出一个解析回来不同的 URI。
    #[test]
    fn serialize_rejects_colon_in_account() {
        let auth = OtpAuth {
            uri_type: UriType::Totp,
            secret: OtpSecret::from_bytes(vec![1, 2, 3, 4]).expect("非空"),
            issuer: Some("ACME".to_owned()),
            account: "john:8080".to_owned(),
            algorithm: Algorithm::Sha1,
            digits: Digits::Six,
            period: DEFAULT_PERIOD,
            counter: None,
        };
        assert!(matches!(
            serialize(&auth),
            Err(Error::UriAccountContainsColon { .. })
        ));
    }

    #[test]
    fn issuer_mismatch_is_rejected() {
        let result = resolve_issuer(Some("GitHub"), Some("Gitlab".to_owned()));
        assert!(matches!(result, Err(Error::UriIssuerMismatch { .. })));
    }

    #[test]
    fn issuer_may_come_from_either_source() {
        assert_eq!(
            resolve_issuer(Some("GitHub"), None).expect("应成功"),
            Some("GitHub".to_owned())
        );
        assert_eq!(
            resolve_issuer(None, Some("GitHub".to_owned())).expect("应成功"),
            Some("GitHub".to_owned())
        );
        assert_eq!(
            resolve_issuer(Some("GitHub"), Some("GitHub".to_owned())).expect("一致时应成功"),
            Some("GitHub".to_owned())
        );
    }

    #[test]
    fn period_bounds_are_enforced() {
        assert_eq!(parse_period("30").expect("30 合法"), 30);
        assert!(matches!(parse_period("0"), Err(Error::InvalidPeriod)));
        assert!(matches!(
            parse_period("99999999999999999999"),
            Err(Error::UriInvalidParameter { .. })
        ));
        assert!(matches!(
            parse_period(&(MAX_PERIOD + 1).to_string()),
            Err(Error::UriInvalidParameter { .. })
        ));
        assert!(parse_period(&MAX_PERIOD.to_string()).is_ok());
    }

    #[test]
    fn counter_parsing_is_strict() {
        assert_eq!(parse_counter("0").expect("0 合法"), 0);
        assert_eq!(
            parse_counter("18446744073709551615").expect("u64 上限合法"),
            u64::MAX
        );
        for bad in ["-1", "1.5", "", "abc", "18446744073709551616"] {
            assert!(
                matches!(parse_counter(bad), Err(Error::UriInvalidParameter { .. })),
                "{bad:?} 应被拒绝"
            );
        }
    }

    #[test]
    fn percent_encoding_roundtrips_through_decoding() {
        for original in [
            "simple",
            "with space",
            "with+plus",
            "with:colon",
            "with/slash",
            "中文",
            "a%b",
            "a&b=c",
            "100%",
        ] {
            let encoded = percent_encode_path(original);
            let decoded = percent_decode_path(&encoded)
                .unwrap_or_else(|e| panic!("{original:?} 编码为 {encoded:?} 后无法解码: {e}"));
            assert_eq!(decoded, original, "路径编码往返失败：{encoded:?}");
        }
    }

    #[test]
    fn query_encoding_roundtrips_through_form_decoding() {
        for original in ["simple", "with space", "with+plus", "中文", "a&b=c", "a%b"] {
            let encoded = percent_encode_query(original);
            let decoded = form_urlencoded::parse(format!("v={encoded}").as_bytes())
                .next()
                .expect("应有一个参数")
                .1
                .into_owned();
            assert_eq!(decoded, original, "query 编码往返失败：{encoded:?}");
        }
    }

    #[test]
    fn truncate_never_splits_a_character() {
        // 每个中文字符 3 字节，max=16 会落在字符中间，必须回退到边界。
        let long = "中".repeat(20);
        let text = truncate(&long, 16);
        assert!(text.ends_with('…'));
        assert!(long.starts_with(text.trim_end_matches('…')));
    }

    #[test]
    fn debug_output_hides_the_secret() {
        let auth = parse("otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME")
            .expect("合法 URI");
        let text = format!("{auth:?}");
        assert!(text.contains("redacted"), "应标注脱敏：{text}");
        assert!(
            !text.contains("JBSWY3DPEHPK3PXP"),
            "Debug 泄露了 Base32 种子：{text}"
        );
        // issuer 与 account 不是秘密，应正常显示以便调试。
        assert!(text.contains("ACME"), "应显示 issuer：{text}");
        assert!(text.contains("alice"), "应显示 account：{text}");
    }

    /// `Debug` 必须截断超长的 `issuer` / `account`。
    ///
    /// 这两个字段来自攻击者可控的 URI 且长度无界，同时可能含用户隐私
    /// （真实场景里是邮箱）。无界打印会让一个恶意二维码把任意长度内容灌进日志，
    /// 而这类日志常被上传到问题追踪系统。
    ///
    /// 该问题由 fuzz 目标 `uri_parse` 发现：一个构造出的超长 issuer 让 `Debug`
    /// 输出里出现了数十字节的任意内容。
    #[test]
    fn debug_truncates_oversized_issuer_and_account() {
        let long_issuer = "I".repeat(500);
        let long_account = "A".repeat(500);
        let input = format!("otpauth://totp/{long_issuer}:{long_account}?secret=AA");
        let auth = parse(&input).expect("应可解析");

        let text = format!("{auth:?}");

        // 完整的 500 字符值不得出现在输出里。
        assert!(!text.contains(&long_issuer), "超长 issuer 未被截断：{text}");
        assert!(
            !text.contains(&long_account),
            "超长 account 未被截断：{text}"
        );
        // 截断应带省略号标记。
        assert!(text.contains('…'), "截断应带省略号：{text}");

        // 关键：截断只作用于**显示**，真实数据不受影响。
        assert_eq!(auth.account, long_account, "截断不应修改真实数据");
        assert_eq!(auth.issuer.as_deref(), Some(long_issuer.as_str()));

        // 输出总长度应有界（两个字段各 ≤64 字节 + 省略号 + 其它字段）。
        assert!(
            text.len() < 512,
            "Debug 输出应被限长，实际 {} 字节：{text}",
            text.len()
        );
    }
}
