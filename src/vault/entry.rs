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

//! 保险库条目：明文结构与条目标识。
//!
//! # 明文里有什么
//!
//! 一条 2FA 条目在**解密后**由 [`Entry`] 承载：显示名、发行方、账号、种子、
//! 算法、位数、周期/计数器、备注、以及创建与修改时间。
//!
//! # 明文里没有什么
//!
//! **条目没有任何全局可读的元数据。** 保险库文件中，一条条目除了它的
//! [`EntryId`] 与密文之外，不含任何结构化信息——连「这是 TOTP 还是 HOTP」
//! 都看不出来，因为那在密文内部。这是刻意的：保险库文件可能被同步到不可信的
//! 位置（用户自己选的网盘、二维码、另一台设备），任何明文字段都会被泄露。
//!
//! 因此 [`EntryId`] 是**唯一**的例外，而它是 128-bit CSPRNG 随机数，不携带
//! 任何语义——它的作用只是让两台设备能谈论「同一条条目」。

use crate::{Error, Result, otp};

/// 条目标识：128-bit CSPRNG 随机数。
///
/// # 为什么是随机数而不是哈希或序号
///
/// - **不是序号**：两台设备各自新建条目时，序号必然冲突（都从 0 开始），
///   同步取并集时会把两条无关条目当成同一条。
/// - **不是内容的哈希**：内容相同的两条条目（用户在同一服务注册了两个账号，
///   碰巧参数一致）会被合并，这是数据丢失。而且哈希会随内容变化，改名即变 ID，
///   同步会认为是两条不同的条目。
/// - **随机 128-bit**：碰撞概率在 2^64 条条目时才到生日界，实际使用规模下
///   可忽略。且它不泄露内容信息，可以安全地明文存放在保险库文件里。
///
/// # 显示
///
/// [`Debug`] 与 [`Display`](core::fmt::Display) 都只打印十六进制形式。ID 不是
/// 秘密（它明文存在文件里），但也不适合直接给用户看——它的用途是日志与
/// 排错时区分条目。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryId([u8; Self::LEN]);

impl EntryId {
    /// 标识的字节长度。
    pub const LEN: usize = 16;

    /// 生成一个新的随机标识。
    ///
    /// # 错误
    ///
    /// OS 随机源不可用时返回 [`Error::RandomnessUnavailable`]。此时**不得**
    /// 回退到任何用户态 PRNG：可预测的 ID 会让两台设备生成同一条目，
    /// 同步时静默合并成一条。
    pub fn generate() -> Result<Self> {
        let mut bytes = [0_u8; Self::LEN];
        crate::getrandom::fill(&mut bytes).map_err(|_| Error::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    /// 从字节数组构造。
    ///
    /// 用于从文件解析已有 ID——**创建新条目请用 [`EntryId::generate`]**，
    /// 否则两台设备会得到相同 ID。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// 取出原始字节，用于写入文件与构造 AAD。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl core::fmt::Debug for EntryId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EntryId({self})")
    }
}

impl core::fmt::Display for EntryId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// 时间戳：Unix 秒。
///
/// 由调用方传入，本库不读时钟（见 crate 文档的纯度约定）。
///
/// # 用途仅限用户可见的元数据
///
/// 这些时间戳**不参与**同步合并的胜负判定。合并规则是「发起方版本胜出」
/// （见设计决定 D2），不依赖时间戳比较——那样会需要时钟同步，而离线设备的
/// 时钟不可信。
pub type Timestamp = u64;

/// 一条解密后的 2FA 条目。
///
/// # 为什么字段是 `pub` 而不是 getter
///
/// 这是一个**纯数据载体**，没有任何不变量需要靠封装维持：合法性在
/// [`Entry::new`] 与反序列化时就已经验证过。用 getter 只会增加噪音。
///
/// 唯一的例外是 `secret`——它虽然不是私有字段，但它的类型
/// [`otp::OtpSecret`] 本身不给 `Clone`、不实现 `Debug` 的明文输出，
/// 秘密保护的约束由类型而不是可见性承担。
///
/// # 不变量：`issuer` 是 `None` 而不是 `Some("")`
///
/// 「没有发行方」只有 [`None`] 一种表示。若允许 `Some("")` 存在，条目就会有一个
/// **往返不稳定**的状态：存储格式把空串写成零长度节点，读回来归一为 `None`，
/// 于是「写出去再读回来」得到的是一个与原值不相等的条目。
///
/// 这种不稳定不会立刻造成故障，但会让「两份保险库是否等价」这类比较给出错误
/// 结论——而同步正是建立在比较之上。因此 [`Entry::new`] 直接把它归一掉，让
/// 非法状态**无法被构造出来**。
///
/// # 为什么没有 `PartialEq`
///
/// 因为 `secret` 字段的类型 [`otp::OtpSecret`] **刻意不实现 `PartialEq`**。
/// 派生会要求它实现，从而把「用 `==` 快速比较两个种子」变成一件随手可做的
/// 事——那是非恒定时间的比较，会通过耗时泄露前缀匹配长度。
///
/// 需要判断两个条目是否等价时，请逐字段比较，种子那一项用
/// [`otp::verify_code`] 那类恒定时间原语，或比较
/// [`otp::OtpSecret::to_base32`] 的结果（后者不是恒定时间，但只用于
/// 测试与显示，不参与认证判定）。
#[derive(Debug)]
pub struct Entry {
    /// 显示名。用户可读，可以与 `issuer`/`account` 无关。
    pub name: String,
    /// 发行方（`otpauth://` 的 `issuer`）。
    pub issuer: Option<String>,
    /// 账号名。
    pub account: String,
    /// OTP 种子。类型层面保证不被打印、不被误克隆。
    pub secret: otp::OtpSecret,
    /// HMAC 算法。
    pub algorithm: otp::Algorithm,
    /// 验证码位数。
    pub digits: otp::Digits,
    /// TOTP 的时间步长（秒）。HOTP 条目忽略此字段。
    pub period: u64,
    /// HOTP 的计数器。TOTP 条目为 `None`。
    pub counter: Option<u64>,
    /// 用户备注。可为空。
    pub note: String,
    /// 创建时间（Unix 秒）。
    pub created_at: Timestamp,
    /// 最后修改时间（Unix 秒）。
    pub updated_at: Timestamp,
}

impl PartialEq for Entry {
    /// 逐字段比较，其中秘密那一项走恒定时间比较。
    ///
    /// # 顺序是刻意的
    ///
    /// 先比**廉价且几乎必然不同**的字段（名字、账号、时间戳），最后才比种子。种子那一
    /// 项是恒定时间的（见 [`OtpSecret`](crate::otp::OtpSecret) 的 `PartialEq`），意味着
    /// 它总是比较全部字节；放在最后，那些名字就不同的条目对在第一个字段就被排除了，
    /// 不会付出那个代价。
    ///
    /// 这不是「优化」而是让恒定时间比较的代价可控：同步的合并循环要对成千上万对条目
    /// 做这个判断，而其中绝大多数连名字都不一样。
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.issuer == other.issuer
            && self.account == other.account
            && self.note == other.note
            && self.created_at == other.created_at
            && self.updated_at == other.updated_at
            && self.algorithm == other.algorithm
            && self.digits == other.digits
            && self.period == other.period
            && self.counter == other.counter
            && self.secret == other.secret
    }
}

impl Eq for Entry {}

impl Entry {
    /// 复制一份内容完全相同的条目。
    ///
    /// # 为什么需要它，而 `Clone` 又是刻意不给的
    ///
    /// [`OtpSecret`](crate::otp::OtpSecret) 刻意不实现 `Clone`，理由是「克隆会让同一
    /// 密钥在内存中多存一份、各自独立擦除，增加泄露面」。那个理由在**一般**情况下
    /// 成立，但同步有两个绕不开的需要：
    ///
    /// 1. **把对端的版本与本地版本同时呈现给裁决界面。** 冲突的本质就是「有两个不同
    ///    的版本」，只给一个就没法裁决。
    /// 2. **把对端那一版原样收进本地保险库。** 接收到的条目要落盘，而它同时也被记在
    ///    冲突记录里。
    ///
    /// 因此这里提供一个**显式**的复制入口，而不是给 `Entry` 派生 `Clone`：调用点必须
    /// 写下 `duplicate()`，从而在代码审查中可见「这里又复制了一份密钥材料」。派生
    /// `Clone` 会让复制在无数地方静默发生。
    ///
    /// # 实现
    ///
    /// 走一遍编解码往返，而不是逐字段复制。这样**新增字段时不需要记得改这里**——逐字段
    /// 复制的版本漏掉一个新字段，症状是「同步之后新字段全空了」，一个很容易漏过测试的
    /// 静默数据损失。代价是一次编解码，而复制发生在用户手动触发的同步路径上，不在任何
    /// 热路径里。
    ///
    /// # 错误
    ///
    /// 只有当条目本身违反格式约束时才会失败（例如某个字段超过
    /// [`Entry::MAX_FIELD_LEN`]）。能构造出这样一个条目就已经是 bug 了。
    pub fn duplicate(&self) -> Result<Self> {
        // `super` 是 `vault` 模块，编解码函数是那里的私有项。
        let encoded = super::encode_entry(self)?;
        super::decode_entry(&encoded)
    }

    /// 索引上限：单个可变长字段的最大字节数。
    ///
    /// # 为什么要有上限
    ///
    /// 这些字段在解密后成为 `String`，而密文长度不受任何天然约束——一个
    /// 构造出来的保险库文件可以声称某条目的名称有 4 GiB，解密时直接吃光内存。
    /// 解密**之后**才发现超长已经太晚，因此上限必须在分配时生效。
    ///
    /// 64 KiB 远大于任何真实字段（最长的账号名或备注也很少超过几百字节），
    /// 同时把「几百条条目」的最坏内存占用限制在可接受范围。
    pub const MAX_FIELD_LEN: usize = 64 * 1024;

    /// 条目的最大字段数，用于在解析时限制未知节的数量。
    ///
    /// 解析器遇到未知节点会跳过而不是报错（向前兼容），但没有上限的话，
    /// 一个全是未知节点的文件可以让跳过的循环跑很久。
    pub const MAX_FIELDS: usize = 64;

    /// 构造一条条目。
    ///
    /// # 错误
    ///
    /// - 种子为空 → [`Error::SecretEmpty`]（空种子无意义，且会让所有验证码相同）
    /// - 任一字段超过 [`Entry::MAX_FIELD_LEN`] → [`Error::FieldTooLong`]
    /// - `period` 为 0 → [`Error::InvalidPeriod`]（会导致除零）
    ///
    /// **不检查**种子长度是否达到推荐值：短种子在真实世界存在，属于告警而非
    /// 拒绝，见 [`otp::recommended_min_secret_len`]。
    ///
    /// # 条目的类型由 `counter` 决定
    ///
    /// `counter` 为 `Some` 即 HOTP，为 `None` 即 TOTP（见 [`Entry::uri_type`]）。
    /// 这里**不**额外要求「HOTP 必须给出 `counter`」——`None` 已经被解释为
    /// TOTP，不存在「HOTP 却没有计数器」这个状态。
    ///
    /// # 为什么参数这么多
    ///
    /// 11 个参数确实多，但它们全是条目的必填字段，没有一个可以省略或推导出来。
    /// 用构造器（builder）模式会让「忘记设置某个字段」从编译错误变成运行时错误，
    /// 而这里恰恰是密码学数据——一个静默默认值（`period` 默认 0、种子默认空）
    /// 造成的故障极难定位。参数表让「所有字段都必须给出」由类型系统强制。
    ///
    /// 调用方通常也不需要手工填这一长串：从二维码接入的路径走
    /// [`entry_from_parsed_uri`]，从文件恢复的路径走
    /// [`crate::vault::VaultFile::parse`]。
    #[expect(
        clippy::too_many_arguments,
        reason = "全部参数都是必填字段；改用 builder 会把编译期保证换成运行时默认值"
    )]
    pub fn new(
        name: String,
        issuer: Option<String>,
        account: String,
        secret: otp::OtpSecret,
        algorithm: otp::Algorithm,
        digits: otp::Digits,
        period: u64,
        counter: Option<u64>,
        note: String,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Result<Self> {
        // `OtpSecret` 自身保证非空（`from_bytes` 拒绝空输入），这里的检查是
        // 冗余的，但保留它意味着 `Entry` 的不变量不依赖另一个类型的历史行为。
        if secret.len() == 0 {
            return Err(Error::SecretEmpty);
        }
        if period == 0 {
            return Err(Error::InvalidPeriod);
        }
        for (field, value) in [
            ("name", Some(&name)),
            ("issuer", issuer.as_ref()),
            ("account", Some(&account)),
            ("note", Some(&note)),
        ] {
            if let Some(value) = value
                && value.len() > Self::MAX_FIELD_LEN
            {
                return Err(Error::FieldTooLong {
                    field,
                    limit: Self::MAX_FIELD_LEN,
                    actual: value.len(),
                });
            }
        }
        Ok(Self {
            name,
            // 空发行方归一为 `None`。这不是「顺手清理」，而是维持一个**往返
            // 稳定**的状态空间：见本类型文档里关于 `issuer` 不变量的说明。
            issuer: issuer.filter(|text| !text.is_empty()),
            account,
            secret,
            algorithm,
            digits,
            period,
            counter,
            note,
            created_at,
            updated_at,
        })
    }

    /// 该条目是 HOTP 还是 TOTP。
    ///
    /// 判据是 `counter` 是否存在，因为那是两者的**结构性**差异：TOTP 由时间
    /// 派生计数器，HOTP 的计数器必须由用户或同步状态提供。
    #[must_use]
    pub const fn uri_type(&self) -> crate::uri::UriType {
        if self.counter.is_some() {
            crate::uri::UriType::Hotp
        } else {
            crate::uri::UriType::Totp
        }
    }
}

/// 从 `otpauth://` 解析结果构造条目。
///
/// 这是把二维码扫进来的配置与本库的存储模型接起来的那一步。`now` 是当前
/// Unix 秒，由调用方传入（本库不读时钟），同时用作创建与修改时间。
///
/// # 错误
///
/// 与 [`Entry::new`] 相同的校验，因此正常解析出的 URI 不会失败——`uri::parse`
/// 已经保证了种子非空与 `period` 非零。二者都保留校验是为了让 [`Entry`]
/// 的不变量不依赖于调用顺序。
pub fn entry_from_parsed_uri(parsed: &crate::uri::OtpAuth, now: Timestamp) -> Result<Entry> {
    // `OtpSecret` 不可克隆（那会复制明文），因此这里重新从 Base32 解码一份。
    let secret = otp::OtpSecret::from_base32(&parsed.secret.to_base32())?;
    let name = match &parsed.issuer {
        Some(issuer) => format!("{issuer}:{}", parsed.account),
        None => parsed.account.clone(),
    };
    Entry::new(
        name,
        parsed.issuer.clone(),
        parsed.account.clone(),
        secret,
        parsed.algorithm,
        parsed.digits,
        parsed.period,
        parsed.counter,
        String::new(),
        now,
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secret() -> otp::OtpSecret {
        otp::OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("合法种子")
    }

    fn sample_entry() -> Entry {
        Entry::new(
            "GitHub".into(),
            Some("GitHub".into()),
            "alice".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::Six,
            30,
            None,
            String::new(),
            1_700_000_000,
            1_700_000_000,
        )
        .expect("合法条目")
    }

    #[test]
    fn entry_id_is_16_bytes_and_hex_displayed() {
        let id = EntryId::generate().expect("OS 随机源可用");
        assert_eq!(id.as_bytes().len(), 16);
        let text = id.to_string();
        assert_eq!(text.len(), 32, "十六进制应为 32 字符：{text}");
        assert!(text.chars().all(|c| c.is_ascii_hexdigit()));

        // 同一个 ID 的两种打印形式必须一致，避免日志里出现两种表示。
        assert_eq!(format!("{id:?}"), format!("EntryId({text})"));
    }

    #[test]
    fn entry_id_generation_does_not_repeat() {
        // 不是严格的随机性检验，只挡住「生成器退化为常量」这类错误。
        let ids: Vec<_> = (0..64)
            .map(|_| EntryId::generate().expect("OS 随机源可用"))
            .collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "随机 ID 出现重复");
    }

    #[test]
    fn rejects_empty_secret() {
        let empty = otp::OtpSecret::from_bytes(Vec::new());
        assert!(matches!(empty, Err(Error::SecretEmpty)));
    }

    #[test]
    fn rejects_zero_period() {
        let err = Entry::new(
            "x".into(),
            None,
            "a".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::Six,
            0,
            None,
            String::new(),
            0,
            0,
        );
        assert!(matches!(err, Err(Error::InvalidPeriod)));
    }

    #[test]
    fn rejects_oversized_field() {
        let err = Entry::new(
            "x".repeat(Entry::MAX_FIELD_LEN + 1),
            None,
            "a".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::Six,
            30,
            None,
            String::new(),
            0,
            0,
        );
        match err {
            Err(Error::FieldTooLong { field, .. }) => assert_eq!(field, "name"),
            other => panic!("应拒绝超长字段，实际 {other:?}"),
        }
    }

    /// **不变量测试**：空发行方必须在构造时就被归一为 `None`。
    ///
    /// # 这条测试的来历
    ///
    /// 由属性测试 `roundtrip_preserves_every_entry` 发现：策略生成了一条
    /// `issuer = Some("")` 的条目，存储格式把空串写成零长度节点，读回来归一为
    /// `None`，于是往返前后不相等——`Entry` 存在一个**往返不稳定**的状态。
    ///
    /// 修法是在唯一能构造 `Entry` 的入口把它归一掉，而不是在序列化时特判。
    /// 前者让非法状态无法存在，后者只是掩盖了它。
    #[test]
    fn empty_issuer_is_normalized_to_none() {
        let entry = Entry::new(
            "x".into(),
            Some(String::new()),
            "a".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::Six,
            30,
            None,
            String::new(),
            0,
            0,
        )
        .expect("其余字段合法");
        assert_eq!(entry.issuer, None, "空发行方应归一为 None");

        // 空白字符串**不**归一：它是用户输入的、可见的内容，不是「没有值」。
        let blank = Entry::new(
            "x".into(),
            Some("   ".into()),
            "a".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::Six,
            30,
            None,
            String::new(),
            0,
            0,
        )
        .expect("其余字段合法");
        assert_eq!(blank.issuer.as_deref(), Some("   "));
    }

    #[test]
    fn uri_type_follows_counter_presence() {
        let totp = sample_entry();
        assert_eq!(totp.uri_type(), crate::uri::UriType::Totp);

        let hotp = Entry::new(
            "h".into(),
            None,
            "a".into(),
            sample_secret(),
            otp::Algorithm::Sha1,
            otp::Digits::Six,
            30,
            Some(7),
            String::new(),
            0,
            0,
        )
        .expect("合法条目");
        assert_eq!(hotp.uri_type(), crate::uri::UriType::Hotp);
        assert_eq!(hotp.counter, Some(7));
    }

    /// `Debug` 是条目最可能被误打进日志的路径，必须不含种子。
    #[test]
    fn debug_does_not_leak_secret() {
        let entry = sample_entry();
        let debug = format!("{entry:?}");
        assert!(debug.contains("GitHub"), "非秘密字段应正常：{debug}");
        assert!(debug.contains("alice"), "非秘密字段应正常：{debug}");

        // 种子的 Base32 与原始字节两种形态都不得出现。
        let base32 = entry.secret.to_base32();
        assert!(
            !debug.contains(&base32),
            "Debug 泄露了种子的 Base32：{debug}"
        );
        assert!(!debug.contains("JBSWY3DP"), "Debug 泄露了种子：{debug}");
    }

    #[test]
    fn convert_from_parsed_uri() {
        let parsed =
            crate::uri::parse("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
                .expect("合法 URI");
        let entry = entry_from_parsed_uri(&parsed, 1_700_000_000).expect("可转换");
        assert_eq!(entry.issuer.as_deref(), Some("GitHub"));
        assert_eq!(entry.account, "alice");
        assert_eq!(entry.name, "GitHub:alice");
        assert_eq!(entry.uri_type(), crate::uri::UriType::Totp);
        assert!(entry.note.is_empty());
        assert_eq!(entry.created_at, 1_700_000_000);
        assert_eq!(entry.created_at, entry.updated_at);

        // 转换必须真的搬走了种子，而不只是留下一个空壳。
        assert_eq!(
            entry.secret.to_base32(),
            parsed.secret.to_base32(),
            "转换后种子发生了变化"
        );
    }
}
