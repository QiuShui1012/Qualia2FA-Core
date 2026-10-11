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

//! 错误类型。
//!
//! 本库所有对外函数返回 [`Result`]，**任何输入都不得导致 panic**。
//!
//! # 秘密信息纪律
//!
//! 错误类型**绝不能携带秘密材料**：不放原始输入、不放密钥字节、不放 OTP 码。
//! 本模块的变体只记录「哪一类输入非法」以及必要的**非秘密**数值（如长度、
//! 位置），以便调用方定位问题而不泄露值。

use thiserror::Error;

/// 本库的统一错误类型。
///
/// 当前只有 URI 解析与 Base32 相关变体（为 M1 准备）；后续里程碑会逐步扩充，
/// 因此本枚举**不标记 `#[non_exhaustive]` 之外的兼容承诺**，但保持变体新增
/// 不破坏下游 `match` 的方式演进。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Base32 输入含字母表外的字符。
    ///
    /// 只报告**位置**，不报告该位置上的字符，避免把（可能来自密钥的）输入
    /// 内容带进日志。
    #[error("Base32 输入在第 {index} 个字符处含非法字符")]
    Base32InvalidCharacter {
        /// 非法字符在**剔除 ASCII 空白后**的字符序列中的位置。
        ///
        /// 之所以不是原始字节偏移：用户常从网页复制带空格或换行的种子，
        /// 此时「第几个有效字符」比「第几个字节」更容易定位问题。
        index: usize,
    },

    /// Base32 输入的（去除填充后）长度不是 8 的合法余数。
    ///
    /// 合法的 Base32 长度余数只有 0、2、4、5、7 这几种。
    #[error("Base32 长度非法：{length} 个有效字符")]
    Base32InvalidLength {
        /// 去除填充后的有效字符数。
        length: usize,
    },

    /// Base32 编码损坏：最后一个字符中未被使用的比特不为零。
    ///
    /// 这不是「填充格式」问题——填充本身可缺失或可带（两者都接受）。此错误表示
    /// 编码数据本身损坏，例如把有效比特写进了应为零的填充位。
    #[error("Base32 编码尾部残留比特非零，数据已损坏")]
    Base32InvalidPadding,

    /// OTP 密钥为空。
    ///
    /// 与 [`Error::SecretTooShort`] 分开：空种子是**结构性问题**（URI 里根本没有
    /// `secret`、或 Base32 解出来是空），而短种子是**强度问题**。前者必须拒绝，
    /// 后者由 UI 告警——混在一起会让调用方无法区分。
    #[error("OTP 密钥为空")]
    SecretEmpty,

    /// OTP 密钥长度不满足所选算法的最小要求。
    ///
    /// **注意**：本库当前只在「密钥为空」时拒绝，不会因长度不足而返回此错误。
    /// HMAC 接受任意长度密钥，且真实世界存在短种子；长度不足应作为**告警**
    /// 在 UI 层呈现，见 `otp::recommended_min_secret_len`。
    #[error("OTP 密钥过短：需要至少 {required} 字节，实际 {actual} 字节")]
    SecretTooShort {
        /// RFC 6238 为该算法规定的最小种子长度（字节）。
        required: usize,
        /// 实际得到的长度（字节）。长度本身不是秘密。
        actual: usize,
    },

    /// `otpauth://` 的 `algorithm` 参数无法识别。
    ///
    /// **拒绝而非回退到 SHA-1**：静默回退会让用户拿到一个恒定错误的验证码，
    /// 而错误信息无从查起。
    #[error("不支持的算法：{name}")]
    UnsupportedAlgorithm {
        /// 被截断到 16 字符以内的原始参数值。
        ///
        /// 截断是必要的：该值来自攻击者可控的 URI，不允许把任意长度输入
        /// 原样带进日志。
        name: String,
    },

    /// `otpauth://` 的 `digits` 参数不在支持范围内。
    ///
    /// 只接受 6、7、8。必须严格校验——若接受任意值，`10^digits` 会溢出。
    #[error("不支持的位数：{value}（只接受 6、7、8）")]
    UnsupportedDigits {
        /// 被截断到 16 字符以内的原始参数值。
        value: String,
    },

    /// TOTP 的 `period` 为 0，会导致除零。
    #[error("TOTP 周期不能为 0")]
    InvalidPeriod,

    /// 无法从操作系统取得密码学安全的随机字节。
    ///
    /// 这是**不可恢复**的失败：本库刻意不使用任何用户态 PRNG 作为回退，
    /// 因为一个确定性种子会让「双方独立生成」的密钥发生碰撞。宁可让操作失败、
    /// 由用户重试，也不能悄悄换用弱随机源。
    ///
    /// 触发场景：目标平台的 `getrandom` 后端不可用（例如受限的沙箱、
    /// 缺少必要的 syscall、或内核熵源初始化失败）。
    ///
    /// **不携带 `getrandom::Error` 的细节**：它的内部表示在不同版本/平台上
    /// 不一致，且对调用方没有可操作价值——能做的只有重试或告知用户。
    #[error("无法从操作系统取得安全随机数")]
    RandomnessUnavailable,

    /// URI 的 scheme 不是 `otpauth`。
    #[error("URI 的 scheme 不是 otpauth")]
    UriUnsupportedScheme,

    /// URI 缺少 type 部分（`otpauth://` 后没有 `/`）。
    #[error("URI 缺少类型段（应为 totp 或 hotp）")]
    UriMissingType,

    /// URI 的 type 不是 `totp` 或 `hotp`。
    #[error("不支持的 URI 类型：{name}")]
    UriUnsupportedType {
        /// 截断到 16 字符以内的原始 type 段。
        name: String,
    },

    /// URI 缺少 `secret` 参数。
    #[error("URI 缺少必需的 secret 参数")]
    UriMissingSecret,

    /// HOTP 的 URI 缺少 `counter` 参数。
    #[error("HOTP 的 URI 缺少必需的 counter 参数")]
    UriMissingCounter,

    /// TOTP 的 URI 却带了 `counter` 参数。
    ///
    /// 严格拒绝而非忽略：这种 URI 是生成器出错的信号，忽略它会让用户拿到一个
    /// 看起来正常但语义错误的条目。
    #[error("TOTP 的 URI 不应包含 counter 参数")]
    UriUnexpectedCounter,

    /// URI 含重复的已知参数。
    ///
    /// 不同实现取「第一个」还是「最后一个」并不一致，是经典解析歧义，也是攻击面。
    #[error("URI 含重复参数：{name}")]
    UriDuplicateParameter {
        /// 重复的参数名（截断到 16 字符）。
        name: String,
    },

    /// URI 的参数值非法。
    #[error("URI 参数 {name} 非法：{reason}")]
    UriInvalidParameter {
        /// 参数名。
        name: String,
        /// 不含完整原始值的原因说明（值本身会被截断）。
        reason: String,
    },

    /// URI 的百分号编码格式错误。
    #[error("URI 含非法的百分号编码（% 后必须跟两个十六进制数字）")]
    UriInvalidPercentEncoding,

    /// label 里的 issuer 与 `issuer` 参数不一致。
    ///
    /// 严格拒绝：两个来源给出不同发行方意味着 URI 被拼接或篡改过，
    /// 静默选一个会让用户把一个条目的验证码错配到另一个服务上。
    #[error("issuer 冲突：label 里是 {in_label}，参数里是 {in_parameter}")]
    UriIssuerMismatch {
        /// label 前缀中的 issuer（截断）。
        in_label: String,
        /// `issuer` 参数中的值（截断）。
        in_parameter: String,
    },

    /// URI 的 label 中，账号名含 `:`。
    ///
    /// label 用 `:` 分隔 issuer 与 account，因此账号名里的 `:` 无法与分隔符区分，
    /// 会造成往返歧义——序列化后再解析，issuer/account 的归属会**静默改变**。
    /// 百分号编码救不了它：`%3A` 与字面 `:` 在解码后无从区分。
    ///
    /// 故**解析与序列化两端都拒绝**，把这个不变量强制住。
    #[error("账号名不能包含冒号（会与 issuer 分隔符混淆）：{account}")]
    UriAccountContainsColon {
        /// 截断到 32 字符的账号名。
        account: String,
    },

    /// 保险库文件比声明的结构短，或结构在此处被截断。
    ///
    /// 这是最常见的结构性问题：文件被截断、或某个长度字段声称的字节数超出
    /// 实际剩余数据。
    #[error("保险库文件不完整或被截断")]
    VaultTruncated,

    /// 保险库文件开头的魔数不匹配。
    ///
    /// 意味着这不是一个保险库文件（选错了文件、或文件被换成了别的东西）。
    #[error("不是 Qualia2FA 保险库文件")]
    VaultBadMagic,

    /// 保险库文件的格式版本不被本版本支持。
    #[error("不支持的保险库格式版本：{version}")]
    VaultUnsupportedVersion {
        /// 文件里声明的版本号。
        version: u8,
    },

    /// 保险库文件头部的保留字节不是 0。
    ///
    /// 保留字节存在的意义就是「将来可以不再为 0」。当前版本遇到非 0 值必须
    /// 拒绝：它意味着文件由更新的版本写出，而新版本可能给这个字节赋予了本
    /// 版本不理解的语义，继续读下去会按错误的假设解析。
    #[error("保险库保留字节应为 0，实际为 {value}")]
    VaultReservedByteNotZero {
        /// 文件里的实际取值。
        value: u8,
    },

    /// 保险库记录的种类字节无法识别。
    ///
    /// **不当作活条目处理**：把未知种类当成「大概是个条目」会让一个未来版本
    /// 写出的墓碑被本版本当成活条目复活。
    #[error("无法识别的保险库记录种类：{value}")]
    VaultUnknownRecordKind {
        /// 文件里的实际取值。
        value: u8,
    },

    /// 单条记录的长度超出上限。
    ///
    /// 上限存在的理由是拒绝「声称有 4 GiB 的恶意文件」，避免为不可信输入
    /// 分配巨大内存。因此这是**结构性问题**，不是「条目太大」这类业务问题。
    #[error("保险库记录过长：上限 {limit} 字节，实际声明 {actual} 字节")]
    VaultRecordTooLong {
        /// 允许的上限。
        limit: usize,
        /// 文件里声明的长度。
        actual: usize,
    },

    /// 保险库的记录条数超出上限。
    #[error("保险库记录数超出上限（最多 {})", crate::vault::MAX_RECORDS)]
    VaultTooManyRecords,

    /// 保险库文件末尾有多余字节。
    ///
    /// **拒绝而不是忽略**：多余字节意味着文件被追加过内容，而本版本无法解释
    /// 那是什么。静默忽略会让「文件被改过」这一事实消失。
    #[error("保险库文件末尾有多余的 {count} 字节")]
    VaultTrailingBytes {
        /// 多余字节数。
        count: usize,
    },

    /// 保险库文件里同一个 `entry_id` 出现了两次。
    ///
    /// **拒绝而不是覆盖**：文件里出现重复 ID 意味着它被构造或损坏过。
    /// 静默取其一会让用户悄悄丢掉一条 2FA 条目，而现象是「某个验证码突然
    /// 不对了」，极难定位。
    #[error("保险库文件含重复的条目 ID")]
    VaultDuplicateEntryId,

    /// 文件里的主密钥检查值结构不对（长度不符）。
    ///
    /// 与 [`Error::VaultDecryptionFailed`] 严格区分：**这个是结构问题，那个是密钥
    /// 不对或文件被改过**。合并两者会让「文件被构造坏了」被误报成「你的密钥错了」，
    /// 用户于是去比对密钥，而问题根本不在那里。
    ///
    /// 检查值本身是一个明文的定长字段，长度不符意味着文件被截断、被追加、或者写入
    /// 方根本没有按格式写——三种都是「这个文件不可信」，不是「密钥不对」。
    #[error("保险库文件的主密钥检查值长度不对")]
    VaultBadKeyCheck,

    /// 按标识找不到条目。
    ///
    /// 与「保险库为空」不同：这是调用方指名要某一条、而那一条不在库里。上层要据此
    /// 区分两种界面动作——「列表是空的，引导用户添加」与「你正在操作的那一条已经
    /// 不在了，刷新列表」。把后者当成前者会让界面显示一个空列表，而用户明明刚才
    /// 还在看条目。
    ///
    /// 常见成因是两台设备的同步把该条目在另一端删掉了，而这一端还留着它的标识。
    #[error("保险库里没有这条条目")]
    VaultEntryNotFound,

    /// 保险库条目的明文结构里有重复的字段节点。
    ///
    /// 不同实现取「第一个」还是「最后一个」并不一致，是经典解析歧义，也是
    /// 攻击面——攻击者可以在一个合法节点后面追加一个覆盖用的节点。
    #[error("保险库条目含重复字段（标签 {tag:#04x}）")]
    VaultDuplicateField {
        /// 重复出现的字段标签。
        tag: u8,
    },

    /// 保险库条目的明文结构损坏（缺少必填字段、字段长度错误等）。
    ///
    /// 注意：这个错误只有在**认证通过之后**才可能出现——AEAD 的认证标签覆盖
    /// 了整段明文，因此解密成功意味着明文确实是我们写进去的那一份。它能被
    /// 触发，说明写入端产生了不合法的结构（本库的 bug），或密钥来自另一个
    /// 版本的实现。**它也可能由 fuzz 直接调用解析器时触发**，因为那些测试
    /// 会绕过 AEAD 喂入任意明文。
    #[error("保险库条目结构损坏")]
    VaultCorrupt,

    /// 保险库条目的文本字段不是合法 UTF-8。
    ///
    /// **拒绝而不是 lossy 替换**：替换会把损坏的数据变成一份看起来正常但内容
    /// 已变的条目，用户不会知道自己的账号名已经被改过。
    #[error("保险库条目的文本字段不是合法 UTF-8")]
    VaultInvalidUtf8,

    /// 保险库解密或认证失败。
    ///
    /// **不区分**「主密钥不对」「密文被篡改」「AAD 不匹配」三种原因，理由有两个：
    ///
    /// - **对攻击者有用**：区分它们等于给出一个预言机，让攻击者可以据此判断
    ///   猜测的密钥是否正确、或篡改的是哪一部分。
    /// - **对使用者无用**：三种情况的应对完全相同——这份保险库打不开。
    ///
    /// 用户真正需要知道的「是不是选错了主密钥」，由上层结合「主密钥来自哪里」
    /// 判断，不需要密码学层泄露信息。
    #[error("保险库无法解密：主密钥不匹配或文件已被篡改")]
    VaultDecryptionFailed,

    /// 主密钥长度不正确。
    #[error("主密钥长度应为 {expected} 字节，实际 {actual} 字节")]
    MasterKeyWrongLength {
        /// 要求的长度。
        expected: usize,
        /// 实际得到的长度。
        actual: usize,
    },

    /// 保险库条目里某个可变长字段超出上限。
    ///
    /// 上限在解密**之前**按密文长度挡不住（密文长度不反映字段长度），因此必须
    /// 在解密后的解析阶段检查。见 [`crate::vault::Entry::MAX_FIELD_LEN`]。
    #[error("字段 {field} 过长：上限 {limit} 字节，实际 {actual} 字节")]
    FieldTooLong {
        /// 字段名（固定字符串，不含用户数据）。
        field: &'static str,
        /// 允许的上限。
        limit: usize,
        /// 实际长度。
        actual: usize,
    },

    /// 保险库文件的读写失败。
    ///
    /// 只携带**操作系统的错误描述**，不含文件内容——`reason` 来自
    /// `std::io::Error`，它不会包含我们写进去的字节。
    #[error("保险库文件读写失败：{reason}")]
    VaultIo {
        /// 操作系统的错误描述。
        reason: String,
    },

    /// 设备身份公钥非法。
    ///
    /// 公钥来自外部输入（二维码、网络），必须在使用前验证。**非法曲线攻击**是
    /// 真实存在的：把不属于曲线、而属于某个小子群的点交给对方，可以从对方的运算
    /// 结果里反推出私钥信息。因此本错误是安全边界的一部分，不是格式检查。
    ///
    /// `reason` 是固定的内部描述，**不含输入的原始字节**——那可能来自攻击者，
    /// 把它放进错误消息等于让日志变成注入点。
    #[error("设备公钥非法：{reason}")]
    DevicePublicKeyInvalid {
        /// 固定的原因描述。
        reason: &'static str,
    },

    /// 设备身份签名非法或验证不通过。
    ///
    /// **签名格式错误与验证不通过刻意共用这一个变体。** 调用方能做的应对完全
    /// 相同（拒绝这次认证），而区分它们只会给攻击者一个微小的预言机。
    #[error("设备签名无效：{reason}")]
    DeviceSignatureInvalid {
        /// 固定的原因描述。
        reason: &'static str,
    },

    /// 配对载荷（二维码内容）结构非法。
    ///
    /// 与 [`Error::PairingUnsupportedVersion`] 分开：长度不对/缺少必需字段是
    /// **这一版就能判断**的损坏，而版本不认识是我们**看不懂**它。对使用者来说
    /// 前者的建议是「重新生成二维码」，后者是「升级应用」——建议不同，因此不合并。
    ///
    /// `reason` 是固定的内部描述，**不含输入字节**：二维码内容可能来自攻击者。
    #[error("配对载荷非法：{reason}")]
    PairingPayloadMalformed {
        /// 固定的原因描述。
        reason: &'static str,
    },

    /// 配对载荷的协议版本不受支持。
    ///
    /// 必须**明确拒绝**而不是尽力解释：把未知版本的字段按本版本的布局去读，
    /// 会让一个未来版本写出的「禁止某种操作」被当成「允许」。
    #[error("配对协议版本不受支持：{version}")]
    PairingUnsupportedVersion {
        /// 载荷里声明的版本号。
        version: u8,
    },

    /// 配对消息认证失败。
    ///
    /// **密文被篡改、标签不对、消息来自另一个会话、加入方用错了公钥**——四种
    /// 原因刻意共用这一个变体。调用方能做的应对完全相同（这次配对失败，请重新
    /// 扫码），而区分它们会给攻击者一个可用来试探的预言机。
    #[error("配对消息认证失败：密文被篡改、或不属于本次配对")]
    PairingAuthenticationFailed,

    /// 恢复文件结构非法。
    ///
    /// 与 [`Error::RecoveryAuthenticationFailed`] 分开，是因为这两件事对**用户**
    /// 的含义完全不同：本变体的意思是「拿错文件了 / 文件坏了」，而那个是「口令
    /// 打错了」。把它们合并会让用户在一个方向上反复重试口令。
    ///
    /// `reason` 是固定的内部描述，**不含输入字节**。
    #[error("恢复文件非法：{reason}")]
    RecoveryFileMalformed {
        /// 固定的原因描述。
        reason: &'static str,
    },

    /// 恢复文件的派生参数非法。
    ///
    /// 这些参数**来自文件本身**，因此是不可信输入。没有这层校验，一个被改成
    /// `m_cost = u32::MAX` 的文件就能让导入变成一次内存耗尽攻击。
    #[error("恢复文件的派生参数非法：{reason}")]
    RecoveryParametersInvalid {
        /// 固定的原因描述。
        reason: &'static str,
    },

    /// 口令为空。
    ///
    /// **明确拒绝而不是当成一个弱口令接受**：允许它会让用户在一个「看起来成功了」
    /// 的界面上拿到一份实际上一秒就能被解开的备份。
    #[error("恢复口令不得为空")]
    RecoveryPassphraseEmpty,

    /// 恢复文件的认证失败：口令错误，或文件被篡改。
    ///
    /// 这两种原因刻意共用一个变体（理由同 [`Error::PairingAuthenticationFailed`]）。
    #[error("恢复文件认证失败：口令错误，或文件已被篡改")]
    RecoveryAuthenticationFailed,

    /// 恢复文件加密阶段失败。
    ///
    /// 只可能来自 AEAD 的实现限制（明文或 AAD 过长），在实际参数下不会发生；
    /// 单独列出是为了不把这种情况错误地归到「口令错误」上。
    #[error("恢复文件加密失败")]
    RecoveryEncryptionFailed,

    /// Argon2id 计算失败。
    ///
    /// 最常见的真实原因是**内存不足**：默认参数要一次性分配 64 MiB。
    #[error("口令派生失败（可能是内存不足）")]
    RecoveryKdfFailed,

    /// 持久化格式的版本不受支持。
    ///
    /// 用于恢复文件这类**会被长期保存**的数据：一个未来版本写出的文件落到旧版本
    /// 手里时，必须**明确拒绝**，而不是按当前版本的布局去解释它。后者会让「新版本
    /// 提升了安全性」变成「旧版本用一个更弱的解释接受了它」。
    #[error("格式版本不受支持：{version}")]
    UnsupportedFormatVersion {
        /// 文件里声明的版本号。
        version: u8,
    },

    /// 挑战-应答消息结构非法。
    ///
    /// 长度不对、或携带的公钥不是合法曲线点。**这与 [`Error::AuthProofFailed`]
    /// 是两件事**：本变体说的是「这条消息根本不成形」，而那个说的是「消息成形，
    /// 但对方算不出正确的 tag」。
    ///
    /// `reason` 是固定的内部描述，**不含输入字节**。
    #[error("认证消息非法：{reason}")]
    AuthMessageMalformed {
        /// 固定的原因描述。
        reason: &'static str,
    },

    /// 挑战-应答的证明或确认标签不匹配。
    ///
    /// 含义是「对方没能证明它持有主密钥」。可能是 tag 被篡改、会话标识不一致、
    /// 或者对方压根没有主密钥——三种原因刻意共用这一个变体，因为调用方能做的
    /// 应对完全相同（判定这次认证失败、断开），而区分它们只会给出可试探的信号。
    #[error("认证失败：对方未能证明持有主密钥")]
    AuthProofFailed,

    // ── 编排（`crate::flow`）─────────────────────────────────────────────
    /// 本设备还没有设备身份，而这一步需要它。
    ///
    /// 与「身份创建失败」不同：这个是「调用方在取得身份之前就要求签名」，属于
    /// 调用顺序错误，而不是平台能力问题。
    #[error("本设备还没有设备身份，请先取得身份再签名")]
    DeviceKeyMissing,

    /// 本设备尚未注册或登录过。
    ///
    /// 与「主密钥存在但读不出来」刻意分开：前者是正常路径（引导用户去注册或登录），
    /// 后者意味着数据可能已经损坏。若两者共用同一个错误，界面就会把后者也当成
    /// 「还没登录」，从而引导用户**重新注册**，把原有数据永久丢掉。
    #[error("本设备尚未注册或登录")]
    DeviceNotRegistered,

    /// 声明的设备身份与本地的不是同一个。
    #[error("设备身份不匹配：对方声明的身份与本机取得的不一致")]
    DeviceIdentityMismatch,

    /// 主密钥写入平台存储失败。
    ///
    /// `reason` 是**固定字符串**且不得含密钥材料：它会被记进日志，而这是极少数
    /// 会碰主密钥的路径之一。
    #[error("主密钥无法写入平台存储：{reason}")]
    SecureStoreWriteFailed {
        /// 面向开发者的原因说明，不含任何秘密。
        reason: &'static str,
    },

    /// 时间戳为 `0`。
    ///
    /// `0` 通常意味着调用方忘了传时间（本库不读时钟，时间一律由调用方给出）。让
    /// 这样的值进入保险库会污染按时间排序的合并逻辑，而且后果稳定地错、不好定位。
    #[error("时间戳不得为 0")]
    TimestampZero,

    // ── M4：同步 ──────────────────────────────────────────────────────────────
    /// 同步载荷的魔数不符。
    ///
    /// 与「载荷损坏」分开：魔数不符通常意味着**这根本不是一份同步载荷**（用户选错
    /// 了文件、或者某个别的协议的数据被喂了进来），而排查方向与「本应用产生的载荷
    /// 坏了」完全不同。
    #[error("不是 Qualia2FA 的同步载荷")]
    SyncBadMagic,

    /// 同步载荷的格式版本不受支持。
    #[error("同步载荷版本 {version} 不受支持")]
    SyncUnsupportedVersion {
        /// 载荷声明的版本。
        version: u8,
    },

    /// 载荷为空。
    ///
    /// 从「压缩层」或「外层信封」任一处发现都归到这里。「根本没有载荷」与「载荷坏了」
    /// 在排查时指向完全不同的方向：前者通常是调用方传了一个空缓冲，后者是对端或
    /// 传输出了问题。
    #[error("同步载荷为空")]
    SyncEmptyPayload,

    /// 载荷被截断。
    #[error("同步载荷被截断")]
    SyncTruncated,

    /// 载荷中声明的记录数与实际内容不符。
    ///
    /// 与 [`Error::SyncTruncated`] 分开：截断是「字节不够」，这个是「字节够但数不上」——
    /// 后者意味着载荷被重新拼装过，是比截断更强的信号。
    #[error("同步载荷声明有 {declared} 条记录，实际只解出 {actual} 条")]
    SyncRecordCountMismatch {
        /// 载荷声明的记录数。
        declared: usize,
        /// 实际解出的记录数。
        actual: usize,
    },

    /// 载荷里有超出上限的记录数。
    #[error("同步载荷的记录数 {count} 超过上限 {limit}")]
    SyncTooManyRecords {
        /// 载荷声明的记录数。
        count: usize,
        /// 允许的上限。
        limit: usize,
    },

    /// 压缩失败。
    ///
    /// deflate 对任意输入都有定义，因此实践中不会出现。保留它是为了不 `unwrap`
    /// `miniz_oxide` 的返回值。
    #[error("同步载荷压缩失败")]
    SyncCompressionFailed,

    /// 解压出的内容超过 [`MAX_DECOMPRESSED_LEN`]，或输入根本不是合法的 deflate 流。
    ///
    /// [`MAX_DECOMPRESSED_LEN`]: crate::sync::compress::MAX_DECOMPRESSED_LEN
    ///
    /// 损坏、截断、长度对不上三种成因合成一个变体是**刻意的**：它们的处置完全相同
    /// （拒绝这次同步，让对方重发），而逐个区分对使用者没有可操作价值。
    #[error("同步载荷解压失败")]
    SyncDecompressionFailed,

    /// 载荷解压后超过了长度上限。
    ///
    /// # 它为什么与 [`Error::SyncDecompressionFailed`] 分开
    ///
    /// 因为它是这一组里**唯一一个不代表攻击**的成因。一个真有七万条目的用户会撞上
    /// 上限，而那时告诉他「载荷损坏」会让他去查网络、查设备、重新配对——全都查不出
    /// 问题。告诉他「太大了，请改用局域网」才是可操作的信息。
    ///
    /// 代价是攻击者能用一个 bit 探出上限的位置，而这个上限本来就写在开源代码里。
    /// 另一条相关事实：解压发生在外层 AEAD **之后**，因此走到这里的输入已经过认证。
    #[error("同步载荷解压后超过 {limit} 字节上限，请改用局域网模式")]
    SyncPayloadTooLarge {
        /// 上限，附在错误里免得调用方还要去查常量。
        limit: usize,
    },

    /// 载荷里出现了未知的记录种类。
    ///
    /// 与保险库文件的同类错误一样，未知种类一律拒绝而不是跳过：跳过会让未来版本
    /// 新增的语义在旧版本上**静默消失**，而「同步完了但少了几条」是最难定位的一类
    /// 故障。
    #[error("同步载荷含未知记录种类 {value:#04x}")]
    SyncUnknownRecordKind {
        /// 读到的种类字节。
        value: u8,
    },

    /// 载荷里出现了无法解释的字段或结构。
    ///
    /// 这个变体是**兜底**：具体到能命名的结构问题都有各自的变体，用到它意味着
    /// 「载荷自洽性检查失败，但说不出是哪一个」。
    #[error("同步载荷结构不合法：{reason}")]
    SyncMalformed {
        /// 人类可读的原因，用于日志与诊断。**不得包含秘密材料。**
        reason: &'static str,
    },

    /// 载荷的外层认证失败。
    ///
    /// 与 [`Error::VaultDecryptionFailed`] 分开：那个是「保险库文件打不开」，这个是
    /// 「这次同步的载荷不可信」。端侧的处置不同——前者要引导用户检查主密钥，后者
    /// 只需要提示「这次同步失败，请重试」。
    ///
    /// **不区分**「主密钥不对」「载荷被篡改」「发送方标识不符」三种原因：区分它们
    /// 对攻击者有用，对使用者没有可操作价值。
    #[error("同步载荷认证失败")]
    SyncAuthenticationFailed,

    /// 这份同步载荷已经处理过了。
    ///
    /// 重放一份旧载荷本身无害（合并是幂等的），但**白做一次完整解密与合并**是实打实
    /// 的开销，而且会误导界面上的「上次同步时间」。因此记住见过的载荷标识，重复的
    /// 直接拒绝。
    ///
    /// 这是**独立的错误**而不是静默成功：调用方需要知道「同步确实做过，这次是重复的」
    /// 而不是「同步刚刚成功了一次」。
    #[error("这份同步载荷已经处理过了")]
    SyncAlreadyApplied,

    /// 已用载荷标识的日志已满。
    ///
    /// 与「静默丢弃最旧的那条」相比，显式失败是更好的选择：静默丢弃会让一份很旧
    /// 的载荷重新变得可接受，而那正是重放防护要挡住的。调用方看到这个错误应当提示
    /// 用户「同步历史过长」，由更上层的策略决定怎么办。
    #[error("已用同步载荷标识的日志已满（上限 {limit}）")]
    SyncIdLogFull {
        /// 允许的最大条目数。
        limit: usize,
    },

    // ── M4.5：传输层 ──
    /// 传输通道本身失败（断开、超时、平台拒绝）。
    ///
    /// # 为什么不把底层错误直接透出来
    ///
    /// 底层是 `std::io::Error`、平台权限错误之类**不属于本 crate 的抽象**的东西。
    /// 本 crate 有 `#![forbid(unsafe_code)]` 且不依赖任何 I/O，把那些类型写进错误
    /// 枚举就等于把平台细节固化进协议层。因此只保留一个不透明的 `reason`——它是给
    /// 日志看的，不是给程序判断用的。
    #[error("传输失败：{reason}")]
    TransportFailed {
        /// 不透明的说明，供日志使用。
        reason: &'static str,
    },

    /// 对方报出来的设备标识与传输通道声称的发送方不一致。
    ///
    /// # 为什么这是一个必须存在的检查
    ///
    /// 载荷里的 `sender` 是**自报的**，而它在 AAD 里只保证「没被第三方改过」。在广播
    /// 型通道上（局域网组播），任何设备都能把一份**别人签过名**的载荷原样重放，于是
    /// 载荷里写着 B、实际发出来的是 C。这个检查把「是谁送来的」这件事交给传输通道，
    /// 再与载荷自报的值对照。
    ///
    /// 注意它挡的是**冒名**，不是重放——重放由 [`Error::SyncAlreadyApplied`] 挡。
    #[error("载荷自报的发送方与通道声称的发送方不一致")]
    SyncSenderMismatch,

    /// 载荷声称的种类不是本版本认识的任何一种。
    ///
    /// 与 [`Error::SyncUnknownRecordKind`] 分开：那个说的是**载荷内部**某一条记录的种类
    /// （条目还是墓碑），这个说的是**整份载荷**的种类（状态交换还是请求）。见
    /// [`crate::sync::PayloadKind`]。
    #[error("未知的载荷种类 {value:#04x}")]
    SyncUnknownPayloadKind {
        /// 线格式里的原始字节。
        value: u8,
    },

    /// 传输通道不支持该操作。
    ///
    /// 例如：一条只能承载单条消息的通道（二维码）被要求建立长连接。**不**用它表示
    /// 「这条通道装不下这份载荷」——那是 [`Error::TransportMessageTooLarge`]，两者的
    /// 处置完全不同（前者只能换通道，后者可以换模式或引导用户走局域网）。
    #[error("传输通道不支持该操作：{operation}")]
    TransportUnsupported {
        /// 被拒绝的操作名。
        operation: &'static str,
    },
    /// 一次性通道已经被用过了。
    ///
    /// 二维码是最典型的一次性通道：一张码只承载一次交换。把它当成可重复使用的通道
    /// 会让「扫两次同一张码」变成两次同步，而那正是重放防护之外的一条歧路。
    #[error("该传输通道已经使用过，不能再次使用")]
    TransportAlreadyUsed,

    /// 单条消息超过了通道能承载的长度。
    ///
    /// 触发它的通常是二维码：它是**定长**通道，装不下就只能换模式或换通道。调用方
    /// 应当据此引导用户改用局域网，而不是把载荷截断——截断的载荷过不了 AEAD，用户
    /// 看到的会是「数据损坏」。
    #[error("单条消息需要 {needed} 字节，超过该通道的 {limit} 字节上限")]
    TransportMessageTooLarge {
        /// 这条消息需要的字节数。
        needed: usize,
        /// 通道声明的上限。
        limit: usize,
    },

    /// 没有找到可加入的同步会话。
    ///
    /// 与「找到了但握手失败」分开：前者是正常的「附近没人」，调用方应当让用户重试或
    /// 检查网络；后者才是异常。
    #[error("未发现可加入的同步会话")]
    SyncNoSessionFound,
}

/// 本库的统一结果类型。
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// 展示的错误文本必须包含可定位的数值，且不得 panic。
    #[test]
    fn display_includes_diagnostic_numbers() {
        let cases: [(Error, &str); 3] = [
            (Error::Base32InvalidCharacter { index: 7 }, "7"),
            (Error::Base32InvalidLength { length: 3 }, "3"),
            (
                Error::SecretTooShort {
                    required: 20,
                    actual: 4,
                },
                "20",
            ),
        ];
        for (err, needle) in cases {
            let text = err.to_string();
            assert!(text.contains(needle), "错误文本 {text:?} 未包含 {needle:?}");
        }
    }

    /// `Error` 必须实现 `std::error::Error`，以便调用方用 `?` 与 `source()` 链式处理。
    #[test]
    fn implements_std_error() {
        fn assert_is_std_error<E: std::error::Error>() {}
        assert_is_std_error::<Error>();
    }
}
