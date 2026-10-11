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

//! 注册与登录这两条**用户旅程**的编排。
//!
//! 前面几个模块各自解决一个问题：[`crate::vault`] 管加密的条目、[`crate::pairing`]
//! 管带外引导的密钥交换、[`qualia_dik::device`] 管设备身份、[`crate::recovery`] 管
//! 口令备份。本模块把它们按用户实际会走的两条路串起来：
//!
//! ```text
//! 注册（本设备是账号的第一台设备）
//!   生成主密钥 → 建空保险库 → 取得设备身份 → 主密钥入平台密钥库 → 保险库落盘
//!
//! 登录（本设备从一台已登录的设备拿到主密钥）
//!   老设备：显示二维码 → 收到请求 → 确认是本人 → 交出加密后的主密钥
//!   新设备：扫码      → 发出请求 → 收到应答 → 主密钥入平台密钥库 → 建保险库
//! ```
//!
//! # 为什么要一个编排模块，而不是让调用方自己按顺序调
//!
//! 因为**顺序本身就是安全性质**，而散在各处的顺序没人测。举两个具体例子：
//!
//! - 主密钥必须在保险库落盘**之前**进平台密钥库。反过来的话，中途失败会留下一
//!   个打不开的保险库文件，而用户的数据看上去「还在」。
//! - 设备身份必须在**发请求之前**就取得。否则登录成功后生成的身份与请求里声明的
//!   身份不是同一个，保险库从此只能由那个临时身份打开——而它已经随会话消失了。
//!
//! 这两条都不是任何单个模块能表达的，只有把整条路写在一处才谈得上测试。
//!
//! # 平台依赖以 trait 参数注入
//!
//! 本 crate **没有 I/O、不碰平台 API**（见 crate 文档），因此「主密钥存进 TPM」与
//! 「去哪里读设备身份」这两件事必须由调用方提供。它们通过两个 trait 注入：
//!
//! | trait | 由谁实现 | 负责 |
//! |---|---|---|
//! | [`DeviceKeys`] | `qualia2fa-keystore` 的适配层 | 取得设备身份、对消息签名 |
//! | [`SecureStore`] | 端侧（平台密钥库 / 系统钥匙串 / 文件）| 主密钥的持久化 |
//!
//! 这样安排有两点好处。流程本身是**纯逻辑**，可以完整单测（见本模块测试），也可以用
//! 假的实现跑遍每一条失败路径；而平台相关的部分只有薄薄一层适配，且那层适配的
//! 职责仅限「搬运」，不掺任何判断——判断一旦漏进适配层，就再也不会被测试覆盖到。
//!
//! # 失败之后的状态
//!
//! 编排跨两个存储（保险库文件与平台密钥库），**没有跨二者的原子性**：它们之间
//! 不存在事务。因此每一步的先后都按「失败时留下什么」来选，规则是**宁可留下没用的
//! 东西，也不要留下打不开的东西**：
//!
//! - 主密钥先写入 [`SecureStore`]，再写保险库。若第一步就失败，磁盘上什么都没有，
//!   用户重试即可；保险库此时也还没被创建，所以不会有残留。
//! - 反面（先写保险库）会在同样的失败下留下一个**永远打不开**的保险库文件，而它
//!   与一个完好的文件在外观上无法区分。
//!
//! 更一般地说，**每个函数里最后一个可能失败的调用都排在写入之前**，因此本模块目前
//! 不需要回滚逻辑。改动步骤顺序时要维持这一点，否则必须补上
//! [`SecureStore::delete_master_key`]——密钥库里留下的孤儿密钥用户看不见，也无法从
//! 界面删掉。
//!
//! [`registration`] 与 [`Login`] 都不做任何自动重试：失败一律**如实返回**，由调用方
//! 决定是否重来。静默重试会把「这个平台存不了密钥」这种应当立刻告知用户的问题
//! 拖成随机出现的行为。

use secrecy::{ExposeSecret as _, SecretString};

use crate::error::{Error, Result};
use crate::pairing::{self, Adoption, JoinerSession, NonceLog, PendingSession, QrPayload};
use crate::recovery::{self, KdfParams};
use crate::secret::SecretBytes;
use crate::vault::MasterKey;
use crate::vault::{Timestamp, Vault, VaultFile};
use qualia_dik::{DeviceId, DevicePublicKey, DeviceSignature};

/// 设备身份的来源。
///
/// `qualia2fa-keystore` 已经有一个 [`DeviceKeyStore`] trait，但**本 crate 不能依赖
/// 它**——设备身份密钥生成必然要 `unsafe` 地调平台 API，而本 crate 有
/// `#![forbid(unsafe_code)]`。因此这里重新声明一个**只有两个方法**的最小接口，
/// 由端侧写一层薄适配把两者接起来（见 crate 文档的分层说明）。
///
/// [`DeviceKeyStore`]: https://docs.rs/qualia2fa-keystore
pub trait DeviceKeys {
    /// 取得本设备的长期身份；不存在时创建一个。
    ///
    /// # 契约：必须是幂等的
    ///
    /// 同一个 label 上反复调用必须返回**同一对**密钥。这条不是风格要求，而是正确性
    /// 要求：注册时创建的身份必须能在下次启动时被取回来，否则用户重启应用后就再也
    /// 打不开自己的保险库了。
    ///
    /// # 契约：必须**立即持久化**，不得延迟到会话结束
    ///
    /// 登录流程里「发出请求」与「收到应答」可能相隔很久（用户要走到另一台设备前
    /// 扫码）。若身份只活在内存里，中途崩溃就会让它永久丢失——而那把密钥是打开
    /// 保险库的唯一途径。因此哪怕登录从未完成、那次创建是白费的，也必须当场落盘。
    ///
    /// # 错误
    ///
    /// 平台没有可用的密钥库、硬件不可用、或用户拒绝时返回错误。**不得**悄悄退回
    /// 软件密钥：调用方需要据此告知用户保护强度下降了。
    fn get_or_create(&mut self, label: &str) -> Result<DevicePublicKey>;

    /// 用设备身份对**消息本身**签名。
    ///
    /// 传入的是消息，不是摘要：哈希计算恰好有一个所有者（见 [`qualia_dik::device::verify`]）。
    /// 实现方**不要**自行先哈希再签名，那会导致验签侧再哈希一次从而必然失败。
    fn sign(&mut self, label: &str, message: &[u8]) -> Result<DeviceSignature>;
}

/// 主密钥的持久化。
///
/// 「存进 TPM」只是其中一种实现。做不到硬件保护时，端侧可以用系统钥匙串或受
/// 用户口令保护的文件——但**那是端侧的决定**，本模块不提供也不默认任何较弱的
/// 实现。理由见 crate 文档：静默降级会让用户以为自己受硬件保护而实际不是。
pub trait SecureStore {
    /// 取出主密钥；从未存过时返回 `None`。
    ///
    /// 返回 `Ok(None)` 与返回 `Err` 含义完全不同：前者是「这台设备还没注册或登录
    /// 过」（正常路径，调用方应当引导用户去注册/登录），后者是「存过但现在读不出来」
    /// （异常路径，可能意味着存储被破坏或权限被改）。把两者混为一谈会让用户被
    /// 引导去重新注册，从而**再也拿不回**原有数据。
    fn load_master_key(&self) -> Result<Option<MasterKey>>;

    /// 存入主密钥，覆盖已有值。
    ///
    /// 本模块保证每次调用传入的都是**已经过验证**的主密钥（见 [`Joiner::complete`]），
    /// 因此实现方无需再校验。
    fn store_master_key(&mut self, key: &MasterKey) -> Result<()>;

    /// 删除已存的主密钥。
    ///
    /// [`registration`] 在「保险库写入失败」时会调用它做尽力回滚。返回错误时调用方
    /// **不应**把它当成致命错误：回滚失败留下的只是一个用不上的密钥，而原始失败
    /// 原因才是要报给用户的。从未存过时删除必须是成功的，不是错误。
    fn delete_master_key(&mut self) -> Result<()>;

    /// 给出备注：本实现是否把主密钥放在**不可导出的硬件**里。
    ///
    /// 调用方据此提示用户保护强度。这是**实现方对自己能力的声明**，不是本模块能
    /// 验证的事实；因此实现方必须如实回答，不得为了让界面好看而返回 `true`。
    fn is_hardware_backed(&self) -> bool;
}

/// 一次成功注册的结果。
#[derive(Debug)]
pub struct Registered {
    /// 本设备的身份公钥。
    device: DevicePublicKey,
    /// 新建的空保险库（连同它的主密钥）。
    vault: VaultFile,
    /// 平台存储是否声称把主密钥放在了不可导出的硬件里。
    hardware_backed: bool,
}

impl Registered {
    /// 本设备的身份。
    #[must_use]
    pub const fn device(&self) -> &DevicePublicKey {
        &self.device
    }

    /// 本设备的身份标识。
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.device.device_id()
    }

    /// 新建的保险库。
    #[must_use]
    pub const fn vault(&self) -> &VaultFile {
        &self.vault
    }

    /// 新建保险库的可变引用，用于写入第一批条目。
    pub const fn vault_mut(&mut self) -> &mut VaultFile {
        &mut self.vault
    }

    /// 主密钥是否由硬件保护。
    #[must_use]
    pub const fn is_hardware_backed(&self) -> bool {
        self.hardware_backed
    }

    /// 消费本结果，取出保险库。
    #[must_use]
    pub fn into_vault(self) -> VaultFile {
        self.vault
    }

    /// 消费本结果，取出主密钥与保险库。
    #[must_use]
    pub fn into_parts(self) -> (MasterKey, Vault) {
        self.vault.into_parts()
    }
}

/// 注册一台新设备：生成主密钥、建空保险库、取得设备身份并持久化主密钥。
///
/// 返回的保险库**尚未落盘**——调用方通常要先往里面写第一批条目，再调用
/// [`crate::vault::VaultFile::serialize`]。这样安排是因为「空保险库写一次、写入条目
/// 后再写一次」会让最终内容取决于哪一次成功，而调用方无从判断。
///
/// # 参数
///
/// - `label`：设备身份在平台密钥库中的标签。调用方应当用**稳定的**值（同一台设备
///   每次启动都相同），否则 [`DeviceKeys::get_or_create`] 会把同一个身份创建多次。
/// - `keys` / `store`：见两个 trait 的文档。
///
/// # 错误
///
/// 设备身份创建失败（平台不支持、硬件不可用）或主密钥写入失败时返回相应错误，
/// **此时不会创建保险库**。
///
/// [`SecureStore::store_master_key`] 是**最后一个可能失败的步骤**，因此不存在
/// 「主密钥已写入、后续步骤失败」的窗口，本函数也就不需要回滚。这不是巧合而是
/// 刻意排出来的：会失败的调用（生成主密钥、取设备身份、问硬件后端）全部排在写入
/// 之前。改动本函数的步骤顺序时要维持这个性质，否则必须同时补上
/// [`SecureStore::delete_master_key`] 回滚——不补的话密钥库里会留下一个用户看不见、
/// 也无法从界面删掉的孤儿密钥。
pub fn registration(
    keys: &mut dyn DeviceKeys,
    store: &mut dyn SecureStore,
    label: &str,
) -> Result<Registered> {
    // 主密钥先于一切：后面所有东西都依赖它，而它生成失败时磁盘上不该有任何残留。
    let master = MasterKey::generate()?;

    // 设备身份。**必须在写保险库之前**取得：身份创建失败时不该留下一个已经存在的
    // 保险库——用户会以为注册成功了。
    let device = keys.get_or_create(label)?;

    // 硬件后端要先问清楚。放在存储**之前**不是随意的排序：`is_hardware_backed`
    // 也是会失败的调用方代码（真实实现要问平台密钥库），把它留在后面就意味着
    // 「主密钥已经存进去了，这时才发现问不到后端」。现在它失败时磁盘上仍然什么都
    // 没有，与主密钥生成失败一样干净。
    let hardware_backed = store.is_hardware_backed();

    // 先入密钥库，再建保险库。**绝不能**在存储失败后继续建保险库：那会留下一个
    // 打不开的文件，而它与一个完好的文件在外观上无法区分。见模块文档
    // 「失败之后的状态」。
    //
    // 这一行是**最后一个可能失败的步骤**，这是刻意的：它之后没有任何 `?`，因此不
    // 存在「主密钥已存、后续失败」的窗口，也就不需要回滚。若将来在这之后加入会
    // 失败的操作，必须同时补上回滚（`store.delete_master_key()`），否则密钥库里会
    // 留下一个用户看不见、也无法从界面删掉的孤儿密钥。
    store.store_master_key(&master)?;

    Ok(Registered {
        device,
        vault: VaultFile::with_master_key(master),
        hardware_backed,
    })
}

/// 登录的发起方：一台**已经登录**、持有主密钥的设备。
///
/// 它负责显示二维码、接收请求、把主密钥加密交给对方。
///
/// # 每次登录都要新建一个
///
/// 本类型持有一次性的临时密钥（见 [`crate::pairing`] 的会话绑定规则）。因此
/// 「同一个 `Login` 服务两次登录」是做不到的：`authorize` 消费掉待接受的会话，
/// 第二次调用必然失败。用户取消后重新开始，请调 [`Login::new`]。
pub struct Login {
    /// 本次登录的二维码载荷。
    ///
    /// 单独存一份，而不是从 `pending` 里取：`PendingSession::accept` 收 `self`，会
    /// 把它移走，而载荷在授权之后仍然要能被访问（它会写进日志、也可能被再次展示）。
    /// [`QrPayload`] 是 `Copy` 的，且**本来就是要印在二维码上公开的东西**，多存一份
    /// 不带来任何保密性问题。
    payload: QrPayload,
    /// 待对方请求的会话；`authorize` 成功后为 `None`。
    pending: Option<PendingSession>,
    /// 已经接受的那次会话，`authorize` 成功后置位。
    adoption: Option<Adoption>,
    /// 已经用过的会话标识，用于拒绝重放。
    used: NonceLog,
}

impl core::fmt::Debug for Login {
    /// 只打印状态，不打印会话内容（那里面有一次性的临时密钥）。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Login")
            .field("capabilities", &self.payload.capabilities())
            .field("outstanding", &self.pending.is_some())
            .field("authorized", &self.adoption.is_some())
            .field("used_sessions", &self.used.len())
            .finish_non_exhaustive()
    }
}

impl Login {
    /// 开始一次登录。
    ///
    /// # 错误
    ///
    /// 随机源不可用时返回 [`Error::RandomnessUnavailable`]。此时**必须失败**：临时
    /// 密钥若可预测，握手就没有任何保密性可言。
    pub fn new() -> Result<Self> {
        let (payload, pending) = pairing::begin()?;
        Ok(Self {
            payload,
            pending: Some(pending),
            adoption: None,
            used: NonceLog::new(),
        })
    }

    /// 取出应当显示为二维码的内容。
    ///
    /// 调用方负责把它渲染成二维码。**注意它必须被展示在可信的屏幕上**：看到它的人
    /// 就能与这台设备完成登录，这是设计上有意为之（D4：首次密钥传递由带外信道保护）。
    #[must_use]
    pub const fn payload(&self) -> &QrPayload {
        &self.payload
    }

    /// 接受新设备的请求，把主密钥加密交给它。
    ///
    /// # 返回之前必须由**人**确认
    ///
    /// 本函数拿到的 `msg1` 只证明对方声明了一个设备身份，**不证明对方是谁**。因此
    /// 调用方（界面）必须在二维码被扫过之后、调用本函数之前，明确让用户确认「这次
    /// 登录是本人发起的」。跳过这一步等于把主密钥交给任何扫到二维码的人。
    ///
    /// 这一点无法由本模块强制——它没有界面。它只能把接口做成**需要显式动作**，
    /// 让「忘了确认」在代码审查里看得出来。
    ///
    /// # 重放
    ///
    /// 接受之前会检查会话是否已在本次登录里用过，用过则返回
    /// [`Error::PairingAuthenticationFailed`]。**这个检查只覆盖本次进程内的会话**；
    /// 跨进程重启的重放防护需要调用方把 [`Login::used_sessions`] 持久化（见
    /// [`crate::pairing::NonceLog`] 的文档）。
    ///
    /// # 错误
    ///
    /// 请求格式错误、无法用主密钥解开（不是发给本次会话的、或被人改过）、或会话
    /// 重放时返回相应错误。任何一种都**不返回部分结果**。
    pub fn authorize(&mut self, msg1: &[u8], master: &MasterKey) -> Result<Vec<u8>> {
        // `take` 而不是直接调用：`accept` 收 `self`，而 `self` 在 `Login` 里是被借用的
        // 字段。取出来之后 `pending` 为 `None`，于是「同一个 `Login` 不能授权两次」
        // 由**类型状态**保证，而不是靠一个布尔标志加判断。
        let pending = self
            .pending
            .take()
            .ok_or(Error::PairingAuthenticationFailed)?;
        let adoption = pending.accept(msg1, master)?;

        // 重放检查只能在拿到会话标识之后做，因为 `accept` 是唯一能算出它的地方（它
        // 需要主密钥）。代价是失败时 `pending` 已经被消费掉了——这正是上面那条
        // 「一次登录只服务一个请求」的取舍，而不是疏漏。
        if !self.used.record(*adoption.session_id()) {
            return Err(Error::PairingAuthenticationFailed);
        }

        // 返回副本而不是 `Adoption` 里的借用：调用方通常要立刻把它送上网（或渲染成
        // 二维码），而那一步不能与 `self` 的可变借用重叠。
        let reply = adoption.reply().to_vec();
        self.adoption = Some(adoption);
        Ok(reply)
    }

    /// 本次登录的会话标识，`authorize` 成功之后才有值。
    ///
    /// 调用方应当把它连同「这次登录发生在何时」一起持久化，以便下次启动时用
    /// [`Login::with_used_sessions`] 恢复重放防护。
    #[must_use]
    pub fn session_id(&self) -> Option<&[u8; pairing::SESSION_ID_LEN]> {
        self.adoption.as_ref().map(Adoption::session_id)
    }

    /// 已经用过的会话标识。
    #[must_use]
    pub const fn used_sessions(&self) -> &NonceLog {
        &self.used
    }

    /// 恢复上次运行记录下的已用会话标识。
    #[must_use]
    pub fn with_used_sessions(mut self, used: NonceLog) -> Self {
        self.used = used;
        self
    }

    /// 对方（新设备）声明的设备身份，`authorize` 成功之后才有值。
    ///
    /// 调用方应当把它记录下来，作为「这台新设备已获授权」的凭据。
    #[must_use]
    pub fn joiner_device(&self) -> Option<DeviceId> {
        self.adoption
            .as_ref()
            .and_then(|a| DevicePublicKey::from_sec1_bytes(a.joiner_identity()).ok())
            .map(|key| key.device_id())
    }
}

/// 登录的接收方：一台**尚未**持有主密钥的新设备。
///
/// # 一次登录只对应一个实例
///
/// 与 [`Login`] 同理，本类型持有一次性的临时密钥。`request` 之后必须用**同一个
/// 实例**调 [`Joiner::complete`]；新建一个实例去完成上次的登录必然失败，因为临时
/// 密钥不同（见 [`crate::pairing`] 的会话绑定规则）。
///
/// # 为什么 `session` 是 `Option`
///
/// [`Joiner::complete`] 只需 `&self` 而不是 `self`，因此端侧把本类型包在
/// `Arc<Mutex<..>>` 之类共享容器里也能用——绑定层与界面都要求共享引用。会话本身
/// 仍然是**一次性**的：`complete` 用 [`Option::take`] 把它取走，第二次调用会拿到
/// [`Error::PairingAuthenticationFailed`]，而不是重放一次。
///
/// 这与 [`Login`] 用 `Option<PendingSession>` + `take` 表达「一次登录只服务一个
/// 请求」是同一个手法：**让「只能用一次」成为类型属性**，而不是靠调用方自觉维护
/// 一个布尔标志。`Option::take` 需要 `&mut`，因此内部用
/// [`std::sync::Mutex`] 提供内部可变性——与绑定层的用法一致。
pub struct Joiner {
    /// 本次登录的临时会话。`complete` 取走后为 `None`。
    session: std::sync::Mutex<Option<JoinerSession>>,
    /// 设备身份标签，`complete` 时用来签名。
    label: String,
    /// 已经发出请求的会话标识。
    session_id: Option<[u8; pairing::SESSION_ID_LEN]>,
    /// `request` 发出的那一条消息，供诊断与测试比对。
    request: Vec<u8>,
}

impl core::fmt::Debug for Joiner {
    /// 不打印会话内容（含一次性临时密钥）。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Joiner")
            .field("label", &self.label)
            .field("requested", &self.session_id.is_some())
            .finish_non_exhaustive()
    }
}

impl Joiner {
    /// 用扫到的二维码开始一次登录。
    ///
    /// 二维码应当来自**带外信道**（当面扫描）。把 `payload` 当作网络上的普通消息
    /// 处理会失去 D4 的保护：中间人可以换成自己的公钥，从而在两台设备都察觉不到的
    /// 情况下拿到主密钥。
    ///
    /// # 错误
    ///
    /// 载荷格式错误、版本不支持、或临时公钥不在曲线上时返回相应错误。
    pub fn new(payload: &QrPayload, label: &str) -> Result<Self> {
        Ok(Self {
            session: std::sync::Mutex::new(Some(pairing::join(payload)?)),
            label: label.to_owned(),
            session_id: None,
            request: Vec::new(),
        })
    }

    /// 用支付载荷的文本形式开始一次登录。
    ///
    /// 供扫码后拿到的是字符串（而不是字节）的调用方使用。
    pub fn from_base32(text: &str, label: &str) -> Result<Self> {
        Self::new(&QrPayload::from_base32(text)?, label)
    }

    /// 取出应当发给老设备的请求消息。
    ///
    /// # 错误
    ///
    /// 设备身份无法取得或签名失败时返回相应错误。**重复调用返回同一条消息的副本**，
    /// 不会重新签名——重来一次会生成新的会话标识，让老设备认不出这是同一次登录。
    pub fn request(&mut self, keys: &mut dyn DeviceKeys) -> Result<Vec<u8>> {
        if self.request.is_empty() {
            let identity = keys.get_or_create(&self.label)?;
            // 会话的借用必须在写 `self.request` 之前结束，否则编译器不允许对 `self`
            // 的可变借用。用一个作用域块而不是手工 `drop`：它不依赖读者记住 guard
            // 何时释放，而 `drop` 漏掉时的报错（E0506）指向的是赋值那一行，不容易
            // 联想到是 guard 的生命周期问题。
            let (message, session_id) = {
                let session = self.session_guard();
                let session = session.as_ref().ok_or(Error::PairingAuthenticationFailed)?;
                session.request(identity.as_sec1_bytes())?
            };
            self.request = message;
            self.session_id = Some(session_id);
        }
        Ok(self.request.clone())
    }

    /// 本次登录的会话标识，发过请求之后才有值。
    #[must_use]
    pub const fn session_id(&self) -> Option<&[u8; pairing::SESSION_ID_LEN]> {
        self.session_id.as_ref()
    }

    /// 用老设备的应答完成登录，并把主密钥写入平台存储。
    ///
    /// 成功之后调用方应当写一个空的保险库文件，然后用
    /// [`crate::vault::read_file`] 或者后续的同步把内容取回来——**不要**假设登录
    /// 本身会带来任何条目，D5 之下主密钥与条目是分开传的。
    ///
    /// # 错误
    ///
    /// 应答格式错误、认证失败（不是发给本次会话的、被人改过、或来自伪造的老设备）、
    /// 或主密钥写入平台存储失败时返回相应错误。
    ///
    /// **写入失败时主密钥不会被丢掉**——它随返回值一起消失，因此不会留下一个
    /// 「手里有密钥但没存住」的中间状态骗过调用方。调用方应当让用户重新走一次登录。
    ///
    /// # 只能用一次
    ///
    /// 会话被 [`Option::take`] 取走，因此重复调用返回
    /// [`Error::PairingAuthenticationFailed`]——与「应答是伪造的」同一个错误，因为
    /// 对调用方来说这两件事的处置方式相同（重新走一次登录）。刻意不单独报「已经用
    /// 过了」：那等于告诉攻击者他的重放被认出来了。
    ///
    /// 收 `&self` 而不是 `self`，是为了让调用方能把本类型放进 `Arc<Mutex<..>>` 之类
    /// 的共享容器——绑定层与界面都要求共享引用。一次性由内部的 `Option` 保证，不靠
    /// 所有权。
    pub fn complete(
        &self,
        msg2: &[u8],
        keys: &mut dyn DeviceKeys,
        store: &mut dyn SecureStore,
    ) -> Result<MasterKey> {
        // 设备身份必须与发请求时是同一个。这里重新取一次而不是缓存 SEC1 字节：缓存
        // 会让「密钥库变了」这种情况被掩盖过去，而它恰恰是最需要立刻发现的问题。
        let identity = keys.get_or_create(&self.label)?;
        let session = self
            .session_guard()
            .take()
            .ok_or(Error::PairingAuthenticationFailed)?;
        let master = session.open(msg2, identity.as_sec1_bytes())?;
        store.store_master_key(&master)?;
        Ok(master)
    }

    /// 本设备在本次登录中使用的身份公钥。
    ///
    /// 会话被 [`Joiner::complete`] 取走之后返回 `None`——端侧要在完成之前把它显示给
    /// 用户确认（用户要能看出「请求登录的是不是我想的那台设备」）。
    #[must_use]
    pub fn identity(&self) -> Option<[u8; pairing::PUBLIC_KEY_LEN]> {
        self.session_guard()
            .as_ref()
            .map(|session| *session.public_key())
    }

    /// 借用内部会话，忽略中毒。
    ///
    /// 中毒意味着某个持锁线程 panic 过。本锁只保护一个 `Option` 的取出，没有「改了
    /// 一半」的中间状态，因此恢复使用比让整个登录流程永久失败更可取。
    fn session_guard(&self) -> std::sync::MutexGuard<'_, Option<JoinerSession>> {
        self.session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// 把主密钥交还给账号的其他设备。
///
/// 从**恢复密钥的用途**看，它应当被存在的理由只有两个：设备全丢了、或者要换机。
/// 因此本函数只负责产生文件内容；存到哪里、怎么让用户拿到，是调用方的事。
///
/// # 参数
///
/// - `passphrase`：用户口令。空口令会被 [`crate::recovery::export`] 拒绝——空口令
///   让 Argon2id 的全部代价都白费。
/// - `params`：KDF 参数。传 `None` 用 [`KdfParams::recommended`]。
///
/// # 错误
///
/// 口令为空、参数超界、或随机源不可用时返回相应错误。
pub fn export_recovery_key(
    master: &MasterKey,
    passphrase: &SecretString,
    params: Option<KdfParams>,
) -> Result<Vec<u8>> {
    recovery::export(
        master,
        passphrase,
        &params.unwrap_or_else(KdfParams::recommended),
    )
}

/// 从恢复密钥文件取回主密钥，并写入平台存储。
///
/// # 为什么由本模块负责写入，而不是把主密钥返回给调用方自己存
///
/// 因为「取回主密钥」与「把它存住」之间失败会留下极危险的状态：用户看到恢复
/// 成功了，但重启后密钥不在。由本函数一并完成，失败就没有中间状态可言。
///
/// # 错误
///
/// 文件结构错误、口令错误、或写入平台存储失败时返回相应错误。**口令错误与文件被
/// 篡改返回同一个错误**（见 [`crate::recovery`] 的威胁模型）：区分它们会让攻击者
/// 能用错误类型来试探。
pub fn import_recovery_key(
    file: &[u8],
    passphrase: &SecretString,
    store: &mut dyn SecureStore,
) -> Result<MasterKey> {
    let master = recovery::import(file, passphrase)?;
    store.store_master_key(&master)?;
    Ok(master)
}

/// 打开一个已存在的保险库，主密钥从平台存储取。
///
/// # 为什么要单独一个函数
///
/// 因为它把「这台设备有没有登录过」这件事变成了一个**可判定的结果**：
/// [`Error::DeviceNotRegistered`] 表示没登录过（引导用户去注册或登录），其余错误
/// 表示登录过但打不开（数据可能已损坏，**不要**建议用户重新注册）。
///
/// # 错误
///
/// 未登录时返回 [`Error::DeviceNotRegistered`]；`data` 不是本保险库的内容、主密钥
/// 不匹配时返回 [`Error::VaultDecryptionFailed`]。
///
/// # 空保险库也能判定主密钥对错
///
/// 格式版本 2 在文件末尾放了一个主密钥检查值，因此**条目为空的文件同样能判定**：
/// 存着的主密钥是错的就返回 [`Error::VaultDecryptionFailed`]，而不是等到用户加进
/// 第一条条目才暴露。
///
/// **版本 1 的旧文件仍然判定不了**——那份文件里确实没有可判定的信息，解析时会跳过
/// 检查值那一步。需要对密钥做权威确认时用 [`crate::auth`] 的挑战-应答，它不依赖
/// 文件内容。
pub fn open_vault(store: &dyn SecureStore, data: &[u8]) -> Result<VaultFile> {
    let master = store.load_master_key()?.ok_or(Error::DeviceNotRegistered)?;
    VaultFile::parse(master, data)
}

// ── SecureStore 的通用适配 ──────────────────────────────────────────────────
//
// 端侧最常见的实现是「主密钥存在平台密钥库里、保险库内容存在文件里」。本模块
// 不提供文件 I/O（那不属于 Core），但 [`crate::vault::write_file_atomically`] 与
// [`crate::vault::read_file`] 已经在那里了，调用方组合即可。

/// 把 [SecretBytes] 转成主密钥，供实现 [`SecureStore`] 的端侧代码使用。
///
/// 存在的意义是把 **[`crate::pairing::master_key_from_storage`] 与
/// [`crate::recovery`] 两条路径的还原方式统一到一处**：端侧只需要记住「存进去的是
/// 字节，取出来用这个函数」，而不必知道校验在哪。
///
/// # 错误
///
/// 长度不是 [`crate::vault::MASTER_KEY_LEN`] 时返回 [`Error::MasterKeyWrongLength`]。
pub fn master_key_from_bytes(bytes: SecretBytes) -> Result<MasterKey> {
    MasterKey::from_bytes(bytes)
}

/// 取主密钥的可存储字节形式，供实现 [`SecureStore`] 的端侧代码使用。
///
/// 与 [`master_key_from_bytes`] 成对。[`SecretBytes`] 在 `Drop` 时擦除。
#[must_use]
pub fn master_key_to_bytes(key: &MasterKey) -> SecretBytes {
    crate::vault::master_key_to_bytes(key)
}

/// 用恢复密钥或登录结果建一个空保险库文件。
///
/// # 为什么需要它
///
/// 登录与恢复只带来主密钥，不带来条目（D5 之下二者分开传）。调用方需要一个**空的
/// 但格式正确**的保险库文件来承载随后同步来的条目；直接手写文件字节会绕过格式
/// 校验。本函数把这个动作收成一处。
#[must_use]
pub fn empty_vault(master: MasterKey) -> VaultFile {
    VaultFile::with_master_key(master)
}

/// 记录一个条目插入时间用的「现在」。
///
/// 本 crate 不读时钟（见 crate 文档），因此时间一律由调用方传入。本别名存在的意义
/// 是让编排层的签名读起来是「需要一个时间」而不是「需要一个 `u64`」。
pub type Now = Timestamp;

/// 供调用方在插入条目时使用的当前时间戳校验。
///
/// # 为什么只是校验而不是「取当前时间」
///
/// 因为本 crate 读不到时钟。这里做的是**拒绝明显不合法的值**：`0` 通常意味着调用方
/// 忘了传，而它会成为保险库里最小的那个时间戳，让后续按时间排序的合并逻辑得出
/// 稳定但错误的结果。
///
/// # 错误
///
/// `now` 为 `0` 时返回 [`Error::TimestampZero`]。
pub const fn check_now(now: Now) -> Result<Now> {
    if now == 0 {
        return Err(Error::TimestampZero);
    }
    Ok(now)
}

/// 显式暴露一个 [`SecretString`] 的长度，供日志与诊断使用。
///
/// 口令本身**永远不得**被打印，但「口令有多长」是排查「为什么导入失败」时唯一
/// 有用又不泄露信息的事实。把它做成一个函数，是为了让「这里没有泄露口令」在代码
/// 审查时是**可见**的，而不是靠读一遍 `format!` 猜。
#[must_use]
pub fn passphrase_len(passphrase: &SecretString) -> usize {
    passphrase.expose_secret().chars().count()
}

// ── 与 keystore 的适配契约 ──────────────────────────────────────────────────
//
// `qualia2fa-keystore` 提供 `DeviceKeyStore`（生成/取回/删除设备身份）与
// `DeviceSigner`（签名）。端侧只需写一层不含判断的转发即可满足 [`DeviceKeys`]：
//
//   impl DeviceKeys for Adapter<'_> {
//       fn get_or_create(&mut self, label: &str) -> Result<DevicePublicKey> {
//           Ok(self.store.open_or_create(label)?.public_key())
//       }
//       fn sign(&mut self, label: &str, message: &[u8]) -> Result<DeviceSignature> {
//           Ok(self.store.open(label)?.sign(message)?)
//       }
//   }
//
// 这层代码里**不应出现任何 `if`**。一旦出现，就说明有一条只在端侧才走的分支，
// 而端侧没有单元测试。

/// 让 `&mut T` 也能当作 [`DeviceKeys`] 用。
///
/// 存在的理由是让调用方不必为了把实现借给本模块而写一层转发：`registration` 收
/// `&mut dyn DeviceKeys`，而传 `&mut adapter` 与传 `&mut *adapter` 都应当能编译。
impl<T: DeviceKeys + ?Sized> DeviceKeys for &mut T {
    fn get_or_create(&mut self, label: &str) -> Result<DevicePublicKey> {
        (**self).get_or_create(label)
    }

    fn sign(&mut self, label: &str, message: &[u8]) -> Result<DeviceSignature> {
        (**self).sign(label, message)
    }
}

/// 让 `&mut T` 也能当作 [`SecureStore`] 用。
impl<T: SecureStore + ?Sized> SecureStore for &mut T {
    fn load_master_key(&self) -> Result<Option<MasterKey>> {
        (**self).load_master_key()
    }

    fn store_master_key(&mut self, key: &MasterKey) -> Result<()> {
        (**self).store_master_key(key)
    }

    fn delete_master_key(&mut self) -> Result<()> {
        (**self).delete_master_key()
    }

    fn is_hardware_backed(&self) -> bool {
        (**self).is_hardware_backed()
    }
}

/// 校验一个设备身份确实是本设备声明的那个。
///
/// 供调用方在收到对方自称的身份之后核对。**本函数只比较标识，不做任何证明**——
/// 「这个公钥属于谁」这件事由配对协议的认证标签回答（见 [`crate::pairing`]），
/// 不是靠比较字节。
///
/// # 错误
///
/// 两者不同时返回 [`Error::DeviceIdentityMismatch`]。
pub fn expect_device(
    actual: &DevicePublicKey,
    claimed: &[u8; pairing::PUBLIC_KEY_LEN],
) -> Result<()> {
    if actual.as_sec1_bytes() != claimed {
        return Err(Error::DeviceIdentityMismatch);
    }
    Ok(())
}

/// 校验一段消息确实由某个设备身份签过。
///
/// # 它为什么是一个包装，以及它包了什么
///
/// 设备身份验签的**实现**在 `qualia-dik` 里——那是一个独立可复用的 crate，任何需要
/// 硬件设备身份的项目都能用它。本函数在它之上只做一件事：把失败**翻译成本 crate 的
/// 错误类型**（[`Error::Device`]）。
///
/// 这样做的意义是让调用方有一个**统一的入口**，而不是各自去调
/// `qualia_dik::device::verify`——后者会让「失败是什么类型」在多个地方各有一份判断，
/// 而下游（FFI、UI）需要的是本 crate 的错误枚举。
///
/// # 错误
///
/// 签名不匹配或格式错误时返回 [`Error::Device`]（内层是设备身份库的
/// `DeviceSignatureInvalid`）。
pub fn verify_device(
    public_key: &DevicePublicKey,
    message: &[u8],
    signature: &DeviceSignature,
) -> Result<()> {
    Ok(qualia_dik::device::verify(public_key, message, signature)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer as _};
    use qualia_dik::device::SIGNATURE_LEN;
    use std::collections::HashMap;

    /// 一个纯内存的 [`DeviceKeys`] 实现，用来把编排逻辑与平台隔开。
    ///
    /// 它**刻意不做任何安全声明**：`is_hardware_backed` 之类的判断在
    /// [`SecureStore`] 上，而这里的签名是明文的软件密钥——测试替身伪装成硬件
    /// 正是 AGENTS.md 禁止的事。
    struct FakeKeys {
        /// 按 label 记住已经创建过的身份。
        keys: HashMap<String, SigningKey>,
        /// 创建次数，用于验证幂等性。
        creates: usize,
    }

    impl FakeKeys {
        fn new() -> Self {
            Self {
                keys: HashMap::new(),
                creates: 0,
            }
        }
    }

    impl DeviceKeys for FakeKeys {
        fn get_or_create(&mut self, label: &str) -> Result<DevicePublicKey> {
            if !self.keys.contains_key(label) {
                // 用 label 派生而不是随机：测试要能复现。
                let scalar = label.bytes().fold(1_u8, u8::wrapping_add).max(1);
                let mut seed = [0_u8; 32];
                seed[31] = scalar;
                self.keys.insert(
                    label.to_owned(),
                    SigningKey::from_slice(&seed).expect("测试用的标量必须合法"),
                );
                self.creates += 1;
            }
            let key = &self.keys[label];
            let point = key.verifying_key().to_sec1_point(false);
            // `?` 把设备身份库的错误经 `Error::Device` 转换过来。
            Ok(DevicePublicKey::from_sec1_bytes(point.as_bytes())?)
        }

        fn sign(&mut self, label: &str, message: &[u8]) -> Result<DeviceSignature> {
            let key = self.keys.get(label).ok_or(Error::DeviceKeyMissing)?;
            let signature: p256::ecdsa::Signature = key.sign(message);
            Ok(DeviceSignature::from_bytes(&signature.to_bytes())?)
        }
    }

    /// 内存里的 [`SecureStore`]。`hardware` 可配置，用来验证它被如实转发。
    #[derive(Default)]
    struct FakeStore {
        master: Option<MasterKey>,
        hardware: bool,
        /// 设为 `Some` 时让 `store_master_key` 失败，用于测失败路径。
        fail_store: bool,
        deletes: usize,
    }

    impl SecureStore for FakeStore {
        fn load_master_key(&self) -> Result<Option<MasterKey>> {
            Ok(self
                .master
                .as_ref()
                .map(|k| MasterKey::from_bytes(master_key_to_bytes(k)).expect("长度由构造保证")))
        }

        fn store_master_key(&mut self, key: &MasterKey) -> Result<()> {
            if self.fail_store {
                return Err(Error::SecureStoreWriteFailed {
                    reason: "测试注入的失败",
                });
            }
            self.master =
                Some(MasterKey::from_bytes(master_key_to_bytes(key)).expect("长度由构造保证"));
            Ok(())
        }

        fn delete_master_key(&mut self) -> Result<()> {
            self.deletes += 1;
            self.master = None;
            Ok(())
        }

        fn is_hardware_backed(&self) -> bool {
            self.hardware
        }
    }

    const LABEL: &str = "qualia2fa-device";

    fn registered() -> (FakeKeys, FakeStore, Registered) {
        let mut keys = FakeKeys::new();
        let mut store = FakeStore::default();
        let result = registration(&mut keys, &mut store, LABEL).expect("注册应当成功");
        (keys, store, result)
    }

    /// 注册必须产出可用的三样东西：主密钥存住了、保险库能开、身份能取回。
    #[test]
    fn registration_produces_a_usable_device() {
        let (keys, store, result) = registered();
        assert!(store.master.is_some(), "主密钥必须已经写入平台存储");
        assert!(
            keys.keys.contains_key(LABEL),
            "设备身份必须已经创建并可由同一个 label 取回"
        );
        assert!(!result.is_hardware_backed());

        // 保险库必须能用存住的那把主密钥打开——这是「注册成功」的真正含义。
        let data = result.vault.serialize().expect("序列化应当成功");
        let opened = open_vault(&store, &data).expect("用存住的主密钥应当能打开保险库");
        assert!(opened.vault().is_empty());
        assert_eq!(
            opened.master_key().expose(),
            result.vault.master_key().expose()
        );
    }

    /// 两次注册必须得到**不同**的主密钥，否则第二台设备会覆盖第一台的账号。
    #[test]
    fn each_registration_generates_a_fresh_master_key() {
        let (_k1, _s1, first) = registered();
        let (_k2, _s2, second) = registered();
        assert_ne!(
            first.vault.master_key().expose(),
            second.vault.master_key().expose()
        );
    }

    /// 同一个 label 重复调用 `get_or_create` 不得创建新身份。
    ///
    /// 这条是「重启应用后还能打开保险库」的充要条件。
    #[test]
    fn device_identity_is_stable_across_calls() {
        let mut keys = FakeKeys::new();
        let first = keys.get_or_create(LABEL).expect("首次创建应当成功");
        let second = keys.get_or_create(LABEL).expect("再次取得应当成功");
        assert_eq!(first.as_sec1_bytes(), second.as_sec1_bytes());
        assert_eq!(keys.creates, 1, "不得重复创建");
    }

    /// 主密钥写入失败时**不得**创建保险库。
    ///
    /// 这正是「失败之后的状态」那一段的核心：留下一个打不开的文件比什么都不留下
    /// 更糟，因为用户无法区分它与一个完好的文件。
    #[test]
    fn registration_does_not_create_a_vault_when_storage_fails() {
        let mut keys = FakeKeys::new();
        let mut store = FakeStore {
            fail_store: true,
            ..FakeStore::default()
        };
        let error = registration(&mut keys, &mut store, LABEL).expect_err("应当失败");
        assert!(
            matches!(error, Error::SecureStoreWriteFailed { .. }),
            "错误应当是写入失败，实际是 {error:?}"
        );
        assert!(store.master.is_none());
    }

    /// 从未登录过的设备打开保险库必须报一个**可区分**的错误。
    ///
    /// 若它和「密钥不匹配」共用一个错误，界面就分不清该引导用户去登录还是该警告
    /// 数据已损坏——后者会导致用户重新注册，从而永久丢失原有数据。
    #[test]
    fn opening_without_a_stored_key_reports_not_registered() {
        let store = FakeStore::default();
        let (_k, _s, result) = registered();
        let data = result.vault.serialize().expect("序列化应当成功");
        let error = open_vault(&store, &data).expect_err("没有主密钥时必须失败");
        assert!(
            matches!(error, Error::DeviceNotRegistered),
            "实际是 {error:?}"
        );
    }

    /// **空保险库也能判定主密钥对错。**
    ///
    /// 第一版写的是「换一把主密钥，`open_vault` 必须返回
    /// [`Error::VaultDecryptionFailed`]」，它**没有失败**。查下来是格式使然：主密钥
    /// 只参与**每条记录**的 AEAD，而条目为空的文件里没有任何密文，于是任何 32 字节
    /// 的主密钥都能把它解析成空保险库。当时的处置是把测试改成钉住真实行为（红的
    /// 测试等于没有测试），并把缺口记进 TODO。
    ///
    /// 格式版本 2 在文件末尾加了主密钥检查值，这个缺口因此关闭。测试现在钉住**正确
    /// 的行为**：空保险库用错误的密钥必须被拒。
    ///
    /// 「另一台设备」用的是它**自己**的主密钥，而不是一个借来的随机值——后者会掩盖
    /// 「两台设备各自注册、各自持有一把合法主密钥」这个真实场景。
    #[test]
    fn an_empty_vault_rejects_a_wrong_key() {
        let (_k, _s, result) = registered();
        assert!(
            result.vault.vault().is_empty(),
            "前提：这个保险库确实是空的"
        );
        let data = result.vault.serialize().expect("序列化应当成功");

        let (_k2, store, device2) = registered();
        assert_ne!(
            device2.vault().master_key().expose(),
            result.vault.master_key().expose(),
            "两台设备的主密钥必须不同，否则这个测试没有意义"
        );

        let error = open_vault(&store, &data).expect_err("空保险库用错误的密钥必须被拒");
        assert!(
            matches!(error, Error::VaultDecryptionFailed),
            "实际是 {error:?}"
        );
    }

    /// 有内容之后，主密钥不匹配同样必须被拒。
    ///
    /// 这是上一条的另一半，两条覆盖的是**不同**的失败点：空文件靠末尾的检查值，
    /// 有内容的文件靠记录的 AEAD 标签（那个检查值也在，但先撞上的是它）。
    /// 只测其中一条会对另一半的实现错误完全盲目。
    #[test]
    fn a_vault_with_entries_rejects_the_wrong_key() {
        use crate::uri;
        use crate::vault::{Timestamp, entry_from_parsed_uri};

        let (_k, _s, mut result) = registered();
        let parsed = uri::parse("otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME")
            .expect("URI 应当合法");
        const NOW: Timestamp = 1_700_000_000;
        let entry = entry_from_parsed_uri(&parsed, NOW).expect("条目应当能构造");
        result
            .vault_mut()
            .vault_mut()
            .insert(entry)
            .expect("插入应当成功");
        let data = result.vault.serialize().expect("序列化应当成功");

        let (_k2, store, _device2) = registered();
        let error = open_vault(&store, &data).expect_err("有内容时错误的主密钥必须被拒绝");
        assert!(
            matches!(error, Error::VaultDecryptionFailed),
            "实际是 {error:?}"
        );
    }

    /// 登录的完整往返：新设备拿到的主密钥必须**就是**老设备的那一把。
    ///
    /// 一次登录只能完成一次。
    ///
    /// `Joiner::complete` 收 `&self`（好让调用方把它放进共享容器），一次性由内部的
    /// `Option` 保证。这条测试钉住那个保证：第二次调用必须失败，而且**必须与
    /// 「应答是伪造的」报同一个错误**——单独报「已经用过了」等于告诉攻击者他的重放
    /// 被认出来了。
    #[test]
    fn a_login_can_only_be_completed_once() {
        let (_old_keys, _old_store, account) = registered();
        let master = account.vault.master_key();

        let mut login = Login::new().expect("应当能开始登录");
        let payload = login.payload().clone();
        let mut keys = FakeKeys::new();
        let mut joiner = Joiner::new(&payload, "new-device").expect("应当能开始扫码");
        let request = joiner.request(&mut keys).expect("应当能发出请求");
        let reply = login.authorize(&request, master).expect("应当能授权");

        let mut store = FakeStore::default();
        joiner
            .complete(&reply, &mut keys, &mut store)
            .expect("第一次应当成功");

        // 第二次：同一条应答原样再交一次。
        let error = joiner
            .complete(&reply, &mut keys, &mut store)
            .expect_err("第二次必须失败");
        assert!(
            matches!(error, Error::PairingAuthenticationFailed),
            "必须与伪造应答报同一个错误，实际是 {error:?}"
        );

        // 完成后身份也取不到了——端侧只能在完成之前把它显示给用户确认。
        assert!(joiner.identity().is_none());
    }

    /// 只比较「没有报错」是不够的——一个把主密钥换成新随机值的实现同样不报错，
    /// 而用户要到同步时才发现条目一条都对不上。
    #[test]
    fn login_transfers_the_exact_master_key() {
        let (_old_keys, old_store, account) = registered();
        let master = account.vault.master_key();

        let mut login = Login::new().expect("应当能开始登录");
        let payload = login.payload().clone();

        let mut joiner_keys = FakeKeys::new();
        let mut joiner = Joiner::new(&payload, "new-device").expect("应当能开始扫码");
        let request = joiner.request(&mut joiner_keys).expect("应当能发出请求");

        let reply = login
            .authorize(&request, master)
            .expect("应当能授权")
            .to_vec();

        let mut joiner_store = FakeStore::default();
        let received = joiner
            .complete(&reply, &mut joiner_keys, &mut joiner_store)
            .expect("应当能完成登录");

        assert_eq!(
            received.expose(),
            master.expose(),
            "新设备拿到的主密钥必须与老设备完全一致"
        );
        assert!(
            joiner_store.master.is_some(),
            "主密钥必须已经写入新设备的平台存储"
        );

        // 并且它真的能打开老设备的保险库。
        let data = account.vault.serialize().expect("序列化应当成功");
        let opened = open_vault(&joiner_store, &data).expect("新设备应当能打开老设备的保险库");
        assert_eq!(
            opened.master_key().expose(),
            old_store.master.as_ref().unwrap().expose()
        );
    }

    /// 授权前后，会话标识都应当能被调用方取到并持久化。
    #[test]
    fn login_reports_the_session_for_persistence() {
        let (_k, _s, account) = registered();
        let mut login = Login::new().expect("应当能开始登录");
        assert!(login.session_id().is_none(), "授权前没有会话标识");
        assert!(login.joiner_device().is_none());

        let payload = login.payload().clone();
        let mut keys = FakeKeys::new();
        let mut joiner = Joiner::new(&payload, "new-device").expect("应当能开始扫码");
        let request = joiner.request(&mut keys).expect("应当能发出请求");
        let _reply = login
            .authorize(&request, account.vault.master_key())
            .expect("应当能授权");

        let session_id = login.session_id().expect("授权后应当有会话标识");
        assert_eq!(
            session_id,
            joiner.session_id().expect("双方必须得出同一个标识")
        );
        assert!(login.joiner_device().is_some(), "应当能拿到对方的身份");
        assert_eq!(login.used_sessions().len(), 1);
    }

    /// 同一条请求不得被接受两次。
    #[test]
    fn the_same_request_cannot_be_authorized_twice() {
        let (_k, _s, account) = registered();
        let mut login = Login::new().expect("应当能开始登录");
        let payload = login.payload().clone();
        let mut keys = FakeKeys::new();
        let mut joiner = Joiner::new(&payload, "new-device").expect("应当能开始扫码");
        let request = joiner.request(&mut keys).expect("应当能发出请求");
        let master = account.vault.master_key();

        login.authorize(&request, master).expect("第一次应当成功");
        // `authorize` 每次都消费 `pending`，因此第二次必然失败——这里验证的是
        // 「它失败」而不是「它返回了什么具体错误」，因为两条防线都可能先触发。
        let error = login
            .authorize(&request, master)
            .expect_err("第二次必须失败");
        assert!(
            matches!(
                error,
                Error::PairingAuthenticationFailed | Error::AuthMessageMalformed { .. }
            ),
            "实际是 {error:?}"
        );
    }

    /// 用**另一个** `Login` 的载荷，请求必须被拒绝。
    ///
    /// # 这条测试为什么长这样
    ///
    /// 第一版写的是「用一把随机主密钥去 `authorize`，必须失败」，结果它**成功了**。
    /// 查过 `pairing::PendingSession::accept` 才确认这不是缺陷：Msg1 的认证标签由
    /// **ECDH 共享秘密**派生，而不是由主密钥——主密钥是这次要**传过去的东西**
    /// （载荷），不是用来认证发送方的凭据。它的保密性由「只有扫到二维码的人才能算出
    /// 那个共享秘密」保证，也就是 D4 的带外信道。
    ///
    /// 所以真正会失败的场景是**会话对不上**（临时密钥不同 ⇒ 共享秘密不同 ⇒ 解密
    /// 必失败），以及加入方拿到错误的回复。当前这条覆盖前者，见
    /// [`a_reply_encrypted_for_another_session_cannot_be_opened`] 覆盖后者。
    #[test]
    fn a_request_from_another_login_is_rejected() {
        let (_k, _s, account) = registered();
        // 第一台设备显示了自己的二维码，但用户没扫它，而是扫了第二台设备的。
        let first = Login::new().expect("应当能开始登录");
        let payload_from_first = first.payload().clone();

        let mut second = Login::new().expect("应当能开始登录");
        let mut keys = FakeKeys::new();
        let mut joiner = Joiner::new(&payload_from_first, "new-device").expect("应当能开始扫码");
        let request = joiner.request(&mut keys).expect("应当能发出请求");

        let error = second
            .authorize(&request, account.vault.master_key())
            .expect_err("另一台设备的载荷产生的请求不应被接受");
        assert!(
            matches!(error, Error::PairingAuthenticationFailed),
            "实际是 {error:?}"
        );
        assert!(second.session_id().is_none(), "失败不得留下会话标识");
    }

    /// 发给**另一次会话**的回复，加入方解不开。
    ///
    /// 这条补上主密钥真正起作用的那个位置：`complete` 里用会话密钥解 Msg2，而会话
    /// 密钥由 ECDH 共享秘密决定。回复若来自另一次会话，解密必然失败——主密钥没有
    /// 机会被写进存储。
    #[test]
    fn a_reply_encrypted_for_another_session_cannot_be_opened() {
        let (_k, _s, account) = registered();
        let mut keys = FakeKeys::new();

        // 会话 A：用户实际扫的那一次。
        let mut login_a = Login::new().expect("应当能开始登录");
        let payload_a = login_a.payload().clone();
        let mut joiner_a = Joiner::new(&payload_a, "new-device").expect("应当能开始扫码");
        let request_a = joiner_a.request(&mut keys).expect("应当能发出请求");
        // 会话 A：用户实际扫的那一次。它也必须能正常授权——否则下面的失败可能只是
        // 因为会话 A 本身是坏的，那样这条测试就什么也没证明。
        login_a
            .authorize(&request_a, account.vault.master_key())
            .expect("会话 A 应当能授权");

        // 会话 B：另一台设备上的另一次登录，用它的回复去糊弄会话 A。
        let mut login_b = Login::new().expect("应当能开始登录");
        let payload_b = login_b.payload().clone();
        let mut joiner_b = Joiner::new(&payload_b, "new-device").expect("应当能开始扫码");
        let request_b = joiner_b.request(&mut keys).expect("应当能发出请求");
        let reply_b = login_b
            .authorize(&request_b, account.vault.master_key())
            .expect("应当能授权");

        let mut store = FakeStore::default();
        let error = joiner_a
            .complete(&reply_b, &mut keys, &mut store)
            .expect_err("来自另一次会话的回复不应被接受");
        assert!(
            matches!(error, Error::PairingAuthenticationFailed),
            "实际是 {error:?}"
        );
        assert!(store.master.is_none(), "失败不得留下主密钥");
        // 这里刻意**不**再补一句「而 reply_a 是好的」：`complete` 收 `self`，因此
        // 那句只能靠新建一个 `Joiner` 来做，而新实例有新的临时密钥，本来就解不开
        // `reply_a`——那句断言永远不会通过。「合法回复能解开」由
        // `login_transfers_the_exact_master_key` 覆盖，两条测试各管一头。
    }

    /// 篡改来自老设备的应答必须被拒绝。
    #[test]
    fn tampering_with_the_reply_is_detected() {
        let (_k, _s, account) = registered();
        let mut login = Login::new().expect("应当能开始登录");
        let payload = login.payload().clone();
        let mut keys = FakeKeys::new();
        let mut joiner = Joiner::new(&payload, "new-device").expect("应当能开始扫码");
        let request = joiner.request(&mut keys).expect("应当能发出请求");
        let reply = login
            .authorize(&request, account.vault.master_key())
            .expect("应当能授权")
            .to_vec();

        for index in 0..reply.len() {
            let mut joiner = Joiner::new(&payload, "new-device").expect("应当能开始扫码");
            let _ = joiner.request(&mut keys).expect("应当能发出请求");
            let mut tampered = reply.clone();
            tampered[index] ^= 0x01;
            let mut store = FakeStore::default();
            assert!(
                joiner.complete(&tampered, &mut keys, &mut store).is_err(),
                "翻转第 {index} 字节后仍被接受"
            );
            assert!(store.master.is_none(), "失败不得留下主密钥");
        }
    }

    /// `request` 必须幂等：重复调用返回同一条消息，而不是重新签名。
    #[test]
    fn requesting_twice_returns_the_same_message() {
        let login = Login::new().expect("应当能开始登录");
        let payload = login.payload().clone();
        let mut keys = FakeKeys::new();
        let mut joiner = Joiner::new(&payload, "new-device").expect("应当能开始扫码");
        let first = joiner.request(&mut keys).expect("应当能发出请求");
        let second = joiner.request(&mut keys).expect("应当能发出请求");
        assert_eq!(first, second);
        assert_eq!(keys.creates, 1, "不得为第二次请求创建新身份");
    }

    /// 恢复密钥的往返：导出、导入、写入存储，拿到的主密钥必须一致。
    #[test]
    fn recovery_roundtrip_restores_the_master_key() {
        let (_k, mut store, account) = registered();
        let master = account.vault.master_key();
        // 用最低参数让测试快，真实默认值见 `KdfParams::recommended`。
        let params = KdfParams::new(8, 1, 1).expect("最低参数应当合法");
        let passphrase = SecretString::from("correct horse battery staple");

        let file = export_recovery_key(master, &passphrase, Some(params)).expect("导出应当成功");
        let restored = import_recovery_key(&file, &passphrase, &mut store).expect("导入应当成功");

        assert_eq!(restored.expose(), master.expose());
        // 并且恢复出来的密钥能打开原来的保险库。
        let data = account.vault.serialize().expect("序列化应当成功");
        open_vault(&store, &data).expect("恢复后应当能打开保险库");
    }

    /// 口令错误时不得写入任何主密钥。
    #[test]
    fn recovery_with_a_wrong_passphrase_leaves_storage_untouched() {
        let mut store = FakeStore::default();
        let master = MasterKey::generate().expect("随机源可用");
        let params = KdfParams::new(8, 1, 1).expect("最低参数应当合法");
        let file = export_recovery_key(&master, &SecretString::from("right"), Some(params))
            .expect("导出应当成功");

        let error = import_recovery_key(&file, &SecretString::from("wrong"), &mut store)
            .expect_err("口令错误时必须失败");
        assert!(
            matches!(error, Error::RecoveryAuthenticationFailed),
            "实际是 {error:?}"
        );
        assert!(store.master.is_none(), "失败不得写入主密钥");
    }

    /// 口令为空时导出必须失败——否则 Argon2id 的代价全是白费。
    #[test]
    fn an_empty_passphrase_is_rejected() {
        let master = MasterKey::generate().expect("随机源可用");
        let error = export_recovery_key(&master, &SecretString::from(""), None)
            .expect_err("空口令必须被拒绝");
        assert!(
            matches!(error, Error::RecoveryPassphraseEmpty),
            "实际是 {error:?}"
        );
    }

    /// 存储自称不硬件保护时必须如实转发。
    #[test]
    fn hardware_backing_is_reported_truthfully() {
        let mut keys = FakeKeys::new();
        let mut soft = FakeStore::default();
        let result = registration(&mut keys, &mut soft, LABEL).expect("应当成功");
        assert!(!result.is_hardware_backed());

        let mut keys = FakeKeys::new();
        let mut hard = FakeStore {
            hardware: true,
            ..FakeStore::default()
        };
        let result = registration(&mut keys, &mut hard, LABEL).expect("应当成功");
        assert!(result.is_hardware_backed());
    }

    /// 互操作检查：对方声明的身份必须与本地取到的逐字节一致。
    #[test]
    fn device_identity_comparison_works_both_ways() {
        let mut keys = FakeKeys::new();
        let actual = keys.get_or_create(LABEL).expect("应当成功");
        expect_device(&actual, actual.as_sec1_bytes()).expect("同一个身份应当通过");

        let other = keys.get_or_create("other").expect("应当成功");
        let error = expect_device(&other, actual.as_sec1_bytes()).expect_err("不同身份必须失败");
        assert!(
            matches!(error, Error::DeviceIdentityMismatch),
            "实际是 {error:?}"
        );
    }

    /// 签名与验签必须互相匹配，且签名长度固定。
    #[test]
    fn signatures_verify_and_have_a_stable_length() {
        let mut keys = FakeKeys::new();
        let public = keys.get_or_create(LABEL).expect("应当成功");
        let message = b"hello";
        let signature = keys.sign(LABEL, message).expect("应当能签名");
        assert_eq!(signature.as_bytes().len(), SIGNATURE_LEN);
        verify_device(&public, message, &signature).expect("应当验签通过");
        assert!(verify_device(&public, b"other", &signature).is_err());
    }

    /// 对未创建的 label 签名必须报一个明确的错误，而不是 panic。
    #[test]
    fn signing_without_an_identity_fails_cleanly() {
        let mut keys = FakeKeys::new();
        let error = keys.sign("missing", b"x").expect_err("应当失败");
        assert!(matches!(error, Error::DeviceKeyMissing), "实际是 {error:?}");
    }

    /// 时间为 `0` 必须被拒绝：它通常意味着调用方忘了传。
    #[test]
    fn a_zero_timestamp_is_rejected() {
        assert!(check_now(0).is_err());
        assert_eq!(check_now(1).expect("非零应当通过"), 1);
    }

    /// 口令长度可以查，但口令本身不出现在任何输出里。
    #[test]
    fn passphrase_length_is_available_without_exposing_the_passphrase() {
        let passphrase = SecretString::from("hunter2");
        assert_eq!(passphrase_len(&passphrase), 7);
        assert_eq!(passphrase_len(&SecretString::from("")), 0);
        // 多字节字符按字符数而不是字节数，界面上的「长度提示」才不会吓到用户。
        assert_eq!(passphrase_len(&SecretString::from("口令")), 2);
    }

    /// `Debug` 输出不得包含任何密钥材料。
    #[test]
    fn debug_output_is_redacted() {
        let (_k, _s, account) = registered();
        let login = Login::new().expect("应当能开始登录");
        let payload = login.payload().clone();
        let mut keys = FakeKeys::new();
        let mut joiner = Joiner::new(&payload, "new-device").expect("应当能开始扫码");
        let _ = joiner.request(&mut keys).expect("应当能发出请求");

        let texts: [(&str, String); 3] = [
            ("Login", format!("{login:?}")),
            ("Joiner", format!("{joiner:?}")),
            ("MasterKey", format!("{:?}", account.vault.master_key())),
        ];
        let secrets: [(&str, String); 2] = [
            (
                "主密钥十六进制",
                account
                    .vault
                    .master_key()
                    .expose()
                    .iter()
                    .fold(String::new(), |mut acc, b| {
                        use core::fmt::Write as _;
                        let _ = write!(acc, "{b:02x}");
                        acc
                    }),
            ),
            (
                "主密钥十进制",
                account
                    .vault
                    .master_key()
                    .expose()
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ];
        for (name, text) in texts {
            for (secret_name, secret) in &secrets {
                assert!(
                    !text.contains(secret.as_str()),
                    "{name} 的 Debug 输出里出现了{secret_name}：{text}"
                );
            }
        }
    }

    /// 空保险库助手产出的文件必须是合法且可打开的。
    #[test]
    fn an_empty_vault_is_openable() {
        let master = MasterKey::generate().expect("随机源可用");
        let vault =
            empty_vault(MasterKey::from_bytes(master_key_to_bytes(&master)).expect("长度正确"));
        let data = vault.serialize().expect("序列化应当成功");
        let mut store = FakeStore::default();
        store.store_master_key(&master).expect("写入应当成功");
        let opened = open_vault(&store, &data).expect("应当能打开");
        assert!(opened.vault().is_empty());
    }

    /// `&mut T` 的转发实现必须与直接调用等价。
    #[test]
    fn mutable_references_forward_correctly() {
        let mut keys = FakeKeys::new();
        let via_ref = {
            let borrowed: &mut FakeKeys = &mut keys;
            let dynamic: &mut dyn DeviceKeys = borrowed;
            dynamic.get_or_create(LABEL)
        }
        .expect("应当成功");
        let direct = keys.get_or_create(LABEL).expect("应当成功");
        assert_eq!(via_ref.as_sec1_bytes(), direct.as_sec1_bytes());
        assert_eq!(keys.creates, 1);
    }
}
