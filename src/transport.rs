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

//! 传输抽象：本模块只认识「把一段字节送到某个对端」，不认识 WiFi、二维码、蓝牙。
//!
//! # 它为什么在核心库里，而具体通道不在
//!
//! 核心库有 `#![forbid(unsafe_code)]`、不依赖任何 I/O。而**每一种真实的传输方式都要
//! I/O**：UDP 组播要 socket，二维码要摄像头与屏幕，Quick Share 要平台 API。因此边界
//! 只能划在这里：核心库定义「一次同步交换长什么样」，平台侧实现「字节怎么过去」。
//!
//! 这也让同一套协议能在**测试里跑通**而不需要网络——见 [`Transport`] 的实现要求与
//! 本模块的测试。协议的正确性（谁的载荷先到、冲突怎么报、重放怎么挡）因此可以在
//! 一个进程里验证，而不是靠两台真机对拍。
//!
//! # 三种传输方式，一套协议
//!
//! | 方式 | 队形 | 单条上限 | 说明 |
//! |------|------|----------|------|
//! | 二维码 | 两方 | 有（几千字节，随版本变化） | 一次性、带外 |
//! | 局域网（QWBP） | 多方 | 无（可靠字节流） | 主要方式 |
//! | 热点 | 多方 | 无 | 局域网的一种，平台差异在实现里 |
//!
//! 三者的差别全部被 [`TransportCapabilities`] 描述，因此 [`SyncSession`] 不需要为
//! 它们各写一条分支。
//!
//! # 两方与多方的分工（用户要求）
//!
//! **两方通道直接开始传**——只有一个人会来，没有「等谁来」的问题。
//! **多方通道由发起方决定何时开始**——否则先连上的设备会在其他人到齐之前就把载荷
//! 换完，而那一轮同步的结果取决于谁先连上。
//!
//! 这条规则写成 [`TransportCapabilities::needs_start_signal`]，而不是散在调用点的
//! `if`，因为它是**协议性质**：任何一方判错都会导致「同步成功了但少了几条」。

use core::fmt;

use crate::error::{Error, Result};
use crate::sync::{self, MergedRecord, Payload, PayloadKind, SeenSyncIds, SyncId};
use crate::vault::{MasterKey, Vault};
use qualia_dik::DeviceId;

/// 一次同步里有几方。
///
/// 决定「要不要等发起方下令」。这个区分必须在**通道**层面声明，而不是由调用方猜：
/// 同一份代码在二维码上是两方、在局域网上的同一次使用却可能是多方。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Roster {
    /// 只会有两方。连上就开始传。
    TwoParty,
    /// 可能有三方或更多。由发起方决定何时开始。
    MultiParty,
}

impl Roster {
    /// 是否需要在开始前等发起方下令。
    #[must_use]
    pub const fn needs_start_signal(self) -> bool {
        matches!(self, Self::MultiParty)
    }
}

/// 收件人。
///
/// # 为什么发送时必须指定收件人，而不是所有方法都当成广播
///
/// 载荷里的每条记录都被主密钥保护，因此**广播本身不会泄露内容**。问题在别处：一次
/// 多设备同步里，「我这一轮把 B 的改动转发给 C」与「我把我自己的改动广播出去」是
/// 两个不同的动作，而后者会在 B 与 C 各自已经直接收到过的情况下重复传一遍。把收件人
/// 变成显式参数，能让误用（想发给一个却发给了全部）在签名上就看得出来。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipient {
    /// 只发给这一个对端。
    One(DeviceId),
    /// 发给本次会话里的全部对端。
    All,
}

/// 一种传输方式能做什么。
///
/// # 为什么能力要「声明」而不是「试探」
///
/// 试探的代价是真实且不可逆的：二维码要试探「装不装得下」就得先生成一张码，而用户
/// 已经把它举到另一台设备的摄像头前了。声明则让调用方在**开始之前**就知道该选哪种
/// 模式，装不下时直接引导用户改用局域网。
///
/// 远期要支持智能手表时，唯一变化的就是这里的一个数字——那是把它做成能力声明的
/// 全部理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportCapabilities {
    /// 队形。
    pub roster: Roster,
    /// 单条消息的字节上限；`None` 表示可靠字节流、整份载荷一次过。
    ///
    /// 二维码是 `Some`：它的容量随版本变化，且**装不下就是装不下**，没有重试余地。
    /// 局域网是 `None`：那是字节流，几千条记录的载荷照发。
    pub max_message_len: Option<usize>,
    /// 展示二维码时允许的最大版本（1–40）。
    ///
    /// `None` 表示这条通道不展示二维码。远期的智能手表会填一个很小的值，桌面端可以
    /// 填 40。**这个值属于平台，不属于数据集**：同一个数据集在手表上装不下、在桌面端
    /// 绰绰有余，而「装不下」的处置（引导改用局域网）也由平台决定。
    pub max_qr_version: Option<u8>,
    /// 这条通道是否只能使用一次。
    ///
    /// 二维码是 `true`：一张码承载一次交换，复用同一张码等于把重放防护之外的一条歧路
    /// 打开。局域网是 `false`。
    pub single_use: bool,
    /// 这条通道能否承载**整份**载荷（D9 的「全量提供」模式）。
    ///
    /// 为 `false` 时只能用「建链」模式：通道本身只用来交换地址/密钥，载荷另外走一条
    /// 字节流。
    pub can_carry_payload: bool,
}

impl TransportCapabilities {
    /// 一条**位流**通道（局域网、热点、将来的 Quick Share）。
    ///
    /// 载荷整份走这条通道，没有单条上限，可以反复使用。
    #[must_use]
    pub const fn stream(roster: Roster) -> Self {
        Self {
            roster,
            max_message_len: None,
            max_qr_version: None,
            single_use: false,
            can_carry_payload: true,
        }
    }

    /// 一条**定长**通道（二维码）。
    ///
    /// `max_message_len` 是这条码在给定版本下能装的字节数，由平台侧按纠错级别算好。
    /// 这里不接受「版本号」作为输入，因为「40 版能装多少字节」取决于纠错级别与编码
    /// 模式，而那是平台库的事——核心库替它算，就是把一个易变的表抄进来。
    #[must_use]
    pub const fn qr(max_qr_version: u8, max_message_len: usize) -> Self {
        Self {
            // 二维码天然是两方通道：一张码只会被一台设备扫。
            roster: Roster::TwoParty,
            max_message_len: Some(max_message_len),
            max_qr_version: Some(max_qr_version),
            single_use: true,
            can_carry_payload: true,
        }
    }

    /// 这条通道能否装下一份 `len` 字节的载荷。
    ///
    /// # 错误
    ///
    /// 装不下时返回 [`Error::TransportMessageTooLarge`]，带上实际需要的字节数——调用
    /// 方据此才能告诉用户「差多少」，而不是一个「太大了」。
    pub fn check_fits(&self, len: usize) -> Result<()> {
        match self.max_message_len {
            Some(limit) if len > limit => {
                Err(Error::TransportMessageTooLarge { needed: len, limit })
            }
            _ => Ok(()),
        }
    }

    /// 是否必须等发起方下令才能开始。
    #[must_use]
    pub const fn needs_start_signal(&self) -> bool {
        self.roster.needs_start_signal()
    }
}

/// 一条能搬运同步载荷的通道。
///
/// # 实现契约
///
/// 1. **`receive` 必须如实报告发送方**，不能只交回字节。载荷里的 `sender` 是自报的，
///    因此它只能作为**交叉校验**用；「是谁送来的」这件事只有通道知道。在广播型通道上
///    （局域网组播）任何设备都能把别人发过的载荷原样重放，于是「载荷说自己是 B」与
///    「实际是 C 发来的」可以同时成立。核心库把这个比对做成硬检查
///    （[`Error::SyncSenderMismatch`]），因此实现方谎报发送方**不能**换来任何好处，
///    只会让同步失败。
/// 2. **`send` 必须尊重 [`Recipient`]**。`Recipient::One` 不得退化成广播。
/// 3. **`receive` 不得无限阻塞**。它应当在通道当前没有消息时返回
///    [`Error::SyncNoSessionFound`]，由调用方决定要不要再等。核心库没有时钟，因此
///    「等多久」只能由实现方与调用方共同决定。
/// 4. **`single_use` 的通道第二次用必须返回 [`Error::TransportAlreadyUsed`]**。
///
/// # 为什么签名里没有 `&mut self`
///
/// 平台侧的通道实现通常需要在内部维护 socket、缓冲区、状态机，而 `send`/`receive`
/// 在语义上是「取一条消息」「放一条消息」。用 `&self` 把内部可变性的选择留给实现方
/// （`Mutex` / 原子 / 无锁队列），比在 trait 上逼它选一个更合适。这也让实现方能在
/// 多个线程上同时收发——局域网通道必然要这么做。
pub trait Transport {
    /// 这条通道能做什么。
    fn capabilities(&self) -> TransportCapabilities;

    /// 本设备的标识。
    ///
    /// 载荷里的 `sender` 由它填写，因此收发两侧看到的是同一个值。
    fn local_device(&self) -> DeviceId;

    /// 送出一条消息。
    fn send(&self, to: Recipient, message: &[u8]) -> Result<()>;

    /// 收一条消息，交回**字节**与**通道声称的发送方**。
    ///
    /// 当前没有消息时返回 [`Error::SyncNoSessionFound`]。
    fn receive(&self) -> Result<(DeviceId, Vec<u8>)>;

    /// 本次会话里的全部对端。
    ///
    /// 两方通道上是零个或一个元素；多方通道上可能有多个。`Recipient::All` 的语义由
    /// 它定义。刻意返回 `Vec` 而不是迭代器：调用方多半要先数一下有几个（决定要不要
    /// 等下令），而迭代器会让那件事变成一次隐式的两次遍历。
    fn peers(&self) -> Result<Vec<DeviceId>>;
}

/// 一次同步的结果。
#[derive(Debug)]
pub struct SyncOutcome {
    /// 刚处理完的那份载荷的标识。
    ///
    /// 调用方应当把它记下来（或交给 [`SeenSyncIds`]），下次收到同一个标识时
    /// [`SyncSession::receive`] 会直接拒绝。
    pub sync_id: SyncId,
    /// 合并结果：加了几条、删了几条、几条需要裁决。
    pub merge: sync::MergeOutcome,
}

impl SyncOutcome {
    /// 这次同步是否**什么也没改**。
    ///
    /// 与「合并报错」不是一回事：对端没有任何本机没有的改动是**正常**结果，调用方
    /// 应当告诉用户「已是最新」。把它做成一个方法而不是让调用方自己拼条件，是因为
    /// 拼错的方向是「明明没变却说变了」，而那会让用户以为同步很忙。
    #[must_use]
    pub fn made_no_change(&self) -> bool {
        self.merge.made_no_change()
    }

    /// 这次同步是否留下了需要用户裁决的冲突。
    #[must_use]
    pub fn needs_adjudication(&self) -> bool {
        self.merge.needs_adjudication()
    }
}

impl fmt::Display for SyncOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "新增 {}、墓碑 {}、应用删除 {}、未变 {}、冲突 {}",
            self.merge.added,
            self.merge.tombstones_added,
            self.merge.deletions_applied,
            self.merge.unchanged,
            self.merge.conflicts.len()
        )
    }
}

/// 一次同步会话。
///
/// # 它不持有传输通道
///
/// 每个方法都把通道当作参数收。原因是生命周期：真实通道（局域网 socket）的存活时间
/// 由平台的网络栈决定，而一次同步可能跨越「用户还没扫完码」这样长的时间；把通道钉在
/// 会话结构里会逼着会话与通道同生共死，而那正是最容易写出「用户取消后 socket 还开着」
/// 的地方。
///
/// # 它借用 `seen` 而不是拥有它
///
/// 重放日志必须**跨越多次会话**存活（否则重启一次应用就能重放所有旧载荷），因此它
/// 的所有权在调用方。会话只借用它，并在**成功解密并合并之后**才把标识记进去。
pub struct SyncSession<'a> {
    /// 本设备的主密钥，用来封/拆载荷。
    master: &'a MasterKey,
    /// 本设备的保险库，合并的目标。
    vault: &'a mut Vault,
    /// 跨会话存活的重放日志。
    seen: &'a mut SeenSyncIds,
    /// 只接受来自这些设备的载荷。
    ///
    /// 空表示「接受任何对端」——那是**建链之后**的状态：通道已经通过带外（二维码）
    /// 或配对确认过对方是谁。相反，局域网组播大厅里的载荷必须来自名单之内，否则
    /// 任何同一网段的设备都能往你的保险库里灌记录。
    allowed_senders: Vec<DeviceId>,
}

impl<'a> SyncSession<'a> {
    /// 建立一个只接受名单内设备的会话。
    ///
    /// # 为什么默认是「只信名单」
    ///
    /// 载荷本身是被主密钥认证的，因此名单**不是**机密性的防线——一个没有主密钥的
    /// 攻击者本来就造不出能通过认证的记录。名单防的是另一件事：把**别人签过名的**
    /// 载荷原样重放，从而让用户以为自己与 B 同步过。在局域网组播上这件事零成本。
    #[must_use]
    pub fn restricted(
        master: &'a MasterKey,
        vault: &'a mut Vault,
        seen: &'a mut SeenSyncIds,
        allowed_senders: Vec<DeviceId>,
    ) -> Self {
        Self {
            master,
            vault,
            seen,
            allowed_senders,
        }
    }

    /// 建立一个接受任何对端的会话。
    ///
    /// 只应当在通道**已经**确认过对方身份之后使用（带外二维码、配对完成的连接）。
    #[must_use]
    pub fn open(master: &'a MasterKey, vault: &'a mut Vault, seen: &'a mut SeenSyncIds) -> Self {
        Self {
            master,
            vault,
            seen,
            allowed_senders: Vec::new(),
        }
    }

    /// 把本机当前的保险库封成一份载荷并发出去。
    ///
    /// # 它**不**把这份载荷记进重放日志
    ///
    /// 日志只记**收到**的载荷。把自己的发出去的也记进去是很容易犯的错，而且它会造成
    /// 一个奇怪的故障：一旦对端把这份载荷回传（或用户在两台设备之间来回同步），本机
    /// 会因为「这个标识我见过」而拒绝一份**自己刚发出去的**载荷。日志的语义是
    /// 「已经处理过的入站载荷」，不是「见过的载荷」。
    ///
    /// # 载荷种类由调用方决定
    ///
    /// `kind` 决定这份载荷是「我的全量状态」还是「请把你的发给我」。它不在这里写死，
    /// 因为「要不要顺便把状态也带过去」是**协议层**的选择：局域网上一轮就够（状态
    /// 交换），而二维码那条路上往往先发一个小请求（塞得进码里），再让对方把大数据走
    /// 局域网发回来。
    ///
    /// # 错误
    ///
    /// 打包失败（见 [`Payload::from_vault`]）、通道装不下
    /// （[`Error::TransportMessageTooLarge`]）、或通道本身失败。
    pub fn send(
        &self,
        transport: &dyn Transport,
        to: Recipient,
        kind: PayloadKind,
    ) -> Result<SyncId> {
        let payload = match kind {
            PayloadKind::Vault => {
                Payload::from_vault(self.master, transport.local_device(), self.vault)?
            }
            PayloadKind::Request => Payload::request(transport.local_device())?,
        };
        let sealed = payload.seal(self.master)?;

        // 先问通道装不装得下，再发。顺序不能反：装不下时发送本身可能就是有意义的动作
        // （二维码已经把码显示出来了），而那时用户已经在扫码了。
        transport.capabilities().check_fits(sealed.len())?;
        transport.send(to, &sealed)?;
        Ok(payload.sync_id)
    }

    /// 收一条消息，把里面的记录并进本地保险库。
    ///
    /// # 顺序（每一步都不能换位置）
    ///
    /// 1. **对端在名单内吗**——不在就直接丢。这一步挡的是原样重放别人载荷的第三方。
    /// 2. **这条载荷我处理过吗**——处理过就拒绝，且**不**重复记账。
    /// 3. **解密封装**——失败就拒绝。这一步之后 `sender` 才是可信的（它在 AAD 里）。
    /// 4. **载荷自报的发送方与通道声称的一致吗**——不一致拒绝。见
    ///    [`Error::SyncSenderMismatch`]。
    /// 5. **逐条解密并合并**——这一步才动保险库。
    /// 6. **记账**——只有前面全部成功才把标识记进日志。
    ///
    /// 第 6 步放在最后是刻意的：若在解密之前记账，一个攻击者只要发一份**垃圾**载荷
    /// 并声称标识是 X，就能让真正的 X 永远被拒绝——一条零成本的拒绝服务。
    ///
    /// # 错误
    ///
    /// 任一环节失败都返回对应的错误，且**不改变保险库与日志**。唯一的例外是合并本身
    /// 中途失败（复制密钥材料失败），那时已合并的部分会留下——原子性要跨两个存储，
    /// 而本库刻意不做跨存储事务。
    pub fn receive(&mut self, transport: &dyn Transport) -> Result<SyncOutcome> {
        let (claimed_sender, message) = transport.receive()?;

        // ① 对端在名单内吗。
        if !self.allowed_senders.is_empty() && !self.allowed_senders.contains(&claimed_sender) {
            return Err(Error::SyncSenderMismatch);
        }

        // ② 这条载荷处理过吗。`peek` 只读明文头，因此这一步不花任何解密代价——重放
        //    防护必须在动保险库之前生效。
        let header = Payload::peek(&message)?;
        if self.seen.contains(&header.sync_id) {
            return Err(Error::SyncAlreadyApplied);
        }

        // ③ 拆封。失败时保险库与日志都没有被碰过。
        let payload = Payload::open(self.master, &message)?;

        // ④ 自报发送方 vs 通道声称的发送方。`payload.sender` 已经在 AAD 里，因此它
        //    只有可能等于真实发送方（诚实的对端）或等于一个被原样重放的载荷的原作者
        //    （不诚实的第三方）。
        if payload.sender != claimed_sender {
            return Err(Error::SyncSenderMismatch);
        }

        // ⑤ 逐条解密并合并。
        let opened = payload.open_records(self.master)?;
        let records: Vec<MergedRecord> = opened
            .into_iter()
            .map(sync::OpenedRecord::into_merged)
            .collect();
        let mut set = sync::RecordSet::new();
        for record in records {
            set.insert(record);
        }
        let merge = sync::merge_into(self.vault, &set)?;

        // ⑥ 记账。
        self.seen.record(payload.sync_id)?;

        Ok(SyncOutcome {
            sync_id: payload.sync_id,
            merge,
        })
    }
}

/// # 「通道暂时没消息」与「载荷被拒绝」必须分开
///
/// [`SyncSession`] 刻意**不**提供 `try_receive` 之类「失败也继续」的便捷方法。把两种
/// 情况混在一个返回值里，是让重放防护出现缺口的最短路径——调用方会顺手写
/// `let _ = session.receive(...)`，于是 [`Error::SyncAlreadyApplied`] 被丢掉，重放
/// 变成静默接受。
///
/// 调用方要自己区分 [`Error::SyncNoSessionFound`]（继续等）与其它错误（拒绝）。
/// 这条约束写在类型上而不是文档里：**没有那个方法**，就没有那个误用。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::{Algorithm, Digits, OtpSecret};
    use crate::sync::{RecordSet, merge_into};
    use crate::vault::{Entry, EntryId, Timestamp, Vault as VaultAlias};

    /// 一条纯内存通道，用于在没有网络的情况下验证协议。
    ///
    /// # 它为什么必须是「诚实但愚蠢」的
    ///
    /// 它只做搬运，不做任何协议判断——所有判断都在 [`SyncSession`] 里。一个会在测试
    /// 里「帮忙」的通道（比如自动去重）会让协议的真实缺陷被它掩盖掉。
    struct MemoryTransport {
        /// 本设备的标识。
        me: DeviceId,
        /// 出站队列：`(收件人, 发送方, 字节)`。
        outbox: std::sync::Mutex<Vec<(Recipient, DeviceId, Vec<u8>)>>,
        /// 入站队列：`(通道声称的发送方, 字节)`。
        inbox: std::sync::Mutex<Vec<(DeviceId, Vec<u8>)>>,
        /// 这条通道声称自己有什么能力。
        caps: TransportCapabilities,
        /// 这条通道声称的对端。
        peers: Vec<DeviceId>,
    }

    impl MemoryTransport {
        fn new(me: DeviceId, caps: TransportCapabilities) -> Self {
            Self {
                me,
                outbox: std::sync::Mutex::new(Vec::new()),
                inbox: std::sync::Mutex::new(Vec::new()),
                caps,
                peers: Vec::new(),
            }
        }

        fn with_peers(mut self, peers: Vec<DeviceId>) -> Self {
            self.peers = peers;
            self
        }

        /// 把这条通道的出站队列搬到另一条通道的入站队列。
        ///
        /// # 出站队列**不**被清空
        ///
        /// 一次广播要送到 N 个对端，因此投递必须可以被调用 N 次。第一版这里写的是
        /// `drain(..)`，于是「广播给 B 和 C」实际只送到了 B——而失败现象是
        /// 「C 说没人跟它同步」，一个与「出站队列只被读一次」毫无关系的现象。
        /// 想开始新一轮的调用方请显式 [`MemoryTransport::clear_outbox`]。
        ///
        /// `honest` 为 `false` 时改掉「通道声称的发送方」——用来模拟一个在广播型通道上
        /// 原样重放别人载荷的第三方。
        fn deliver_to(&self, target: &MemoryTransport, honest: bool) {
            let outbox = self.outbox.lock().expect("锁未中毒");
            let mut inbox = target.inbox.lock().expect("锁未中毒");
            for (recipient, sender, bytes) in outbox.iter() {
                let addressed = match recipient {
                    Recipient::All => true,
                    Recipient::One(id) => *id == target.me,
                };
                if !addressed {
                    continue;
                }
                let claimed = if honest { *sender } else { self.me };
                inbox.push((claimed, bytes.clone()));
            }
        }

        /// 丢弃出站队列里的全部消息。
        ///
        /// 一次同步「轮次」的边界：调用方在每一轮开始时清一次，避免上一轮的载荷被
        /// 重复投递——那会让接收方报 [`Error::SyncAlreadyApplied`]，看起来像是重放
        /// 防护误伤。
        fn clear_outbox(&self) {
            self.outbox.lock().expect("锁未中毒").clear();
        }

        /// 直接往入站队列塞一条消息（模拟攻击者）。
        fn inject(&self, claimed_sender: DeviceId, bytes: Vec<u8>) {
            self.inbox
                .lock()
                .expect("锁未中毒")
                .push((claimed_sender, bytes));
        }
    }

    impl Transport for MemoryTransport {
        fn capabilities(&self) -> TransportCapabilities {
            self.caps
        }

        fn local_device(&self) -> DeviceId {
            self.me
        }

        fn send(&self, to: Recipient, message: &[u8]) -> Result<()> {
            // 契约 2：`Recipient::One` 不得退化成广播。这里如实记录收件人，由投递
            // 那一步去执行——一个「反正都会送到」的实现会让这条契约在测试里失效。
            self.outbox
                .lock()
                .expect("锁未中毒")
                .push((to, self.me, message.to_vec()));
            Ok(())
        }

        fn receive(&self) -> Result<(DeviceId, Vec<u8>)> {
            let mut inbox = self.inbox.lock().expect("锁未中毒");
            if inbox.is_empty() {
                return Err(Error::SyncNoSessionFound);
            }
            Ok(inbox.remove(0))
        }

        fn peers(&self) -> Result<Vec<DeviceId>> {
            Ok(self.peers.clone())
        }
    }

    fn a_device(seed: u8) -> (DeviceId, MasterKey, Vault) {
        let master = MasterKey::generate().expect("OS 随机源可用");
        (DeviceId::from_bytes([seed; 32]), master, Vault::new())
    }

    fn sample_entry(name: &str, updated_at: u64) -> Entry {
        Entry::new(
            name.into(),
            Some("组织".into()),
            "user@example.com".into(),
            OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("合法 Base32"),
            Algorithm::Sha1,
            Digits::Six,
            30,
            None,
            String::new(),
            Timestamp::from(1_700_000_000_u64),
            Timestamp::from(updated_at),
        )
        .expect("字段合法")
    }

    /// 两方通道的完整往返：A 的条目出现在 B 的保险库里。
    #[test]
    fn a_two_party_exchange_moves_entries() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        vault_a
            .insert(sample_entry("A 的条目", 1_700_000_000))
            .expect("随机源可用");

        let caps = TransportCapabilities::stream(Roster::TwoParty);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b]);
        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_a]);

        let mut seen_a = SeenSyncIds::new();
        let mut seen_b = SeenSyncIds::new();

        // A 发出。
        let session_a = SyncSession::open(&master, &mut vault_a, &mut seen_a);
        session_a
            .send(&ta, Recipient::One(id_b), PayloadKind::Vault)
            .expect("发送");

        // 通道搬运。
        ta.deliver_to(&tb, true);

        // B 收到并合并。会话借用 `vault_b` 与 `seen_b`，因此必须把它放进一个块里——
        // 否则后面的断言读到的是被借走的值。这不是测试的麻烦，而是 API 刻意的形状：
        // 会话存活期间保险库就是它的。
        let outcome = {
            let mut session_b = SyncSession::open(&master, &mut vault_b, &mut seen_b);
            session_b.receive(&tb).expect("接收")
        };

        assert_eq!(outcome.merge.added, 1, "应当并进来一条：{outcome}");
        assert_eq!(vault_b.len(), 1);
        assert!(!outcome.needs_adjudication(), "内容相同不该报冲突");
        assert_eq!(seen_b.len(), 1, "收到之后应当记一笔");

        // A 的日志**不**应当因为自己发出去过而多一笔。
        assert_eq!(seen_a.len(), 0, "发出载荷不该记进重放日志");

        // 再来一次：同一个标识必须被拒绝。
        ta.deliver_to(&tb, true);
        let again = {
            let mut session_b = SyncSession::open(&master, &mut vault_b, &mut seen_b);
            session_b.receive(&tb)
        };
        assert!(
            matches!(again, Err(Error::SyncAlreadyApplied)),
            "重复的载荷未被拒绝，实际 {again:?}"
        );
    }

    /// **重放：第三方把 B 发过的载荷原样转发给 C。**
    ///
    /// 载荷在密码学上完全有效——它确实是 B 签发的。挡不住它的部署会让 C 以为自己
    /// 与 B 同步过。名单检查是唯一能挡住它的东西。
    #[test]
    fn a_replayed_payload_from_a_third_party_is_rejected() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        let (id_c, _, mut vault_c) = a_device(3);
        vault_b
            .insert(sample_entry("B 的条目", 1_700_000_000))
            .expect("随机源可用");

        let caps = TransportCapabilities::stream(Roster::MultiParty);

        // B 广播给自己的两个对端。C 只在名单里放 A，**不放 B**——模拟「C 已经与 A
        // 建链，而攻击者 A 把 B 的载荷转给它」。
        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_a, id_c]);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b, id_c]);
        let tc = MemoryTransport::new(id_c, caps).with_peers(vec![id_a]);

        let mut seen_b = SeenSyncIds::new();
        let session_b = SyncSession::open(&master, &mut vault_b, &mut seen_b);
        session_b
            .send(&tb, Recipient::All, PayloadKind::Vault)
            .expect("发送");

        // B 发出的那份字节。它在 `tb` 的**出站**队列里（是 B 发出去的），不在 `ta`
        // 的入站里——第一版读错了队列。
        let b_payload = tb
            .outbox
            .lock()
            .expect("锁未中毒")
            .first()
            .map(|(_, _, bytes)| bytes.clone())
            .expect("B 的出站里应当有那份载荷");

        // 送到 A（诚实），A 正常收下。
        tb.deliver_to(&ta, true);
        let mut seen_a = SeenSyncIds::new();
        let outcome_a = {
            let mut session_a = SyncSession::open(&master, &mut vault_a, &mut seen_a);
            session_a.receive(&ta).expect("A 正常收到")
        };
        assert_eq!(outcome_a.merge.added, 1, "A 应当收下 B 的那条");

        // 现在 A 把**同一份字节**转给 C。A 是诚实的通道，因此通道会如实说「发送方是
        // A」——而载荷里自报的是 B。这个不一致正是要被挡住的。
        ta.send(Recipient::One(id_c), &b_payload).expect("转发");
        ta.deliver_to(&tc, true);

        // C 会拿到这份载荷，且通道说发送方是 A。它必须被拒绝——不是因为解密失败
        // （解密会成功，它确实是 B 用真主密钥签的），而是因为载荷自报的发送方是 B。
        let mut seen_c = SeenSyncIds::new();
        let mut session_c = SyncSession::restricted(&master, &mut vault_c, &mut seen_c, vec![id_a]);
        let result = session_c.receive(&tc);
        assert!(
            matches!(result, Err(Error::SyncSenderMismatch)),
            "被转发的载荷未被拒绝，实际 {result:?}"
        );
        assert_eq!(vault_c.len(), 0, "被拒绝的载荷不得改动保险库");
        assert_eq!(seen_c.len(), 0, "被拒绝的载荷不得记账");
    }

    /// 名单之外的对端发来的载荷直接被丢。
    #[test]
    fn a_payload_from_an_unlisted_peer_is_rejected() {
        let (id_a, master, _) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        let (id_c, _, mut vault_c) = a_device(3);
        vault_b
            .insert(sample_entry("B 的条目", 1_700_000_000))
            .expect("随机源可用");

        let caps = TransportCapabilities::stream(Roster::MultiParty);
        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_c]);
        let tc = MemoryTransport::new(id_c, caps).with_peers(vec![id_b]);

        let mut seen_b = SeenSyncIds::new();
        SyncSession::open(&master, &mut vault_b, &mut seen_b)
            .send(&tb, Recipient::All, PayloadKind::Vault)
            .expect("发送");
        tb.deliver_to(&tc, true);

        // C 的名单里只有 A。B 不在名单内。
        let mut seen_c = SeenSyncIds::new();
        let result = {
            let mut session_c =
                SyncSession::restricted(&master, &mut vault_c, &mut seen_c, vec![id_a]);
            session_c.receive(&tc)
        };
        assert!(
            matches!(result, Err(Error::SyncSenderMismatch)),
            "名单外的对端未被拒绝，实际 {result:?}"
        );
        assert_eq!(vault_c.len(), 0);
    }

    /// **垃圾载荷不得把它的标识记进日志。**
    ///
    /// 若在解密之前记账，攻击者只要发一份垃圾并声称标识是 X，就能让真正的 X 永远被
    /// 拒绝。这条测试是那条拒绝服务的回归保护。
    #[test]
    fn a_garbage_payload_does_not_poison_the_seen_log() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, _) = a_device(2);
        let caps = TransportCapabilities::stream(Roster::TwoParty);

        // 先造一份**合法**载荷，记下它的标识。
        let mut source_vault = Vault::new();
        source_vault
            .insert(sample_entry("条目", 1_700_000_000))
            .expect("随机源可用");
        let payload = Payload::from_vault(&master, id_b, &source_vault).expect("打包");
        let sealed = payload.seal(&master).expect("封装");
        let good_id = payload.sync_id;

        // 把密文里的一位改坏（保留头部，因此 `peek` 仍能读出标识）。
        let mut broken = sealed.clone();
        let last = broken.len() - 1;
        broken[last] ^= 0xFF;

        let ta = MemoryTransport::new(id_a, caps);
        ta.inject(id_b, broken);

        let mut seen_a = SeenSyncIds::new();
        let result = {
            let mut session_a = SyncSession::open(&master, &mut vault_a, &mut seen_a);
            session_a.receive(&ta)
        };
        assert!(result.is_err(), "被篡改的载荷应当被拒绝");
        assert_eq!(seen_a.len(), 0, "被拒绝的载荷不得记账");
        assert!(
            !seen_a.contains(&good_id),
            "垃圾载荷把合法载荷的标识污染了——真正的载荷将永远被拒绝"
        );

        // 真正的载荷随后必须仍然被接受。
        ta.inject(id_b, sealed);
        let outcome = {
            let mut session_a = SyncSession::open(&master, &mut vault_a, &mut seen_a);
            session_a.receive(&ta).expect("合法载荷应当被接受")
        };
        assert_eq!(outcome.merge.added, 1);
        assert_eq!(seen_a.len(), 1);
    }

    /// 通道装不下时必须在发送**之前**就报出来，且带上实际需要的字节数。
    #[test]
    fn a_payload_larger_than_the_channel_is_reported_before_sending() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, _) = a_device(2);
        for i in 0..40_u64 {
            vault_a
                .insert(sample_entry(&format!("条目 {i}"), 1_700_000_000 + i))
                .expect("随机源可用");
        }

        // 一条只装得下 64 字节的「二维码」。
        let caps = TransportCapabilities::qr(4, 64);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b]);

        let mut seen = SeenSyncIds::new();
        let session = SyncSession::open(&master, &mut vault_a, &mut seen);
        let result = session.send(&ta, Recipient::One(id_b), PayloadKind::Vault);

        match result {
            Err(Error::TransportMessageTooLarge { needed, limit }) => {
                assert_eq!(limit, 64);
                assert!(needed > 64, "报出来的需求量 {needed} 应当大于上限");
            }
            other => panic!("应当报「装不下」，实际 {other:?}"),
        }

        // 报错时**不得**已经发出去。
        assert!(
            ta.outbox.lock().expect("锁未中毒").is_empty(),
            "装不下时不该已经往通道里写了东西"
        );
    }

    /// 两方通道不需要下令，多方通道需要。
    #[test]
    fn only_multi_party_channels_need_a_start_signal() {
        assert!(!TransportCapabilities::stream(Roster::TwoParty).needs_start_signal());
        assert!(TransportCapabilities::stream(Roster::MultiParty).needs_start_signal());
        // 二维码天然是两方。
        assert!(!TransportCapabilities::qr(40, 2900).needs_start_signal());
        assert!(TransportCapabilities::qr(40, 2900).single_use);
        assert!(!TransportCapabilities::stream(Roster::TwoParty).single_use);
    }

    /// 多方会话：A 广播之后 B 与 C 都拿到了同样的内容。
    #[test]
    fn a_multi_party_broadcast_reaches_every_peer() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        let (id_c, _, mut vault_c) = a_device(3);
        vault_a
            .insert(sample_entry("A 的条目", 1_700_000_000))
            .expect("随机源可用");

        let caps = TransportCapabilities::stream(Roster::MultiParty);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b, id_c]);
        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_a, id_c]);
        let tc = MemoryTransport::new(id_c, caps).with_peers(vec![id_a, id_b]);

        let mut seen_a = SeenSyncIds::new();
        SyncSession::open(&master, &mut vault_a, &mut seen_a)
            .send(&ta, Recipient::All, PayloadKind::Vault)
            .expect("广播");

        ta.deliver_to(&tb, true);
        ta.deliver_to(&tc, true);

        let mut seen_b = SeenSyncIds::new();
        let outcome_b = SyncSession::open(&master, &mut vault_b, &mut seen_b)
            .receive(&tb)
            .expect("B 接收");
        assert_eq!(outcome_b.merge.added, 1);

        let mut seen_c = SeenSyncIds::new();
        let outcome_c = SyncSession::open(&master, &mut vault_c, &mut seen_c)
            .receive(&tc)
            .expect("C 接收");
        assert_eq!(outcome_c.merge.added, 1);

        assert_eq!(vault_b.len(), 1);
        assert_eq!(vault_c.len(), 1);
    }

    /// `Recipient::One` 必须真的只送到一个对端。
    ///
    /// 这条契约靠实现方遵守，因此必须有一条测试盯着它——一个「反正都会送到」的实现
    /// 会让一次定向发送变成广播，而用户看不到任何异常。
    #[test]
    fn a_targeted_send_does_not_reach_other_peers() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        let (id_c, _, mut vault_c) = a_device(3);
        vault_a
            .insert(sample_entry("只给 B", 1_700_000_000))
            .expect("随机源可用");

        let caps = TransportCapabilities::stream(Roster::MultiParty);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b, id_c]);
        let tb = MemoryTransport::new(id_b, caps);
        let tc = MemoryTransport::new(id_c, caps);

        let mut seen_a = SeenSyncIds::new();
        SyncSession::open(&master, &mut vault_a, &mut seen_a)
            .send(&ta, Recipient::One(id_b), PayloadKind::Vault)
            .expect("定向发送");

        ta.deliver_to(&tc, true);
        assert!(
            tc.inbox.lock().expect("锁未中毒").is_empty(),
            "定向发给 B 的消息送到了 C"
        );

        ta.deliver_to(&tb, true);
        assert!(!tb.inbox.lock().expect("锁未中毒").is_empty(), "应当送到 B");
        let _ = &mut vault_b;
        let _ = &mut vault_c;
    }

    /// 「已是最新」是一种正常结果，不是错误。
    #[test]
    fn syncing_with_nothing_new_reports_no_change() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        vault_a
            .insert(sample_entry("同一条", 1_700_000_000))
            .expect("随机源可用");

        let caps = TransportCapabilities::stream(Roster::TwoParty);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b]);
        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_a]);

        // 第一轮：B 学到 A 的条目。
        let mut seen_a = SeenSyncIds::new();
        SyncSession::open(&master, &mut vault_a, &mut seen_a)
            .send(&ta, Recipient::One(id_b), PayloadKind::Vault)
            .expect("发送");
        ta.deliver_to(&tb, true);
        let mut seen_b = SeenSyncIds::new();
        let first = SyncSession::open(&master, &mut vault_b, &mut seen_b)
            .receive(&tb)
            .expect("接收");
        assert_eq!(first.merge.added, 1);
        assert!(!first.made_no_change(), "第一轮确实改了东西");

        // 第二轮：A 再发一次（内容完全相同，但载荷标识是新的）。
        // 先把上一轮的载荷从出站队列里清掉，否则它会被再投递一次，而接收方会按重放
        // 拒绝——那看起来像重放防护误伤，其实是投递层重复送了同一份载荷。
        ta.clear_outbox();
        SyncSession::open(&master, &mut vault_a, &mut seen_a)
            .send(&ta, Recipient::One(id_b), PayloadKind::Vault)
            .expect("发送");
        ta.deliver_to(&tb, true);
        let second = SyncSession::open(&master, &mut vault_b, &mut seen_b)
            .receive(&tb)
            .expect("接收");

        assert!(
            second.made_no_change(),
            "内容相同时应当报「无改动」，实际 {second}"
        );
        assert!(!second.needs_adjudication());
    }

    /// 三台设备两轮同步之后内容一致。
    ///
    /// 这是把 [`SyncSession`] 与 `merge` 一起用起来时的端到端性质，也是「多种传输方式
    /// 共用一套协议」的验收点：同样的字节序列，无论走哪条通道，收敛结果必须一样。
    #[test]
    fn three_devices_converge_over_the_session() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        let (id_c, _, mut vault_c) = a_device(3);

        vault_a
            .insert(sample_entry("A", 1_700_000_000))
            .expect("随机源可用");
        vault_b
            .insert(sample_entry("B", 1_700_000_100))
            .expect("随机源可用");
        vault_c
            .insert(sample_entry("C", 1_700_000_200))
            .expect("随机源可用");

        let caps = TransportCapabilities::stream(Roster::MultiParty);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b, id_c]);
        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_a, id_c]);
        let tc = MemoryTransport::new(id_c, caps).with_peers(vec![id_a, id_b]);

        let mut seen_a = SeenSyncIds::new();
        let mut seen_b = SeenSyncIds::new();
        let mut seen_c = SeenSyncIds::new();

        for _ in 0..2 {
            // 每台设备各广播一次自己的当前状态。先把上一轮的残留清掉。
            ta.clear_outbox();
            tb.clear_outbox();
            tc.clear_outbox();
            SyncSession::open(&master, &mut vault_a, &mut seen_a)
                .send(&ta, Recipient::All, PayloadKind::Vault)
                .expect("A 广播");
            SyncSession::open(&master, &mut vault_b, &mut seen_b)
                .send(&tb, Recipient::All, PayloadKind::Vault)
                .expect("B 广播");
            SyncSession::open(&master, &mut vault_c, &mut seen_c)
                .send(&tc, Recipient::All, PayloadKind::Vault)
                .expect("C 广播");

            // 全部投递，再让各自处理收到的全部消息。
            ta.deliver_to(&tb, true);
            ta.deliver_to(&tc, true);
            tb.deliver_to(&ta, true);
            tb.deliver_to(&tc, true);
            tc.deliver_to(&ta, true);
            tc.deliver_to(&tb, true);

            for transport in [&ta, &tb, &tc] {
                loop {
                    let result = match transport.local_device() {
                        id if id == id_a => {
                            SyncSession::open(&master, &mut vault_a, &mut seen_a).receive(transport)
                        }
                        id if id == id_b => {
                            SyncSession::open(&master, &mut vault_b, &mut seen_b).receive(transport)
                        }
                        _ => {
                            SyncSession::open(&master, &mut vault_c, &mut seen_c).receive(transport)
                        }
                    };
                    match result {
                        Ok(_) => {}
                        // 队列空了，换下一台。
                        Err(Error::SyncNoSessionFound) => break,
                        Err(other) => panic!("不该出现的错误：{other:?}"),
                    }
                }
            }
        }

        assert_eq!(vault_a.len(), 3, "A 应当有三条");
        assert_eq!(vault_b.len(), 3, "B 应当有三条");
        assert_eq!(vault_c.len(), 3, "C 应当有三条");
    }

    /// 冲突会被如实报出来，而不是被静默选边。
    #[test]
    fn a_divergent_entry_is_reported_for_adjudication() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);

        // 两台设备上同一个标识、不同内容。
        let shared = EntryId::from_bytes([9; EntryId::LEN]);
        vault_a
            .insert_with_id(shared, sample_entry("本机版本", 1_700_000_000))
            .expect("插入");
        vault_b
            .insert_with_id(shared, sample_entry("对端版本", 1_700_000_500))
            .expect("插入");

        let caps = TransportCapabilities::stream(Roster::TwoParty);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b]);
        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_a]);

        let mut seen_a = SeenSyncIds::new();
        SyncSession::open(&master, &mut vault_a, &mut seen_a)
            .send(&ta, Recipient::One(id_b), PayloadKind::Vault)
            .expect("发送");
        ta.deliver_to(&tb, true);

        let mut seen_b = SeenSyncIds::new();
        let outcome = SyncSession::open(&master, &mut vault_b, &mut seen_b)
            .receive(&tb)
            .expect("接收");

        assert!(
            outcome.needs_adjudication(),
            "两端内容不同时应当报冲突，实际 {outcome}"
        );
        assert_eq!(outcome.merge.conflicts.len(), 1);
        // 冲突不改变本地那一版。
        assert_eq!(
            vault_b.get(&shared).expect("条目还在").name,
            "对端版本",
            "冲突不该自动改掉本地内容"
        );
    }

    /// `RecordSet` / `merge_into` 在会话之外也能直接用（供端侧做裁决预览）。
    #[test]
    fn the_merge_helpers_stay_usable_without_a_transport() {
        let (_, master, mut vault) = a_device(1);
        let mut source = VaultAlias::new();
        source
            .insert(sample_entry("来自别处", 1_700_000_000))
            .expect("随机源可用");

        let payload =
            Payload::from_vault(&master, DeviceId::from_bytes([2; 32]), &source).expect("打包");
        let mut set = RecordSet::new();
        for record in payload.open_records(&master).expect("解密") {
            set.insert(record.into_merged());
        }
        let outcome = merge_into(&mut vault, &set).expect("合并");
        assert_eq!(outcome.added, 1);
        assert_eq!(vault.len(), 1);
    }
}
