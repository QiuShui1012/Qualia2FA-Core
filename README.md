# Qualia2FA-Core

Qualia2FA 的核心库。承载双因素认证（2FA）的全部核心逻辑：TOTP/HOTP 计算、加密保险库、
设备配对与同步合并。**刻意不含任何界面或命令行入口**，以便 Windows 桌面端、Android、
iOS 各自作为独立项目依赖本库。

> 本仓库是**独立仓库**，预期被其它端以 git submodule 引入。
> 因此本文件内的所有路径都相对于**本仓库根目录**，不假设任何上层目录结构。

## 元信息

| 项 | 值 |
|---|---|
| Crate 名 | `qualia2fa-core` |
| 版本 | `0.1.0` |
| 类型 | 纯 library crate（`src/lib.rs`） |
| Edition | 2024 |
| MSRV | **1.89** |
| 开发工具链 | `stable`（由 `rust-toolchain.toml` 固定） |
| 许可证 | `LGPL-3.0-or-later` |
| 状态 | **工程骨架**——TOTP/HOTP、保险库、配对与同步尚未实现 |

## 核心纯度约定

本库是**无 I/O、无时钟**的纯逻辑库。这不是风格偏好，而是可测试性与可移植性的前提：

- 不访问文件系统、网络、环境变量，不读取系统时钟。**当前时间由调用方以 `u64` Unix 秒传入。**
- 随机数只用 `getrandom`（OS CSPRNG），不经任何用户态 PRNG。
- `#![forbid(unsafe_code)]`——整个 crate 不含一行 `unsafe`。
- 所有对外函数返回 `Result`，错误类型化；**任何输入都不得导致 panic**，不 `unwrap` 外部输入。
- 错误类型**绝不携带秘密材料**：不放进原始输入、不放密钥字节、不放 OTP 码。

> 平台原生调用（如 Windows TPM/CNG 密钥库）**不属于本 crate**。那类需要 `unsafe` 的代码
> 会隔离到独立 crate，以保住本库的 `forbid(unsafe_code)`。

## 秘密材料的处理

库内所有秘密（OTP 种子、保险库主密钥、会话密钥）一律用 [`secrecy`] 的类型承载，
**不用裸 `Vec<u8>` / `String`**，使「这是秘密」在类型上可见：

| 用途 | 类型 |
|---|---|
| 任意字节秘密（种子、密钥、nonce） | `SecretBytes`（= `SecretSlice<u8>`） |
| 文本秘密（口令、恢复短语） | `SecretString` |
| 定长 / 其它秘密 | `SecretBox` |
| 取用明文 | `ExposeSecret` / `ExposeSecretMut` |

以上类型全部由本库再导出，调用方**不需要**直接依赖 `secrecy`。

**该依赖已人工审计**（`cargo-deny` 不做依赖必要性判断，故逐项核过）：

- 唯一必需依赖是 `zeroize ^1.6`，与本库此前所用版本同一 major，**全树只有一个 `zeroize`**。
- 可选依赖 `serde ^1` 本库不启用，不进依赖树。
- 上游 monorepo 活跃（未归档、近期有推送）；crate 本身自 2024-10 无新版本，属**成熟稳定而非废弃**，实现为纯逻辑封装（无 `unsafe`、无 FFI）。
- 本库**只在 `src/secret.rs` 一处接触它**，替换成本可控。

**务必知晓的上游行为**（与直觉不同）：

- `secrecy` 的 `Debug` **连长度都不打印**，输出形如 `SecretBox<str>([REDACTED])`。需要长度时请自行 `expose_secret()`。
- `secrecy` 只为**原始整数**实现 `CloneableSecret`，**没有** `Vec`/`String`/`Box` 的实现。因此本库的字节秘密统一用可克隆的 `SecretSlice<u8>`；**不要**改成 `SecretBox<Vec<u8>>`，那会因不可克隆而无法通过编译。
- 这些保障**只覆盖**「明文被打印 / 忘记擦除 / 误克隆」，**不覆盖**编译器把明文复制到寄存器、栈副本或交换区。`forbid(unsafe_code)` 之下无法用 `mlock` 阻止换页，也**不防同进程内的恶意代码**。

[`secrecy`]: https://crates.io/crates/secrecy

## 目录结构

```
.
├── Cargo.toml                  # crate 清单（含 MSRV、许可证、依赖理由注释）
├── Cargo.lock                  # 入库以保证可复现构建
├── rust-toolchain.toml         # 开发工具链固定为 stable
├── src/
│   ├── lib.rs                  # 库入口、crate 文档、纯度约定
│   ├── error.rs                # 类型化错误（thiserror），不泄露秘密
│   └── secret.rs               # 秘密容器：基于 secrecy 统一导出与别名
├── tests/
│   └── proptest.rs             # 基于属性的测试
├── fuzz/                       # cargo-fuzz（libFuzzer）目标，独立 crate
│   ├── Cargo.toml
│   └── fuzz_targets/
│       └── secret_debug_redaction.rs
├── .github/workflows/ci.yml    # CI：fmt/clippy/test/doc、MSRV、依赖审计、fuzz 冒烟
├── deny.toml                   # 依赖与许可证策略（cargo-deny）
├── LICENSE                     # GPL-3.0 全文（LGPL-3.0 通过引用并入）
├── COPYING.LESSER              # LGPL-3.0 全文
├── .gitignore
├── .gitattributes              # 统一 LF 行尾，保护许可证正文
└── README.md
```

## 被其它端引入

作为 submodule 引入本仓库：

```powershell
git submodule add <本仓库地址> core
git submodule update --init --recursive
```

在宿主项目的 `Cargo.toml` 中以路径依赖引用：

```toml
[dependencies]
qualia2fa-core = { path = "core" }
```

> ⚠️ 若宿主项目用 **Gobley + uniffi** 做 Kotlin 绑定，注意 Gobley 当前强制
> `uniffi = "0.29.4"`。**不要**把 uniffi 依赖加进本库——绑定应放在宿主侧或独立的
> FFI crate，以保持本库的依赖面干净、且不受绑定生成器的版本锁定牵连。

## 构建与校验

```powershell
cargo build                                  # 编译
cargo test --all-targets                     # 单元测试 + 文档测试 + property 测试
cargo fmt --all -- --check                   # 格式检查
cargo clippy --all-targets -- -D warnings    # 静态检查（警告即错误）
cargo doc --no-deps --open                   # 生成并查看 API 文档
```

依赖审计与许可证策略：

```powershell
cargo deny check                             # 漏洞 + 许可证 + 禁用清单
cargo audit                                  # 仅漏洞（RustSec 库）
```

模糊测试（需要 nightly 与 cargo-fuzz，因为要用 `-Zsanitizer`）：

```powershell
rustup toolchain install nightly --component rust-src
cargo install cargo-fuzz --locked

cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run secret_debug_redaction -- -max_total_time=300
```

提交前必须全绿：`cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test`。

## MSRV 策略

`rust-version = "1.89"` 是**最低支持声明**，不是开发工具链版本：

- **开发工具链**由 `rust-toolchain.toml` 固定为 `stable`，避免各人本机漂移。
- **MSRV 下限**由依赖栈决定（当前实际约束来自 `thiserror` 与传递引入的 `zeroize`；
  将来引入 AEAD/KEM 后会更紧）。
- CI 有独立的 MSRV job，用 1.89 真机编译一遍——**声明的 MSRV 必须真的能编译**，
  否则这个字段就是谎言。

## 安全与依赖纪律

- **常量时间是编译产物的属性，不是 crate 的属性。** 上游源码看着是常量时间的，
  编译器仍可能生成分支（RustSec 上多起此类公告均属 codegen 失败）。因此
  **升级任何 crypto 依赖后必须重跑常量时间相关测试**。
- **依赖审计是安全控制，不是杂事。** RustSec 库 2026 年新增 334 条公告（2025 年为 172 条），
  本项目关注的上游问题几乎都在补丁/次版本中修复。`Cargo.lock` 入库，CI 跑 `cargo-deny`。
- **只发布 release 构建**：常量时间比较库的 `debug_assert` 使用依赖秘密的分支。
- **秘密材料永不进入**日志、错误消息、panic 信息或 `Debug` 输出。
  `SecretBytes` 的 `Debug` 只打印长度。
- `deny.toml` 中有明确的禁用 crate 清单，每条都附了理由。

## 许可

本项目按 **GNU Lesser General Public License v3.0 or later**（`LGPL-3.0-or-later`）授权。
你可以依据自由软件基金会发布的 GNU 宽通用公共许可证第 3 版，或（任选）任何更高版本的条款，
再分发和/或修改本作品。

- [`COPYING.LESSER`](COPYING.LESSER)：LGPL-3.0 全文
- [`LICENSE`](LICENSE)：GPL-3.0 全文（LGPL-3.0 通过引用并入）

本作品出于希望其有用的目的分发，但不提供任何担保，甚至不提供适销性或特定用途适用性的默示担保。
详见许可证正文。
