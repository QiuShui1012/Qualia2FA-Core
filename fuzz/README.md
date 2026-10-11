# fuzz 使用说明

本目录是本仓库的 libFuzzer 目标（基于 `cargo-fuzz`）。

## 为什么需要 nightly

`cargo-fuzz` 依赖 `-Zsanitizer`，这是 nightly 专属特性。稳定版无法运行 fuzz。

```powershell
rustup toolchain install nightly --component rust-src
cargo install cargo-fuzz --locked
```

## ⚠️ Windows 上必须先修 PATH（否则 fuzz 跑不起来）

在 Windows + MSVC 上，Rust 的 `-Zsanitizer=address` 链接**动态** ASan 运行时，
所以运行时需要 `clang_rt.asan_dynamic-x86_64.dll` 在 `PATH` 上。它随 Visual Studio
分发，但**不在**默认 `PATH` 中，因此默认会看到：

```
error: process didn't exit successfully: ... (exit code: 0xc0000135, STATUS_DLL_NOT_FOUND)
```

加上 DLL 所在目录即可。**注意版本必须匹配**：先用 VS **2022** 的，2025 年 3 月版本的
VS 2019 那份会报 `0xc0000139 STATUS_ENTRYPOINT_NOT_FOUND`（DLL 找到了但符号对不上）。

```powershell
# 找出本机所有候选（版本不同，报错也不同）
Get-ChildItem 'C:\Program Files\Microsoft Visual Studio','C:\Program Files (x86)\Microsoft Visual Studio' `
  -Recurse -Filter 'clang_rt.asan_dynamic-x86_64.dll' -ErrorAction SilentlyContinue |
  Select-Object FullName, LastWriteTime, Length

# 把可用的那一份加到 PATH 前面（路径按上一步结果替换）
$asanDir = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\<版本>\bin\Hostx64\x64'
$env:PATH = "$asanDir;$env:PATH"
```

该路径与 VS 版本号绑死，**无法写死在仓库里**，所以必须每次手动设置（或在自己的
shell profile 里固化）。

替代方案：在 **WSL / Linux** 上跑 fuzz 不需要这一步。CI 的 fuzz job 就跑在 Linux 上。

## 运行

```powershell
cd fuzz

# 列出所有目标
cargo +nightly fuzz list

# 限时跑（**务必带限时**：libFuzzer 不会因为 -runs=N 就退出，
# 不带 -max_total_time 会一直跑下去）
cargo +nightly fuzz run secret_debug_redaction -- -max_total_time=300

# 复现某个崩溃
cargo +nightly fuzz run secret_debug_redaction artifacts/secret_debug_redaction/<crash-file>
```

`corpus/`、`artifacts/`、`coverage/` 均不入库（见 `.gitignore`）。自动生成的
`corpus/` 每次跑都会增长，入库只会让 `git status` 永远脏。

**值得长期保留的样本放进 `regressions/<目标>/`，那个目录是入库的。** 放进去的
样本会被 CI 在跑 fuzz 前先喂进语料库（见 `.github/workflows/ci.yml`），因此它们
每一轮都会被真正执行到——这是防止同一个缺陷复发的唯一持久化手段，也是把崩溃
调小后固化成回归用例的地方。

## 现有目标

| 目标 | 覆盖的输入面 | 检查的性质 |
|---|---|---|
| `secret_debug_redaction` | `SecretBytes`（秘密处理路径） | 不 panic、`new`→`expose` 透明、`Debug` 不泄露明文（十进制与十六进制两种表示） |
| `uri_parse` | `otpauth://` URI 解析器 | 不 panic、`Debug` 的 `secret` 字段恒为脱敏标记、超长 `issuer` 被截断、解析出的配置自洽、序列化往返幂等 |
| `base32_and_otp` | Base32 编解码 + OTP 计算 | 编解码精确往返（含有/无填充）、宽容模式与严格模式一致、验证码长度与取值范围正确、Steam 字母表正确 |
| `vault_parse` | 保险库文件（攻击者可完整构造） | 不 panic、长度字段不会引发越界或巨量分配、条目明文的节点解析能正确跳过未知标签、能解开的文件必能重新序列化 |

## 为什么 `vault_parse` 需要专门绕开 AEAD

保险库的每条记录都被 XChaCha20-Poly1305 保护，因此**随手构造的字节流几乎一定在
认证那一步就被拒绝**，根本走不到条目明文的解析逻辑——而那（`decode_entry` 里的
「按长度跳过未知节点」）才是最容易写成越界的地方。

所以该目标有第二种模式：先造一份**用输入派生的确定密钥**加密的合法骨架，再把
fuzz 输入插进**密文位置**，并同步改掉长度字段。这样输入会长驱直入地进入解密后的
明文解析循环。

两个容易踩空的地方：

- **骨架的密钥必须能重新构造出来。** 最初用 `MasterKey::generate()`，结果目标
  自己都解不开自己造的文件，模式 2 完全失效（表现为覆盖率停在文件头附近）。
  改用输入派生的密钥后才有意义。
- **长度字段必须跟着改。** 不改的话解析器会在长度检查那一步就返回，仍然到不了
  深层逻辑。

## 写断言时的陷阱

fuzz 断言里的**字符串包含检查**极易写出假阳性：只要断言检查「输出里是否含某串」，
fuzzer 就会构造出把该串放进**别的字段**的输入。本仓库已经踩过两次：

- 「`Debug` 里出现了种子的 Base32」——结果 fuzzer 把种子串放进了 `issuer`，
  两个无关字段恰好同值，并非泄露。改为结构性地断言 `secret` 字段恒为
  `<redacted>`。
- 「`Debug` 里出现了 `secret: Some`」——结果 fuzzer 把这段文本整段放进了
  `issuer`，于是子串命中了那个**字段名**，而不是任何实际字段。该断言本身也是
  多余的：`OtpAuth.secret` 的类型就是 `OtpSecret` 而非 `Option<OtpSecret>`，
  结构上不可能被包在 `Some` 里，且上一条已断言 `secret` 字段恒为脱敏标记。

结论：断言要**绑定到具体字段的结构**，不要做全局子串搜索。

## 同类陷阱：`prop_assert!` 会把表达式当格式串

`proptest` 的 `prop_assert!` 与 `assert!` 一样，**第一个参数是格式串**。它会先
把整个表达式字符串化再交给 `format!`，因此表达式里出现的花括号会被当成占位符：

```rust
// 编译失败：invalid format string: expected `}`, found `.`
prop_assert!(matches!(result, Err(MyError::Variant { .. })));
```

`matches!` 的模式匹配天然要写 `{ .. }`，两者正好冲突，而错误信息指向的是
「格式串」而不是「你不该在这里写 `matches!`」，很费时间。

写法是先把判定绑到一个 `bool`，让表达式里不含花括号：

```rust
let is_expected = matches!(result, Err(MyError::Variant { .. }));
prop_assert!(is_expected, "未拒绝非法输入");
```

## 断言失败有时是断言写错了

`vault_parse` 的同门属性测试（`tests/vault_proptest.rs`）第一次跑就报了两个失败，
但**其中只有一个是代码缺陷**：

- 「在任意位置截断文件，解析必须失败」——反例是「把空保险库截断到它自己的
  14 字节文件头」。那不是缺陷，是一个合法的空保险库。正确的性质是**截断不得让
  任何数据存活**（解析成功时条目数与墓碑数都必须为 0）。
- 「任意条目集合往返后所有字段相同」——反例是 `issuer = Some("")`。这是真缺陷：
  存储格式把空串写成零长度节点、读回来归一为 `None`，于是条目有一个**往返不稳定**
  的状态。修法在唯一能构造 `Entry` 的入口把它归一掉，让非法状态无法存在。

写属性测试时要预期到「第一条性质可能是错的」：先问「如果这条性质不成立，会不会
其实是我描述错了」，再去看代码。
