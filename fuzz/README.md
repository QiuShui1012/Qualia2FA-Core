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

`corpus/`、`artifacts/`、`coverage/` 均不入库（见 `.gitignore`）。

## 现有目标

| 目标 | 覆盖的输入面 | 检查的性质 |
|---|---|---|
| `secret_debug_redaction` | `SecretBytes`（秘密处理路径） | 不 panic、`new`→`expose` 透明、`Debug` 不泄露明文（十进制与十六进制两种表示） |

## 待补（M1）

`otpauth://` URI 解析器与 Base32 解码是**真正攻击者可控**的输入面，实现后必须
补上对应目标：

- `uri_parse`：任意字节串喂给 URI 解析器，不得 panic。
- `base32_decode`：任意字节串喂给 Base32 解码器，不得 panic、不得越界。

在此之前，`secret_debug_redaction` 是秘密处理路径唯一的自动化防线，不要删除。
