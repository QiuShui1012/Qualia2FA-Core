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

//! 同步载荷的压缩层。
//!
//! # 为什么压缩要在加密之前
//!
//! 密文与随机数无法压缩——先加密再压缩的产物**比明文还大**（认证标签与 nonce 都
//! 是随机的）。而同步载荷里有大量重复结构：每个条目的字段标签、算法与位数这两个
//! 枚举、以及数量不小的短字符串。在真实数据集上这一层的收益是数倍。
//!
//! # 它为什么是独立一层
//!
//! 换算法（或将来因为某个平台的实现问题要临时关掉压缩）应当只改这个文件。压缩
//! **不参与任何安全性质**——载荷的机密性与完整性全部由外层的 AEAD 负责，压缩只是
//! 把字节变短。因此这一层可以被整体替换、甚至被替换成恒等变换，而协议不受影响。
//!
//! # 与保险库文件的关系
//!
//! 互不相干。保险库文件**不压缩**：它要支持随机访问单条记录，而整体压缩会让
//! 「只改一条」变成「重写整个文件」。
//!
//! # 一个必须显式挡住的攻击面：解压炸弹
//!
//! 压缩后的载荷可以声称解出任意大的内容。输入来自对端，而同步是**未认证的对端
//! 也能发起**的（任何人都能广播自己的存在并尝试同步）。因此解压必须带上限，且
//! 上限要小于「能让我们 OOM」的量级。见 [`MAX_DECOMPRESSED_LEN`]。

use miniz_oxide::deflate::compress_to_vec;
use miniz_oxide::inflate::{TINFLStatus, decompress_to_vec_with_limit};

use crate::{Error, Result};

/// 解压后的载荷长度上限。
///
/// # 这个数字怎么来的
///
/// 单条记录的密文上限是 [`crate::vault::MAX_RECORD_LEN`]（1 MiB），记录数上限是
/// [`crate::vault::MAX_RECORDS`]（100 万）。两者相乘是 1 TiB——**不能**拿它当上限，
/// 那等于没有上限。真实数据集是「几百到几万条、每条几百字节」，即几 MiB 量级；
/// 留两个数量级余量之后取 64 MiB。
///
/// 64 MiB 的含义：一个恶意对端最多让我们分配 64 MiB，而且是在他必须先让我们接受
/// 外层 AEAD 之后。相比之下，一次 Argon2id 派生本来就要 64 MiB。
///
/// # 为什么是「解压后」而不是「解压前」
///
/// 解压**前**的长度由对端直接给出，限制它几乎没有意义（一个 1 KiB 的 deflate
/// 流就能解出 1 GiB）。真正的资源消耗发生在解压**后**，因此必须限制后者。
pub const MAX_DECOMPRESSED_LEN: usize = 64 * 1024 * 1024;

/// 压缩级别。
///
/// 6 是 zlib 的传统默认值，在压缩率与耗时之间取平衡。同步发生在用户按了一次按钮
/// 之后，因此可以偏向压缩率一些；但**不能**用 9：那一档在 deflate 上耗时可能翻倍
/// 而只多压几个百分点，而 M4 的验收标准是「30 秒内完成两次完整加解密 + 同步」，
/// 压缩比加密贵得多，没有理由把它花在最后那几个百分点上。
const LEVEL: u8 = 6;

/// 压缩一段载荷明文。
///
/// # 错误
///
/// [`Error::SyncCompressionFailed`]。实践中不会发生（deflate 对任意输入都有定义），
/// 但 `miniz_oxide` 的接口返回 `Result`，而我们不 `unwrap`。
pub fn compress(plaintext: &[u8]) -> Result<Vec<u8>> {
    Ok(compress_to_vec(plaintext, LEVEL))
}

/// 解压一段载荷明文。
///
/// # 错误
///
/// - [`Error::SyncPayloadTooLarge`]：解出的内容超过 [`MAX_DECOMPRESSED_LEN`]。
/// - [`Error::SyncDecompressionFailed`]：输入不是合法的 deflate 流（损坏、截断、
///   或长度对不上）。
/// - [`Error::SyncEmptyPayload`]：**输入为空**。空输入不是合法的 deflate 流，而
///   把它与前两者分开报是有用的：「根本没有载荷」与「载荷坏了」在排查时指向完全
///   不同的方向。
///
/// # 为什么「太大」必须与「坏了」分开报
///
/// 两者对**攻击者**的处置完全相同（都是拒绝），但对**合法用户**指向完全不同的
/// 方向。一个真有 7 万条目的用户会撞上上限，而那时告诉他「载荷损坏」会让他去查
/// 网络、查设备、重新配对——全都查不出问题。告诉他「太大了，请改用局域网」才是
/// 可操作的信息。
///
/// 代价是攻击者能用一个 bit 探出上限在哪。而这个上限**本来就写在开源代码里**，
/// 不值得为它牺牲一条真实的诊断路径。
///
/// 注意时间点：本函数跑在外层 AEAD **之后**，因此输入已经过认证。能走到这里的
/// 对端要么持有主密钥，要么是在外层认证上已经失败过的那一类——区分错误类型不会
/// 向未认证的一方泄露任何东西。
///
/// # 为什么不用流式解压（上游文档推荐的那个做法）
///
/// `miniz_oxide` 自己在 `decompress_to_vec_with_limit` 的文档里写着「*it's not ideal
/// for general use outside of tests*」，并建议改用 `flate2` 的流式解压。这里刻意
/// 不采纳，理由有两条，都记下来免得以后有人照文档「修」一遍：
///
/// 1. **`flate2` 的默认后端是 C 的 miniz/zlib**，与本库的 `#![forbid(unsafe_code)]`
///    相冲突；要用纯 Rust 后端就得显式打开 `rust_backend` feature，而那是一个谁
///    在后人的 `Cargo.toml` 里删一行就会被静默破坏的约定。
/// 2. **上游那段「不理想」针对的是内存，而上限已经把内存管住了。** 读一下它的实现
///    （`inflate/mod.rs` 的 `decompress_to_vec_inner`）可以看到输出缓冲始终
///    `min(输入长度 × 2, max_output_size)` 起步、按倍增长、**封顶在 `max_size`**，
///    溢出时返回的错误里只带 ≤ `max_size` 字节。也就是说最坏情况是我们**已经**
///    为之定价的那 64 MiB，不多一个字节。真正的流式解压能省下的是「合法载荷恰好
///    远小于 64 MiB 时那几次倍增长的内存峰值」，而那个峰值同样封顶在 64 MiB。
///
/// 换句话说：流式解压会换来一个 C 依赖或一条易碎的 feature 约定，来优化一个已经被
/// 上限压平的常数。不划算。
pub fn decompress(compressed: &[u8]) -> Result<Vec<u8>> {
    if compressed.is_empty() {
        return Err(Error::SyncEmptyPayload);
    }
    decompress_to_vec_with_limit(compressed, MAX_DECOMPRESSED_LEN).map_err(|error| {
        match error.status {
            // 这是唯一一个「不是攻击」的失败：真实数据集超过了上限。
            TINFLStatus::HasMoreOutput => Error::SyncPayloadTooLarge {
                limit: MAX_DECOMPRESSED_LEN,
            },
            // 其余全部归为一类。逐个区分（截断 / 校验和错 / 参数非法）对使用者没有可
            // 操作价值——它们都只能靠「换一份载荷重试」来解决。
            _ => Error::SyncDecompressionFailed,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_preserves_content() {
        for size in [0_usize, 1, 15, 4096, 100_000] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let packed = compress(&data).expect("可压缩");
            let back = decompress(&packed).expect("可解压");
            assert_eq!(back, data, "长度 {size} 的往返不一致");
        }
    }

    /// 真实载荷有大量重复，压缩必须真的变小。
    ///
    /// 「压缩函数返回了东西」不等于「它压小了」——一个恒等实现也能通过往返测试。
    #[test]
    fn repetitive_payload_actually_shrinks() {
        // 模拟一批条目：同样的字段标签与枚举反复出现。
        let mut data = Vec::new();
        for i in 0..500_u32 {
            data.extend_from_slice(b"\x01name\x02otpauth://totp/ACME:alice@example.com");
            data.extend_from_slice(&i.to_be_bytes());
        }
        let packed = compress(&data).expect("可压缩");
        assert!(
            packed.len() * 4 < data.len(),
            "压缩后 {} 字节，原 {} 字节——收益太差，压缩层可能没生效",
            packed.len(),
            data.len()
        );
    }

    /// 随机数据不可压缩，但必须仍能往返（不得报错、不得丢字节）。
    #[test]
    fn incompressible_payload_still_roundtrips() {
        let mut data = vec![0_u8; 8192];
        crate::getrandom::fill(&mut data).expect("OS 随机源可用");
        let packed = compress(&data).expect("可压缩");
        let back = decompress(&packed).expect("可解压");
        assert_eq!(back, data);
    }

    #[test]
    fn empty_input_is_reported_as_empty_not_corrupt() {
        // 「根本没有载荷」与「载荷坏了」要分开：排查时指向完全不同的方向。
        let err = decompress(&[]);
        assert!(matches!(err, Err(Error::SyncEmptyPayload)), "实际 {err:?}");
    }

    #[test]
    fn garbage_is_rejected() {
        for garbage in [
            vec![0xFF_u8; 64],
            vec![0x78, 0x9C],
            b"not deflate at all".to_vec(),
        ] {
            let err = decompress(&garbage);
            assert!(
                matches!(err, Err(Error::SyncDecompressionFailed)),
                "垃圾输入 {garbage:?} 未被拒绝，实际 {err:?}"
            );
        }
    }

    /// **解压炸弹必须被挡住。**
    ///
    /// 这个测试是关键的安全性质，不是性能测试：一个 64 MiB 的全零输入压成几百
    /// 字节，若解压不带上限，一个几百字节的载荷就能让我们分配任意大的内存。
    #[test]
    fn a_decompression_bomb_is_rejected() {
        // 全零可压到极限：64 MiB + 1 字节压出来只有几十 KiB。
        let bomb = vec![0_u8; MAX_DECOMPRESSED_LEN + 1];
        let packed = compress(&bomb).expect("可压缩");
        assert!(
            packed.len() < bomb.len() / 100,
            "前提不成立：炸弹没被压得足够小（压后 {} 字节）",
            packed.len()
        );

        let err = decompress(&packed);
        assert!(
            matches!(err, Err(Error::SyncPayloadTooLarge { .. })),
            "超过上限的解压未被拒绝，实际 {err:?}"
        );
    }

    /// 不可压缩的数据超过上限一字节时，同样必须被拒绝。
    ///
    /// # 为什么这条与上一条不能合并
    ///
    /// 上一条用的是全零，压缩比约 1000:1，因此 deftate 流内部会以很大的步长增长输出
    /// 缓冲。而随机数据只压得动一点点，于是缓冲会一路按倍增长到**恰好等于上限**，
    /// 在那里撞上 `HasMoreOutput`。两条路径在 `miniz_oxide` 内部走的是不同的分支
    /// （「缓冲太小」与「已经到顶了」），只有这一条能覆盖后者。
    #[test]
    fn incompressible_data_over_the_limit_is_rejected() {
        let mut data = vec![0_u8; MAX_DECOMPRESSED_LEN + 1];
        crate::getrandom::fill(&mut data).expect("OS 随机源可用");
        let packed = compress(&data).expect("可压缩");

        let err = decompress(&packed);
        assert!(
            matches!(err, Err(Error::SyncPayloadTooLarge { .. })),
            "随机数据超限未被拒绝，实际 {err:?}"
        );
    }

    /// **恰好**等于上限必须通过，否则上限就成了「比声称的小一字节」。
    ///
    /// 用随机数据而不是全零：全零的压缩比会让缓冲以很大的步长跳过去，恰好错过
    /// 「等于上限」那个边界。随机数据会一路增长到 `min(2^n, MAX)`，因此最后一步
    /// 必然落在**正好等于上限**上，这才是真正的边界。
    #[test]
    fn exactly_at_the_limit_is_accepted() {
        let mut data = vec![0_u8; MAX_DECOMPRESSED_LEN];
        crate::getrandom::fill(&mut data).expect("OS 随机源可用");
        let packed = compress(&data).expect("可压缩");
        let back = decompress(&packed).expect("恰好到上限应当通过");
        assert_eq!(back.len(), MAX_DECOMPRESSED_LEN);
        assert_eq!(back, data, "恰好到上限的内容应当逐字节一致");
    }

    /// 截断的 deflate 流必须被拒绝，不得解出半份数据。
    #[test]
    fn truncated_stream_is_rejected() {
        let data = vec![3_u8; 4096];
        let packed = compress(&data).expect("可压缩");
        for cut in 1..packed.len().min(24) {
            let truncated = &packed[..packed.len() - cut];
            let result = decompress(truncated);
            if let Ok(partial) = result {
                panic!(
                    "截断 {cut} 字节后仍解出 {} 字节（原 {} 字节）",
                    partial.len(),
                    data.len()
                );
            }
        }
    }
}
