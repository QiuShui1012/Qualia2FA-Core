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

//! 定长大端序读写游标。
//!
//! 只服务保险库文件格式。之所以自己写而不引入 `byteorder`/`nom`：整个需求
//! 就是「定长大端整数 + 有界切片」，十几行代码，而多一个依赖就多一份需要
//! 审计的攻击面——这个模块处理的是**攻击者可能构造的文件**。
//!
//! # 一切读取都必须是带边界的
//!
//! 这是本模块存在的核心理由。解析不可信输入时，最容易犯的错误是
//! `data[offset..offset + n]` 这类「先算再切」的写法——`offset + n` 会溢出
//! （release 构建下回绕成一个小值，于是切片悄悄取到错误的数据），或者越界
//! panic。本模块的所有读取都用 [`slice::get`]，越界返回 `None`，由调用方
//! 转成 [`crate::Error::VaultTruncated`]。
//!
//! fuzz 目标 `vault_parse` 专门盯这一点。

/// 读取游标。所有方法在数据不足时返回 `None`，**从不 panic**。
pub(crate) struct Reader<'a> {
    /// 剩余未读的数据。
    data: &'a [u8],
    /// 已消耗的字节数，只用于错误报告与测试断言。
    consumed: usize,
}

impl<'a> Reader<'a> {
    /// 在给定数据上创建游标。
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, consumed: 0 }
    }

    /// 已消耗的字节数。
    #[cfg(test)]
    pub(crate) const fn consumed(&self) -> usize {
        self.consumed
    }

    /// 剩余可读字节数。
    pub(crate) const fn remaining(&self) -> usize {
        self.data.len()
    }

    /// 是否已读完。
    pub(crate) const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// 读取固定长度的字节切片。
    pub(crate) fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let head = self.data.get(..len)?;
        self.data = self.data.get(len..)?;
        self.consumed += len;
        Some(head)
    }

    /// 读取一个字节。
    pub(crate) fn u8(&mut self) -> Option<u8> {
        Some(*self.take(1)?.first()?)
    }

    /// 读取一个大端 `u32`。
    pub(crate) fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }

    /// 读取 16 字节的条目标识。
    pub(crate) fn entry_id(&mut self) -> Option<super::entry::EntryId> {
        let bytes = self.take(super::entry::EntryId::LEN)?;
        Some(super::entry::EntryId::from_bytes(bytes.try_into().ok()?))
    }

    /// 读取 24 字节的 nonce。
    pub(crate) fn nonce(&mut self) -> Option<super::crypto::Nonce> {
        let bytes = self.take(super::crypto::NONCE_LEN)?;
        bytes.try_into().ok()
    }
}

/// 把一个大端 `u32` 追加到缓冲区。
pub(crate) fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// 把一段带长度前缀的字节追加到缓冲区。
///
/// # Panics
///
/// 若 `bytes` 长度超过 `u32::MAX` 则 panic。这在实践中不可达——所有可变长
/// 字段在进入本函数前都已按
/// [`crate::vault::Entry::MAX_FIELD_LEN`] 校验过，
/// 而记录本身也受 [`crate::vault::MAX_RECORD_LEN`] 约束。
pub(crate) fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "调用方已保证长度不超过 u32::MAX；下面有断言兜底"
    )]
    let len = bytes.len() as u32;
    assert!(
        bytes.len() <= u32::MAX as usize,
        "字段长度超出 u32 表示范围"
    );
    put_u32(out, len);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 本模块只读固定宽度整数，`u64` 由调用方用 `to_be_bytes` 直接写——因此
    /// 这个辅助函数只服务于测试。
    fn put_u64(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    #[test]
    fn reader_reads_sequential_values() {
        let mut buf = Vec::new();
        put_u32(&mut buf, 0xDEAD_BEEF);
        put_u64(&mut buf, 0x0123_4567_89AB_CDEF);
        buf.push(0x7F);
        put_bytes(&mut buf, b"hi");

        let mut r = Reader::new(&buf);
        assert_eq!(r.u32(), Some(0xDEAD_BEEF));
        assert_eq!(
            r.take(8),
            Some(&0x0123_4567_89AB_CDEF_u64.to_be_bytes()[..])
        );
        assert_eq!(r.u8(), Some(0x7F));
        assert_eq!(r.u32(), Some(2));
        assert_eq!(r.take(2), Some(&b"hi"[..]));
        assert!(r.is_empty());
        assert_eq!(r.consumed(), buf.len());
    }

    /// **核心性质**：任何读取都不得 panic，且读不到就返回 `None`。
    #[test]
    fn reader_never_panics_on_short_input() {
        // 对每一种长度都试一遍，覆盖「差一字节」的边界。
        for len in 0..40_usize {
            let data = vec![0xAB_u8; len];
            let mut r = Reader::new(&data);
            // 依次尝试各种读取，只要不 panic 即可；成功与否不作断言。
            let _ = r.u32();
            let _ = r.take(8);
            let _ = r.entry_id();
            let _ = r.nonce();
            let _ = r.take(usize::MAX);
            let _ = r.take(1000);
            let _ = r.u8();
        }
    }

    /// 超长长度前缀不得导致越界或巨大分配。
    #[test]
    fn huge_length_prefix_does_not_allocate() {
        let mut buf = Vec::new();
        put_u32(&mut buf, u32::MAX); // 声称后面有 4 GiB
        buf.extend_from_slice(b"short");

        let mut r = Reader::new(&buf);
        let claimed = r.u32().expect("长度前缀可读");
        assert_eq!(claimed, u32::MAX);
        // 真正读取时会因数据不足而失败，而不是尝试分配 4 GiB。
        assert_eq!(r.take(claimed as usize), None);
    }

    #[test]
    fn put_bytes_roundtrips_via_reader() {
        for payload in [&b""[..], b"a", b"hello world"] {
            let mut buf = Vec::new();
            put_bytes(&mut buf, payload);
            let mut r = Reader::new(&buf);
            let len = r.u32().expect("长度可读");
            assert_eq!(len as usize, payload.len());
            assert_eq!(r.take(len as usize), Some(payload));
            assert!(r.is_empty());
        }
    }

    #[test]
    fn entry_id_and_nonce_roundtrip() {
        let id = super::super::entry::EntryId::from_bytes([0x5A; 16]);
        let nonce = [0x3C; super::super::crypto::NONCE_LEN];

        let mut buf = Vec::new();
        buf.extend_from_slice(id.as_bytes());
        buf.extend_from_slice(&nonce);

        let mut r = Reader::new(&buf);
        assert_eq!(r.entry_id(), Some(id));
        assert_eq!(r.nonce(), Some(nonce));
        assert!(r.is_empty());
    }
}
