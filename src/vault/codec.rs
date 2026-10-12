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

//! Fixed-width big-endian read/write cursor.
//!
//! Serves only the vault file format: fixed-width big-endian integers and bounded
//! slices, with no dependencies outside `core`. The bytes it parses may have been
//! constructed by an attacker.
//!
//! # Every read is bounds-checked
//!
//! `data[offset..offset + n]` is the classic mistake when parsing untrusted input:
//! `offset + n` overflows (wrapping to a small value in release builds, so the slice
//! silently yields the wrong bytes) or panics out of range. Every read here goes
//! through [`slice::get`]; data that runs short returns `None`, which the caller turns
//! into [`crate::Error::VaultTruncated`].
//!
//! The `vault_parse` fuzz target exercises this module.

/// Read cursor. Every method returns `None` when the data runs short and **never
/// panics**.
pub(crate) struct Reader<'a> {
    /// Bytes not yet read.
    data: &'a [u8],
    /// Bytes consumed so far; used only for error reporting and test assertions.
    consumed: usize,
}

impl<'a> Reader<'a> {
    /// Creates a cursor over the given data.
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, consumed: 0 }
    }

    /// Bytes consumed so far.
    #[cfg(test)]
    pub(crate) const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Bytes still readable.
    pub(crate) const fn remaining(&self) -> usize {
        self.data.len()
    }

    /// Whether everything has been read.
    pub(crate) const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Reads a fixed-length byte slice.
    pub(crate) fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let head = self.data.get(..len)?;
        self.data = self.data.get(len..)?;
        self.consumed += len;
        Some(head)
    }

    /// Reads one byte.
    pub(crate) fn u8(&mut self) -> Option<u8> {
        Some(*self.take(1)?.first()?)
    }

    /// Reads a big-endian `u32`.
    pub(crate) fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }

    /// Reads a 16-byte entry identifier.
    pub(crate) fn entry_id(&mut self) -> Option<super::entry::EntryId> {
        let bytes = self.take(super::entry::EntryId::LEN)?;
        Some(super::entry::EntryId::from_bytes(bytes.try_into().ok()?))
    }

    /// Reads a 24-byte nonce.
    pub(crate) fn nonce(&mut self) -> Option<super::crypto::Nonce> {
        let bytes = self.take(super::crypto::NONCE_LEN)?;
        bytes.try_into().ok()
    }
}

/// Appends a big-endian `u32` to the buffer.
pub(crate) fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Appends length-prefixed bytes to the buffer.
///
/// # Panics
///
/// Panics when `bytes` is longer than `u32::MAX`. Unreachable in practice: every
/// variable-length field is checked against
/// [`crate::vault::Entry::MAX_FIELD_LEN`] before it reaches this function, and a record
/// is bounded by [`crate::vault::MAX_RECORD_LEN`].
pub(crate) fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the caller guarantees the length fits in u32; an assertion below backs it up"
    )]
    let len = bytes.len() as u32;
    assert!(
        bytes.len() <= u32::MAX as usize,
        "field length exceeds the u32 range"
    );
    put_u32(out, len);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This module reads only fixed-width integers and callers write `u64` directly with
    /// `to_be_bytes`, so this helper serves tests only.
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

    /// **Core property**: no read may panic, and a read that cannot be satisfied returns
    /// `None`.
    #[test]
    fn reader_never_panics_on_short_input() {
        for len in 0..40_usize {
            let data = vec![0xAB_u8; len];
            let mut r = Reader::new(&data);
            let _ = r.u32();
            let _ = r.take(8);
            let _ = r.entry_id();
            let _ = r.nonce();
            let _ = r.take(usize::MAX);
            let _ = r.take(1000);
            let _ = r.u8();
        }
    }

    /// An oversized length prefix must not cause an out-of-range read or a huge
    /// allocation.
    #[test]
    fn huge_length_prefix_does_not_allocate() {
        let mut buf = Vec::new();
        put_u32(&mut buf, u32::MAX);
        buf.extend_from_slice(b"short");

        let mut r = Reader::new(&buf);
        let claimed = r.u32().expect("length prefix readable");
        assert_eq!(claimed, u32::MAX);
        assert_eq!(r.take(claimed as usize), None);
    }

    #[test]
    fn put_bytes_roundtrips_via_reader() {
        for payload in [&b""[..], b"a", b"hello world"] {
            let mut buf = Vec::new();
            put_bytes(&mut buf, payload);
            let mut r = Reader::new(&buf);
            let len = r.u32().expect("length readable");
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
