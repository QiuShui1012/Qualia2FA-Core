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

//! Compression layer for sync payloads.
//!
//! The payload is compressed **before** encryption: ciphertext and nonce are random and
//! cannot be compressed, so compressing after encryption produces output larger than the
//! plaintext. Sync payloads contain a lot of repeated structure — the field tags of every
//! entry, the algorithm and digit-count enums, and a good number of short strings — and on
//! a real dataset this layer shrinks the payload by a factor of several.
//!
//! Compression is a layer of its own so that changing the algorithm, or temporarily
//! disabling compression because of a platform's implementation problem, touches this file
//! only. It **carries no security property**: confidentiality and integrity of the payload
//! are entirely the responsibility of the outer AEAD, and compression only makes the bytes
//! shorter. The layer can therefore be replaced as a whole, or even replaced by the
//! identity transform, without affecting the protocol.
//!
//! The vault file is unrelated and is **not** compressed: it has to support random access
//! to a single record, and compressing it as a whole would turn "change one entry" into
//! "rewrite the whole file".
//!
//! # Decompression bombs
//!
//! A compressed payload can claim to decompress to arbitrarily large content, and the
//! input comes from a peer: sync can be started by an **unauthenticated** peer (anyone can
//! announce their existence and attempt to sync). Decompression therefore enforces the
//! limit [`MAX_DECOMPRESSED_LEN`], which is well below the amount that would let a peer
//! exhaust our memory.

use miniz_oxide::deflate::compress_to_vec;
use miniz_oxide::inflate::{TINFLStatus, decompress_to_vec_with_limit};

use crate::{Error, Result};

/// Maximum length of a decompressed payload, in bytes.
///
/// The ciphertext of a single record is capped at [`crate::vault::MAX_RECORD_LEN`]
/// (1 MiB) and the number of records at [`crate::vault::MAX_RECORDS`] (1 million). Their
/// product is 1 TiB, which is **not** a usable limit — it is no limit at all. A real
/// dataset is a few hundred to a few tens of thousands of entries of a few hundred bytes
/// each, i.e. of the order of a few MiB; leaving two orders of magnitude of headroom gives
/// 64 MiB.
///
/// 64 MiB means a malicious peer can make us allocate at most 64 MiB, and only after it
/// has first made us accept the outer AEAD. A single Argon2id derivation already costs
/// 64 MiB.
///
/// The bound applies to the length **after** decompression. The length **before**
/// decompression is stated by the peer directly and bounding it would be close to
/// meaningless (a 1 KiB deflate stream can decompress to 1 GiB); the actual resource
/// consumption happens after decompression, so that is the side that has to be bounded.
pub const MAX_DECOMPRESSED_LEN: usize = 64 * 1024 * 1024;

/// Compression level.
///
/// 6 is zlib's traditional default and balances compression ratio against time. Level 9
/// is **not** used: on deflate it can double the time for only a few extra percent of
/// ratio, and compression already costs far more than encryption.
const LEVEL: u8 = 6;

/// Compresses a payload plaintext.
///
/// # Errors
///
/// [`Error::SyncCompressionFailed`]. It cannot happen in practice (deflate is defined for
/// every input), but the `miniz_oxide` interface returns a `Result` and this crate does
/// not `unwrap`.
pub fn compress(plaintext: &[u8]) -> Result<Vec<u8>> {
    Ok(compress_to_vec(plaintext, LEVEL))
}

/// Decompresses a payload plaintext.
///
/// # Errors
///
/// - [`Error::SyncPayloadTooLarge`]: the decompressed content exceeds
///   [`MAX_DECOMPRESSED_LEN`].
/// - [`Error::SyncDecompressionFailed`]: the input is not a valid deflate stream
///   (corrupt, truncated, or a length mismatch).
/// - [`Error::SyncEmptyPayload`]: the input is **empty**. An empty input is not a valid
///   deflate stream, and reporting it separately is useful: "there is no payload at all"
///   and "the payload is broken" point in completely different directions when
///   diagnosing.
///
/// Of the statuses `miniz_oxide` reports, `HasMoreOutput` maps to "too large" and every
/// other status maps to "corrupt". The two are kept apart because a
/// [`Error::SyncPayloadTooLarge`] failure is a genuine dataset over the limit, while the
/// rest are indistinguishable to the caller and are all resolved the same way, by
/// retrying with another payload.
///
/// The distinction also tells a legitimate user whether the dataset is too large or the
/// payload is damaged — the latter would send them to inspect the network, the devices
/// and the pairing, none of which is at fault. It costs one bit to a peer probing for the
/// limit, and the limit is public anyway.
///
/// The function runs **after** the outer AEAD, on input that has already been
/// authenticated: a peer that reaches it either holds the master key or has already failed
/// outer authentication, so telling the error kinds apart leaks nothing to an
/// unauthenticated party. The output buffer is bounded by the limit inside `miniz_oxide`
/// as well, so the worst case is the 64 MiB the limit already accounts for; decompression
/// is not streaming, which would pull in `flate2`, whose default backend is C and
/// conflicts with this crate's `#![forbid(unsafe_code)]`.
pub fn decompress(compressed: &[u8]) -> Result<Vec<u8>> {
    if compressed.is_empty() {
        return Err(Error::SyncEmptyPayload);
    }
    decompress_to_vec_with_limit(compressed, MAX_DECOMPRESSED_LEN).map_err(|error| {
        match error.status {
            TINFLStatus::HasMoreOutput => Error::SyncPayloadTooLarge {
                limit: MAX_DECOMPRESSED_LEN,
            },
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
            let packed = compress(&data).expect("compression succeeds");
            let back = decompress(&packed).expect("decompression succeeds");
            assert_eq!(back, data, "round trip differs at length {size}");
        }
    }

    /// A real payload has a lot of repetition, so compression must actually shrink it.
    ///
    /// A compression function returning something does not mean it compressed: an identity
    /// implementation passes a roundtrip test too.
    #[test]
    fn repetitive_payload_actually_shrinks() {
        let mut data = Vec::new();
        for i in 0..500_u32 {
            data.extend_from_slice(b"\x01name\x02otpauth://totp/ACME:alice@example.com");
            data.extend_from_slice(&i.to_be_bytes());
        }
        let packed = compress(&data).expect("compression succeeds");
        assert!(
            packed.len() * 4 < data.len(),
            "compressed to {} bytes from {} bytes: gain too small, the compression layer may be inactive",
            packed.len(),
            data.len()
        );
    }

    /// Random data is incompressible but must still roundtrip: no error, no lost byte.
    #[test]
    fn incompressible_payload_still_roundtrips() {
        let mut data = vec![0_u8; 8192];
        crate::getrandom::fill(&mut data).expect("OS randomness available");
        let packed = compress(&data).expect("compression succeeds");
        let back = decompress(&packed).expect("decompression succeeds");
        assert_eq!(back, data);
    }

    #[test]
    fn empty_input_is_reported_as_empty_not_corrupt() {
        let err = decompress(&[]);
        assert!(
            matches!(err, Err(Error::SyncEmptyPayload)),
            "actual {err:?}"
        );
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
                "garbage input {garbage:?} was not rejected, actual {err:?}"
            );
        }
    }

    /// **A decompression bomb must be rejected.**
    ///
    /// This is a security property, not a performance test: a 64 MiB all-zero input
    /// compresses to a few hundred bytes, so without a limit on decompression a payload of
    /// a few hundred bytes would let a peer make us allocate arbitrarily large memory.
    #[test]
    fn a_decompression_bomb_is_rejected() {
        let bomb = vec![0_u8; MAX_DECOMPRESSED_LEN + 1];
        let packed = compress(&bomb).expect("compression succeeds");
        assert!(
            packed.len() < bomb.len() / 100,
            "precondition failed: the bomb did not compress small enough ({} bytes after compression)",
            packed.len()
        );

        let err = decompress(&packed);
        assert!(
            matches!(err, Err(Error::SyncPayloadTooLarge { .. })),
            "decompression past the limit was not rejected, actual {err:?}"
        );
    }

    /// Incompressible data one byte over the limit must be rejected as well.
    ///
    /// This case reaches a different `miniz_oxide` branch than the all-zero case above:
    /// all-zero data compresses about 1000:1, so the output buffer inside the deflate
    /// stream grows in large steps, whereas random data compresses only slightly and the
    /// buffer doubles all the way to exactly the limit, where it hits `HasMoreOutput`.
    /// The two paths take different branches inside `miniz_oxide` ("buffer too small"
    /// versus "already at the top"), and only this test covers the latter.
    #[test]
    fn incompressible_data_over_the_limit_is_rejected() {
        let mut data = vec![0_u8; MAX_DECOMPRESSED_LEN + 1];
        crate::getrandom::fill(&mut data).expect("OS randomness available");
        let packed = compress(&data).expect("compression succeeds");

        let err = decompress(&packed);
        assert!(
            matches!(err, Err(Error::SyncPayloadTooLarge { .. })),
            "random data past the limit was not rejected, actual {err:?}"
        );
    }

    /// **Exactly** at the limit must be accepted, otherwise the limit would be one byte
    /// smaller than it claims to be.
    ///
    /// Random data rather than all zeros: the ratio of all zeros makes the buffer jump in
    /// large steps and skip over the "equal to the limit" boundary. Random data grows to
    /// `min(2^n, MAX)`, so the last step necessarily lands on exactly the limit, which is
    /// the real boundary.
    #[test]
    fn exactly_at_the_limit_is_accepted() {
        let mut data = vec![0_u8; MAX_DECOMPRESSED_LEN];
        crate::getrandom::fill(&mut data).expect("OS randomness available");
        let packed = compress(&data).expect("compression succeeds");
        let back = decompress(&packed).expect("exactly at the limit must pass");
        assert_eq!(back.len(), MAX_DECOMPRESSED_LEN);
        assert_eq!(
            back, data,
            "content exactly at the limit must be byte-identical"
        );
    }

    /// A truncated deflate stream must be rejected and never partially decompressed.
    #[test]
    fn truncated_stream_is_rejected() {
        let data = vec![3_u8; 4096];
        let packed = compress(&data).expect("compression succeeds");
        for cut in 1..packed.len().min(24) {
            let truncated = &packed[..packed.len() - cut];
            let result = decompress(truncated);
            if let Ok(partial) = result {
                panic!(
                    "truncating {cut} bytes still decompressed to {} bytes (originally {} bytes)",
                    partial.len(),
                    data.len()
                );
            }
        }
    }
}
