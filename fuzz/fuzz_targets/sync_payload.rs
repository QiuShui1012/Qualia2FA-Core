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

//! Fuzz target: parsing of the sync payload.
//!
//! # Input surface
//!
//! A vault file arrives through a channel the user chose; a sync payload can be sent
//! by **any device on the local network**. The attacker needs no action from the
//! user — sharing the same WiFi is enough to feed arbitrary bytes into the parser.
//! This input surface is therefore wider than the file path.
//!
//! # Two independent input paths
//!
//! 1. **The whole input as a payload** (mode 1). Covers the outer envelope: magic,
//!    version, `sync_id`, sender, length fields. A fixed key derived from the input
//!    is used, so the vast majority of inputs are rejected at the AEAD step — but
//!    that is exactly one of the paths to cover (authentication must be the end
//!    point of **every** malformed input, not a crash).
//! 2. **The whole input as a compressed stream** (mode 2). This is the main reason
//!    the target exists:
//!
//!    - Decompression is the one place an **attacker can amplify**: a deflate stream
//!      of a few hundred bytes can claim to decompress to 64 MiB. The limit check
//!      (`compress::MAX_DECOMPRESSED_LEN`) is the denial-of-service defense, and
//!      boundaries such as "the claimed length is exactly the limit" or "exactly one
//!      byte over the limit" are only hit by random input.
//!    - The plaintext parsing **after** decompression (record count plus each
//!      record's id / nonce / length / ciphertext) has a stretch of variable-length
//!      structure. Mode 1 does not reach it, because AEAD comes first.
//!
//!    `compress` is a public module, so this path can be covered in full.
//!
//! # Input-derived key
//!
//! For the same reason as in `vault_parse`: `MasterKey::generate()` differs every
//! time, and with it the target cannot open what it built itself. Being able to open
//! it is not actually needed here — mode 1 only requires no panic — but a derived
//! key makes the behavior **reproducible**, which is required to minimize a crashing
//! input into a regression seed.
//!
//! Preconditions: no feature flags, and no valid skeleton has to be built — the
//! target feeds arbitrary bytes to the envelope, and most of them stop at AEAD by
//! design.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia2fa_core::sync::{self, Payload};
use qualia2fa_core::vault::{self, MasterKey};

/// Derives a deterministic 32-byte master key from the input.
///
/// **This is not a key derivation function** — it only makes the fuzz target's
/// behavior reproducible, and it takes part in no real security decision.
fn master_from(data: &[u8]) -> MasterKey {
    let mut key = [0_u8; vault::MASTER_KEY_LEN];
    let take = data.len().min(vault::MASTER_KEY_LEN);
    key[..take].copy_from_slice(&data[..take]);
    MasterKey::from_bytes(key.to_vec().into()).expect("the length is always 32")
}

fuzz_target!(|data: &[u8]| {
    // ── Mode 1: the whole input as a payload ────────────────────────────────
    let master = master_from(data);
    match Payload::open(&master, data) {
        Ok(payload) => {
            if let Ok(again) = payload.seal(&master) {
                let Ok(reparsed) = Payload::open(&master, &again) else {
                    panic!("a payload sealed by this target must open again");
                };
                assert_eq!(
                    reparsed.len(),
                    payload.len(),
                    "the record count changed after the round trip"
                );
            }
            let _ = payload.open_records(&master);
        }
        Err(_) => {}
    }

    // ── Mode 2: the whole input as a compressed stream ──────────────────────
    if let Ok(plaintext) = sync::compress::decompress(data) {
        assert!(
            plaintext.len() <= sync::compress::MAX_DECOMPRESSED_LEN,
            "the decompressed result is {} bytes, over the claimed limit {}",
            plaintext.len(),
            sync::compress::MAX_DECOMPRESSED_LEN
        );
    }

    // ── Mode 3: round-trip of compression itself ────────────────────────────
    if let Ok(packed) = sync::compress::compress(data) {
        let back = sync::compress::decompress(&packed).expect("a stream this target compressed itself must decompress again");
        assert_eq!(back, data, "the compression round trip changed the content");
    }
});
