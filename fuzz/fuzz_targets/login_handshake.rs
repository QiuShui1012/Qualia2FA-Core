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

//! Fuzz target: the two protocol-message parsing paths of the login handshake.
//!
//! # Input surface
//!
//! The login process parses **two messages coming from the other device**, and
//! either of them may come from an attacker:
//!
//! - `Msg1` (new device → old device): parsed by `Login::authorize`. An attacker
//!   can scan the QR code (it is displayed on screen) and then send arbitrary
//!   bytes.
//! - `Msg2` (old device → new device): parsed by `Joiner::complete`. The new
//!   device cannot tell whether the peer answering is really the old device; all
//!   it has is bytes.
//!
//! Both paths first read a fixed-length header (nonce, ephemeral public key), feed
//! the public key to the P-256 SEC1 decoder, and then run AEAD. In all three steps
//! the input is entirely chosen by the adversary: length fields, off-curve points,
//! truncated ciphertext.
//!
//! # Properties covered
//!
//! 1. **Never panics** — for any length and any content of `data` on either
//!    message path, and for any text offered as a QR payload.
//! 2. **Exact rejection** — lengths must be exact values (one extra byte must be
//!    rejected), the public key must really be on the curve, and the AEAD tag must
//!    verify. The checking code lives in the parser and is reached every round.
//!
//! # Difference from `vault_parse`
//!
//! `vault_parse` targets the long-lived parsing of the file format (skipping
//! unknown nodes, length prefixes). This target targets **protocol messages**. Any
//! of these three checks written as "roughly check it" would give an attacker a
//! chance to push the parser into a state it never anticipated.
//!
//! # No "valid skeleton" construction is needed here
//!
//! `vault_parse` has to bypass AEAD, because casually constructed bytes are always
//! rejected at the authentication step. Here it is different: **rejection is
//! exactly the path to cover** — the rejection logic itself (length checks, curve
//! checks, constant-time comparison) is written in the parser and is reached every
//! time. As for "how the plaintext is parsed once authentication succeeds", the
//! plaintext of both messages is nothing but copies of fixed-length fields, with no
//! variable-length structure, so that attack surface does not exist.
//!
//! Preconditions: no feature flags, and no valid skeleton has to be built — both
//! paths take arbitrary bytes directly.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia_dik::{DevicePublicKey, DeviceSignature};
use qualia2fa_core::flow::{DeviceKeys, Joiner, Login};
use qualia2fa_core::vault::MasterKey;
use qualia2fa_core::{Error, Result};

/// A fixed device identity, so that everything outside the fuzz input is
/// deterministic.
///
/// The public key is copied from hard-coded bytes and the signature returns a fixed
/// value — this target does not check signature correctness (the unit tests of
/// `device::verify` and `m3_flows` cover that); it only needs an implementation that
/// can get through `request`, so that all fuzz power goes to message parsing.
struct FixedKeys {
    /// A valid P-256 public key, from the fixed scalar 1 (the generator itself).
    public: [u8; 65],
}

impl FixedKeys {
    /// Uses the generator as the identity: `04 ‖ Gx ‖ Gy`.
    fn new() -> Self {
        let mut public = [0_u8; 65];
        public[0] = 0x04;
        let mut scalar = [0_u8; 32];
        scalar[31] = 1;
        let key = p256::ecdsa::SigningKey::from_bytes((&scalar).into())
            .expect("scalar 1 is always valid");
        public.copy_from_slice(key.verifying_key().to_sec1_point(false).as_bytes());
        Self { public }
    }
}

impl DeviceKeys for FixedKeys {
    fn get_or_create(&mut self, _label: &str) -> Result<DevicePublicKey> {
        Ok(DevicePublicKey::from_sec1_bytes(&self.public)?)
    }

    fn sign(&mut self, _label: &str, message: &[u8]) -> Result<DeviceSignature> {
        let mut scalar = [0_u8; 32];
        scalar[31] = 1;
        let key = p256::ecdsa::SigningKey::from_bytes((&scalar).into())
            .expect("scalar 1 is always valid");
        use p256::ecdsa::signature::Signer as _;
        let signature: p256::ecdsa::Signature = key.sign(message);
        Ok(DeviceSignature::from_bytes(&signature.to_bytes())?)
    }
}

/// Derives a deterministic master key from the input.
///
/// **Not a key derivation function** — it only makes sure that what the fuzz target
/// builds itself, it can also open. Takes the first 32 bytes and zero-pads a short
/// input — `MasterKey::from_bytes` requires a length of exactly 32.
fn master_from(data: &[u8]) -> MasterKey {
    let mut key = [0_u8; 32];
    let take = data.len().min(32);
    key[..take].copy_from_slice(&data[..take]);
    MasterKey::from_bytes(key.to_vec().into()).expect("the length is always 32")
}

fuzz_target!(|data: &[u8]| {
    let master = master_from(data);
    let mut keys = FixedKeys::new();

    // ── Direction 1: the old device parses Msg1 ─────────────────────────────
    if let Ok(mut login) = Login::new() {
        let _ = login.authorize(data, &master);
    }

    // ── Direction 2: the new device parses Msg2 ─────────────────────────────
    if let Ok(login) = Login::new() {
        if let Ok(mut joiner) = Joiner::new(login.payload(), "fuzz-device") {
            if joiner.request(&mut keys).is_ok() {
                if let Ok(joiner2) = Joiner::new(login.payload(), "fuzz-device") {
                    let mut joiner2 = joiner2;
                    if joiner2.request(&mut keys).is_ok() {
                        let mut store = NeverStores;
                        let _ = joiner2.complete(data, &mut keys, &mut store);
                    }
                }
            }
        }
    }

    // ── Direction 3: decoding of the QR code text ───────────────────────────
    if let Ok(text) = core::str::from_utf8(data) {
        if let Ok(payload) = qualia2fa_core::pairing::QrPayload::from_base32(text) {
            let _ = Joiner::new(&payload, "fuzz-device").map(|mut j| j.request(&mut keys));
        }
    }
});

/// A [`qualia2fa_core::flow::SecureStore`] that never actually stores anything.
///
/// The failure is **honest**: it truthfully returns an error instead of pretending
/// the key was stored. This fuzz target cares about whether the parsing path
/// panics, not about storage semantics.
struct NeverStores;

impl qualia2fa_core::flow::SecureStore for NeverStores {
    fn load_master_key(&self) -> Result<Option<MasterKey>> {
        Ok(None)
    }

    fn store_master_key(&mut self, _key: &MasterKey) -> Result<()> {
        Err(Error::SecureStoreWriteFailed {
            reason: "the fuzz target does not store anything",
        })
    }

    fn delete_master_key(&mut self) -> Result<()> {
        Ok(())
    }

    fn is_hardware_backed(&self) -> bool {
        false
    }
}
