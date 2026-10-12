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

//! Challenge-response: prove possession of the master key without handing it over.
//!
//! # What it does
//!
//! [`crate::pairing`] covers handing the master key to a new device. Two devices that are
//! **already paired** then communicate repeatedly (the sync layer does), and re-scanning a
//! QR code every time is not acceptable, while sending the master key itself is worse —
//! that would put it on the wire.
//!
//! Holding the master key is itself a credential, provided possession can be proven without
//! revealing it. This module implements that proof as a standard challenge-response
//! exchange.
//!
//! # Division of labour with the pairing protocol
//!
//! | | Pairing ([`crate::pairing`]) | Challenge-response (this module) |
//! |---|---|---|
//! | Precondition | the two sides share **no** secret | the two sides **already** share the master key |
//! | Goal | establish a shared secret | confirm the other side still holds it |
//! | Sends the master key | yes, encrypted | **no** |
//! | Man-in-the-middle resistance | out-of-band authentication through the QR code | **not provided** (see below) |
//!
//! ## This module does not resist man in the middle, deliberately
//!
//! Whether a man in the middle can impersonate a peer depends on passing the response. An
//! attacker without the master key cannot compute the tag, so impersonation fails. An
//! **active** man in the middle can still **forward** the two sides' messages and make both
//! believe they are talking to each other; that is a limitation shared by every protocol
//! that is not channel-bound.
//!
//! This layer is deliberately **transport-agnostic**, so it does not solve that problem
//! itself. A caller that needs man-in-the-middle resistance should **bind** this layer's
//! session identifier to the peer identity of the transport and verify the pair:
//! [`Verified::session_id`] and [`Responder::session_id`] exist to provide an anchor that
//! both sides agree on and that is determined by both sides' inputs.
//!
//! A **responder** (`Responder`) that does not know who the presented ephemeral public key
//! belongs to can likewise be led by a man in the middle: the verifier side only obtains the
//! session identifier after [`Verifier::verify`] succeeds, so a caller should check that
//! identifier against the transport once authentication completes, before exchanging any
//! data.
//!
//! # Protocol
//!
//! ```text
//!   A (verifier)                            B (responder)
//!       │                                          │
//!       │ ① generate an ephemeral key pair (a, A_pub) and a random nonce_A
//!       │ ────── challenge = { A_pub, nonce_A } ─► │
//!       │                                          │ ② S = ECDH(b, A_pub)
//!       │                                          │    derive K_proof from the master key
//!       │                                          │    tag = HMAC(K_proof, sid)
//!       │ ◄── response = { B_pub, nonce_B, device ─ │    sid = H(A_pub‖n_A‖B_pub‖n_B)
//!       │       public key, tag, signature } ───── │
//!       │ ③ recompute the tag and compare          │
//!       │    verify the device signature           │
//!       │ ────── confirm = HMAC(K_confirm, sid) ─► │ ④ check the confirmation
//!       │                                          │
//! ```
//!
//! `sid` contains **both** sides' ephemeral public keys and nonces, and the ECDH shared
//! secret takes part in the derivation as the HKDF salt. The tag's key comes from the
//! **master key** (the only source of "proves possession of it"), while its input has to
//! contain something **only A and B can compute**, so A feeds the nonce its peer claims into
//! its own transcript, not only its own. Therefore:
//!
//! - the attacker changes any field → the two sides compute different `sid`s → the tag does not match.
//! - the attacker replays a whole response into a new session → the new `A_pub`/`nonce_A` make `sid` differ → no match.
//! - the attacker has no master key → it cannot compute the tag.
//!
//! The tag proves "the peer holds the master key", and **any** device holding the master key
//! can compute it. A caller that needs to know "which device is answering" adds a device
//! identity signature (ECDSA P-256, see [`qualia_dik::device`]). The two prove different
//! things, so both are present:
//!
//! - tag → "you do hold the master key" (**unforgeable**, even if the attacker controls the channel)
//! - signature → "you are device X" (forgeable by whoever holds X's private key, which is the definition of X)
//!
//! The signature covers `sid` and both sides' public values, so one device's signature
//! **cannot** be transplanted into another session.
//!
//! # Replay protection
//!
//! Three layers, all required:
//!
//! 1. **Input**: `sid` is determined by both sides' ephemeral public keys and nonces, and
//!    differs for every session.
//! 2. **Session**: [`Verifier::verify`] takes `self`, so the type system guarantees one
//!    challenge cannot be verified twice.
//! 3. **Across restarts**: a caller can record used `sid`s in [`crate::pairing::NonceLog`]
//!    and keep recognising "this session was already handled" after a process restart.

use crate::pairing::{CONFIRMATION_LEN, NONCE_LEN, PUBLIC_KEY_LEN, SESSION_ID_LEN};
use crate::vault::MasterKey;
use crate::{Error, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::Generate;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use qualia_dik::{DevicePublicKey, DeviceSignature};
use secrecy::zeroize::Zeroize;
use sha2::{Digest, Sha256};

/// Byte length of the challenge: `A_pub ‖ nonce_A`.
pub const CHALLENGE_LEN: usize = PUBLIC_KEY_LEN + NONCE_LEN;

/// Byte length of the response **without its signature**: `B_pub ‖ nonce_B ‖ device public key ‖ tag`.
pub const RESPONSE_LEN: usize = PUBLIC_KEY_LEN + NONCE_LEN + PUBLIC_KEY_LEN + CONFIRMATION_LEN;

/// Full byte length of the response, including the device signature.
pub const RESPONSE_SIGNED_LEN: usize = RESPONSE_LEN + qualia_dik::device::SIGNATURE_LEN;

/// Byte length of the confirmation tag.
pub const CONFIRM_LEN: usize = CONFIRMATION_LEN;

/// Domain-separation string for the proof key derived from the master key.
const HKDF_INFO_PROOF: &[u8] = b"Qualia2FA auth v1 proof key";

/// Domain-separation string for the confirmation key derived from the master key.
const HKDF_INFO_CONFIRM: &[u8] = b"Qualia2FA auth v1 confirm key";

/// Domain-separation string for the proof tag.
const PROOF_LABEL: &[u8] = b"Qualia2FA auth v1 proof";

/// Domain-separation string for the confirmation tag.
const CONFIRM_LABEL: &[u8] = b"Qualia2FA auth v1 confirm";

/// Domain-separation string for the session identifier.
const SESSION_LABEL: &[u8] = b"Qualia2FA auth v1 session";

/// Domain-separation string for the message covered by the device signature.
const SIGNATURE_LABEL: &[u8] = b"Qualia2FA auth v1 device signature";

/// Verifier A: has sent a challenge and awaits the response.
///
/// # Single use
///
/// [`Verifier::verify`] takes `self`, so one challenge cannot be verified twice. That
/// constraint is enforced by the type system, which rules out replaying a response at the
/// session level: there is no session left to pass it to.
///
/// The ephemeral private key is erased on `Drop` by `p256` (`EphemeralSecret` implements
/// `ZeroizeOnDrop`).
pub struct Verifier {
    /// This side's ephemeral private key.
    secret: EphemeralSecret,
    /// The nonce generated by this side.
    nonce: [u8; NONCE_LEN],
    /// SEC1 encoding of this side's ephemeral public key.
    public_key: [u8; PUBLIC_KEY_LEN],
}

impl Verifier {
    /// The challenge bytes to send to the responder.
    #[must_use]
    pub fn challenge(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHALLENGE_LEN);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.nonce);
        out
    }

    /// This side's (the verifier's) ephemeral public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// This side's nonce.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// Verify the response and produce the confirmation tag to send back.
    ///
    /// # Parameters
    ///
    /// - `response`: the responder's full response, signature included.
    /// - `master`: the master key held by this side. It is used **only** to recompute the
    ///   tag and never appears in any output.
    ///
    /// # Returns
    ///
    /// [`Verified`]: the peer's device identity, the session identifier, and the
    /// confirmation tag to send back.
    ///
    /// # Errors
    ///
    /// - wrong length, or a public key that is not a valid curve point:
    ///   [`Error::AuthMessageMalformed`]
    /// - **tag mismatch** (the peer has no master key): [`Error::AuthProofFailed`]
    /// - **device signature does not verify**: [`Error::DeviceSignatureInvalid`]
    ///
    /// The checks run in this order: response length and SEC1 decoding of both public keys,
    /// then the tag, then the device signature. The device public key is validated because it
    /// is handed to the caller as the answer to "who is the peer".
    ///
    /// The last two errors are **deliberately distinct**: a tag failure means "the peer has
    /// no master key", a signature failure means "the peer has the master key but is not the
    /// device it claims to be". The two mean very different things to a user (the first is
    /// dangerous, the second usually just means the device identity changed), and neither
    /// involves secret values — a failure tells an attacker only what it already knew.
    pub fn verify(self, response: &[u8], master: &MasterKey) -> Result<Verified> {
        if response.len() != RESPONSE_SIGNED_LEN {
            return Err(Error::AuthMessageMalformed {
                reason: "应答长度不对",
            });
        }
        let body = &response[..RESPONSE_LEN];
        let mut responder_public = [0_u8; PUBLIC_KEY_LEN];
        responder_public.copy_from_slice(&body[..PUBLIC_KEY_LEN]);
        let mut responder_nonce = [0_u8; NONCE_LEN];
        responder_nonce.copy_from_slice(&body[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + NONCE_LEN]);
        let mut device_public = [0_u8; PUBLIC_KEY_LEN];
        device_public.copy_from_slice(
            &body[PUBLIC_KEY_LEN + NONCE_LEN..PUBLIC_KEY_LEN + NONCE_LEN + PUBLIC_KEY_LEN],
        );
        let mut tag = [0_u8; CONFIRMATION_LEN];
        tag.copy_from_slice(&body[PUBLIC_KEY_LEN + NONCE_LEN + PUBLIC_KEY_LEN..]);

        let responder_public = PublicKey::from_sec1_bytes(&responder_public).map_err(|_| {
            Error::AuthMessageMalformed {
                reason: "应答里的临时公钥不是合法的 P-256 SEC1 点",
            }
        })?;
        let device_key = DevicePublicKey::from_sec1_bytes(&device_public).map_err(|_| {
            Error::AuthMessageMalformed {
                reason: "应答里的设备公钥不是合法的 P-256 SEC1 点",
            }
        })?;

        let session_id = session_id_of(
            &self.public_key,
            &self.nonce,
            &body[..PUBLIC_KEY_LEN],
            &responder_nonce,
        );
        let shared = self.secret.diffie_hellman(&responder_public);
        let keys = AuthKeys::derive(master, shared.raw_secret_bytes(), &session_id);

        if !constant_time_eq(&tag, &proof_tag(&keys.proof, &session_id)) {
            return Err(Error::AuthProofFailed);
        }

        let message = signature_message(
            &session_id,
            &self.public_key,
            &self.nonce,
            &body[..PUBLIC_KEY_LEN],
            &responder_nonce,
            &tag,
        );
        qualia_dik::device::verify(
            &device_key,
            &message,
            &signature_of(&response[RESPONSE_LEN..])?,
        )?;

        Ok(Verified {
            session_id,
            device_key,
            device_public,
            confirm: keys.confirm,
        })
    }
}

impl core::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Verifier")
            .field("public_key", &"<65 bytes>")
            .field("nonce", &"<redacted>")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The result of [`Verifier::verify`].
pub struct Verified {
    /// Identifier of this session (both sides agree on it).
    session_id: [u8; SESSION_ID_LEN],
    /// The peer's device identity public key (strongly typed).
    device_key: DevicePublicKey,
    /// The peer's device identity public key (raw SEC1 bytes, for the caller to interpret or store).
    device_public: [u8; PUBLIC_KEY_LEN],
    /// The derived confirmation key.
    confirm: [u8; 32],
}

impl Verified {
    /// Session identifier.
    ///
    /// A caller should bind-verify it against the peer identity of the transport, otherwise a
    /// man in the middle can forward messages (see the "does not resist man in the middle"
    /// section of the module documentation).
    #[must_use]
    pub const fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// The peer's device identity public key.
    #[must_use]
    pub const fn device_key(&self) -> &DevicePublicKey {
        &self.device_key
    }

    /// SEC1 encoding of the peer's device identity public key.
    #[must_use]
    pub const fn device_public(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.device_public
    }

    /// The confirmation tag to send back to the responder.
    ///
    /// It lets the responder confirm that the other side really holds the master key.
    /// **One-way authentication is not enough**: if only the responder were verified, an
    /// attacker could impersonate the verifier and solicit one successful response. It would
    /// not obtain the master key, but the responder would believe it was talking to a
    /// legitimate device and go on to exchange data.
    #[must_use]
    pub fn confirmation(&self) -> [u8; CONFIRM_LEN] {
        confirm_tag(&self.confirm, &self.session_id)
    }
}

impl core::fmt::Debug for Verified {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Verified")
            .field("session_id", &&self.session_id[..8])
            .field("device_id", &self.device_key.device_id())
            .field("confirm", &"<redacted>")
            .finish()
    }
}

/// Responder B: has received the challenge.
pub struct Responder {
    /// This side's ephemeral private key.
    secret: EphemeralSecret,
    /// SEC1 encoding of this side's ephemeral public key.
    public_key: [u8; PUBLIC_KEY_LEN],
    /// This side's nonce.
    nonce: [u8; NONCE_LEN],
    /// The verifier's ephemeral public key.
    verifier_public: [u8; PUBLIC_KEY_LEN],
    /// The verifier's nonce.
    verifier_nonce: [u8; NONCE_LEN],
}

impl Responder {
    /// Session identifier.
    #[must_use]
    pub fn session_id(&self) -> [u8; SESSION_ID_LEN] {
        session_id_of(
            &self.verifier_public,
            &self.verifier_nonce,
            &self.public_key,
            &self.nonce,
        )
    }

    /// SEC1 encoding of this side's ephemeral public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// This side's nonce. Not a secret, but **unique**.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// Produce the response.
    ///
    /// # Parameters
    ///
    /// - `master`: the master key held by this side. It **never appears in the response** —
    ///   it only derives the tag.
    /// - `device_public`: SEC1 encoding of this side's device identity public key.
    /// - `sign`: callback that signs the **raw message** with the device private key.
    ///
    ///   It is a callback rather than a `DeviceSigner` because signing is platform code
    ///   (`DeviceSigner` from `qualia-dik`) and **the core library must not depend on
    ///   the keystore** — the dependency direction is keystore → core. The callback keeps
    ///   this layer free of platform dependencies and testable on any platform.
    ///
    ///   The callback receives the **message itself**, not a digest. A platform implementation
    ///   that talks to a digest-only hardware API (Windows CNG's `NCryptSignHash` names its
    ///   parameter `pbHashValue`) must therefore hash once with SHA-256 itself and go through
    ///   `sign_digest`. The number of hashes has exactly one owner: the verifying side always
    ///   goes through [`qualia_dik::device::verify`], which in standard ECDSA mode **hashes the
    ///   message once itself**.
    ///
    /// # Errors
    ///
    /// - wrong device public key length or curve membership: [`Error::AuthMessageMalformed`]
    /// - errors returned by `sign` are passed through unchanged
    pub fn respond(
        &self,
        master: &MasterKey,
        device_public: &[u8],
        sign: impl FnOnce(&[u8]) -> Result<DeviceSignature>,
    ) -> Result<Vec<u8>> {
        if device_public.len() != PUBLIC_KEY_LEN {
            return Err(Error::AuthMessageMalformed {
                reason: "设备身份公钥长度不是 65 字节",
            });
        }
        DevicePublicKey::from_sec1_bytes(device_public).map_err(|_| {
            Error::AuthMessageMalformed {
                reason: "设备身份公钥不是合法的 P-256 SEC1 点",
            }
        })?;

        let verifier_public = PublicKey::from_sec1_bytes(&self.verifier_public).map_err(|_| {
            Error::AuthMessageMalformed {
                reason: "挑战里的临时公钥不是合法的 P-256 SEC1 点",
            }
        })?;
        let session_id = self.session_id();
        let shared = self.secret.diffie_hellman(&verifier_public);
        let keys = AuthKeys::derive(master, shared.raw_secret_bytes(), &session_id);

        let tag = proof_tag(&keys.proof, &session_id);
        let message = signature_message(
            &session_id,
            &self.verifier_public,
            &self.verifier_nonce,
            &self.public_key,
            &self.nonce,
            &tag,
        );
        let signature = sign(&message)?;

        let mut out = Vec::with_capacity(RESPONSE_SIGNED_LEN);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(device_public);
        out.extend_from_slice(&tag);
        out.extend_from_slice(signature.as_bytes());
        Ok(out)
    }
}

impl core::fmt::Debug for Responder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Responder")
            .field("public_key", &"<65 bytes>")
            .field("nonce", &"<redacted>")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Start one authentication as the verifier and return the challenge to send to the
/// responder.
///
/// # Errors
///
/// Fails only when the OS random source is unavailable ([`Error::RandomnessUnavailable`]).
#[must_use = "挑战必须被发出去，否则这次认证无法开始"]
pub fn begin() -> Result<(Vec<u8>, Verifier)> {
    let secret = EphemeralSecret::generate();
    let point = secret.public_key().to_sec1_point(false);
    let mut public_key = [0_u8; PUBLIC_KEY_LEN];
    public_key.copy_from_slice(point.as_bytes());

    let mut nonce = [0_u8; NONCE_LEN];
    crate::getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;

    let mut challenge = Vec::with_capacity(CHALLENGE_LEN);
    challenge.extend_from_slice(&public_key);
    challenge.extend_from_slice(&nonce);
    Ok((
        challenge,
        Verifier {
            secret,
            nonce,
            public_key,
        },
    ))
}

/// Accept a challenge as the responder.
///
/// # Errors
///
/// - wrong challenge length, or a public key that is not on the curve:
///   [`Error::AuthMessageMalformed`]
/// - the OS random source is unavailable: [`Error::RandomnessUnavailable`]
///
/// The verifier's ephemeral public key is checked for curve membership here, before it is
/// handed to ECDH.
pub fn accept(challenge: &[u8]) -> Result<Responder> {
    if challenge.len() != CHALLENGE_LEN {
        return Err(Error::AuthMessageMalformed {
            reason: "挑战长度不对",
        });
    }
    let mut verifier_public = [0_u8; PUBLIC_KEY_LEN];
    verifier_public.copy_from_slice(&challenge[..PUBLIC_KEY_LEN]);
    let mut verifier_nonce = [0_u8; NONCE_LEN];
    verifier_nonce.copy_from_slice(&challenge[PUBLIC_KEY_LEN..]);

    PublicKey::from_sec1_bytes(&verifier_public).map_err(|_| Error::AuthMessageMalformed {
        reason: "挑战里的临时公钥不是合法的 P-256 SEC1 点",
    })?;

    let secret = EphemeralSecret::generate();
    let point = secret.public_key().to_sec1_point(false);
    let mut public_key = [0_u8; PUBLIC_KEY_LEN];
    public_key.copy_from_slice(point.as_bytes());
    let mut nonce = [0_u8; NONCE_LEN];
    crate::getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;

    Ok(Responder {
        secret,
        public_key,
        nonce,
        verifier_public,
        verifier_nonce,
    })
}

/// Let the responder check the confirmation tag sent back by the verifier.
///
/// # Parameters
///
/// `session_id` and `confirmation` are what [`Verified`] returned over the communication
/// channel; the caller supplies the rest from its own [`Responder`] and `master`.
///
/// # Errors
///
/// Returns [`Error::AuthProofFailed`] when the tag does not match. The checks run in this
/// order: confirmation length, the returned `session_id` against the one this responder
/// computes, SEC1 decoding of the verifier's ephemeral public key, then the tag. A
/// `session_id` mismatch means the two sides disagree about this session (the messages may
/// have been substituted), and the exchange **must not** continue past it.
pub fn confirm(
    master: &MasterKey,
    responder: &Responder,
    session_id: &[u8; SESSION_ID_LEN],
    confirmation: &[u8],
) -> Result<()> {
    if confirmation.len() != CONFIRM_LEN {
        return Err(Error::AuthMessageMalformed {
            reason: "确认标签长度不对",
        });
    }
    if *session_id != responder.session_id() {
        return Err(Error::AuthProofFailed);
    }
    let verifier_public = PublicKey::from_sec1_bytes(&responder.verifier_public).map_err(|_| {
        Error::AuthMessageMalformed {
            reason: "挑战里的临时公钥不是合法的 P-256 SEC1 点",
        }
    })?;
    let shared = responder.secret.diffie_hellman(&verifier_public);
    let keys = AuthKeys::derive(master, shared.raw_secret_bytes(), session_id);
    if !constant_time_eq(confirmation, &confirm_tag(&keys.confirm, session_id)) {
        return Err(Error::AuthProofFailed);
    }
    Ok(())
}

/// The two keys derived from the master key and the ECDH shared secret.
///
/// The two keys are derived from the master key **and** the ECDH shared secret: the master key
/// makes the tag computable only by a holder, and the shared secret (as the HKDF salt) binds it to
/// **this** session, so a recorded session cannot be replayed as a brand new one even though every
/// byte of `sid` is visible on the channel.
struct AuthKeys {
    /// The key the responder uses to prove it holds the master key.
    proof: [u8; 32],
    /// The key the verifier uses to confirm.
    confirm: [u8; 32],
}

impl AuthKeys {
    /// Derive both keys.
    ///
    /// The master key is the HKDF input key material and the ECDH shared secret is the salt.
    /// `session_id` does not enter the derivation; the tags are computed over it by the
    /// callers. `expand` can only fail for output lengths above `255 * HashLen`, which 32 bytes
    /// never reach, and a failure is still not unwrapped, because no input may panic in this
    /// library. On failure both keys are zeroized, so later authentication necessarily fails
    /// instead of silently using a predictable key.
    fn derive(master: &MasterKey, shared: &[u8], session_id: &[u8; SESSION_ID_LEN]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(shared), master.expose());
        let mut proof = [0_u8; 32];
        let mut confirm = [0_u8; 32];
        let failed = hkdf.expand(HKDF_INFO_PROOF, &mut proof).is_err()
            || hkdf.expand(HKDF_INFO_CONFIRM, &mut confirm).is_err();
        if failed {
            proof.zeroize();
            confirm.zeroize();
        }
        let _ = session_id;
        Self { proof, confirm }
    }
}

impl Drop for AuthKeys {
    fn drop(&mut self) {
        self.proof.zeroize();
        self.confirm.zeroize();
    }
}

/// Compute the session identifier.
///
/// SHA-256 over `SESSION_LABEL`, the verifier's ephemeral public key and nonce, then the
/// responder's. The input order is fixed inside **this single** function; both directions
/// call it.
fn session_id_of(
    verifier_public: &[u8; PUBLIC_KEY_LEN],
    verifier_nonce: &[u8; NONCE_LEN],
    responder_public: &[u8],
    responder_nonce: &[u8; NONCE_LEN],
) -> [u8; SESSION_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_LABEL);
    hasher.update(verifier_public);
    hasher.update(verifier_nonce);
    hasher.update(responder_public);
    hasher.update(responder_nonce);
    let digest = hasher.finalize();
    let mut out = [0_u8; SESSION_ID_LEN];
    out.copy_from_slice(&digest);
    out
}

/// The message covered by the device signature:
/// `SIGNATURE_LABEL ‖ session_id ‖ A_pub ‖ n_A ‖ B_pub ‖ n_B ‖ tag`.
///
/// It covers the session identifier, both sides' public values and the tag, so **one signature
/// is valid for one session only**. Dropping any item would let an attacker move a device's
/// signature into another session, which would break the property that the signature proves
/// which device is answering.
fn signature_message(
    session_id: &[u8; SESSION_ID_LEN],
    verifier_public: &[u8; PUBLIC_KEY_LEN],
    verifier_nonce: &[u8; NONCE_LEN],
    responder_public: &[u8],
    responder_nonce: &[u8; NONCE_LEN],
    tag: &[u8; CONFIRMATION_LEN],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        SIGNATURE_LABEL.len()
            + SESSION_ID_LEN
            + PUBLIC_KEY_LEN
            + NONCE_LEN
            + responder_public.len()
            + NONCE_LEN
            + CONFIRMATION_LEN,
    );
    message.extend_from_slice(SIGNATURE_LABEL);
    message.extend_from_slice(session_id);
    message.extend_from_slice(verifier_public);
    message.extend_from_slice(verifier_nonce);
    message.extend_from_slice(responder_public);
    message.extend_from_slice(responder_nonce);
    message.extend_from_slice(tag);
    message
}

/// Build a device signature from a byte slice.
///
/// Goes through [`DeviceSignature::from_bytes`] instead of assembling the array here: length
/// validation belongs in exactly one place.
fn signature_of(bytes: &[u8]) -> Result<DeviceSignature> {
    Ok(DeviceSignature::from_bytes(bytes)?)
}

/// Compute the proof tag.
fn proof_tag(key: &[u8; 32], session_id: &[u8; SESSION_ID_LEN]) -> [u8; CONFIRMATION_LEN] {
    tag(key, PROOF_LABEL, session_id)
}

/// Compute the confirmation tag.
fn confirm_tag(key: &[u8; 32], session_id: &[u8; SESSION_ID_LEN]) -> [u8; CONFIRM_LEN] {
    tag(key, CONFIRM_LABEL, session_id)
}

/// Generic tag computation: `HMAC-SHA256(key, label ‖ session_id)`.
///
/// `new_from_slice` accepts a key of any length for HMAC-SHA256 and cannot fail; should it
/// fail anyway, the result is an all-zero tag rather than a panic.
fn tag(key: &[u8; 32], label: &[u8], session_id: &[u8; SESSION_ID_LEN]) -> [u8; CONFIRMATION_LEN] {
    let Ok(mut mac) = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key) else {
        return [0_u8; CONFIRMATION_LEN];
    };
    mac.update(label);
    mac.update(session_id);
    let digest = mac.finalize().into_bytes();
    let mut out = [0_u8; CONFIRMATION_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Constant-time comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer as _};

    /// Build one "device": a software-held P-256 private key plus the matching public material.
    ///
    /// In production the device private key lives in platform hardware and signing is
    /// initiated by `qualia-dik`, but **this module does not care where the private
    /// key is stored** — it only asks a callback for a signature. A software key therefore
    /// exercises the same protocol properties; the real hardware path is covered by
    /// integration tests in the keystore repository.
    ///
    /// `scalar` selects a specific device, so a test can name one. Small values such as 1, 2, 3
    /// are far below the curve order and are always valid private keys.
    fn device(scalar: u8) -> (SigningKey, [u8; PUBLIC_KEY_LEN]) {
        let mut bytes = [0_u8; 32];
        bytes[31] = scalar;
        let signing = SigningKey::from_bytes((&bytes).into()).expect("合法标量");
        let public = signing.verifying_key().to_sec1_point(false);
        let mut out = [0_u8; PUBLIC_KEY_LEN];
        out.copy_from_slice(public.as_bytes());
        (signing, out)
    }

    /// Create a master key.
    fn new_master() -> MasterKey {
        MasterKey::generate().expect("随机源可用")
    }

    /// Run one complete handshake and return both sides' intermediate results.
    ///
    /// It returns the `Responder` rather than only the confirmation result so that "is the
    /// confirmation tag right or wrong" can be checked separately. A `Responder` cannot be
    /// copied, so every test runs its own handshake.
    fn handshake(master: &MasterKey) -> (Verified, Responder, [u8; PUBLIC_KEY_LEN], Vec<u8>) {
        let (signing, device_public) = device(7);
        let (challenge, verifier) = begin().expect("生成挑战");
        let responder = accept(&challenge).expect("接受挑战");
        let response = responder
            .respond(master, &device_public, |message| {
                let signature: p256::ecdsa::Signature = signing.sign(message);
                signature_of(&signature.to_bytes())
            })
            .expect("生成应答");
        let verified = verifier.verify(&response, master).expect("验证应答");
        (verified, responder, device_public, response)
    }

    /// A normal handshake must succeed, and both sides must agree on the session identifier.
    #[test]
    fn handshake_succeeds_and_both_sides_agree_on_the_session() {
        let master = new_master();
        let (verified, responder, device_public, _) = handshake(&master);

        assert_eq!(
            verified.session_id(),
            &responder.session_id(),
            "双方算出的会话标识必须一致"
        );
        assert_eq!(verified.device_public(), &device_public);

        confirm(
            &master,
            &responder,
            verified.session_id(),
            &verified.confirmation(),
        )
        .expect("确认标签应当被接受");
    }

    /// **A responder without the master key must fail.** The response is produced with a
    /// different master key and must be rejected with [`Error::AuthProofFailed`], because an
    /// attacker can see the challenge and the response but cannot compute the tag.
    #[test]
    fn responder_without_the_master_key_cannot_answer() {
        let real = new_master();
        let wrong = new_master();
        let (_, device_public) = device(7);
        let (challenge, verifier) = begin().expect("生成挑战");
        let responder = accept(&challenge).expect("接受挑战");

        let response = responder
            .respond(&wrong, &device_public, |digest| {
                let (signing, _) = device(7);
                let signature: p256::ecdsa::Signature = signing.sign(digest);
                signature_of(&signature.to_bytes())
            })
            .expect("签名本身会成功");

        assert!(
            matches!(
                verifier.verify(&response, &real),
                Err(Error::AuthProofFailed)
            ),
            "用错的主密钥却通过了认证"
        );
    }

    /// An attacker without the private key cannot forge a signature, **even when the tag is
    /// valid**: a genuine response has its signature segment replaced (the tag stays valid,
    /// since the attacker can see the channel) and must be rejected by the signature check.
    #[test]
    fn forged_signature_is_rejected_even_with_a_valid_tag() {
        let master = new_master();

        let (challenge, verifier) = begin().expect("生成挑战");
        let responder = accept(&challenge).expect("接受挑战");
        let (real_signing, real_device) = device(7);
        let response = responder
            .respond(&master, &real_device, |message| {
                let signature: p256::ecdsa::Signature = real_signing.sign(message);
                signature_of(&signature.to_bytes())
            })
            .expect("生成应答");

        let (_attacker_signing, attacker_device) = device(9);
        let mut forged = response.clone();
        for byte in &mut forged[RESPONSE_LEN..] {
            *byte = 0;
        }
        assert_ne!(attacker_device, real_device);

        assert!(
            matches!(
                verifier.verify(&forged, &master),
                Err(Error::Device(
                    qualia_dik::Error::DeviceSignatureInvalid { .. }
                ))
            ),
            "被换成无效签名的应答却通过了"
        );
    }

    /// **Tampering with any byte of the response except the signature must be detected.**
    #[test]
    fn tampering_with_the_response_is_detected() {
        let master = new_master();
        let (signing, device_public) = device(7);

        for index in 0..RESPONSE_SIGNED_LEN {
            let (challenge, verifier) = begin().expect("生成挑战");
            let responder = accept(&challenge).expect("接受挑战");
            let mut response = responder
                .respond(&master, &device_public, |digest| {
                    let signature: p256::ecdsa::Signature = signing.sign(digest);
                    signature_of(&signature.to_bytes())
                })
                .expect("生成应答");
            response[index] ^= 0x01;

            assert!(
                verifier.verify(&response, &master).is_err(),
                "第 {index} 字节被翻转却通过了认证"
            );
        }
    }

    /// A challenge with the wrong length must be rejected.
    #[test]
    fn challenge_with_wrong_length_is_rejected() {
        for length in [0_usize, 1, CHALLENGE_LEN - 1, CHALLENGE_LEN + 1] {
            let mut challenge = vec![0_u8; length];
            if length > 0 {
                challenge[0] = 0x04;
            }
            assert!(
                matches!(accept(&challenge), Err(Error::AuthMessageMalformed { .. })),
                "长度 {length} 的挑战应被拒绝"
            );
        }
    }

    /// A challenge whose public key is not on the curve must be rejected.
    #[test]
    fn challenge_with_off_curve_key_is_rejected() {
        let (challenge, _) = begin().expect("生成挑战");
        let mut broken = challenge.clone();
        broken[PUBLIC_KEY_LEN - 1] ^= 0x01;

        assert!(matches!(
            accept(&broken),
            Err(Error::AuthMessageMalformed { .. })
        ));
    }

    /// A response whose public key is not on the curve must be rejected (**before the tag is computed**).
    #[test]
    fn response_with_off_curve_key_is_rejected() {
        let master = new_master();
        let (challenge, verifier) = begin().expect("生成挑战");
        let responder = accept(&challenge).expect("接受挑战");
        let (signing, device_public) = device(7);
        let mut response = responder
            .respond(&master, &device_public, |message| {
                let signature: p256::ecdsa::Signature = signing.sign(message);
                signature_of(&signature.to_bytes())
            })
            .expect("生成应答");
        response[PUBLIC_KEY_LEN - 1] ^= 0x01;

        assert!(matches!(
            verifier.verify(&response, &master),
            Err(Error::AuthMessageMalformed { .. })
        ));
    }

    /// A wrong confirmation tag must be rejected, and so must a confirmation of the wrong
    /// length.
    #[test]
    fn wrong_confirmation_is_rejected() {
        let master = new_master();
        let (verified, responder, _, _) = handshake(&master);
        let mut confirmation = verified.confirmation();
        confirmation[0] ^= 0x01;

        assert!(matches!(
            confirm(&master, &responder, verified.session_id(), &confirmation),
            Err(Error::AuthProofFailed)
        ));

        assert!(matches!(
            confirm(
                &master,
                &responder,
                verified.session_id(),
                &confirmation[..1]
            ),
            Err(Error::AuthMessageMalformed { .. })
        ));
    }

    /// **A mismatched session identifier must be rejected**, even when the tag itself is
    /// correct. This blocks moving one session's confirmation tag onto another session.
    #[test]
    fn confirmation_with_a_mismatched_session_id_is_rejected() {
        let master = new_master();
        let (verified, responder, _, _) = handshake(&master);
        let mut wrong_session = *verified.session_id();
        wrong_session[0] ^= 0x01;

        assert!(matches!(
            confirm(
                &master,
                &responder,
                &wrong_session,
                &verified.confirmation()
            ),
            Err(Error::AuthProofFailed)
        ));
    }

    /// Confirmation with the wrong master key must fail.
    #[test]
    fn confirmation_with_the_wrong_master_key_is_rejected() {
        let master = new_master();
        let (verified, responder, _, _) = handshake(&master);
        let other = new_master();

        assert!(matches!(
            confirm(
                &other,
                &responder,
                verified.session_id(),
                &verified.confirmation()
            ),
            Err(Error::AuthProofFailed)
        ));
    }

    /// **Two sessions must never share a session identifier or a tag**; otherwise an attacker
    /// could replay a whole response.
    #[test]
    fn two_sessions_never_share_a_session_id_or_tag() {
        let master = new_master();
        let mut sessions = Vec::new();
        let mut tags = Vec::new();
        for _ in 0..8 {
            let (_, _, _, response) = handshake(&master);
            let (challenge, verifier) = begin().expect("生成挑战");
            let responder = accept(&challenge).expect("接受挑战");
            sessions.push(responder.session_id());
            tags.push(response[PUBLIC_KEY_LEN + NONCE_LEN + PUBLIC_KEY_LEN..].to_vec());
            drop(verifier);
        }

        for i in 0..sessions.len() {
            for j in (i + 1)..sessions.len() {
                assert_ne!(sessions[i], sessions[j], "两次会话出现了相同的会话标识");
                assert_ne!(tags[i], tags[j], "两次会话出现了相同的证明标签");
            }
        }
    }

    /// The **lengths** of the messages are a fixed contract.
    #[test]
    fn message_lengths_are_stable() {
        assert_eq!(CHALLENGE_LEN, 65 + 32);
        assert_eq!(RESPONSE_LEN, 65 + 32 + 65 + 32);
        assert_eq!(RESPONSE_SIGNED_LEN, RESPONSE_LEN + 64);
        assert_eq!(CONFIRM_LEN, 32);
    }

    /// The master key must **not** appear in plaintext inside a response.
    #[test]
    fn response_never_contains_the_master_key() {
        let master = new_master();
        let (_, _, _, response) = handshake(&master);
        assert!(
            !response
                .windows(crate::vault::MASTER_KEY_LEN)
                .any(|w| w == master.expose()),
            "应答里出现了主密钥明文"
        );
    }

    /// `Debug` output must be redacted: secret material must not reach logs, error messages or
    /// `Debug` output. This checks the module's three types: the ephemeral private key, the
    /// nonces, and the derived confirmation key.
    #[test]
    fn debug_output_is_redacted() {
        let master = new_master();
        let (challenge, verifier) = begin().expect("生成挑战");
        let responder = accept(&challenge).expect("接受挑战");
        let (signing, device_public) = device(7);
        let response = responder
            .respond(&master, &device_public, |message| {
                let signature: p256::ecdsa::Signature = signing.sign(message);
                signature_of(&signature.to_bytes())
            })
            .expect("生成应答");
        let verifier_text = format!("{verifier:?}");
        let responder_text = format!("{responder:?}");
        let verified = verifier.verify(&response, &master).expect("验证");
        let verified_text = format!("{verified:?}");

        let master_hex: String = master.expose().iter().map(|b| format!("{b:02x}")).collect();
        let responder_nonce_hex: String = responder_side_nonce(&response)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        for (what, text) in [
            ("Verifier", &verifier_text),
            ("Responder", &responder_text),
            ("Verified", &verified_text),
        ] {
            assert!(
                !text.contains(&master_hex),
                "{what} 的 Debug 输出泄露了主密钥"
            );
            assert!(
                !text.contains(&responder_nonce_hex),
                "{what} 的 Debug 输出泄露了 nonce"
            );
            assert!(
                text.contains("redacted") || text.contains("bytes"),
                "{what} 的 Debug 输出没有出现脱敏占位符：{text}"
            );
        }
    }

    /// Take the responder's nonce out of a response body (`PUBLIC_KEY_LEN..PUBLIC_KEY_LEN+NONCE_LEN`).
    fn responder_side_nonce(response: &[u8]) -> [u8; NONCE_LEN] {
        let mut out = [0_u8; NONCE_LEN];
        out.copy_from_slice(&response[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + NONCE_LEN]);
        out
    }

    /// Constant-time comparison must behave correctly.
    #[test]
    fn constant_time_eq_behaves() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 3]), "长度不同必须为假");
        assert!(constant_time_eq(&[], &[]));
    }
}
