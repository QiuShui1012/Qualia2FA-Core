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

//! Device-login pairing: hand the master key to a new device.
//!
//! # The problem it solves
//!
//! This application has no central server and no account password. "Logging in" means: a device
//! that **already holds the master key** (the **initiator** A) hands the master key to a new
//! device (the **joiner** B). Once B holds the master key, both devices can open the same
//! entries.
//!
//! # Threat model
//!
//! Attackers that must be resisted:
//!
//! 1. **Sees only a photo of the QR code** (shot through a window, or an old screenshot).
//! 2. **Sees the QR code and can modify it** (the user is talked into scanning a replaced code).
//! 3. **Can read, write, replay and drop any message on the channel between A and B** (man in
//!    the middle).
//!
//! Attackers that **need not** be resisted: one that already controls A or B. That device
//! already holds the master key, so pairing can offer no extra protection.
//!
//! # Protocol
//!
//! ```text
//!   A (signed in, holds master key M)       B (new device, no M)
//!       │                                          │
//!       │ ① generate an ephemeral key pair (a, A_pub) and a random nonce_A
//!       │    QR code = { A_pub, nonce_A }          │
//!       │ ───── out-of-band scan (QR code) ────►   │
//!       │                                          │ ② generate (b, B_pub)
//!       │                                          │    S = ECDH(b, A_pub)
//!       │                                          │    derive the session keys from
//!       │                                          │    S, A_pub, B_pub,
//!       │                                          │    nonce_A, nonce_B
//!       │ ◄── Msg1 = AEAD(K_ba, B identity pub) ─  │ ③ send its device identity
//!       │         ‖ confirmation tag               │    public key to A
//!       │ ④ check the confirmation tag: the peer   │
//!       │    holds the session keys                │
//!       │     Msg2 = AEAD(K_ab, M ‖ confirmation tag)
//!       │ ──────────────────────────────────────►  │ ⑤ recover M, check the confirmation tag
//!       │                                          │
//! ```
//!
//! **The master key appears only in `Msg2`, and only as ciphertext.** The joiner has no M at
//! all before receiving it.
//!
//! `A_pub` and `nonce_A` are out-of-band authenticated inputs: the QR code is the out-of-band
//! channel (A's screen displays it, B's camera reads it, and B's user **looks at the code being
//! scanned**). Key agreement over the channel alone cannot resist a man in the middle, and with no
//! account password there is no low-entropy shared secret for a PAKE to use.
//!
//! ## What happens if an attacker modifies the QR code
//!
//! The attacker replaces `A_pub` with its own `M_pub`. B then agrees on `S'` with M, encrypts
//! `Msg1` under `S'` and sends it. **M can decrypt `Msg1`, but it holds only B's device identity
//! public key** — M does not obtain the master key. If M then impersonates A and returns a
//! "`Msg2`" to B, that message has to be encrypted under `K_ab'` derived from `S'`, which M can
//! indeed do, but M **does not hold the master key** and so cannot put it into `Msg2`.
//!
//! The attack therefore gains nothing: B either receives a message from which no master key can
//! be recovered (M's forgery) or the pairing times out. **Modifying the QR code cannot yield the
//! master key**, which is exactly what out-of-band authentication is meant to guarantee.
//!
//! The only real cost is denial of service: an attacker can **make pairing fail**. No protocol
//! layer can prevent that, since anyone able to modify the channel can do it, and the user sees
//! "pairing failed" and retries.
//!
//! # Protocol invariants
//!
//! 1. **The master key flows only from A to B, only inside `Msg2`, and only as ciphertext.**
//! 2. **The two directions use two different keys**, derived from the same ECDH secret and
//!    separated by different HKDF info strings.
//! 3. **Each session is used once.** [`PendingSession::accept`] takes `self`, so the type system
//!    makes a second use impossible; the ephemeral private key is erased on `Drop`.
//! 4. **Mutual confirmation.** The tag in `Msg1` proves B holds the session keys; the tag in
//!    `Msg2` proves A holds them and **really decrypted `Msg1`**, which is why that confirmation
//!    tag covers B's identity public key.
//! 5. **Everything is authenticated.** The message kind and the whole transcript go into the AAD.
//!
//! # What this module does not do
//!
//! - **No transport.** How the QR code is displayed and how messages are delivered is up to the
//!   caller. This module only produces and consumes bytes.
//! - **No persistence.** Where the master key is stored (a platform hardware keystore) is up to
//!   the caller.
//! - **No clock.** The core library does not read a clock. A pairing payload expires because
//!   closing the pairing screen drops the [`PendingSession`], not because of a timestamp: a
//!   timestamp would need a clock and would still not stop replaying a payload that has not
//!   expired.

use crate::vault::{MASTER_KEY_LEN, MasterKey, NONCE_LEN as AEAD_NONCE_LEN, master_key_to_bytes};
use crate::{Error, ExposeSecret, Result, SecretBytes};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::Generate;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use secrecy::zeroize::Zeroize;
use sha2::{Digest, Sha256};

/// Pairing protocol version, encoded into the QR code and both messages.
///
/// The version **must** take part in key derivation (see `transcript_hash`): otherwise an
/// attacker could answer a session of a newer version with an `Msg1` of an older one, and both
/// sides would still compute the same transcript.
pub const PROTOCOL_VERSION: u8 = 1;

/// Byte length of a P-256 SEC1 uncompressed public key.
pub const PUBLIC_KEY_LEN: usize = 65;

/// Byte length of a pairing random nonce.
///
/// 256-bit. It is what keeps **one QR code from being used twice**: A generates a fresh
/// ephemeral key and nonce every time the pairing screen is opened, so an `Msg1` captured in a
/// previous round cannot be decrypted in this one.
pub const NONCE_LEN: usize = 32;

/// Byte length of the confirmation tag.
///
/// 256-bit. The tag only proves "I hold the session keys too" and carries no long-term
/// authentication, so 128-bit would suffice; the full HMAC-SHA256 output is kept because that is
/// its natural length and truncating it would only add a rule to explain.
pub const CONFIRMATION_LEN: usize = 32;

/// Byte length of the session identifier.
pub const SESSION_ID_LEN: usize = 32;

/// Byte length of the AEAD authentication tag (the same as in the vault format).
pub const TAG_LEN: usize = 16;

/// Byte length of the QR payload: version + ephemeral public key + nonce + capability flag.
pub const QR_PAYLOAD_LEN: usize = 1 + PUBLIC_KEY_LEN + NONCE_LEN + 1;

/// Byte length of the `Msg1` plaintext header: B's nonce + B's ephemeral public key.
///
/// **Plaintext, because it cannot be ciphertext.** The initiator needs B's ephemeral public key
/// to compute the ECDH shared secret and B's nonce to compute the transcript, and both are
/// prerequisites for decrypting the rest. Putting them inside the ciphertext would be a circular
/// dependency.
///
/// Sending them in the clear is not a weakness: together they amount to the joiner's ephemeral
/// public key, a single public value. Changing them only makes the two sides compute different
/// transcripts, so decryption **necessarily fails**.
pub const MSG1_HEADER_LEN: usize = NONCE_LEN + PUBLIC_KEY_LEN;

/// Plaintext length of the encrypted part of `Msg1`: B's **device identity** public key + the
/// confirmation tag.
///
/// The device identity sits inside the ciphertext rather than in the plaintext header because it
/// says which device joined; that information belongs to the two pairing parties and must not
/// reach anyone who can read the pairing traffic. Only a holder of the session keys — the
/// initiator — can read it.
pub const MSG1_BODY_PLAINTEXT_LEN: usize = PUBLIC_KEY_LEN + CONFIRMATION_LEN;

/// Full byte length of `Msg1`: plaintext header + ciphertext body, AEAD tag included.
pub const MSG1_LEN: usize = MSG1_HEADER_LEN + MSG1_BODY_PLAINTEXT_LEN + TAG_LEN;

/// Plaintext byte length of `Msg2`: master key + confirmation tag.
pub const MSG2_PLAINTEXT_LEN: usize = MASTER_KEY_LEN + CONFIRMATION_LEN;

/// Byte length of the `Msg2` ciphertext, AEAD tag included.
pub const MSG2_LEN: usize = MSG2_PLAINTEXT_LEN + TAG_LEN;

/// The only capability flag in the QR code: this protocol carries the joiner's device identity
/// public key.
///
/// Always 1. It is written into the wire format instead of being omitted so that, when
/// capabilities are added later, an old version can reject the payload with an **explicit** error
/// rather than reading an unknown byte as a known meaning.
const CAPABILITY_DEVICE_IDENTITY: u8 = 0x01;

/// HKDF domain-separation string: joiner → initiator direction.
const HKDF_INFO_JOINER_TO_INITIATOR: &[u8] = b"Qualia2FA pairing v1 joiner-to-initiator";

/// HKDF domain-separation string: initiator → joiner direction.
const HKDF_INFO_INITIATOR_TO_JOINER: &[u8] = b"Qualia2FA pairing v1 initiator-to-joiner";

/// Domain-separation string for the confirmation tag.
const CONFIRMATION_LABEL: &[u8] = b"Qualia2FA pairing v1 confirmation";

/// Domain-separation string for the derived AEAD nonce.
const NONCE_LABEL: &[u8] = b"Qualia2FA pairing v1 aead nonce";

/// The initiator's ephemeral public key and nonce, published through the QR code.
///
/// # Lifetime
///
/// Produced by [`begin`] and used by the joiner to derive the session keys. It is **not** a
/// secret (it is displayed on screen) but it is **short-lived**: once [`PendingSession::accept`]
/// has been called, or the user closes the pairing screen and drops the [`PendingSession`], the
/// matching private key no longer exists.
#[derive(Clone, PartialEq, Eq)]
pub struct QrPayload {
    /// The initiator's ephemeral ECDH public key (SEC1 uncompressed point).
    public_key: [u8; PUBLIC_KEY_LEN],
    /// The initiator's random nonce.
    nonce: [u8; NONCE_LEN],
    /// Capability flags.
    capabilities: u8,
}

impl QrPayload {
    /// SEC1 encoding of the initiator's ephemeral public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// Random nonce. Not a secret, but **unique**: the same nonce is never used twice.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// Capability flags.
    #[must_use]
    pub const fn capabilities(&self) -> u8 {
        self.capabilities
    }

    /// Encode into the byte string that goes into the QR code.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(QR_PAYLOAD_LEN);
        out.push(PROTOCOL_VERSION);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.nonce);
        out.push(self.capabilities);
        out
    }

    /// Reconstruct from scanned bytes.
    ///
    /// # Errors
    ///
    /// - wrong length, or a required capability bit missing: [`Error::PairingPayloadMalformed`]
    /// - unknown version: [`Error::PairingUnsupportedVersion`]
    /// - the public key is not a valid curve point: [`Error::DevicePublicKeyInvalid`]
    ///
    /// **The curve-membership check on the public key is a security boundary, not a format
    /// check**: handing ECDH a point that is off the curve but inside a small subgroup carries a
    /// real key-recovery risk.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != QR_PAYLOAD_LEN {
            return Err(Error::PairingPayloadMalformed {
                reason: "长度不是 1 + 65 + 32 + 1 字节",
            });
        }
        if bytes[0] != PROTOCOL_VERSION {
            return Err(Error::PairingUnsupportedVersion { version: bytes[0] });
        }
        let mut public_key = [0_u8; PUBLIC_KEY_LEN];
        public_key.copy_from_slice(&bytes[1..1 + PUBLIC_KEY_LEN]);
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[1 + PUBLIC_KEY_LEN..1 + PUBLIC_KEY_LEN + NONCE_LEN]);
        let capabilities = bytes[QR_PAYLOAD_LEN - 1];

        PublicKey::from_sec1_bytes(&public_key).map_err(|_| Error::DevicePublicKeyInvalid {
            reason: "二维码里的临时公钥不是合法的 P-256 SEC1 点",
        })?;

        if capabilities & CAPABILITY_DEVICE_IDENTITY == 0 {
            return Err(Error::PairingPayloadMalformed {
                reason: "二维码缺少必需的能力位",
            });
        }

        Ok(Self {
            public_key,
            nonce,
            capabilities,
        })
    }

    /// Encode as a Base32 string, convenient for the QR code's text field.
    ///
    /// Base32 rather than hexadecimal: QR capacity is the tightest constraint here, and Base32
    /// costs only 1.6 characters per byte against hexadecimal's 2.
    #[must_use]
    pub fn to_base32(&self) -> String {
        crate::base32::encode(&self.encode())
    }

    /// Reconstruct from a Base32 string.
    ///
    /// # Errors
    ///
    /// A Base32 decoding failure returns a Base32 error; otherwise as in [`QrPayload::decode`].
    pub fn from_base32(text: &str) -> Result<Self> {
        let bytes = crate::base32::decode(text)?;
        Self::decode(bytes.expose_secret())
    }
}

impl core::fmt::Debug for QrPayload {
    /// Prints the public key and the capability bits, **not the nonce**.
    ///
    /// The nonce is not a secret, but it would let a log correlate which pairing rounds belong
    /// together. Pairing is a sensitive operation, so leaving no correlatable identifier in logs
    /// is preferable.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QrPayload")
            .field("version", &PROTOCOL_VERSION)
            .field("public_key", &"<65 bytes>")
            .field("nonce", &"<redacted>")
            .field("capabilities", &format_args!("0x{:02X}", self.capabilities))
            .finish()
    }
}

/// Initiator A's pending session: it holds the ephemeral private key and waits for the joiner's
/// `Msg1`.
///
/// # Single use, guaranteed by the type system
///
/// [`PendingSession::accept`] takes `self` rather than `&self`, so **the same session cannot be
/// accepted twice**. The constraint does not rely on the caller's discipline:
///
/// - replaying the same `Msg1` a second time does not compile, because there is no session left
///   to pass it to;
/// - reopening the pairing screen yields a **new** [`PendingSession`] with a different nonce and
///   ephemeral public key, so an `Msg1` captured in a previous round cannot be decrypted.
///
/// The ephemeral private key is erased on `Drop` by `p256` (`EphemeralSecret` implements
/// `ZeroizeOnDrop`).
pub struct PendingSession {
    /// This side's ephemeral private key.
    secret: EphemeralSecret,
    /// The payload matching the QR code contents.
    payload: QrPayload,
}

impl PendingSession {
    /// What the QR code should display.
    #[must_use]
    pub const fn payload(&self) -> &QrPayload {
        &self.payload
    }

    /// Accept the joiner's `Msg1`, confirm the peer's identity, and produce the `Msg2` that
    /// carries the master key.
    ///
    /// # Parameters
    ///
    /// - `msg1`: the joiner's complete `Msg1` ciphertext (the return value of
    ///   [`JoinerSession::request`]).
    /// - `master`: the **initiator's own** master key. It goes into the receipt as ciphertext.
    ///
    /// # Returns
    ///
    /// [`Adoption`]: the joiner's device identity public key, the session identifier, and the
    /// `Msg2` to send back to the joiner.
    ///
    /// # Errors
    ///
    /// Every authentication failure returns [`Error::PairingAuthenticationFailed`], **without**
    /// distinguishing "the ciphertext was tampered with", "the message came from another session"
    /// and "the joiner used the wrong public key". Telling them apart would help an attacker and
    /// gives the user nothing to act on: the answer to all three is "this pairing failed, scan
    /// again".
    ///
    /// The whole ciphertext body — the trailing AEAD tag included — is handed to
    /// `decrypt_in_place`, which strips the last `TAG_LEN` bytes itself. After decryption the
    /// joiner's device identity public key is checked for curve membership before it is reported
    /// in [`Adoption`]; a point off the curve would otherwise make later signature verification
    /// fail for reasons far from the cause.
    pub fn accept(self, msg1: &[u8], master: &MasterKey) -> Result<Adoption> {
        if msg1.len() != MSG1_LEN {
            return Err(Error::PairingAuthenticationFailed);
        }
        let mut joiner_nonce = [0_u8; NONCE_LEN];
        joiner_nonce.copy_from_slice(&msg1[..NONCE_LEN]);
        let mut joiner_ephemeral = [0_u8; PUBLIC_KEY_LEN];
        joiner_ephemeral.copy_from_slice(&msg1[NONCE_LEN..MSG1_HEADER_LEN]);
        let joiner_ephemeral = PublicKey::from_sec1_bytes(&joiner_ephemeral).map_err(|_| {
            Error::DevicePublicKeyInvalid {
                reason: "加入方的临时公钥不是合法的 P-256 SEC1 点",
            }
        })?;

        let transcript = transcript_hash(
            &self.payload.public_key,
            &self.payload.nonce,
            &msg1[NONCE_LEN..MSG1_HEADER_LEN],
            &joiner_nonce,
        );
        let shared = self.secret.diffie_hellman(&joiner_ephemeral);
        let keys = SessionKeys::derive(shared.raw_secret_bytes(), &transcript);

        let mut plaintext = msg1[MSG1_HEADER_LEN..].to_vec();
        let aad = aad_for(&transcript, MessageKind::Request);
        let cipher = XChaCha20Poly1305::new(&Key::from(keys.joiner_to_initiator));
        cipher
            .decrypt_in_place(&XNonce::from(keys.nonce), &aad, &mut plaintext)
            .map_err(|_| Error::PairingAuthenticationFailed)?;
        debug_assert_eq!(plaintext.len(), MSG1_BODY_PLAINTEXT_LEN);

        let mut joiner_identity = [0_u8; PUBLIC_KEY_LEN];
        joiner_identity.copy_from_slice(&plaintext[..PUBLIC_KEY_LEN]);
        let expected = confirmation_tag(
            &keys.joiner_to_initiator,
            &transcript,
            MessageKind::Request,
            &joiner_identity,
        );
        if !constant_time_eq(&plaintext[PUBLIC_KEY_LEN..], &expected) {
            return Err(Error::PairingAuthenticationFailed);
        }
        PublicKey::from_sec1_bytes(&joiner_identity).map_err(|_| {
            Error::DevicePublicKeyInvalid {
                reason: "加入方的设备身份公钥不是合法的 P-256 SEC1 点",
            }
        })?;

        let mut reply = Vec::with_capacity(MSG2_PLAINTEXT_LEN);
        reply.extend_from_slice(master.expose());
        reply.extend_from_slice(&confirmation_tag(
            &keys.initiator_to_joiner,
            &transcript,
            MessageKind::Accept,
            &joiner_identity,
        ));
        let aad = aad_for(&transcript, MessageKind::Accept);
        let reply_cipher = XChaCha20Poly1305::new(&Key::from(keys.initiator_to_joiner));
        reply_cipher
            .encrypt_in_place(&XNonce::from(keys.nonce), &aad, &mut reply)
            .map_err(|_| Error::PairingAuthenticationFailed)?;

        Ok(Adoption {
            session_id: transcript,
            joiner_identity,
            reply,
        })
    }
}

impl core::fmt::Debug for PendingSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingSession")
            .field("payload", &self.payload)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The result of [`PendingSession::accept`].
pub struct Adoption {
    /// Session identifier (both sides agree on it; usable for log correlation).
    session_id: [u8; SESSION_ID_LEN],
    /// The joiner's device identity public key (SEC1). This is how the initiator learns which device joined.
    joiner_identity: [u8; PUBLIC_KEY_LEN],
    /// The `Msg2` ciphertext to send back to the joiner.
    reply: Vec<u8>,
}

impl Adoption {
    /// Session identifier. Both sides compute the same value, so the two ends' logs can be matched up.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// The joiner's device identity public key.
    ///
    /// The caller should build a [`qualia_dik::DevicePublicKey`] from it and **record it**: it is
    /// the only basis for "which device this device trusts". Its authenticity comes from the
    /// pairing channel (only a holder of the session keys can deliver it here), but **after
    /// pairing** it is only a recorded identity, and later authentication always goes through
    /// signature verification.
    #[must_use]
    pub const fn joiner_identity(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.joiner_identity
    }

    /// The `Msg2` ciphertext to send back to the joiner.
    #[must_use]
    pub fn reply(&self) -> &[u8] {
        &self.reply
    }
}

impl core::fmt::Debug for Adoption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Adoption")
            .field("session_id", &&self.session_id[..8])
            .field("joiner_identity", &"<65 bytes>")
            .field("reply_len", &self.reply.len())
            .finish()
    }
}

/// Joiner B's session: the QR code has been scanned and it waits to receive the master key.
///
/// The call order is `join` → `request` → `open`. `request` borrows `&self` (the caller still needs
/// the same session for `open` after sending `Msg1`); `open` takes `self` and consumes the session,
/// erasing the ephemeral private key.
pub struct JoinerSession {
    /// This side's ephemeral private key.
    secret: EphemeralSecret,
    /// This side's generated ephemeral public key (SEC1).
    public_key: [u8; PUBLIC_KEY_LEN],
    /// This side's generated nonce. It travels in the `Msg1` plaintext and takes part in the transcript.
    nonce: [u8; NONCE_LEN],
    /// The payload parsed from the QR code.
    payload: QrPayload,
}

impl JoinerSession {
    /// SEC1 encoding of this side's ephemeral public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// Produce `Msg1`: hand this side's device identity public key to the initiator.
    ///
    /// # Parameters
    ///
    /// - `device_identity`: SEC1 encoding of this side's device identity public key (provided by
    ///   `qualia-dik`).
    ///
    /// # Returns
    ///
    /// The complete `Msg1` ciphertext, and this session's identifier.
    ///
    /// # This message carries no master key
    ///
    /// The joiner **does not have** the master key at this point; that is what it is here for.
    /// `Msg1` carries only the joiner's identity public key and a confirmation tag. The master
    /// key arrives in the opposite direction, in [`JoinerSession::open`].
    ///
    /// # Wire format
    ///
    /// `Msg1` is `header(plaintext) ‖ AEAD(identity public key ‖ confirmation tag)`. The header is
    /// assembled separately because it must not enter the ciphertext (see [`MSG1_HEADER_LEN`]).
    /// The device identity public key is checked for curve membership here, before any message is
    /// produced, so an unusable key surfaces as a local error instead of as a reported pairing
    /// failure on the other side.
    ///
    /// # Errors
    ///
    /// - device identity public key of the wrong length, or not a valid curve point:
    ///   [`Error::DevicePublicKeyInvalid`]
    /// - AEAD failure: [`Error::PairingAuthenticationFailed`]
    pub fn request(&self, device_identity: &[u8]) -> Result<(Vec<u8>, [u8; SESSION_ID_LEN])> {
        if device_identity.len() != PUBLIC_KEY_LEN {
            return Err(Error::DevicePublicKeyInvalid {
                reason: "设备身份公钥长度不是 65 字节",
            });
        }
        PublicKey::from_sec1_bytes(device_identity).map_err(|_| Error::DevicePublicKeyInvalid {
            reason: "设备身份公钥不是合法的 P-256 SEC1 点",
        })?;
        let (transcript, keys) = self.derive()?;

        let mut body = Vec::with_capacity(MSG1_BODY_PLAINTEXT_LEN);
        body.extend_from_slice(device_identity);
        body.extend_from_slice(&confirmation_tag(
            &keys.joiner_to_initiator,
            &transcript,
            MessageKind::Request,
            device_identity,
        ));

        let aad = aad_for(&transcript, MessageKind::Request);
        let cipher = XChaCha20Poly1305::new(&Key::from(keys.joiner_to_initiator));
        cipher
            .encrypt_in_place(&XNonce::from(keys.nonce), &aad, &mut body)
            .map_err(|_| Error::PairingAuthenticationFailed)?;

        let mut msg = Vec::with_capacity(MSG1_LEN);
        msg.extend_from_slice(&self.nonce);
        msg.extend_from_slice(&self.public_key);
        msg.extend_from_slice(&body);

        Ok((msg, transcript))
    }

    /// Receive the master key from the initiator's `Msg2`.
    ///
    /// The master key is handed to the caller only here, and `MasterKey::from_bytes` validates its
    /// length, so a payload of the wrong length can never become a master key that looks usable.
    /// The whole ciphertext — the trailing AEAD tag included — goes to `decrypt_in_place`, which
    /// strips the last `TAG_LEN` bytes itself.
    ///
    /// # Errors
    ///
    /// Every authentication failure returns [`Error::PairingAuthenticationFailed`]: **wrong
    /// length, wrong tag, tampered ciphertext and a message from another session** all map to that
    /// one variant. A device identity public key of the wrong length returns
    /// [`Error::DevicePublicKeyInvalid`].
    pub fn open(self, msg2: &[u8], device_identity: &[u8]) -> Result<MasterKey> {
        if msg2.len() != MSG2_LEN {
            return Err(Error::PairingAuthenticationFailed);
        }
        if device_identity.len() != PUBLIC_KEY_LEN {
            return Err(Error::DevicePublicKeyInvalid {
                reason: "设备身份公钥长度不是 65 字节",
            });
        }
        let (transcript, keys) = self.derive()?;

        let mut plaintext = msg2.to_vec();
        let aad = aad_for(&transcript, MessageKind::Accept);
        let cipher = XChaCha20Poly1305::new(&Key::from(keys.initiator_to_joiner));
        cipher
            .decrypt_in_place(&XNonce::from(keys.nonce), &aad, &mut plaintext)
            .map_err(|_| Error::PairingAuthenticationFailed)?;
        debug_assert_eq!(plaintext.len(), MSG2_PLAINTEXT_LEN);

        let expected = confirmation_tag(
            &keys.initiator_to_joiner,
            &transcript,
            MessageKind::Accept,
            device_identity,
        );
        if !constant_time_eq(&plaintext[MASTER_KEY_LEN..], &expected) {
            return Err(Error::PairingAuthenticationFailed);
        }

        let mut raw = plaintext[..MASTER_KEY_LEN].to_vec();
        let secret: SecretBytes = core::mem::take(&mut raw).into();
        raw.zeroize();
        MasterKey::from_bytes(secret)
    }

    /// Derive this side's session material; it must come out exactly as on the initiator.
    fn derive(&self) -> Result<([u8; SESSION_ID_LEN], SessionKeys)> {
        let initiator_public =
            PublicKey::from_sec1_bytes(&self.payload.public_key).map_err(|_| {
                Error::DevicePublicKeyInvalid {
                    reason: "二维码里的临时公钥不是合法的 P-256 SEC1 点",
                }
            })?;
        let transcript = transcript_hash(
            &self.payload.public_key,
            &self.payload.nonce,
            &self.public_key,
            &self.nonce,
        );
        let shared = self.secret.diffie_hellman(&initiator_public);
        Ok((
            transcript,
            SessionKeys::derive(shared.raw_secret_bytes(), &transcript),
        ))
    }
}

impl core::fmt::Debug for JoinerSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JoinerSession")
            .field("payload", &self.payload)
            .field("public_key", &"<65 bytes>")
            .field("nonce", &"<redacted>")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Message kind; it takes part in building the AAD and the confirmation tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageKind {
    /// Joiner → initiator.
    Request,
    /// Initiator → joiner.
    Accept,
}

impl MessageKind {
    /// The byte value taking part in the computations.
    const fn as_byte(self) -> u8 {
        match self {
            Self::Request => 0x01,
            Self::Accept => 0x02,
        }
    }
}

/// The session keys derived by one pairing.
///
/// Both directions are derived from the same ECDH secret but with different HKDF info strings. The
/// AEAD nonce is deliberately identical in both directions (no counter state), which is not nonce
/// reuse: the keys differ, so the two ciphertexts bear no derivable relation to each other.
struct SessionKeys {
    /// Joiner → initiator direction.
    joiner_to_initiator: [u8; 32],
    /// Initiator → joiner direction.
    initiator_to_joiner: [u8; 32],
    /// AEAD nonce (shared by both directions; safe because the keys differ).
    nonce: [u8; AEAD_NONCE_LEN],
}

impl SessionKeys {
    /// Derive from the ECDH shared secret and the session transcript.
    ///
    /// The transcript is the HKDF salt: it contains both sides' public keys and nonces, so the
    /// derived keys are bound to **this** pairing, and changing any of its bytes makes the two
    /// sides derive different keys, after which authentication necessarily fails. The AEAD nonce
    /// is derived from the transcript as well, so the same transcript always yields the same nonce
    /// (the consistency both sides need) and different sessions yield different nonces.
    ///
    /// `expand` can only fail for output lengths above `255 * HashLen`, which 32 bytes never
    /// reach, and a failure is still not unwrapped, because no input may panic in this library. On
    /// failure both keys are zeroized, so later authentication necessarily fails instead of
    /// silently using a predictable key.
    fn derive(shared: &[u8], transcript: &[u8; SESSION_ID_LEN]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(transcript), shared);
        let mut joiner_to_initiator = [0_u8; 32];
        let mut initiator_to_joiner = [0_u8; 32];
        let failed = hkdf
            .expand(HKDF_INFO_JOINER_TO_INITIATOR, &mut joiner_to_initiator)
            .is_err()
            || hkdf
                .expand(HKDF_INFO_INITIATOR_TO_JOINER, &mut initiator_to_joiner)
                .is_err();
        if failed {
            joiner_to_initiator.zeroize();
            initiator_to_joiner.zeroize();
        }

        let mut hasher = Sha256::new();
        hasher.update(NONCE_LABEL);
        hasher.update(transcript);
        let digest = hasher.finalize();
        let mut nonce = [0_u8; AEAD_NONCE_LEN];
        nonce.copy_from_slice(&digest[..AEAD_NONCE_LEN]);

        Self {
            joiner_to_initiator,
            initiator_to_joiner,
            nonce,
        }
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.joiner_to_initiator.zeroize();
        self.initiator_to_joiner.zeroize();
        self.nonce.zeroize();
    }
}

/// Compute the SHA-256 of the session transcript.
///
/// Input: version + initiator ephemeral public key + initiator nonce + joiner ephemeral public
/// key + joiner nonce.
///
/// The result doubles as the HKDF salt, part of the AAD and the session identifier, and it is
/// assembled **only here**, in the order above: both directions call this one function, so the two
/// sides cannot disagree.
fn transcript_hash(
    initiator_public_key: &[u8; PUBLIC_KEY_LEN],
    initiator_nonce: &[u8; NONCE_LEN],
    joiner_public_key: &[u8],
    joiner_nonce: &[u8; NONCE_LEN],
) -> [u8; SESSION_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update([PROTOCOL_VERSION]);
    hasher.update(initiator_public_key);
    hasher.update(initiator_nonce);
    hasher.update(joiner_public_key);
    hasher.update(joiner_nonce);
    let digest = hasher.finalize();
    let mut out = [0_u8; SESSION_ID_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Build the AAD: session identifier + message kind.
///
/// The message kind must enter the AAD: otherwise an attacker could replay an `Msg2` ciphertext
/// to the initiator as if it were an `Msg1` (or the other way round). That is already impossible
/// because the two directions use **different keys**, but writing the kind into the AAD makes the
/// property independent of that implementation detail.
fn aad_for(transcript: &[u8; SESSION_ID_LEN], kind: MessageKind) -> [u8; SESSION_ID_LEN + 1] {
    let mut aad = [0_u8; SESSION_ID_LEN + 1];
    aad[..SESSION_ID_LEN].copy_from_slice(transcript);
    aad[SESSION_ID_LEN] = kind.as_byte();
    aad
}

/// Compute the confirmation tag: `HMAC-SHA256(key, label ‖ kind ‖ transcript ‖ peer_identity)`.
///
/// The peer identity is covered by the tag, so each message says "I see **this** peer and we share
/// the session keys" rather than being a generic "OK" that transfers to another identity.
///
/// HMAC is used rather than comparing the session keys directly: comparing keys leaks whether two
/// key segments are equal, while the HMAC output leaks nothing about the key. `new_from_slice`
/// accepts a key of any length for HMAC-SHA256 and cannot fail; should it fail anyway, the result
/// is an all-zero tag rather than a panic.
fn confirmation_tag(
    key: &[u8; 32],
    transcript: &[u8; SESSION_ID_LEN],
    kind: MessageKind,
    peer_identity: &[u8],
) -> [u8; CONFIRMATION_LEN] {
    let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(key) else {
        return [0_u8; CONFIRMATION_LEN];
    };
    mac.update(CONFIRMATION_LABEL);
    mac.update(&[kind.as_byte()]);
    mac.update(transcript);
    mac.update(peer_identity);
    let digest = mac.finalize().into_bytes();
    let mut out = [0_u8; CONFIRMATION_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Constant-time comparison of two byte strings.
///
/// Different lengths return `false` immediately: the length is not a secret (the protocol fixes
/// it), so leaking it means nothing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Start one pairing as the initiator and return the payload to display as a QR code.
///
/// # Errors
///
/// Fails only when the OS random source is unavailable ([`Error::RandomnessUnavailable`]).
///
/// The payload goes into the QR code and the session keeps the ephemeral private key, so the two are
/// produced and returned as a pair: a public key in the QR code without its matching private key
/// makes every pairing fail.
#[must_use = "配对会话必须被保留，否则二维码里的公钥就没有对应的私钥了"]
pub fn begin() -> Result<(QrPayload, PendingSession)> {
    let secret = EphemeralSecret::generate();
    let public_key = secret.public_key().to_sec1_point(false);
    let mut public_key_bytes = [0_u8; PUBLIC_KEY_LEN];
    public_key_bytes.copy_from_slice(public_key.as_bytes());

    let mut nonce = [0_u8; NONCE_LEN];
    crate::getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;

    let payload = QrPayload {
        public_key: public_key_bytes,
        nonce,
        capabilities: CAPABILITY_DEVICE_IDENTITY,
    };
    let session = PendingSession {
        secret,
        payload: payload.clone(),
    };
    Ok((payload, session))
}

/// Start one pairing as the joiner from a scanned QR code.
///
/// # Errors
///
/// - the public key in the QR code is not on the curve: [`Error::DevicePublicKeyInvalid`]
/// - the OS random source is unavailable: [`Error::RandomnessUnavailable`]
///
/// The public key is validated again here even though [`QrPayload::decode`] already did so: a
/// `JoinerSession` can also be created from a payload the caller assembled by hand, so it must not
/// be assumed to come from `decode`.
pub fn join(payload: &QrPayload) -> Result<JoinerSession> {
    PublicKey::from_sec1_bytes(&payload.public_key).map_err(|_| Error::DevicePublicKeyInvalid {
        reason: "二维码里的临时公钥不是合法的 P-256 SEC1 点",
    })?;

    let secret = EphemeralSecret::generate();
    let public_key = secret.public_key().to_sec1_point(false);
    let mut public_key_bytes = [0_u8; PUBLIC_KEY_LEN];
    public_key_bytes.copy_from_slice(public_key.as_bytes());

    let mut nonce = [0_u8; NONCE_LEN];
    crate::getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;

    Ok(JoinerSession {
        secret,
        public_key: public_key_bytes,
        nonce,
        payload: payload.clone(),
    })
}

/// Wrap the master key into bytes that can be handed to a platform keystore.
///
/// A forward of [`master_key_to_bytes`], provided so that callers need not import both `vault` and
/// `pairing`.
#[must_use]
pub fn master_key_for_storage(master: &MasterKey) -> SecretBytes {
    master_key_to_bytes(master)
}

/// Rebuild the master key from bytes retrieved from a platform keystore.
///
/// # Errors
///
/// Returns [`Error::MasterKeyWrongLength`] when the length is not [`MASTER_KEY_LEN`].
pub fn master_key_from_storage(bytes: SecretBytes) -> Result<MasterKey> {
    MasterKey::from_bytes(bytes)
}

/// A record of already used pairing nonces, used to reject replays.
///
/// # What it protects against
///
/// The pairing protocol already makes each session single-use ([`PendingSession::accept`] takes
/// `self`, and every [`begin`] generates a fresh ephemeral key and nonce). This record covers the
/// layer above: a caller that persists nonces can still recognise "this QR code / this session has
/// already been handled" **after a restart**, instead of accepting it again because in-memory
/// state was lost.
///
/// # Bounded capacity
///
/// Pairing happens at the pace of manual user actions, so a few hundred entries are plenty. An
/// **unbounded** record would be a resource an attacker could exhaust by starting pairings it
/// never finishes. When the record is full the oldest entry is evicted; the session behind an
/// evicted nonce ended long ago, so replaying it could not succeed anyway.
#[derive(Debug, Clone, Default)]
pub struct NonceLog {
    /// Used nonces, in insertion order.
    used: std::collections::VecDeque<[u8; NONCE_LEN]>,
}

impl NonceLog {
    /// Number of nonces kept by default.
    pub const DEFAULT_CAPACITY: usize = 256;

    /// Create an empty record.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.used.len()
    }

    /// Whether the record is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.used.is_empty()
    }

    /// Whether this nonce has already been used.
    #[must_use]
    pub fn is_used(&self, nonce: &[u8; NONCE_LEN]) -> bool {
        self.used.contains(nonce)
    }

    /// Record a nonce.
    ///
    /// `false` means this nonce **was recorded before** (that is, this is a replay) and the caller
    /// should reject the operation; `true` means it was recorded.
    pub fn record(&mut self, nonce: [u8; NONCE_LEN]) -> bool {
        if self.is_used(&nonce) {
            return false;
        }
        if self.used.len() >= Self::DEFAULT_CAPACITY {
            self.used.pop_front();
        }
        self.used.push_back(nonce);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;

    /// Build a **genuinely valid** device identity public key (a point on the curve, 65-byte
    /// SEC1).
    ///
    /// Arbitrary bytes will not do: `from_sec1_bytes` performs the full curve-membership check, and
    /// that is a security boundary. A key derived from a small scalar is enough here, since the
    /// pairing protocol only moves the identity around as **opaque** bytes.
    fn fake_identity() -> [u8; PUBLIC_KEY_LEN] {
        public_key_of(&SecretKey::from_bytes(&[1_u8; 32].into()).expect("标量 1 合法"))
    }

    /// Another valid but different identity.
    fn other_identity() -> [u8; PUBLIC_KEY_LEN] {
        public_key_of(&SecretKey::from_bytes(&[2_u8; 32].into()).expect("标量 2 合法"))
    }

    /// Take the SEC1 uncompressed public key belonging to a private key.
    fn public_key_of(secret: &SecretKey) -> [u8; PUBLIC_KEY_LEN] {
        let point = secret.public_key().to_sec1_point(false);
        let mut out = [0_u8; PUBLIC_KEY_LEN];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Run one complete pairing and return what each end sees.
    fn run_pairing() -> (
        MasterKey,
        MasterKey,
        [u8; SESSION_ID_LEN],
        [u8; SESSION_ID_LEN],
    ) {
        let initiator_master = MasterKey::generate().expect("随机源可用");
        let identity = fake_identity();

        let (payload, pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let (msg1, joiner_sid) = joiner.request(&identity).expect("可生成 Msg1");

        let adoption = pending
            .accept(&msg1, &initiator_master)
            .expect("Msg1 应通过认证");
        assert_eq!(
            adoption.joiner_identity(),
            &identity,
            "发起方应看到加入方的设备身份"
        );

        let joiner_master = joiner
            .open(adoption.reply(), &identity)
            .expect("Msg2 应通过认证");
        (
            initiator_master,
            joiner_master,
            *adoption.session_id(),
            joiner_sid,
        )
    }

    /// The end-to-end happy path: both sides end up with the **same** master key.
    #[test]
    fn happy_path_transfers_the_master_key() {
        let (a, b, sid_a, sid_b) = run_pairing();
        assert_eq!(a.expose(), b.expose(), "双方主密钥必须一致");
        assert_eq!(sid_a, sid_b, "双方会话标识必须一致");
    }

    /// The QR payload must survive a Base32 round trip.
    #[test]
    fn qr_payload_roundtrips_through_base32() {
        let (payload, _pending) = begin().expect("随机源可用");
        let text = payload.to_base32();
        let decoded = QrPayload::from_base32(&text).expect("应能解码");
        assert_eq!(decoded, payload);
    }

    /// The QR byte layout is an external contract; pin it down.
    #[test]
    fn qr_payload_layout_is_stable() {
        let (payload, _pending) = begin().expect("随机源可用");
        let bytes = payload.encode();
        assert_eq!(bytes.len(), QR_PAYLOAD_LEN);
        assert_eq!(bytes[0], PROTOCOL_VERSION);
        assert_eq!(&bytes[1..66], payload.public_key());
        assert_eq!(&bytes[66..98], payload.nonce());
        assert_eq!(bytes[98], CAPABILITY_DEVICE_IDENTITY);
    }

    /// A QR payload of the wrong length must be rejected.
    #[test]
    fn qr_payload_rejects_wrong_length() {
        let (payload, _pending) = begin().expect("随机源可用");
        let bytes = payload.encode();
        for cut in [0_usize, 1, QR_PAYLOAD_LEN - 1] {
            assert!(
                matches!(
                    QrPayload::decode(&bytes[..cut]),
                    Err(Error::PairingPayloadMalformed { .. })
                ),
                "长度 {cut} 应被拒绝"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(QrPayload::decode(&longer).is_err());
    }

    /// An unknown version must be rejected **explicitly**, not read as this version.
    #[test]
    fn qr_payload_rejects_unknown_version() {
        let (payload, _pending) = begin().expect("随机源可用");
        let mut bytes = payload.encode();
        bytes[0] = 0x7F;
        match QrPayload::decode(&bytes) {
            Err(Error::PairingUnsupportedVersion { version }) => assert_eq!(version, 0x7F),
            other => panic!("应报版本不支持，实际 is_ok={}", other.is_ok()),
        }
    }

    /// **A public key off the curve must be rejected.** This is a security boundary, not a format
    /// check. The key is built by flipping the last byte of the public key's coordinates, which
    /// almost certainly leaves the curve.
    #[test]
    fn qr_payload_rejects_off_curve_public_key() {
        let (payload, _pending) = begin().expect("随机源可用");
        let mut bytes = payload.encode();
        bytes[PUBLIC_KEY_LEN] ^= 0x01;
        assert!(
            matches!(
                QrPayload::decode(&bytes),
                Err(Error::DevicePublicKeyInvalid { .. })
            ),
            "曲外公钥应被拒绝"
        );
    }

    /// A missing required capability bit must be rejected.
    #[test]
    fn qr_payload_rejects_missing_capability() {
        let (payload, _pending) = begin().expect("随机源可用");
        let mut bytes = payload.encode();
        bytes[QR_PAYLOAD_LEN - 1] = 0x00;
        assert!(matches!(
            QrPayload::decode(&bytes),
            Err(Error::PairingPayloadMalformed { .. })
        ));
    }

    /// Every session must get a fresh ephemeral public key and nonce.
    #[test]
    fn each_session_gets_a_fresh_payload() {
        let (a, _pa) = begin().expect("随机源可用");
        let (b, _pb) = begin().expect("随机源可用");
        assert_ne!(a.nonce(), b.nonce(), "nonce 被复用");
        assert_ne!(a.public_key(), b.public_key(), "临时公钥被复用");
    }

    /// **Tampering with any byte of `Msg1` must fail.**
    #[test]
    fn tampering_with_msg1_fails() {
        let master = MasterKey::generate().expect("随机源可用");
        let identity = fake_identity();
        let (payload, pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let (baseline, _) = joiner.request(&identity).expect("可生成 Msg1");
        assert_eq!(baseline.len(), MSG1_LEN);

        for index in 0..baseline.len() {
            let (payload_i, pending_i) = begin().expect("随机源可用");
            let joiner_i = join(&payload_i).expect("随机源可用");
            let (mut tampered, _) = joiner_i.request(&identity).expect("可生成 Msg1");
            tampered[index] ^= 0x01;
            assert!(
                pending_i.accept(&tampered, &master).is_err(),
                "Msg1 第 {index} 字节被翻转却通过了认证"
            );
        }
        assert!(pending.accept(&baseline, &master).is_ok());
    }

    /// **Tampering with any byte of `Msg2` must fail**, the master key itself included.
    #[test]
    fn tampering_with_msg2_fails() {
        let master = MasterKey::generate().expect("随机源可用");
        let identity = fake_identity();
        let (payload, pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let (msg1, _) = joiner.request(&identity).expect("可生成 Msg1");
        let adoption = pending.accept(&msg1, &master).expect("应通过认证");
        assert_eq!(adoption.reply().len(), MSG2_LEN);

        let mut tampered = adoption.reply().to_vec();
        tampered[0] ^= 0x01;
        assert!(
            joiner.open(&tampered, &identity).is_err(),
            "被改动的主密钥却通过了认证"
        );
    }

    /// Answering this session with **another session's** `Msg1` must fail.
    #[test]
    fn msg1_from_another_session_fails() {
        let master = MasterKey::generate().expect("随机源可用");
        let identity = fake_identity();
        let (_payload_a, pending_a) = begin().expect("随机源可用");
        let (payload_b, _pending_b) = begin().expect("随机源可用");
        let joiner_b = join(&payload_b).expect("随机源可用");
        let (msg1_b, _) = joiner_b.request(&identity).expect("可生成 Msg1");

        assert!(
            pending_a.accept(&msg1_b, &master).is_err(),
            "跨会话 Msg1 应被拒绝"
        );
    }

    /// A message of the wrong length must be rejected, and must not panic.
    ///
    /// The length check must come **before** any authentication computation: otherwise a very long
    /// input would let an attacker buy a lot of computation for very little cost.
    #[test]
    fn wrong_length_messages_fail() {
        let master = MasterKey::generate().expect("随机源可用");
        let identity = fake_identity();

        let (payload, _pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let (msg1, _) = joiner.request(&identity).expect("可生成 Msg1");
        for cut in [0_usize, 1, MSG1_LEN - 1] {
            let (p, pend) = begin().expect("随机源可用");
            drop(join(&p).expect("随机源可用"));
            assert!(
                pend.accept(&msg1[..cut], &master).is_err(),
                "长度 {cut} 应被拒绝"
            );
        }
        let mut too_long = msg1.clone();
        too_long.push(0);
        let (p, pend) = begin().expect("随机源可用");
        drop(join(&p).expect("随机源可用"));
        assert!(
            pend.accept(&too_long, &master).is_err(),
            "过长的 Msg1 应被拒绝"
        );

        for cut in [0_usize, 1, MSG2_LEN - 1] {
            let (p, pend) = begin().expect("随机源可用");
            let j = join(&p).expect("随机源可用");
            let (m1, _) = j.request(&identity).expect("可生成 Msg1");
            let ad = pend.accept(&m1, &master).expect("应通过认证");
            assert!(
                j.open(&ad.reply()[..cut], &identity).is_err(),
                "长度 {cut} 应被拒绝"
            );
        }
    }

    /// A device identity public key of the wrong length must be rejected **before a message is sent**.
    #[test]
    fn request_rejects_wrong_identity_length() {
        let (payload, _pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        for bad in [&[][..], &[0_u8; 64][..], &[0_u8; 66][..]] {
            assert!(
                matches!(
                    joiner.request(bad),
                    Err(Error::DevicePublicKeyInvalid { .. })
                ),
                "长度 {} 应被拒绝",
                bad.len()
            );
        }
    }

    /// A "device identity public key" off the curve must be rejected.
    #[test]
    fn request_rejects_off_curve_identity() {
        let (payload, _pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let mut bad = fake_identity();
        bad[0] = 0x03;
        assert!(joiner.request(&bad).is_err(), "非法前缀应被拒绝");
    }

    /// **Opening `Msg2` with a different identity public key must fail.**
    ///
    /// This pins down that the confirmation tag is bound to the peer identity: the tag is not a
    /// generic OK that says nothing about who the peer is.
    #[test]
    fn msg2_cannot_be_opened_with_a_different_identity() {
        let master = MasterKey::generate().expect("随机源可用");
        let identity = fake_identity();
        let (payload, pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let (msg1, _) = joiner.request(&identity).expect("可生成 Msg1");
        let adoption = pending.accept(&msg1, &master).expect("应通过认证");

        assert!(
            joiner.open(adoption.reply(), &other_identity()).is_err(),
            "用另一个身份却能打开 Msg2"
        );
    }

    /// The nonce log must identify replays.
    #[test]
    fn nonce_log_detects_replay() {
        let mut log = NonceLog::new();
        let nonce = [7_u8; NONCE_LEN];
        assert!(!log.is_used(&nonce));
        assert!(log.record(nonce), "首次记录应成功");
        assert!(log.is_used(&nonce));
        assert!(!log.record(nonce), "重复记录应被识别为重放");
        assert_eq!(log.len(), 1);
    }

    /// The nonce log's capacity must be bounded; otherwise an attacker could exhaust it with pairings it never finishes.
    #[test]
    fn nonce_log_is_bounded() {
        let mut log = NonceLog::new();
        for i in 0..(NonceLog::DEFAULT_CAPACITY + 50) {
            let mut nonce = [0_u8; NONCE_LEN];
            nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
            assert!(log.record(nonce), "第 {i} 条应记录成功");
        }
        assert_eq!(log.len(), NonceLog::DEFAULT_CAPACITY);
    }

    /// Two pairings must have different transcripts, and therefore different session keys.
    #[test]
    fn transcripts_differ_per_session() {
        let identity = fake_identity();
        let (payload_a, _pa) = begin().expect("随机源可用");
        let (payload_b, _pb) = begin().expect("随机源可用");
        let joiner_a = join(&payload_a).expect("随机源可用");
        let joiner_b = join(&payload_b).expect("随机源可用");
        let (_, sid_a) = joiner_a.request(&identity).expect("可生成");
        let (_, sid_b) = joiner_b.request(&identity).expect("可生成");
        assert_ne!(sid_a, sid_b, "两次会话的 transcript 相同");
    }

    /// Round trip of master key storage.
    #[test]
    fn master_key_storage_roundtrip() {
        let master = MasterKey::generate().expect("随机源可用");
        let bytes = master_key_for_storage(&master);
        let rebuilt = master_key_from_storage(bytes).expect("长度正确");
        assert_eq!(master.expose(), rebuilt.expose());
    }

    /// The byte layout of `Msg1` is an external contract; pin it down.
    ///
    /// The key property: **the plaintext header carries only the nonce and the ephemeral public
    /// key, not the device identity public key**. The device identity is information for the two
    /// pairing parties and must not reach anyone who can read the pairing traffic.
    #[test]
    fn msg1_layout_keeps_device_identity_encrypted() {
        let identity = fake_identity();
        let (payload, _pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let (msg1, _) = joiner.request(&identity).expect("可生成 Msg1");

        assert_eq!(msg1.len(), MSG1_LEN);
        assert_eq!(MSG1_LEN, 32 + 65 + (65 + 32) + 16);
        assert_eq!(
            &msg1[..NONCE_LEN],
            &joiner_nonce_of(&msg1),
            "nonce 应在最前"
        );
        assert_eq!(
            &msg1[NONCE_LEN..MSG1_HEADER_LEN],
            joiner.public_key(),
            "明文头应携带加入方的临时公钥"
        );
        assert!(
            !msg1.windows(PUBLIC_KEY_LEN).any(|w| w == identity),
            "设备身份公钥出现在了 Msg1 的明文部分"
        );
    }

    /// Take the nonce out of `Msg1` (test-only, so tests need not repeat the offset arithmetic).
    fn joiner_nonce_of(msg1: &[u8]) -> [u8; NONCE_LEN] {
        let mut out = [0_u8; NONCE_LEN];
        out.copy_from_slice(&msg1[..NONCE_LEN]);
        out
    }

    #[test]
    fn probe_divergence() {
        let identity = fake_identity();
        let (payload, pending) = begin().expect("rng");
        let joiner = join(&payload).expect("rng");
        let (msg1, sid_j) = joiner.request(&identity).expect("req");

        let (sid_j2, keys_j) = joiner.derive().expect("derive");
        println!(
            "joiner sid  request={} derive={}",
            hex(&sid_j),
            hex(&sid_j2)
        );
        println!("joiner k_ba  = {}", hex(&keys_j.joiner_to_initiator[..8]));
        println!("joiner nonce = {}", hex(&keys_j.nonce));

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&msg1[..NONCE_LEN]);
        let mut eph = [0u8; PUBLIC_KEY_LEN];
        eph.copy_from_slice(&msg1[NONCE_LEN..MSG1_HEADER_LEN]);
        let eph_pub = PublicKey::from_sec1_bytes(&eph).expect("曲线上");
        let sid_i = transcript_hash(
            &pending.payload.public_key,
            &pending.payload.nonce,
            &msg1[NONCE_LEN..MSG1_HEADER_LEN],
            &nonce,
        );
        println!("initiator sid = {}", hex(&sid_i));
        println!(
            "payload.pub == msg1 header eph? {}",
            pending.payload.public_key[..] == eph[..]
        );
        println!(
            "eph_pub == from header? {}",
            eph_pub.to_sec1_point(false).as_bytes() == &eph[..]
        );
        let shared = pending.secret.diffie_hellman(&eph_pub);
        let keys_i = SessionKeys::derive(shared.raw_secret_bytes(), &sid_i);
        println!("initiator k_ba = {}", hex(&keys_i.joiner_to_initiator[..8]));
        println!("initiator nonce = {}", hex(&keys_i.nonce));
        println!(
            "accept err = {:?}",
            pending.accept(&msg1, &MasterKey::generate().unwrap()).err()
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Stored bytes of the wrong length must be rejected.
    #[test]
    fn master_key_storage_rejects_wrong_length() {
        for len in [0_usize, 31, 33] {
            let bytes: SecretBytes = vec![0_u8; len].into();
            assert!(
                master_key_from_storage(bytes).is_err(),
                "长度 {len} 应被拒绝"
            );
        }
    }

    /// **Debug output must not leak the master key.**
    #[test]
    fn debug_output_is_redacted() {
        let master = MasterKey::generate().expect("随机源可用");
        let identity = fake_identity();
        let (payload, pending) = begin().expect("随机源可用");
        let joiner = join(&payload).expect("随机源可用");
        let (msg1, _) = joiner.request(&identity).expect("可生成 Msg1");
        let joiner_debug = format!("{joiner:?}");
        let adoption = pending.accept(&msg1, &master).expect("应通过认证");
        let _ = joiner.open(adoption.reply(), &identity).expect("应能解开");

        let texts = [
            format!("{payload:?}"),
            joiner_debug,
            format!("{adoption:?}"),
        ];
        for text in &texts {
            assert!(!text.contains("XChaCha"), "不该出现内部类型名");
        }
        let hex: String = master.expose().iter().map(|b| format!("{b:02x}")).collect();
        for text in &texts {
            assert!(!text.contains(&hex), "Debug 泄露了主密钥十六进制：{text}");
        }
    }

    /// `Adoption::reply` **really does carry** the master key; this guards against a change that
    /// silently makes pairing succeed while transferring nothing.
    #[test]
    fn reply_actually_carries_the_master_key() {
        let (a, b, _, _) = run_pairing();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), &[0_u8; MASTER_KEY_LEN], "主密钥不该是全零");
    }
}
