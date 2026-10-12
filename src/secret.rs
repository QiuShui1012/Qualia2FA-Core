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

//! Secret material containers.
//!
//! This module does **not** implement secret types itself; it fixes the capabilities
//! of [`secrecy`] to this project's usage: a single re-export, aliases, and a contract
//! locked down by tests. All key material inside the library (OTP seeds, vault master
//! key, session keys) is carried by these types.
//!
//! The pinned upstream release is `secrecy` 0.10.3, used with
//! `default-features = false`. It has exactly two dependencies: `zeroize ^1.6`
//! (required, and the same major as the `zeroize 1.9.1` already used by this crate, so
//! no duplicate version is pulled in) and `serde ^1` (optional, **not** enabled here).
//! The upstream implementation is pure logic: no FFI, no `unsafe`, no network.
//!
//! # Types exported by this module
//!
//! | Purpose | Type |
//! |---|---|
//! | Arbitrary byte secrets (seeds, keys, nonces) | [`SecretSlice<u8>`] |
//! | Text secrets (passphrases, recovery phrases) | [`SecretString`] |
//! | Fixed-size / other secrets | [`SecretBox`] |
//! | Accessing the plaintext | [`ExposeSecret`] / [`ExposeSecretMut`] |
//!
//! # Current limits
//!
//! - **The `Debug` of `secrecy` does not even print the length** (it prints something
//!   like `SecretSlice<u8>([REDACTED])`). Call [`ExposeSecret::expose_secret`] when the
//!   length is needed; do not rely on `Debug` for anything.
//! - It protects only against "plaintext being printed / not being erased /
//!   accidentally cloned"; it does **not** protect against the compiler copying
//!   plaintext into registers, stack copies, or swap. Under `#![forbid(unsafe_code)]`
//!   mechanisms such as `mlock` cannot be used to prevent paging.
//! - It does **not** protect against malicious code in the same process: once
//!   `expose_secret` is called, the plaintext is in the caller's hands.
//! - `Drop` erases, but does **not** guarantee that the compiler left no unerased
//!   intermediate copies.

/// Byte secrets: OTP seeds, master keys, session keys, and the like are all carried by
/// this type.
///
/// It is a distinct type rather than a bare alias of `Vec<u8>`, so that "this is a
/// secret" is visible in the type and it cannot be mistaken for an ordinary byte stream
/// when printed or serialized.
pub type SecretBytes = SecretSlice<u8>;

pub use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretSlice, SecretString};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_from_vec_and_expose_roundtrip() {
        let raw = vec![1_u8, 2, 3, 4, 5];
        let secret: SecretBytes = raw.clone().into();
        assert_eq!(secret.expose_secret(), raw.as_slice());
    }

    /// `Debug` must redact and must not contain any form of the plaintext.
    #[test]
    fn debug_never_leaks_bytes() {
        let secret: SecretBytes = vec![0xde_u8, 0xad, 0xbe, 0xef].into();
        let debug = format!("{secret:?}");
        let lower = debug.to_lowercase();

        assert!(
            lower.contains("redacted"),
            "Debug output is not marked as redacted: {debug}"
        );
        for leak in ["222", "173", "190", "239", "dead", "beef", "de ad"] {
            assert!(
                !lower.contains(leak),
                "Debug output leaks a plaintext trace {leak:?}: {debug}"
            );
        }
    }

    /// A secret nested inside another `#[derive(Debug)]` structure does not leak
    /// either.
    #[test]
    fn nested_in_derived_debug_still_safe() {
        #[expect(
            dead_code,
            reason = "the field exists only to build the Debug output and is never read; that is the entire point of this test"
        )]
        #[derive(Debug)]
        struct Wrapper {
            /// Business field, printable.
            label: &'static str,
            /// Secret field, must be redacted.
            secret: SecretBytes,
        }

        let w = Wrapper {
            label: "github",
            secret: vec![0xde_u8, 0xad].into(),
        };
        let text = format!("{w:?}");
        assert!(
            text.contains("github"),
            "a non-secret field must print normally: {text}"
        );
        assert!(
            !text.contains("222"),
            "nested Debug output leaks plaintext: {text}"
        );
    }

    /// Contract: secret types must be `ZeroizeOnDrop` (erased on drop).
    ///
    /// `zeroize` is not a direct dependency of this crate, so it is taken from
    /// `secrecy::zeroize` — the upstream crate `pub use`s it, which guarantees that the
    /// test targets the version **actually in effect** rather than one we specify
    /// ourselves.
    #[test]
    fn zeroize_on_drop_contract_holds() {
        fn assert_zeroize_on_drop<T: secrecy::zeroize::ZeroizeOnDrop>() {}
        fn assert_zeroize<T: secrecy::zeroize::Zeroize>() {}
        assert_zeroize_on_drop::<SecretBytes>();
        assert_zeroize::<SecretBytes>();
        assert_zeroize_on_drop::<SecretString>();
    }

    /// Secrets must be constructible from `Vec<u8>` and `String`, covering the real
    /// call paths.
    #[test]
    fn constructible_from_owned_input() {
        let bytes: SecretBytes = vec![0_u8; 32].into();
        assert_eq!(bytes.expose_secret().len(), 32);

        let text = SecretString::from("correct horse battery staple");
        assert_eq!(text.expose_secret(), "correct horse battery staple");
    }

    /// `SecretBytes` (that is, `SecretSlice<u8>`) **can** be cloned: `u8` implements
    /// `CloneableSecret`. This locks the behavior down, so that upgrading `secrecy`
    /// cannot change the semantics silently.
    ///
    /// Note that this is **not** an encouragement to clone secrets — a clone means two
    /// plaintext copies that are erased independently. Prefer passing a reference.
    #[test]
    fn secret_bytes_is_cloneable_and_clone_exposes_same() {
        let secret: SecretBytes = vec![9_u8, 8, 7].into();
        let copy = secret.clone();
        assert_eq!(copy.expose_secret(), secret.expose_secret());
        assert_eq!(copy.expose_secret(), &[9, 8, 7]);
    }

    /// Documents a constraint that **cannot be tested**: `SecretBox<T>` itself does not
    /// accept container types.
    ///
    /// `secrecy` implements `CloneableSecret` only for primitive integers (`u8`…`u128`,
    /// `usize`) and provides **no** implementation for `Vec<T>` / `String` / `Box<T>`.
    /// Hence `SecretBox<Vec<u8>>` is **not cloneable** — upstream's way of letting the
    /// type system block silent copies of secrets.
    ///
    /// The property cannot be expressed as a runtime assertion (`Clone` is a
    /// compile-time capability; writing `secret.clone()` would simply fail to compile).
    /// It is therefore recorded here, and byte secrets in this repository avoid the
    /// limitation by using `SecretSlice<u8>` (cloneable) throughout. A caller that needs
    /// a non-cloneable byte secret should use `SecretBox<[u8; N]>` rather than working
    /// around the upstream constraint.
    #[test]
    fn container_secret_box_is_not_cloneable_by_upstream_design() {
        let scalar = SecretBox::new(Box::new(0xAB_u8));
        let copy = scalar.clone();
        assert_eq!(*copy.expose_secret(), 0xAB);
    }
}
