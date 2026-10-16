# Security Policy

## What this repository covers

`qualia2fa-core`: the vault format, the pairing and synchronization protocol, and the cryptography built on them.

## Reporting a vulnerability

Please report it privately rather than in a public issue:

- **GitHub private vulnerability reporting** -- the *Security* tab of this repository, then
  *Report a vulnerability*. This is the preferred route: the report stays private and is
  attached to the repository it concerns.
- **Email** -- qiushui1012@foxmail.com

Include what makes the report reproducible: the version or commit, the platform, what you
did, and what happened. A proof of concept is worth more than a description, and a failing
test is worth more than either.

## Scope

This project is pre-1.0 and has not been independently audited. Reports are read on a best
effort basis, and there is no bug bounty; a reporter who wants to be credited will be, in
the release notes and in the commit that fixes the issue.

In scope: the code in this repository, and the way it uses its dependencies.

## Reading an export from another authenticator

The importer takes a file the user picked and treats every byte of it as attacker-controlled:
lengths, nesting, digit counts, secrets, key derivation parameters. What bounds that surface, and
what a reader has to hold to:

- **The size is compared before anything is allocated or parsed**, and so is the JSON nesting
  depth, which is scanned out of the bytes before they reach a parser that recurses. A stack
  overflow is not a catchable error, so it is refused rather than survived.
- **Every number that decides a cost is bounded before it is used.** The key derivation
  parameters come from the file and drive an allocation proportional to them; the memory a file
  asks for is computed and refused before the derivation runs. The reference implementation of
  that format does not bound them.
- **Only password-protected key slots are opened.** This library has no platform key store and no
  biometric prompt, so an export locked to the device that wrote it is reported as unsupported
  rather than as a wrong password.
- **Base64 and hexadecimal are decoded strictly.** A decoder that tolerates extra padding or
  stray characters turns a modified file into a shorter one, and the result then authenticates as
  a different message.
- **Nothing read from the file reaches an error message.** Problem lists carry a position and a
  phrase; the secret, the PIN and the passphrase never appear in one. That path is
  `import::mapping::safe_reason`, and it deliberately does not use `Display`, because several of
  this crate's errors quote the value that was wrong.

`tinyjson` reads the JSON export, `aes-gcm` and `scrypt` open an encrypted one. They are used for
reading only: the vault and the sync payload keep this project's own constructions, and neither
dependency appears in anything this library writes.

## MD5 is used for one thing only

mOTP is defined as `MD5(counter || secret || pin)` truncated to six hexadecimal characters, so
this repository depends on `md-5`. That is its **only** use: MD5 takes no part in the vault
format, the key derivation, the AEAD, the signatures, the pairing protocol or any integrity
decision this project makes. Nothing else may start using it -- an MD5-based construction
anywhere else would sit next to a genuine collision weakness, while for mOTP the digest is part
of a third-party scheme that has to be reproduced exactly to produce matching codes.

Out of scope: a vulnerability in a dependency itself (report it upstream -- a note is still
welcome), and anything that requires an attacker to already hold the user's device unlocked,
their master key, or their signing key.