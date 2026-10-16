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