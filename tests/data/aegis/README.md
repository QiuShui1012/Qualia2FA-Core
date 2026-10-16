# Real exports from another authenticator

These four files came out of **Aegis** (Android) on 2026-10-17, from a vault holding two TOTP
entries, one export per format it offers:

| File | What it is | Aegis's own name for it |
|---|---|---|
| `plain.json` | the JSON export, unencrypted | `aegis-export-plain-20261017-070740.json` |
| `encrypted.json` | the JSON export, encrypted with a password | `aegis-export-20261017-070729.json` |
| `vault.html` | the HTML export, with a QR code drawn for every entry | `aegis-export-html-20261017-070745.html` |
| `uris.txt` | the text export, one URI per line | `aegis-export-uri-20261017-070749.txt` |

They are here because every other sample in this repository was **written by hand** to the shape
the format documents describe: such a sample proves the reader agrees with our reading of the
document, not that it agrees with the implementation that wrote the file. These four are that
implementation's own output, and `tests/aegis_samples.rs` reads them.

## The accounts are disposable

`tester824@spotify.com` and `tester68@logrocket.com` are throwaway accounts created for this
export, and the two secrets in these files protect nothing. That is deliberate: a fixture holds
real key material in a public repository, so it may only ever hold key material that is worth
nothing.

## The password of the encrypted export

`Afl43670P`

It is written here rather than in the encrypted file, which is where a password belongs; a test
that could not open the sample would not be testing the encrypted path at all. The slot in that
file is a **password** slot (`type: 1`, scrypt cost 32768, block size 8, parallelisation 1, a
32-byte salt), and it carries `repaired: true` - a field of the slot that says Aegis had rebuilt
it at some point, and which this library reads past.

## What they pin

- the JSON shape: `version`/`header`/`db`, `db.version` 3, `icons_optimized`, `icon: null`;
- the encrypted shape: one slot with `key` + `key_params {nonce, tag}`, `params {nonce, tag}`,
  and a database that is base64 **without line breaks**;
- the HTML table: twelve columns in the documented order, the type spelled `TOTP` (upper case),
  `Favorite` spelled `false`, empty cells left empty rather than dashed, and the style block
  after `</body>`;
- the QR code of the HTML export: a 256×256 **RGBA** PNG whose base64 is wrapped across lines,
  holding the entry's whole `otpauth://` URI - which is where that format's only copy of a time
  step lives;
- the text export's parameter order (`period`, `digits`, `algorithm`, `secret`, `issuer`) and
  its percent-encoded label (`Spotify%3Atester824%40spotify.com`).

The files are kept byte for byte as Aegis wrote them. Re-formatting one would destroy the thing
it is here to prove.
