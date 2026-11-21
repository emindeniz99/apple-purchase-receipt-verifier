# Apple's stale and retired-name root lists

Two certificate revocation lists exactly as Apple serves them, downloaded
on 2026-11-05. Each is a shared-case input that a configuration must
refuse (docs/design/revocation.md §4). They are public Apple data: a CA's
revocation list names certificates by serial, not users or purchases.

| File | Source | SHA-256 |
|---|---|---|
| `appleca-root-2025-03-10.crl` | https://www.apple.com/appleca/root.crl | `02b300d7e2edc09a33c0e98c0291da47932320761f6060ea8d7624f6e344f1dd` |
| `certificateauthority-root-2023-09-28.crl` | https://www.apple.com/certificateauthority/root.crl | `6bef4512c47108f231e99173e3a6f4a1cc1f919c51fda6e02ca33b6f97c40661` |

`appleca-root-2025-03-10.crl` is Apple Root CA's list with thisUpdate
2025-03-10 and nextUpdate 2025-07-23, signed sha1WithRSAEncryption, with
no CRL Number. Apple's PKI page still links it, while
http://crl.apple.com/root.crl serves a newer one, so the built-in list's
`newest` for Apple Root CA is later and this list is refused as older,
forever. Case: `revocation/refuse-apple-stale-root-list`.

`certificateauthority-root-2023-09-28.crl` names its issuer "Apple Root
Certificate Authority" (O "Apple Computer, Inc."), Apple Root CA's retired
name, and is signed by Apple Root CA's key with Apple Root CA's
keyIdentifier. No configured root has that subject, so no candidate
issuer exists and the list is refused. Its issuer Name also gives
`revocation/genuine-apple-retired-root-name-does-not-match` an issuer id
for Apple Root CA's key under the other name.

Both signatures were checked against `certs/AppleIncRootCertificate.cer`
when the files were added: the first with `openssl crl -verify`, the
second over its TBSCertList with the root's public key, since OpenSSL
finds no issuer by its name. Neither file is ever refreshed: a newer copy
from Apple would change what the cases pin.
