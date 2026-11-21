# Apple revocation survey sources (2026-11-05)

These back [../2026-11-05-apple-revocation-survey.md](../2026-11-05-apple-revocation-survey.md).

| File | What it answers |
|---|---|
| `fetch-lists.sh` | Which Apple revocation lists exist, over which scheme, how large, how long the CDN caches them, and their header fields. Downloads to `$SCRATCH/crls`, never into the repository. `G1=1` adds the frozen WWDR G1 list. |
| `verify-lists.sh` | Whether each list verifies under the Apple certificate in `certs/` that should have signed it. |
| `ocsp-probe.sh` | What Apple's OCSP responder answers for WWDR G6: who signs, how old a response is without a nonce, and with one. |
| `crl.apple.com_root.crl.txt` | `openssl crl -text` of Apple Root CA's current list (http://crl.apple.com/root.crl). All six were fetched on 2026-11-05 between 14:41 and 15:40 UTC. |
| `crl.apple.com_applerootcag3.crl.txt` | The same for Apple Root CA - G3 (applerootcag3.crl). |
| `crl.apple.com_wwdrg5.crl.txt` | The same for WWDR G5 (wwdrg5.crl), CRL Number 1899. |
| `crl.apple.com_wwdrg6.crl.txt` | The same for WWDR G6 (wwdrg6.crl), CRL Number 2135, eighteen entries. |
| `www.apple.com_appleca_root.crl.txt` | The stale Apple Root CA list Apple's PKI page links (thisUpdate 2025-03-10). |
| `www.apple.com_certificateauthority_root.crl.txt` | The list under Apple Root CA's retired name, "Apple Root Certificate Authority" (thisUpdate 2023-09-28). |

The text dumps are public Apple data: a CA's list names certificates by
serial, not users or purchases. The DER files themselves are not kept here;
the two stale lists are shared-case inputs under `fixtures/apple-crls/`, and
the note records each file's size and SHA-256. The WWDR G1 list
(2,296,869 bytes, about 10 MB as text) is described in the note only.

## Reproduce

```sh
E=$REPO/docs/evidence/2026-11-05-apple-revocation-survey
SCRATCH=$SCRATCH bash $E/fetch-lists.sh
REPO=$REPO SCRATCH=$SCRATCH bash $E/verify-lists.sh
REPO=$REPO SCRATCH=$SCRATCH bash $E/ocsp-probe.sh
```

Apple reissues the WWDR lists daily, so a rerun gives later dates and CRL
Numbers. Apple's PKI page is https://www.apple.com/certificateauthority/;
`tools/refresh-apple-revocations.mjs --check` reads it and the four lists
the same way the weekly `apple-revocation-watch` workflow does.
