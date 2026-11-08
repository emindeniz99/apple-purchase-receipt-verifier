# Apple's revocation lists and what checking them takes, 2026-11-05

**Question.** What does Apple publish about revoked certificates on the
paths APRV verifies, in what form, how fresh, and how do Apple's own
libraries use it? The answers decide the shape of certificate revocation
in 0.14.0: [docs/design/revocation.md](../design/revocation.md) and
DECISIONS.md R47.

## Method

Everything ran or was read on 2026-11-05.

1. `fetch-lists.sh` downloaded every list on an APRV path, the same URLs over
   HTTPS, the two WWDR lists Apple never published, the two lists Apple's PKI
   page links, and the frozen WWDR G1 list. curl 8.5.0, OpenSSL 3.0.13 for
   `openssl crl -text`. The text dumps of six lists are in the sources folder.
2. `verify-lists.sh` checked each signature against the certificate in
   `certs/` (`openssl crl -verify`).
3. `ocsp-probe.sh` asked Apple's OCSP responder about the WWDR G6
   intermediate, without a nonce, with one, and with a SHA-256 CertID.
4. The certificates on Apple's chains were read with `openssl x509 -text`:
   the public sandbox receipt fixtures under `fixtures/` and the JWS chain
   from Apple's own library tests.
5. Apple's App Store Server Libraries were read at their `main` branches:
   Java 6bce52a, Node b71d9c7, Python e5ffded, Swift d4a9311 (with
   swift-certificates 5e9d180). Nothing of theirs ran.
6. OpenSSL 4.0.3's `crypto/x509/x509_vfy.c` was read for
   `X509_V_FLAG_CRL_CHECK`.

The scripts and dumps are in
[2026-11-05-apple-revocation-survey/](./2026-11-05-apple-revocation-survey/).

## Results

### Which list covers which certificate

| Certificate | Its revocation source |
|---|---|
| JWS leaf (Prod ECC Mac App Store and iTunes Store Receipt Signing, to 2027-10-13) | OCSP only (`ocsp03-wwdrg602`); no cRLDistributionPoints. Its issuer WWDR G6 signs `wwdrg6.crl`. |
| WWDR G6 | `http://crl.apple.com/applerootcag3.crl`, signed by Apple Root CA - G3 |
| Receipt leaf (public sandbox fixture, expired 2026-08-23) | `http://crl.apple.com/wwdrg5.crl`, and OCSP |
| WWDR G5 | `http://crl.apple.com/root.crl`, signed by Apple Root CA |
| Legacy receipt leaf under WWDR G1 | OCSP only; WWDR G1 expired 2023-02-07 and is not on `root.crl` |

So the four lists `root.crl`, `applerootcag3.crl`, `wwdrg5.crl` and
`wwdrg6.crl` cover every certificate below an anchor on today's paths, if
each leaf is judged by its issuer's list whether or not the leaf names one.

### The lists

| URL | Bytes | thisUpdate → nextUpdate | Entries | Notes |
|---|---|---|---|---|
| crl.apple.com/root.crl | 511 | 2026-08-25 → 2027-01-07 | 1 | `sha1WithRSAEncryption`, no CRL Number. Entry 3EDF4E5729AECD39, cessationOfOperation, 2024-12-12; not a WWDR intermediate |
| crl.apple.com/applerootcag3.crl | 323 | 2026-08-25 → 2027-01-07 | 0 | `ecdsa-with-SHA384`, CRL Number 56 |
| crl.apple.com/wwdrg5.crl | 526 | 2026-11-04 → 2026-11-18 | 0 | `sha256WithRSAEncryption`, CRL Number 1899, expiredCertsOnCRL 2020-12-16 |
| crl.apple.com/wwdrg6.crl | 1,226 | 2026-11-05 → 2026-11-19 | 18 | `ecdsa-with-SHA384`, CRL Number 2135, no expiredCertsOnCRL; all keyCompromise, revoked between February and October 2026 |
| www.apple.com/appleca/root.crl (linked from the PKI page) | 511 | 2025-03-10 → 2025-07-23 | 1 | Apple Root CA's list, eighteen months older than root.crl |
| www.apple.com/certificateauthority/root.crl (linked from the PKI page) | 505 | 2023-09-28 → 2024-02-10 | 0 | Issuer "Apple Root Certificate Authority" (O "Apple Computer, Inc."), Apple Root CA's retired name; same key and keyIdentifier as Apple Root CA |
| developer.apple.com/certificationauthority/wwdrca.crl (WWDR G1) | 2,296,869 | 2023-02-07 → 2023-02-21 | 56,006 | frozen; critical IssuingDistributionPoint naming its own URL; 18,267 keyCompromise entries |
| crl.apple.com/wwdrg3.crl, wwdrg4.crl | 182 | | | HTTP 404, although WWDR G3 and G4 are on the PKI page with the WWDR marker |

SHA-256 of the files the dumps were made from: root.crl
`14df0c60…c535f3`, applerootcag3.crl `e7491705…f7592c`, wwdrg5.crl
`c2e13057…e954c1`, wwdrg6.crl `212926d4…e1d7ef`, appleca/root.crl
`02b300d7…44f1dd`, certificateauthority/root.crl `6bef4512…c40661`, WWDR G1
`025fb48f…6005a2`. The two PKI-page lists are kept as shared-case inputs
under `fixtures/apple-crls/`.

None of the four current lists has an IssuingDistributionPoint, a
DeltaCRLIndicator or a FreshestCRL, and none uses an indirect entry.

**Signatures.** `verify-lists.sh` (rerun at 23:00 UTC): the four current
lists and appleca/root.crl verify under the expected certificate. The
retired-name list fails `openssl crl -verify` on its issuer Name; its
signature verifies under Apple Root CA's key over the TBSCertList
(`fixtures/apple-crls/README.md`).

**Transport.** `https://crl.apple.com/` answers 404 for all four lists, so
they are served over HTTP only; the signature is the only authentication.
The CDN sends `Cache-Control: max-age=3600, public` on all four.

**Cadence.** WWDR G6 is reissued daily (the built-in list recorded CRL
Number 2135, thisUpdate 2026-11-05 13:36). WWDR G5 too: its list was CRL
Number 1899 with thisUpdate 2026-11-04 21:46 in the morning fetch and 1900
with thisUpdate 2026-11-05 21:46 in the 23:00 rerun. Both WWDR lists are
valid for 14 days; the two root lists for about four and a half months.

**What is on them.** No certificate seen on a genuine App Store chain is
listed: the one Apple Root CA entry matches none of the serials of the
WWDR G2 to G6 certificates on Apple's PKI page (WWDR G1 is not on it
either, table above), WWDR G5's list is empty, and the current JWS
signing leaf (serial 47C287CDD9F9E7867F528ADA74DC7DB7, from Apple's library
tests) is not on WWDR G6's. A list carries only serials, so what the
eighteen WWDR G6 certificates were cannot be read from it. The built-in
list ships all nineteen entries the same (`certs/revocations.json`).

### OCSP

The JWS leaf carries only an OCSP URL, so OCSP was probed too
(`ocsp-probe.sh`, WWDR G6 at `http://ocsp.apple.com/ocsp03-applerootcag3`):

- A delegated responder signs ("Apple Root - G3 OCSP Responder", with the
  OCSPSigning EKU and ocsp-nocheck; the morning probe saw PG1 and PG2, the
  evening one MG2, each valid to 2027-01-06).
- Without a nonce the answer is pre-generated: in the morning it was about
  10.5 hours old, in the 23:02 rerun 41 minutes old, with a 12-hour window
  (thisUpdate to nextUpdate) both times.
- With a nonce the answer is produced on the spot.
- SHA-1 and SHA-256 CertIDs are both answered.
- Status: good.

### Apple's App Store Server Libraries

All four check revocation only with `enableOnlineChecks`, and only with
OCSP, on the leaf and the intermediate, never the root:

- Java: the JDK's PKIX revocation checker with `NO_FALLBACK` (OCSP only),
  date now, cache on (ChainVerifier.java:64-77, 105-112;
  SignedDataVerifier.java:206).
- Node: its own OCSP checker on leaf and intermediate in parallel
  (jws_verification.ts:237, 255-305).
- Python: its own OCSP checker, intermediate then leaf
  (signed_data_verifier.py:177, 231-233).
- Swift: `OCSPVerifierPolicy(failureMode: .hard, validationTime: now)`
  (ChainVerifier.swift:76, 137-147).

Common behaviour:

- With online checks on, the validity date becomes now, so an old JWS
  whose leaf has expired fails. Offline the date is `signedDate`, else an
  app transaction's `receiptCreationDate`, else now, as in APRV.
- Offline there is no revocation check at all.
- An unreachable responder or an UNKNOWN answer fails closed (a network
  error is retryable).
- Timeouts: Java 15 s, Node and Python 30 s, Swift 10 s.
- A leaf without an AIA fails in Java, Node and Python; Swift skips the
  check and passes.
- Answers are cached for 15 minutes, online mode only.
- Freshness skew: Java 15 minutes (and accepts a missing nextUpdate), Node
  and Python 60 seconds (nextUpdate required), Swift 75 minutes. Only
  Swift sends a nonce.

GHSA-8f6j-263m-g72x (published 2026-07-13, moderate, CWE-295/299): the
Python library's `check_ocsp_status` checked the responder's signature and
CertID but not producedAt, thisUpdate or nextUpdate, so a replayed stale
"good" answer was accepted forever. Affected 0.2.0 to 3.1.1, fixed in
3.1.2 (60 s skew, thisUpdate and nextUpdate required). OSV lists no
advisory for the npm, Maven or Swift packages; GitHub's advisory pages were
not reachable from the session, so that part is unconfirmed.

Apple's developer documentation for signed data (JWSDecodedHeader, the
`x5c` pages) gives no revocation guidance.

### OpenSSL's own CRL check

With `X509_V_FLAG_CRL_CHECK` OpenSSL judges a list's thisUpdate and
nextUpdate at the same verification time as the certificates
(`get_verification_time` and `ossl_x509_check_crl_time`, about lines
1481-1528). APRV sets that time to the payload's date
(`rust/openssl/src/path.rs`), so every historical payload would fail as
`CRL_NOT_YET_VALID`. It also verifies every list's signature on every call
(`check_crl`, about line 2131), and a list with an IssuingDistributionPoint
covers only certificates whose cRLDistributionPoints match it
(`crl_crldp_check`, about line 2019), which the JWS leaf has none of. Its
entry rule matches ours: any listed serial is revoked except
`removeFromCRL`, and the revocation date is ignored (`cert_crl`, about
lines 2138-2163).

### Context: a CA compromise elsewhere

eMudhra disclosed on 2026-10-20 that the keys of eight intermediate CAs were
compromised. Unity's CVE-2026-111943 (CWE-295) followed because UnityTLS
validates with OS roots but cannot check revocation; the remedies shipped
were OS and browser block lists and an explicit block in Unity
(https://unity.com/security/unity-emudhra-compromise). APRV is not affected
(pinned Apple roots only), but the remedies show what works when a key
leaks: a list the verifier carries, updated by a release, and a block a
deployer can add before the release.

## Verdict

What the design took from this:

- **Lists, not OCSP.** A CRL is a signed file a host can download on its own
  schedule and the core can check offline. OCSP needs a live call per check,
  and the JWS leaf's only source is OCSP. So the leaf is judged by its
  issuer's list (WWDR G6's), whether or not the leaf names it.
- **Four lists, four issuers.** The built-in issuers are Apple Root CA,
  Apple Root CA - G3, WWDR G5 and WWDR G6; G5 and G6 ship in
  `certs/revocation-issuers/`. G3 and G4 publish no list. G1's list is
  frozen and over the 1 MiB bound, so it is refused.
- **A built-in list**, because a fix that reaches every deployer must not
  depend on each one downloading anything. It is append-only because WWDR G6
  has no expiredCertsOnCRL and may drop an expired, revoked certificate.
- **Revocation ignores dates, and the clock stays the payload's.** Using
  OpenSSL's check, or moving the validity date to now as Apple's libraries
  do online, would fail every old payload.
- **Stale lists pass, with a reported deadline.** The lists come over plain
  HTTP from a CDN; failing closed on a stale list would turn an Apple CDN
  outage into an outage for every host. `revocationValidUntil` is the
  monitoring hook instead.
- **Refuse lists older than the built-in `newest`**, because Apple's own
  PKI page links a stale Apple Root CA list. **An issuer is a name and a
  key**, because the retired-name list is signed by Apple Root CA's key.
- **A distrust list** for deployers who learn of a revocation before a
  release, as Unity's explicit block did.

## Where this stops holding

- Lists, dates, CRL Numbers and entries are as of 2026-11-05 and move daily.
  `tools/refresh-apple-revocations.mjs --check`, run weekly by
  `apple-revocation-watch.yml`, is the living version of the list table.
- The library survey reads one commit of each library; Apple may change
  online mode at any time.
- The OCSP figures come from two probes of one certificate.
- HTTPS returning 404 on `crl.apple.com` was observed through one proxy,
  by these scripts and by `tools/refresh-apple-revocations.mjs` on the same
  day; Apple may enable it later.
