# Certificate revocation

Status: approved by the owner on 2026-11-05, implemented in 0.14.0.
Evidence: [docs/evidence/2026-11-05-apple-revocation-survey.md](../evidence/2026-11-05-apple-revocation-survey.md).

This is the contract the Rust core, the Java implementation, `aprv-server` and every package implement. Where a
package's idiom differs (names, nullability), the package README says how; the behaviour may not differ.

## 1. What it is for, and what it is not

APRV verifies offline against pinned Apple roots. Before 0.14.0 it never asked whether Apple had revoked a
certificate on the path, so a payload signed with a leaked Apple key, back-dated into the certificate's validity
window, verified until a release blocked it (THREAT-MODEL.md, "Certificate revocation").

0.14.0 adds three layers, all evaluated offline, inside the core and inside Java, with no network access:

| Layer | Source | Default |
|---|---|---|
| Built-in revocation list | `certs/revocations.json`, compiled in; append-only | always on, cannot be replaced or disabled |
| `distrust` | the caller's `Config` | empty |
| Live lists | Apple's CRL files that the caller downloads and passes to `Config` | off until lists are passed |

Departures from the reviewed plan v4, all from its third review round and approved with it: an issuer is identified
by name and key together (§2), a `certificateHold` entry on a live list counts only while that list is fresh (§3), and
a genuine list outside the supported profile is ignored rather than refused (§4).

Not in scope: OCSP; any HTTP client, timer or scheduler in a library; network access in the core; OpenSSL's
`X509_V_FLAG_CRL_CHECK` (it judges a CRL's freshness at the chain instant, which is the payload's date, and verifies
every CRL signature on every call); platform trust stores; refund, cancellation or entitlement state (a
`revocationDate` inside a transaction is Apple's business data, unrelated to certificate revocation).

## 2. Identifiers

- **Issuer id**: lowercase hex of SHA-256 over the concatenation of two encodings, taken byte for byte as they appear
  in the issuer certificate's TBSCertificate (never a re-encoding): its `subject` Name, then its
  `subjectPublicKeyInfo`. Name and key together, so
  that two CAs sharing one key under different names (Apple's retired "Apple Root Certificate Authority" and "Apple
  Root CA" do) are different issuers. Both implementations take the element's bytes as they appear in the input certificate: Rust the
  original bytes of the parsed name (`i2d_X509_NAME` returns the cached encoding) and of the key; Java the slices of
  the certificate's own TBS bytes, not `getEncoded("DER")`, which re-encodes (DER sorts the AVAs of a SET). A shared
  case pins a name whose RDN SET holds two AVAs in non-DER order.
- **Serial**: the certificate's serial number as an unsigned integer, written as uppercase hex with an even number of
  digits and no leading `00` pair unless the value is zero (`"00"`): `2` is `"02"`, `0x80` is `"80"`, zero is `"00"`
  (neither `BN_bn2hex` nor `BigInteger.toString(16)` gives that by itself; both implementations normalise). A
  negative serial is never matched. A CRL Number is written the same way (G6's 2135 is `"0857"`). Inputs (`distrust`) accept either letter case and an odd digit count and are normalised; the issuer id of a `distrust` entry is accepted in either letter case and lowercased. An empty serial, a `0x` prefix, a sign or whitespace is refused.
- A certificate's **revocation key** is (issuer id of the certificate above it on the verified path, serial).

## 3. The check

Runs once the path, the Apple markers and the signature have passed, and before the signed content is read or
decoded, so a payload signed with a revoked key is never judged (it cannot be made to answer `UNREADABLE_PAYLOAD`).
For a JWS: between the ES256 signature check and the payload verdict (rust/src/jws.rs, `JwsCore`). For a receipt:
inside the per-signer check, after that signer's CMS signature (rust/src/receipt.rs, `ReceiptCore`), so a receipt
with several SignerInfos verifies when another signer verifies, as today; when none does, the failure reported is the
one the existing rule picks. Every existing case keeps its verdict and reason.

For each certificate C on the verified path that is not the trust anchor, with issuer I above it on that path:

1. If (issuer id of I, serial of C) is in the built-in list or in `distrust`: **`CERTIFICATE_REVOKED`**.
2. If a live list is held for the issuer id of I and lists serial(C):
   - reason `removeFromCRL`: not revoked;
   - reason `certificateHold`: revoked only while that list is fresh at the call's `now` (`now ≤ nextUpdate`);
   - any other reason, or no reason: **`CERTIFICATE_REVOKED`**, whatever the list's freshness, the entry's
     `revocationDate` and `invalidityDate`.
3. Otherwise C is not revoked. A missing list, or a stale one, does not fail the call (owner, 2026-11-05: no outage);
   `revocationValidUntil` exposes it.

Time: a certificate's validity window is judged at the payload's date, as before (receipt creation date; JWS
`signedDate`, else `receiptCreationDate`, else the clock). Revocation ignores dates on purpose: whoever holds a leaked
key chooses the payload's date, so "signed before the revocation" cannot be trusted. The anchor is never checked:
removing a root is done with `roots`.

`CERTIFICATE_REVOKED` is the ninth reason. Its message names the layer (built-in list, distrust, Apple's list) and
the serial, and nothing from the input beyond that. The wording is not part of the contract: the core writes
"revoked: built-in list, serial …", Java "… certificate with serial … is revoked: built-in list". The endpoint emulation
answers 21003 for it, as for the other certificate failures; no new endpoint status exists.

## 4. Configuration

| Setting | Type | Meaning |
|---|---|---|
| `revocationLists` | list of bytes | CRL files exactly as downloaded (DER), any order. Default empty. |
| `revocationIssuers` | list of certificates, in the same form as `roots` | CA certificates that sign lists, added to the built-in ones (§6). Default empty. |
| `distrust` | list of `{issuer, serial}` | Revocation keys to refuse (§2). Default empty. At most 1,000. |

Building the configuration (the `Config` builder, the module's `init`, `aprv-server` start-up) fails, naming the
first problem and its index, when:

Which problem is named when there are several is not part of the contract: the core checks the lists (count, then
each list's size, DER and running entry total, then each list's issuer, signature and age), then added issuers, then
`distrust`; Java checks `distrust` first. Only whether the configuration builds is pinned (DECISIONS.md R47).

- a list is not a DER CRL, is over 1 MiB, or there are more than 16 lists or more than 100,000 entries in all (Apple's
  frozen 2.3 MB WWDR G1 list, still linked from the PKI page, is refused here);
- no candidate issuer verifies it. Candidates are every configured root and authenticated issuer (§6) whose `subject`
  is byte-identical to the list's `issuer` Name, and, when the list has an AuthorityKeyIdentifier, whose
  SubjectKeyIdentifier equals its keyIdentifier (a candidate without a SubjectKeyIdentifier is then not a
  candidate; an AuthorityKeyIdentifier without a keyIdentifier, or one that is repeated or does not read, refuses
  the list). The list belongs to the first
  candidate, in configuration order (roots, then built-in issuers, then added issuers), whose key verifies its
  signature. A SHA-1 signature is accepted: Apple Root CA's list is `sha1WithRSAEncryption`, and the signer is
  pinned. Apple's retired "Apple Root Certificate Authority" list shares Apple Root CA's key but not its name, so it
  is refused;
- a list is older than the newest list the built-in file records for that issuer (§5, `newest`): lower CRL Number, or,
  when either lacks a number, earlier `thisUpdate`. This refuses the stale `www.apple.com/appleca/root.crl` (2025)
  that Apple's PKI page still links;
- a `revocationIssuers` certificate does not chain to a configured root, or is itself revoked (§6);
- a `distrust` entry is not a 64-hex-digit issuer id plus a hex serial, or there are more than 1,000.

A list that is genuine but uses something this profile does not support is **ignored**, not refused, so a format
change at Apple cannot stop a host from building a verifier: version 1, no `nextUpdate`, an
IssuingDistributionPoint, a DeltaCRLIndicator, a FreshestCRL, an indirect entry (certificateIssuer), any other
critical CRL or entry extension, a duplicate serial, a CRL Number that is negative or does not read. "Other" means:
critical is allowed only on the AuthorityKeyIdentifier and the CRL Number of a list, and on the reasonCode and the
invalidityDate of an entry. An ignored list counts as missing in `revocationValidUntil` and takes no part in choosing
the list kept for its issuer; it is still refused when it is older than `newest`, and a CRL Number that is negative or
does not read counts as no number there. An entry whose reasonCode is unknown (7, or above 10) or does not read
revokes. An extension that appears twice does not read: a repeated CRL Number puts the list outside the profile, a
repeated reasonCode revokes, and a repeated extension the profile does not read changes nothing beyond what one copy
would. Only the AuthorityKeyIdentifier, the CRL Number and the reasonCode are decoded; the value of any other
extension is never read.

Several lists for one issuer: the one kept has the highest CRL Number; if any of them lacks a number, the latest
`thisUpdate`; on a tie, the one whose DER sorts first byte by byte. Lists are never merged.

## 5. The built-in list

`certs/revocations.json` is the source; `rust/certs/revocations.json` is the compiled copy
(`tools/check-cert-copies.mjs` diffs every file of `certs/`); `rust/src/roots.rs` pins its SHA-256 the way it pins
the roots; Java keeps the same JSON as a constant (`AppleRevocations`, one string per line, with the WWDR G5 and G6
certificates as base64), pinned byte for byte to `certs/` by `RevocationTest`. Format:

```json
{
  "comment": "...",
  "issuers": [
    { "id": "<issuer id>", "name": "Apple Worldwide Developer Relations Certification Authority G6",
      "certificate": "certs/revocation-issuers/AppleWWDRCAG6.cer", "list": "http://crl.apple.com/wwdrg6.crl",
      "newest": { "crlNumber": "<hex>|null", "thisUpdate": "2026-11-05T13:36:46Z" } }
  ],
  "revoked": [
    { "issuer": "<issuer id>", "serial": "37D3...", "reason": "keyCompromise", "revocationDate": "2026-03-06T23:59:00Z",
      "crlNumber": "<hex>|null" }
  ]
}
```

- An entry may also carry `"delisted": {"crlNumber": ..., "thisUpdate": ...}`, naming the first list of its issuer
  that no longer lists it. The tool writes it; the entry still revokes, and both implementations ignore the member.
- `issuers` holds Apple Root CA, Apple Root CA - G3, WWDR G5 and WWDR G6 (the four whose lists exist and can sit on an
  APRV path). `certificate` is null for a root (the root's file in `certs/` is used). `list` is the URL of the list
  that issuer signs.
- `revoked` is append-only: an entry is never removed, also when Apple drops it from a later list (the WWDR G6 list
  has no `expiredCertsOnCRL`, so an expired, revoked certificate may disappear from it). `certificateHold` and
  `removeFromCRL` entries are not added.
- `tools/refresh-apple-revocations.mjs` writes it: it downloads each issuer's `list` over HTTPS (HTTP when Apple does
  not serve HTTPS, which on 2026-11-05 is all four: `crl.apple.com` answers 404 over HTTPS; the signature, not the
  transport, authenticates it), verifies it with `openssl crl -verify` against the issuer certificate from `certs/`,
  refuses anything outside the §4 profile, and appends new entries and `newest`. It writes `certs/revocations.json`,
  its copy in `rust/certs/`, the copy's SHA-256 pin in `rust/src/roots.rs` and Java's `AppleRevocations.JSON_LINES`
  together: a change to one without the others makes the core refuse the built-in list and Java's tests fail. A weekly
  workflow
  (`apple-revocation-watch.yml`) runs it with `--check` and fails, so the owner is notified, when a new entry, a
  vanished entry not yet marked `delisted`, a reappearing entry, a changed reason, a refused list, or a WWDR
  intermediate not in `issuers` appears on Apple's PKI page (https://www.apple.com/certificateauthority/); a newer
  list alone is reported in the job summary, not a failure (WWDR G6's list is reissued daily), and so are
  `certificateHold` and `removeFromCRL` entries. WWDR G3 and G4 carry the marker but have no list (their URLs answer
  404); the tool names them as known exclusions. The owner runs the tool and opens the pull request; a release ships
  it.
- `rust/certs/` mirrors `certs/` recursively (`revocation-issuers/`, `revocations.json`); `tools/check-cert-copies.mjs`
  walks subdirectories; tests that list root certificates (`rust/server/src/roots.rs` `DEFAULT_ROOT_SHA256`) read
  only the top-level `.cer` files.
- Shipped content on 2026-11-05: nineteen entries (one on Apple Root CA's list, eighteen on WWDR G6's). None is a
  certificate seen on a genuine App Store chain: the Apple Root CA entry is not a WWDR intermediate on an APRV path,
  and the current JWS signing leaf and the receipt signers in `fixtures/` are not listed. A list carries only
  serials, so what the WWDR G6 certificates were is not known.

## 6. Issuers of lists

The built-in issuers are the WWDR G5 and G6 intermediates, kept in `certs/revocation-issuers/` (public Apple
certificates, pinned by SHA-256 in `rust/src/roots.rs` and in Java), plus the configured roots themselves.
`revocationIssuers` adds more, for a new Apple intermediate before a release knows it, or for a test PKI.

An issuer certificate is accepted when, with no clock (the module's `init` has none): its `issuer` Name is
byte-identical to a configured root's `subject` (as a list is matched to its candidates in §4, not compared in
canonical form) and that root's key verifies its signature; it is a CA (basicConstraints cA true); its
keyUsage, when present, has `cRLSign`; it carries the WWDR intermediate marker `1.2.840.113635.100.6.2.1`. Its
validity dates are not judged here: a list it signed is used only for certificates it issued on a path that was
already judged at its payload's date. An issuer whose own revocation key (§2, under the root that signed it) is in
the built-in list, in `distrust`, or on a held list of that root (any reason except `removeFromCRL`; with no clock, a
`certificateHold` counts) is not accepted. An issuer whose serial is negative has no revocation key that can match
(§2), so it is accepted and nothing revokes it. A built-in issuer that does not
chain to the configured roots (custom roots, a test PKI), or is revoked, is dropped silently; an added one is
refused (§4).

## 7. What a verifier reports

- `revocationUrls()`: the `list` URLs of the built-in issuers that chain to the configured roots, then the
  cRLDistributionPoints URIs (http and https only) of added issuers, de-duplicated, in that order. With the default
  roots: `http://crl.apple.com/root.crl`, `http://crl.apple.com/applerootcag3.crl`,
  `http://crl.apple.com/wwdrg5.crl`, `http://crl.apple.com/wwdrg6.crl`. An added issuer's own list URL cannot be
  known (Apple names it only on the leaves it signs); the README says to add it by hand.
- `revocationValidUntil()`: the earliest `nextUpdate` among the lists held for the expected issuers (the issuers of
  `certs/revocations.json` that are, or chain to, a configured root, plus added issuers), or null when any expected
  issuer has no list held (none passed, ignored, or refused). A caller's own root is a candidate signer of lists but
  never an expected issuer, so under custom roots with nothing added there is none to expect and the value is null
  (and `revocationUrls()` is empty). Null means "live revocation is not fully in force"; a date in the past means a
  list is stale. Monitoring alerts on either.

## 8. Wire format (no WIT type change)

`init`'s JSON gains optional members: `"revocation_lists": [base64...]`, `"revocation_issuers": [base64 of DER or
PEM...]`, `"distrust": [{"issuer": "...", "serial": "..."}]`. Its answer gains, when `ok` is true:
`"revocation_urls": [...]` and `"revocation_valid_until_ms": N|null`. Every wrapper reads both from the answer; no
wrapper parses a certificate or a list. `aprv:verifier@0.2.0` keeps its version: only `///` lines of the WIT change.
The reason travels as `"CERTIFICATE_REVOKED"`.

`aprv-server`: `--revocation-list FILE` and `--revocation-issuer FILE` (repeatable), `--distrust ISSUER:SERIAL`
(repeatable); in `--managed` mode the configuration line is one JSON object with the same members as `init`
(`Roots::from_config_json` reads them), and its cap rises from 1 MiB to 32 MiB (base64 of 16 lists of 1 MiB, plus
roots and issuers). `read_init_config` accepts the new members. `GET /v1/info` adds
`revocation_urls`, `revocation_valid_until_ms`, `revocation_lists` (the SHA-256 of each list given, sorted: `init`'s
answer does not say which lists the core kept, so ignored ones are included), `revocation_issuers` (the SHA-256 of
each added issuer's DER, in order) and `distrust` (the entries as given, in order), so the Java `-wasm` artifact's
server mode and PHP can refuse a server whose revocation settings differ from their `Config`, as they already do for
roots. `aprv info` takes `--roots` and the three revocation flags and prints the same members, which is how PHP's
one-process-per-call transport reads the two reported values. A server picks up new lists by restarting (or by a new
managed child). The C ABI gains only the reason (code 17); it has no way to pass revocation settings.

## 9. Packages

Each package adds the three settings to its `Config` in its own idiom, the two read-only properties on its
`Verifier`, and the ninth reason. `revocationIssuers` takes the same type as that package's `roots` (Go
`[]*x509.Certificate`, .NET and Java certificates, bytes elsewhere); `distrust` takes a small value type or pair of
strings; `revocationValidUntil` is nullable in the package's idiom (Go: `(time.Time, bool)`; .NET:
`long? RevocationValidUntilMs`, epoch milliseconds like the package's other dates). Refresh is: build a
new `Verifier` and swap the reference; no package adds a setter, a timer or an HTTP client.

## 10. Tests

- `fixtures/cases.json` moves to `schemaVersion` 3 and `CERTIFICATE_REVOKED` joins both reason enums of the schema;
  every package's runner changes in the PR (Swift asserts the operations it covers). `verifyConfig` and
  `endpointConfig` gain an optional `revocation` object
  (`lists`, `issuers`: fixture ids; `distrust`: entries), and a new operation `buildConfig` asserts that a
  configuration builds or fails, and the two reported values. Fixtures come from the Java test PKI generator (a test
  root, a WWDR-marked test intermediate, test lists), committed under `fixtures/generated-0.7/`.
- Cases cover at least: leaf and intermediate revoked through a list, through `distrust`, and through both; a stale
  list still revokes; a stale or missing list passes an unlisted chain; `certificateHold` fresh and stale;
  `removeFromCRL`; one list kept per issuer by CRL Number and by `thisUpdate`; refused lists (not a CRL, bad
  signature, unknown issuer, AKI mismatch, over a bound); older than `newest`, with Apple's real stale
  `www.apple.com/appleca/root.crl` (thisUpdate 2025-03-10, refused forever because `newest` only advances); Apple's
  real `www.apple.com/certificateauthority/root.crl` (same key, other name: refused); a SHA-1-signed test list; ignored lists (v1, no `nextUpdate`,
  IDP, delta, critical CRL extension, critical entry extension, indirect entry, duplicate serial, a CRL Number that is
  repeated, negative or does not read); a reasonCode that is repeated or does not read (revokes); a repeated unknown
  extension (held); an issuer held, or removed, on its root's list; an issuer whose `issuer` Name spells its root's
  subject in another string type (refused); issuer id parity
  (same key under two names); serial normalisation (`"2"`, `"02"`, `"0080"`); `revocationUrls` and
  `revocationValidUntil` with default and custom roots; the endpoint answering 21003; a JWS whose revoked leaf signs
  a non-JSON payload (`CERTIFICATE_REVOKED`, not `UNREADABLE_PAYLOAD`); a receipt with two SignerInfos, the first
  revoked, the second genuine (ok); two configured roots with one subject and a list without an AKI; a `distrust`
  entry naming the anchor's key (builds, never matches); a stale list for an issuer on no path
  (`revocationValidUntil` in the past, verify ok); an added issuer that is revoked (refused); serial zero and a
  serial whose DER is `00 80`.
- Every package runs every case. Rust tests inject a built-in list through a test-only constructor; Java the same.
- Not shared cases, because the inputs would be too large for `fixtures/` or need an injected built-in list: the
  1 MiB list size, the 100,000-entry total, more than 1,000 `distrust` entries, and a test list older than `newest`.
  Each is a unit test in Rust (`rust/tests/revocation.rs`) and Java (`RevocationTest`); the shared cases cover the
  16-list count and Apple's real stale list.
- The non-DER name case puts the name on a trust anchor: BouncyCastle re-encodes a TBSCertificate before checking its
  signature, so Java cannot verify a certificate below the anchor whose Name is not DER (DECISIONS.md R47).
- The parity corpus must not flip a verdict (no corpus input is on a list).

## 11. Limits, stated

- The built-in list reaches a consumer at the speed of releases and upgrades.
- `distrust` helps only a consumer who learns of a revocation.
- With stale lists passing, a network attacker who keeps feeding an old (but newer-than-`newest`) list reduces the
  live layer to the built-in list; only `revocationValidUntil` monitoring sees it. Fetch over HTTPS where Apple serves
  it (on 2026-11-05 it serves none of the four lists over HTTPS).
- Apple's lists come from a CDN that answers with `Cache-Control: max-age=3600`; a revocation reaches a host about a
  day after Apple lists it, at the earliest.
