# Threat model

What this library defends against, by what mechanism, and which test proves
each line. The security-reviewer's view of the algorithms in
[PLAN.md](./PLAN.md) §2 and the decisions in PLAN.md §0. Reporting a
vulnerability: [SECURITY.md](./SECURITY.md). Why the project exists and what
verification does *not* prove: [INTENT.md](./INTENT.md). Vectors are cited by
id from [`fixtures/cases.json`](./fixtures/cases.json), the language-neutral
conformance file all nine ports run; where no shared vector exists a per-port
test file is cited and the gap is named.

## 1. Assets and trust boundaries

The library is a pure function from bytes to a verdict. It opens no socket,
reads no file at verification time, and consults no operating-system trust
store (PLAN.md D12, D16). Assume every byte of the following is chosen by the
attacker:

| Input | Entry point |
|---|---|
| A legacy PKCS#7 receipt, as the base64 string a client sends as `receipt-data` | `Verifier.verifyReceipt(base64)` |
| Compact JWS (transaction, app transaction, renewal info, notification) | `Verifier.verifySignedData(jws)` |
| The `x5c` chain, and the certificates in a receipt's CMS `SignedData` | reached from the above |
| A whole `verifyReceipt` JSON request body | `Verifier.verifyReceiptEndpoint(environment, requestJson)` |

Trusted input comes from the integrator, not the network: the three pinned
Apple roots in [`certs/`](./certs) (PLAN.md D15; each port bundles its own
copy and never reads it from disk at call time), or roots the caller puts in
its `Config` instead at their own risk (PLAN.md D12); and the `Config` clock,
used for the chain instant only when the payload carries no usable date of
its own, and for `request_date` at the endpoint. Nothing trusted derives from anything
attacker-controlled. The third certificate in `x5c` in particular is parsed
but never trusted: only the intermediate being signed by a pinned anchor
counts (PLAN.md §2.1 step 4).

## 2. Attacker goals

1. **Forge a purchase**: get back a payload Apple never signed.
2. **Reuse a genuine payload**: someone else's receipt, or one for another app.
3. **Downgrade the environment**: a sandbox or Xcode purchase taken as production.
4. **Replay a stale payload** after the entitlement it describes has ended.
5. **Deny service**: burn CPU or memory on a small input.
6. **Make the ports disagree**, then route the input to the accepting backend.

## 3. Mitigations

### 3.1 Trust is pinned, and only pinned

Chain validation terminates at anchors the caller handed in, and no port links
a code path that can reach the platform store or the network. PLAN.md D16
lists that as one reason the readers are hand-written.

*Proof.* `transaction/reject-foreign-root`, `receipt/reject-foreign-root`
(both `UNTRUSTED_CHAIN`), `endpoint/foreign-root-answers-21003`, and Apple's own
Xcode receipts rejected against the real roots
(`receipt/reject-xcode-app-receipt-against-apple-roots`,
`receipt/reject-xcode-signed-public-receipt`). That the OS store is
*unreachable* is asserted per port, by planting a CA the platform accepts and
requiring rejection anyway: `go/systemtrust_test.go`,
`python/tests/test_trust_isolation.py`,
`swift/Tests/ApplePurchaseReceiptVerifierTests/TrustStoreIsolationTests.swift`,
`rust/tests/trust_pinning.rs`, `php/tests/PinnedAnchorsTest.php`,
`ruby/test/hostile_input_test.rb`, `node/test/trust-store-isolation.test.js`,
`java/src/test/.../TrustStoreIsolationTest.java`.

### 3.2 Marker OIDs stop the wrong-purpose certificate

Chaining to a pinned Apple root is not enough: any Apple developer's own
distribution leaf chains through the same WWDR intermediate. So the JWS leaf
must carry `1.2.840.113635.100.6.11.1` and the intermediate
`1.2.840.113635.100.6.2.1` with `CA: true`, and the receipt signer leaf must
carry `1.2.840.113635.100.6.11.1` and, since 0.7, its intermediate
`1.2.840.113635.100.6.2.1` as well. Both are checked after chain validation
so a foreign chain still reports `UNTRUSTED_CHAIN` first (PLAN.md D13, §2.1
step 3, §2.2 step 3). *Proof:* `transaction/reject-leaf-without-apple-marker-oid`,
`transaction/reject-intermediate-without-wwdr-marker-oid`,
`receipt/reject-signer-without-receipt-signing-oid` and
`receipt/reject-intermediate-without-wwdr-marker-oid`, all
`INVALID_CERTIFICATE_PURPOSE`.

### 3.3 Signature over the exact bytes; the claims are the caller's

ES256 over `ASCII(header + "." + payload)` for JWS. For receipts, the CMS
signature over the content. Since 0.7 (#160) no port restricts the signer's
key type, digest or signature algorithm (owner decision: a signer pinned to
an Apple root and carrying Apple's marker is trusted whatever it signs with,
so a change on Apple's side cannot reject genuine receipts; an RSA signature
binds its hash algorithm in the DigestInfo, and a weak hash helps only an
attacker holding an Apple signature over it). No port re-encodes the input
first: the readers keep input slices, one reason library parsers that
normalise to DER were rejected (PLAN.md D16).

Since 0.7 the library checks no claim. Bundle id, environment, app Apple id
and device binding are the caller's to compare on the payload it gets back
(docs/design/0.7-api.md, Principles), so attacker goals 2 and 3 of §2 are
defeated in the caller's code, and the library's part is to return exactly
what Apple signed. Each port README lists those checks; the environment
check accepts a set, because App Review runs production builds against
sandbox (PLAN.md D3).

A legacy receipt is verified in a fixed order, the same in all nine ports:

1. Decode the base64 and parse the CMS. Bad base64, trailing bytes, absent
   content, no `SignerInfo` or more than four are `MALFORMED`.
2. Read the receipt creation date, attribute 12, and nothing else: walk the
   top-level attribute SET, read each entry's type, decode only the value of
   the first type 12. No usable date means the chain is judged at the
   `Config` clock. This step never rejects.
3. Build the chain top-down from the pinned roots at that instant, with each
   certificate's validity window, then check the marker OIDs on the signer
   and the WWDR intermediate (`UNTRUSTED_CHAIN`, `INVALID_CERTIFICATE`,
   `INVALID_CERTIFICATE_PURPOSE`).
4. Check the CMS signature with the now-trusted signer key
   (`INVALID_SIGNATURE`); at least one `SignerInfo` must verify.
5. Parse the whole payload. A failure here is `UNREADABLE_PAYLOAD`.

Nothing is trusted before steps 3 and 4, so step 2 reads as little as it
can and blames no one: an unreadable date only moves the chain instant to
the clock. The chain comes before the signature on purpose. Checking the
signature first would run the attacker's own key, with an RSA size and
exponent the attacker chose, before anything about that key is trusted,
which is CPU spent on demand for free. A failure in step 5 means a trusted
signer signed content this library cannot read: a gap in the library or a
format Apple added, not a defect of the client's request. It is therefore
`UNREADABLE_PAYLOAD`, status 21009 at the endpoint, and never `MALFORMED`,
whose 21002 would tell an app server to deny a paying user. An integrator
should alert and escalate on it, not deny.

A JWS follows the same rule. Before the signature only `signedDate` is read,
to pick the chain instant. A payload that is not a JSON object is carried
past the chain and signature checks: `INVALID_SIGNATURE` if the signature
fails, `UNREADABLE_PAYLOAD` if it verifies. After that nothing is read:
`verifySignedData` returns the payload JSON as signed, so a claim of an
unexpected type is a question for the caller's parser, not a verdict. A
runtime that lacks an algorithm no input chooses (a PKIX implementation) is
`INTERNAL_ERROR`. A key or signature algorithm the certificate names keeps
its input reason, because a missing algorithm and a hostile certificate
cannot be told apart there.

*Proof.* Tampering: `transaction/reject-tampered-payload` and
`receipt/reject-tampered-payload`, both `INVALID_SIGNATURE`. Order:
`receipt/reject-unreadable-creation-date-under-a-foreign-chain` (the chain
answers, not the payload), `receipt/unreadable-creation-date-decodes-to-null`,
`receipt/reject-unreadable-entry-under-a-trusted-chain`,
`receipt/reject-empty-encapsulated-content`,
`receipt/unreadable-payload-under-a-valid-signature` and the two
attribute-type ceilings (all `UNREADABLE_PAYLOAD`),
`receipt/unreadable-payload-under-a-broken-signature` (`INVALID_SIGNATURE`),
and `endpoint/unreadable-payload-answers-21009`. JWS:
`signed-data/unreadable-json-array-payload` and
`signed-data/unreadable-empty-payload`, and the six claim-type cases such as
`transaction/return-bundle-id-claim-as-a-number`, which verify and return
the payload as signed, with `raw/return-claims-of-any-type`. The claims left
to the caller, returned rather than judged (tag `policy-flip`):
`transaction/return-bundle-id-for-the-caller`,
`receipt/return-bundle-id-for-the-caller`,
`transaction/return-apple-official-wrong-bundle-id` (Apple's own negative
fixture), `transaction/return-environment-for-the-caller` and
`app-transaction/return-app-apple-id-for-the-caller`.

### 3.4 Environment routing fails closed

At the `verifyReceipt`-compatible endpoint only `Production` and
`ProductionVPP` receipt types count as production. Sandbox variants,
`ProductionVPPSandbox` included, `Xcode`, and a missing attribute all route as
non-production (PLAN.md D10), a tightening driven by a VPP-sandbox misroute
found in adversarial review. *Proof:* the `endpoint/*` routing cases,
including `endpoint/vpp-sandbox-receipt-on-production-answers-21007`,
`endpoint/vpp-receipt-on-sandbox-answers-21008` and
`endpoint/missing-receipt-type-on-production-answers-21007`.

### 3.5 Time: validity at signing time, freshness left to the caller

Apple's signing certificates rotate, so a receipt signed under a since-expired
certificate is still genuine. The validity window is checked at the payload's
`signedDate` or the receipt's creation date, falling back to the `Config`
clock when the input carries neither (docs/design/0.7-api.md, Setup). For a
receipt, a creation date that is empty, outside the exact
`YYYY-MM-DDTHH:MM:SSZ` grammar, or sits beside a top-level entry the walk
cannot read counts as carried by nothing, and the chain is judged at the
clock; a repeated attribute 12 uses its first copy. A JWS `signedDate` that
is not a representable instant falls back to the clock the same way. No
verifier judges how old a genuinely signed payload may be: that limit
depends on the endpoint (Apple retries a server notification for days, and
a device may present an old but genuine payload), so the caller applies it
to `signedDate` or the receipt creation date, as Apple's own App Store
Server Libraries leave it to their callers (PLAN.md D5). A freshness limit
would not be replay protection either.

*Proof.* Signing-time validity, accepted then rejected:
`transaction/accept-historical-payload-under-expired-chain`,
`receipt/accept-historical-creation-date-under-expired-chain`,
`transaction/reject-fresh-payload-under-expired-chain`,
`receipt/reject-fresh-creation-date-under-expired-chain`. An unusable
creation date judged at the clock: `receipt/accept-missing-creation-date`,
`receipt/unreadable-creation-date-decodes-to-null`,
`receipt/creation-date-outside-the-grammar-leaves-the-chain-to-the-clock`,
`receipt/reject-unreadable-creation-date-under-an-expired-chain` and
`receipt/reject-unreadable-entry-under-an-expired-chain`; the trusted test
PKI they use is valid 2024-01-01 to 2050-01-01 and the expired one 2020-01-01
to 2021-01-01, so every answer is fixed until 2050. The first copy of a
repeated date: `receipt/creation-date-twice-uses-the-first`. A dateless
payload judged at the clock, both directions:
`transaction/reject-dateless-payload-under-an-expired-chain`,
`transaction/accept-payload-without-a-signed-date`, and
`transaction/signed-date-out-of-range-falls-back-to-the-clock`. The clock
moves the verdict of a dateless receipt, both directions:
`endpoint/clock-inside-the-window-verifies-a-dateless-receipt`,
`endpoint/clock-past-the-window-rejects-a-dateless-receipt`.

### 3.6 Device binding, when the caller has the device id

Since 0.7 the library takes no device id and checks no device hash. It
returns `opaqueValue`, `sha1Hash` and `bundleIdBytes` as the octets Apple
signed, so a caller holding the device id compares
`SHA1(deviceId ‖ opaqueValue ‖ bundleIdBytes)` with `sha1Hash` itself; each
port README shows it (PLAN.md D4). Optional because requiring it forces a
client change; sound because each device carries its own receipt with its
own id. *Proof:* `receipt/return-device-hash-inputs` pins the three octet
strings the hash is computed from.

### 3.7 Hostile bytes: bounds, no unbounded recursion, no trailing garbage

Every port applies the same bounds (docs/design/0.7-api.md, Bounds): ASN.1
nesting depth 32, counted in each value parsed on its own; JSON depth 64; at
most 10 certificates embedded in a receipt and 4 SignerInfos; and fixed
input caps of 3,145,728 UTF-8 bytes for receipt base64 and request bodies
and 262,144 for a JWS. Readers refuse bytes after the outermost value.
Before the signer is trusted the payload is read only as far as attribute
12 (§3.3), so the attacker's bytes reach the full payload grammar only
under a trusted signature; a bound hit there is `UNREADABLE_PAYLOAD`, since
only a trusted signer could have put the bytes in front of it. Several
ports also cap the decoded node count. Failures surface as the library's
own result, never as a language-level crash.

*Proof.* Trailing bytes: `parse_exact` in `rust/src/asn1.rs`,
`ErrTrailingBytes` in `go/internal/der/der.go`, `node/src/der.ts`.
Amplification, size bounds and certificate flooding:
`go/internal/der/amplification_test.go`, `go/sizebound_test.go`,
`php/tests/MemoryExhaustionTest.php`, `php/tests/ResourceBoundsTest.php`,
`ruby/test/certificate_flood_test.rb`. Depth, as shared vectors:
`receipt/unreadable-signed-content-nested-33-deep` and
`signed-data/unreadable-payload-nested-65-deep`.
Hostile-input suites: `java/src/test/.../HostileReceiptInputTest.java`,
`php/tests/HostileInputTest.php`, `ruby/test/hostile_input_test.rb`,
`node/test/hostile-input.test.js`. Malformed structure, as shared vectors:
`receipt/reject-attribute-type-above-int32-max`,
`receipt/reject-attribute-type-that-truncates-to-a-modelled-type`,
`transaction/reject-x5c-leaf-that-is-not-a-certificate`,
`transaction/reject-x5c-root-that-is-not-a-certificate`,
`transaction/reject-apple-official-missing-x5c`. Defective certificates, on
both paths: `transaction/reject-x5c-certificate-version-11`,
`transaction/reject-x5c-duplicate-extension`,
`transaction/reject-x5c-corrupt-extension`,
`transaction/reject-x5c-unimplemented-curve`, and their receipt twins
`receipt/reject-signer-certificate-version-11`,
`receipt/reject-signer-carrying-one-extension-twice`,
`receipt/reject-signer-with-a-corrupt-extension`,
`receipt/reject-signer-on-an-unimplemented-curve`.

*Fuzzing.* Coverage-guided targets run in CI over the readers and the public
entry points: [`rust/fuzz/README.md`](./rust/fuzz/README.md) (seven targets),
[`node/fuzz/README.md`](./node/fuzz/README.md) (six),
[`dotnet/fuzz/README.md`](./dotnet/fuzz/README.md) (five),
[`go/fuzz_test.go`](./go/fuzz_test.go) (three). Each carries an anchor-set
invariant as well as "no crash": an input the fuzzer gets accepted must fail
against an unrelated anchor set. Without that, an input that verifies says
nothing about why. PLAN.md D16 makes this the price of hand-written readers.

### 3.8 Base64 malleability at the endpoint

The string a client sends is not the receipt, and two decoders that disagree
about what a string means are two verdicts. The rule is the one Apple's
verifyReceipt applies, measured on 2026-09-23 against production and sandbox
with genuine receipts
([`docs/evidence/2026-09-23-verifyreceipt-base64.md`](./docs/evidence/2026-09-23-verifyreceipt-base64.md)):
`receipt-data` is accepted only as non-empty standard base64 (`[A-Za-z0-9+/]`)
carrying exactly the canonical `=` padding for its length, with nothing else in
the string. Whitespace anywhere (a trailing line feed, line breaks at 64 or 76
columns, a leading space), the base64url alphabet, omitted, partial or extra
padding, anything after the padding and the empty string are all
`MALFORMED`, which is 21002 at the endpoint. The one freedom left
is the unused low bits of the last data character, which Apple accepts, so
every port accepts them too. Every port decodes with its standard library's
base64 decoder (the `base64` crate in Rust) behind a shape check for whatever
that decoder does not refuse on its own.

The rule this replaced accepted everything Foundation's
`base64EncodedString(options:)` can emit. It was reasoned from Apple's
documentation and never measured, and Apple refuses base64url, omitted padding
and line breaks alike.

An `x5c` entry follows the same rule and fails as `INVALID_CERTIFICATE`.

*Proof:* the nineteen `receipt-base64/*` cases, three accepting and sixteen
rejecting, plus `endpoint/receipt-data-urlsafe-padded`,
`endpoint/receipt-data-junk-after-padding`, `endpoint/receipt-data-empty` and
`endpoint/receipt-data-noncanonical-trailing-bits`; for `x5c`,
`transaction/reject-x5c-leaf-with-junk-character`,
`transaction/reject-x5c-leaf-in-base64url-alphabet`,
`transaction/reject-x5c-leaf-with-line-breaks`,
`transaction/reject-x5c-leaf-without-padding` and
`transaction/reject-x5c-leaf-with-extra-padding`.

### 3.9 Port divergence is itself a finding, and roots do not move

One vector file, `fixtures/cases.json`, read in full by all nine ports
through a thin adapter. Every fixture's SHA-256 is re-hashed before any case
runs, so a quietly edited fixture fails loudly in every language.
`node tools/lint-cases.mjs` validates it against
`fixtures/cases.schema.json`, the `conformance` job in
[`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs the same check,
and each port carries a port-divergence suite.

Anchors themselves ship pinned with each release and are never fetched, since
a runtime download would convert pinned trust into trust-the-network
(PLAN.md D12). The scheduled
[`apple-root-watch`](./.github/workflows/apple-root-watch.yml) workflow diffs
Apple's published certificates weekly and fails on change.

## 4. Non-goals

Not defended against here, by decision rather than omission.

- **Replay and entitlement bookkeeping.** A valid signature proves a payload
  came from Apple, not that the presenter is entitled to it. Tracking
  transaction ids is the caller's job (PLAN.md D4, INTENT.md).
- **Refund, revocation and subscription state.** These need Apple's App Store
  Server API or Server Notifications V2. The library has no entitlement
  helper: the signed claims say only what was true at signing, and a billing
  grace period or `isUpgraded` is not in the transaction at all (PLAN.md
  D5).
- **Payload freshness.** No verifier rejects a payload for its age. How old a
  genuine payload may be is the caller's decision, made on its `signedDate`
  or the receipt creation date.
- **Certificate revocation.** No OCSP, no CRL. Offline verification is the
  point, and Apple handles compromised signing certs by rotating them
  (PLAN.md §2.3).
- **Observability.** No logging, metrics or callbacks: machine-readable reason
  codes and nothing else, with alert policy left to the integrator
  (PLAN.md D11).
- **Client-side validation, and any call to an Apple endpoint** (INTENT.md).
- **A malicious integrator**: caller-supplied anchors and clocks are trusted.

## 5. Residual risks

- **No parser differential is open.** Both of the ones this section used to
  list are pinned. Resource bounds: the contract states a floor of 1 MiB and
  20,000 ASN.1 nodes, and `receipt-byte-floor` and `receipt-node-floor` hold
  it from within 2% each; above the floor a port's own cap is its own
  business. `x5c[2]`: java parsed the third certificate and the other eight
  ports never touched it, so an unparseable one was `INVALID_CERTIFICATE`
  there and verified everywhere else. Eight to one, and the majority lost —
  pinning acceptance would have made java drop a rejection it already made.
  All nine ports now parse all three entries, none trusts the third, and
  `transaction/reject-x5c-root-that-is-not-a-certificate` holds it.

  What that closing exposed was an asymmetry rather than a differential, and
  it is closed too: the certificate checks pinned for `x5c` entries — an
  unknown X.509 version, a repeated extension, an extension value that stops
  decoding, a public key on a curve the implementation does not have — sat on
  the JWS path only. Built into the certificate a legacy PKCS#7 receipt is
  signed by, three ports ACCEPTED such a receipt outright (node, ruby,
  dotnet) and the other six answered about the receipt or the chain instead
  of about the certificate. `receipt/reject-signer-*` pins all four as
  rejected before the signature is checked: the signer that does not decode
  as `INVALID_CERTIFICATE` or `MALFORMED`, which ports may choose between
  (docs/design/0.7-api.md), and the key on an unimplemented curve as
  `INVALID_CERTIFICATE`. An embedded certificate that is not the signer keeps
  its old verdict: the bag is unsigned, so bytes that cannot be read there
  are a defect of the receipt (`MALFORMED`), not of a certificate. Since
  0.7 every port decodes a public key only once a pinned root vouches for
  its certificate, so a stranger whose only defect is its key is never read
  and the receipt is judged without it
  (`receipt/verify-with-a-stranger-whose-key-is-unreadable`).
  Telling the two apart means resolving the SignerInfo's issuer
  and serial against every entry's raw DER, before any entry is judged —
  python, rust, java, php and ruby instead blamed whichever entry would not
  decode, so a receipt naming a signer it does not carry came out as a
  defective certificate. `receipt/reject-signer-absent-beside-a-malformed-stranger`
  pins the input that separates them.
- **`asn1crypto` is the one attacker-facing parser this project neither wrote
  nor replaced.** Last release 1.5.1, March 2022. Owner decision: keep it, pin
  the tested range, let the Python fuzz target run through it (PLAN.md D16,
  ROADMAP.md item 5).
- **`jackson-core` in Java** is the one JSON dependency left: 0.7 dropped
  `jackson-databind` and `jackson-annotations`, and with them the databind
  CVE history a consumer's scanner used to surface (PLAN.md D16).
- **Java does not follow the host's security policy.** It parses
  certificates, builds and validates chains, and checks signatures and
  digests with its own pinned BouncyCastle instance, never through the JVM's
  provider list, so `jdk.certpath.disabledAlgorithms` and the rest of
  `java.security` do not apply to it. That is deliberate: a policy that
  disables SHA-1 outright, as RHEL and Fedora crypto policies do, made the
  JDK's PKIX code refuse every genuine legacy receipt. The cost is that an
  administrator cannot restrict this library through that policy; what it
  accepts is set by the library and the caller's roots (java/README.md, "One
  platform caveat: BouncyCastle, not the JDK's PKIX").
- **The C ABI reintroduces `unsafe`, and moves memory discipline to the
  caller.** The library target is `#![forbid(unsafe_code)]`; `rust/ffi` cannot
  be, because a C boundary is raw pointers. Two consequences are the caller's
  and cannot be closed from inside: a handle freed twice, or freed while
  another thread is inside a call on it, is undefined behaviour, and a string
  the ABI returned that is released with the C runtime's `free()` rather than
  `aprv_string_free()` corrupts the allocator. What IS closed from inside: a
  null or non-UTF-8 argument is a status code and never a dereference, no
  input pointer is retained past the call, and every exported function runs
  its body inside `catch_unwind`, asserted by a test that reads the source
  and fails on an unguarded export. No verification logic lives in the ABI —
  a bug there cannot change a verdict, only how a verdict is delivered.
- **RustCrypto is used at a pinned MSRV**, so a security fix released above
  that floor needs the floor raised first.
- **SHA-1 is accepted for legacy receipts**, and the device-hash binding is
  SHA-1, because Apple signs them that way. Neither can be chosen differently
  and still verify genuine receipts.
