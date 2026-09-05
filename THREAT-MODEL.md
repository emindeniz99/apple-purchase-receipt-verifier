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
| Legacy PKCS#7 receipt bytes | `ReceiptVerifier.verify(bytes)` |
| The base64 string a client sends as `receipt-data` | `ReceiptVerifier.verify(string)` |
| Compact JWS (transaction, app transaction, renewal info, notification) | `JwsVerifier.verifyTransaction` / `verifyAppTransaction` / `verifyRaw` |
| The `x5c` chain, and the certificates in a receipt's CMS `SignedData` | reached from the above |
| A whole `verifyReceipt` JSON request body | `VerifyReceiptEndpoint.verifyReceiptJson` |
| A device GUID a caller forwards from a client | `verifyWithDeviceGuid` |

Trusted input comes from the integrator, not the network: the three pinned
Apple roots in [`certs/`](./certs) (PLAN.md D15; each port bundles its own
copy and never reads it from disk at call time), or anchors the caller injects
instead at their own risk (PLAN.md D12); the
verifier config (expected `bundleId`, accepted-environment set, `appAppleId`,
optional max signed age); and the host clock, used only as a fallback when the
payload carries no date of its own. Nothing trusted derives from anything
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
(both `INVALID_CHAIN`), `endpoint/foreign-root-answers-21003`, and Apple's own
Xcode receipts rejected against the real roots
(`receipt/reject-xcode-app-receipt-against-apple-roots`,
`receipt/reject-xcode-signed-public-receipt`). That the OS store is
*unreachable* is asserted per port, by planting a CA the platform accepts and
requiring rejection anyway: `go/systemtrust_test.go`,
`python/tests/test_trust_isolation.py`,
`swift/Tests/ApplePurchaseReceiptVerifierTests/TrustStoreIsolationTests.swift`,
`rust/tests/trust_pinning.rs`, `php/tests/PinnedAnchorsTest.php`,
`ruby/test/hostile_input_test.rb`. *Gap:* Node and Java have no such test yet
(ROADMAP.md "Next").

### 3.2 Marker OIDs stop the wrong-purpose certificate

Chaining to a pinned Apple root is not enough: any Apple developer's own
distribution leaf chains through the same WWDR intermediate. So the JWS leaf
must carry `1.2.840.113635.100.6.11.1` and the intermediate
`1.2.840.113635.100.6.2.1` with `CA: true`, and the receipt signer leaf must
carry `1.2.840.113635.100.6.11.1`, checked after chain validation so a foreign
chain still reports `INVALID_CHAIN` first (PLAN.md D13, §2.1 step 3, §2.2
step 3). *Proof:* `transaction/reject-leaf-without-apple-marker-oid`,
`transaction/reject-intermediate-without-wwdr-marker-oid` and
`receipt/reject-signer-without-receipt-signing-oid`, all
`INVALID_CERTIFICATE_PURPOSE`.

### 3.3 Signature over the exact bytes, then claim binding

ES256 over `ASCII(header + "." + payload)` for JWS. For receipts, the CMS
signature over the content, with an RSA signer key required and the digest OID
read from the `SignerInfo` and matched against a SHA-1/SHA-256 allow-list. No
port re-encodes the input first: the readers keep input slices, one reason
library parsers that normalise to DER were rejected (PLAN.md D16). Only once
that passes are claims checked: `bundleId` must match, `environment` must be
in the accepted set, and in Production `appAppleId` must match (PLAN.md §2.1
step 6). The environment is a *set* deliberately, because App Review runs
production builds against sandbox and a single-environment hard fail would
reject genuine purchases during review (PLAN.md D3).

*Proof.* Tampering: `transaction/reject-tampered-payload` and
`receipt/reject-tampered-payload`, both `INVALID_SIGNATURE`. Claims:
`transaction/reject-wrong-bundle-id`, `receipt/reject-wrong-bundle-id`,
`transaction/reject-apple-official-wrong-bundle-id` (Apple's own negative
fixture), `transaction/reject-environment-outside-accept-set` and
`app-transaction/reject-production-with-wrong-apple-id`.

### 3.4 Environment routing fails closed

At the `verifyReceipt`-compatible endpoint only `Production` and
`ProductionVPP` receipt types count as production. Sandbox variants,
`ProductionVPPSandbox` included, `Xcode`, and a missing attribute all route as
non-production (PLAN.md D10), a tightening driven by a VPP-sandbox misroute
found in adversarial review. *Proof:* the ten `endpoint/*` routing cases,
including `endpoint/vpp-sandbox-receipt-on-production-answers-21007`,
`endpoint/vpp-receipt-on-sandbox-answers-21008` and
`endpoint/missing-receipt-type-on-production-answers-21007`.

### 3.5 Time: validity at signing time, staleness as a separate policy

Apple's signing certificates rotate, so a receipt signed under a since-expired
certificate is still genuine. The validity window is checked at the payload's
`signedDate` or the receipt's creation date, falling back to the system clock
when the input carries neither (PLAN.md §2.1 step 4, §2.2 step 2). Separately,
`JwsVerifier` takes an optional max signed age; a payload signed longer ago is
`STALE_PAYLOAD` (PLAN.md D5). An injected clock drives that policy only, never
chain authentication. Staleness bounds how old a genuinely signed payload may
be. It is not replay protection.

*Proof.* Signing-time validity, accepted then rejected:
`transaction/accept-historical-payload-under-expired-chain`,
`receipt/accept-historical-creation-date-under-expired-chain`,
`transaction/reject-fresh-payload-under-expired-chain`,
`receipt/reject-fresh-creation-date-under-expired-chain`. Clock, both
directions: `transaction/injected-clock-cannot-authenticate-an-expired-chain`,
`endpoint/injected-clock-cannot-expire-a-valid-chain`. Staleness, boundary and
dateless case: `transaction/accept-payload-at-exact-max-signed-age`,
`transaction/reject-payload-one-second-past-max-signed-age`,
`transaction/payload-without-a-signed-date-is-never-stale`.

### 3.6 Device binding, when the caller has the GUID

Optional and off by default: `SHA1(guid ‖ opaqueValue ‖ bundleIdRawBytes)`
must equal receipt attribute 5 (PLAN.md §2.2 step 6, D4). Optional because
requiring it forces a client change; sound because each device carries its own
receipt with its own GUID. *Proof:* `receipt/verify-shared-with-device-hash`
accepts, `receipt/reject-wrong-device-guid` is `DEVICE_HASH_MISMATCH`.

### 3.7 Hostile bytes: bounds, no unbounded recursion, no trailing garbage

Every hand-written reader caps nesting depth (32 in rust, php, ruby and node),
refuses bytes after the outermost value, and caps how many certificates a
receipt may embed (10 in rust and node). Rust, go, ruby and php also cap the
decoded node count, and rust, php and go the input size; §5 records that those
two are not yet uniform. Failures surface as the library's own error type,
never as a language-level crash.

*Proof.* Trailing bytes: `parse_exact` in `rust/src/asn1.rs`,
`ErrTrailingBytes` in `go/internal/der/der.go`, `node/src/der.ts`.
Amplification, size bounds and certificate flooding:
`go/internal/der/amplification_test.go`, `go/sizebound_test.go`,
`php/tests/MemoryExhaustionTest.php`, `php/tests/ResourceBoundsTest.php`,
`node/test/certificate-flood.test.js`, `ruby/test/certificate_flood_test.rb`.
Hostile-input suites: `java/src/test/.../HostileReceiptInputTest.java`,
`php/tests/HostileInputTest.php`, `ruby/test/hostile_input_test.rb`,
`node/test/web-hostile.test.js`. Malformed structure, as shared vectors:
`receipt/reject-attribute-type-above-int32-max`,
`receipt/reject-attribute-type-that-truncates-to-a-modelled-type`,
`transaction/reject-x5c-leaf-that-is-not-a-certificate`,
`transaction/reject-apple-official-missing-x5c`.

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
about what a string means are two verdicts. Everything Foundation's
`base64EncodedString(options:)` can emit is accepted: both alphabets, padded
or unpadded, CR/LF wrapped at 64 or 76 columns, with padding omitted or
canonical but never over- or under-supplied. Anything else is
`INVALID_RECEIPT_FORMAT`, which is 21002 at the endpoint. *Proof:* the sixteen
`receipt-base64/*` cases, eight accepting and eight rejecting, plus
`endpoint/receipt-data-urlsafe-padded`,
`endpoint/receipt-data-junk-after-padding` and `endpoint/receipt-data-empty`.

### 3.9 Port divergence is itself a finding, and roots do not move

One vector file, `fixtures/cases.json`: 82 cases over 73 registered fixtures,
read by all nine ports through a thin adapter. Every fixture's SHA-256 is
re-hashed before any case runs, so a quietly edited fixture fails loudly in
every language. `node tools/lint-cases.mjs` validates it against
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
  Server API or Server Notifications V2; `isActiveAt` and the max-signed-age
  policy cover only what the signed claims already say (PLAN.md D5).
- **Certificate revocation.** No OCSP, no CRL. Offline verification is the
  point, and Apple handles compromised signing certs by rotating them
  (PLAN.md §2.3).
- **Observability.** No logging, metrics or callbacks: machine-readable reason
  codes and nothing else, with alert policy left to the integrator
  (PLAN.md D11).
- **Client-side validation, and any call to an Apple endpoint** (INTENT.md).
- **A malicious integrator**: caller-supplied anchors and clocks are trusted.

## 5. Residual risks

- **Two parser differentials are open and unpinned** (ROADMAP.md "Next").
  An unparseable `x5c[2]`: Java reports `INVALID_CERTIFICATE` where other
  ports reach the signature check, and Go also rejects junk inside an `x5c`
  entry. The third certificate is untrusted everywhere, so no verdict about a
  well-formed JWS moves, but the ports disagree about a malformed one. And
  resource bounds differ by an order of magnitude, several ports declaring
  none: node budgets of 200,000 (ruby), 100,000 (rust, go), 20,000 (php);
  receipt size caps of 8 MiB (rust), 2 MiB (php), 1 MiB (go); only PHP caps
  the JWS input. Genuine receipts are under 80 KB, so nothing breaks today,
  but the contract states no normative floor.
- **`asn1crypto` is the one attacker-facing parser this project neither wrote
  nor replaced.** Last release 1.5.1, March 2022. Owner decision: keep it, pin
  the tested range, let the Python fuzz target run through it (PLAN.md D16,
  ROADMAP.md item 5).
- **`jackson-databind` in Java** carries a CVE history a consumer's scanner
  will surface. The payloads are small and flat and the dependency is
  maintained, but the noise is real (PLAN.md D16).
- **RustCrypto is used at a pinned MSRV**, so a security fix released above
  that floor needs the floor raised first.
- **No trust-store isolation test in Node or Java** (§3.1), and **fuzz
  coverage is uneven**: rust, node, dotnet and go have coverage-guided targets,
  the rest are being brought up one CI job each (ROADMAP.md items 1 and 2).
- **SHA-1 is accepted for legacy receipts**, and the device-hash binding is
  SHA-1, because Apple signs them that way. Neither can be chosen differently
  and still verify genuine receipts.
