# Threat model

What this library defends against, by what mechanism, and which test proves
each line. Sections 1 to 5 are the verification algorithm: what a hostile
receipt or JWS can try and why it fails. Sections 6 to 10 are where that
algorithm runs in 0.8.0 — one Rust core, compiled to `aprv.wasm` and hosted
by eight wrappers or by `aprv-server` — and what an attacker can do to a
wrapper, the module and the server. Section 11 is what the adversarial
reviews of the core found and what was fixed.

The algorithms are in [PLAN.md](./PLAN.md) §2 and the decisions in PLAN.md
§0. Reporting a vulnerability: [SECURITY.md](./SECURITY.md). Why the project
exists and what verification does *not* prove: [INTENT.md](./INTENT.md). The
plan behind 0.8.0, with the reasoning for each choice, is in
[docs/rust-core/](./docs/rust-core/README.md); its own threat model,
[docs/rust-core/THREAT-MODEL.md](./docs/rust-core/THREAT-MODEL.md), carries
the per-host detail this file summarises. Vectors are cited by id from
[`fixtures/cases.json`](./fixtures/cases.json), the language-neutral file
the Rust core and the Java implementation both answer and every package
runs; where no shared vector exists a test file is cited and the gap is
named.

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
| Any request to an `aprv-server` a client can reach | its HTTP routes, bounded by the token when one is set (§9) |

Trusted input comes from the integrator, not the network: the three pinned
Apple roots in [`certs/`](./certs) (PLAN.md D15), compiled into the Rust
core from its copy in `rust/certs/` and into the Java implementation as
constants, never read from disk at call time; or roots the caller puts in
its `Config` instead at their own risk (PLAN.md D12); and the `Config` clock,
used for the chain instant only when the payload carries no usable date of
its own, and for `request_date` at the endpoint. Nothing trusted derives
from anything attacker-controlled. The third certificate in `x5c` in
particular is parsed but never trusted: only the intermediate being signed
by a pinned anchor counts (PLAN.md §2.1 step 4).

What we build is trusted like code, and each piece is pinned: `aprv.wasm`
(every Wasm package checks its copy against a SHA-256), the `aprv-server`
binaries (the Java server engine and PHP's installer check a pinned
SHA-256 before running one), and the precompiled code inside the server.
Section 7 says how each is made and checked.

## 2. Attacker goals

1. **Forge a purchase**: get back a payload Apple never signed.
2. **Reuse a genuine payload**: someone else's receipt, or one for another app.
3. **Downgrade the environment**: a sandbox or Xcode purchase taken as production.
4. **Replay a stale payload** after the entitlement it describes has ended.
5. **Deny service**: burn CPU or memory on a small input.
6. **Make the implementations disagree**, then route the input to the
   accepting backend.
7. **Escape the verifier**: turn a parser bug reached by a hostile receipt
   into code running in the caller's process.
8. **Swap the verifier**: make a package run a module or a server binary
   that is not the one we released.

## 3. Mitigations

### 3.1 Trust is pinned, and only pinned

Chain validation terminates at anchors the caller handed in, and no code
path can reach the platform store or the network. The Rust core reads with
OpenSSL (docs/rust-core/DECISIONS.md R21) and holds the line there: the
store holds the caller's anchors and nothing else, no default trust path,
lookup, configuration file or provider is loaded, and nothing opens a
socket (`rust/openssl/README.md`, Isolation). Inside `aprv.wasm` the core
has no file, network or environment access at all: the module imports one
function, a source of random bytes (§6). The Java implementation checks
chains with its own pinned BouncyCastle instance and never with the JDK's
PKIX or trust store. The order of the anchors does not matter, even
between two that share a subject name, and neither does the order of the
unsigned certificates bag: a certificate that carries an intermediate's
name but signed nothing on the path is never offered to the path builder.

*Proof.* `transaction/reject-foreign-root`, `receipt/reject-foreign-root`
(both `UNTRUSTED_CHAIN`), `endpoint/foreign-root-answers-21003`, and Apple's own
Xcode receipts rejected against the real roots
(`receipt/reject-xcode-app-receipt-against-apple-roots`,
`receipt/reject-xcode-signed-public-receipt`). That the OS store is
*unreachable* is asserted by planting a CA the platform accepts and
requiring rejection anyway: `rust/tests/trust_pinning.rs` with
`rust/openssl/tests/isolation.rs` (a planted `SSL_CERT_FILE`,
`SSL_CERT_DIR` and `OPENSSL_CONF` are ignored),
`java/src/test/.../TrustStoreIsolationTest.java`, and
`python/tests/test_trust_isolation.py`, which also checks that the roots
reaching the module's `init` are byte for byte the caller's. That no
wrapper can build a trust decision of its own is the `one-implementation`
gate (§6). Anchor order:
`receipt/verify-under-the-second-of-two-roots-sharing-a-subject` and
`transaction/verify-under-the-second-of-two-roots-sharing-a-subject`. Bag
order:
`receipt/verify-with-another-roots-same-named-intermediate-before-the-real-one-own-root-{first,second}`
and `receipt/verify-with-a-same-named-sibling-intermediate-before-the-real-one`.

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
signature over the content. Since 0.7 (#160) neither implementation
restricts the signer's key type, digest or signature algorithm (owner
decision: a signer pinned to an Apple root and carrying Apple's marker is
trusted whatever it signs with, so a change on Apple's side cannot reject
genuine receipts; an RSA signature binds its hash algorithm in the
DigestInfo, and a weak hash helps only an attacker holding an Apple
signature over it). The content is digested as the octets that arrived,
constructed chunks joined; no implementation normalises the receipt to DER
first. One re-encoding does happen, in the Rust core: OpenSSL's
`CMS_SignerInfo_verify` re-encodes the signedAttrs (`ASN1_item_i2d` with
`CMS_Attributes_Verify`) before it checks the signature over them, so a set
the signer really signed but sent in non-DER order verifies there where
Java refuses it (docs/rust-core/DECISIONS.md R20). It is still the signer's
own signature.

Since 0.7 the library checks no claim. Bundle id, environment, app Apple id
and device binding are the caller's to compare on the payload it gets back
(docs/design/0.7-api.md, Principles), so attacker goals 2 and 3 of §2 are
defeated in the caller's code, and the library's part is to return exactly
what Apple signed. Each package README lists those checks; the environment
check accepts a set, because App Review runs production builds against
sandbox (PLAN.md D3).

A legacy receipt is verified in a fixed order, the same in the core and in
Java:

1. Decode the base64 and parse the CMS. Bad base64, trailing bytes, absent
   content, no `SignerInfo` or more than four, more than ten embedded
   certificates or CRLs, and an envelope over the depth or value bounds
   (§3.7) are `MALFORMED`.
2. Read the receipt creation date, attribute 12, and nothing else: walk the
   top-level attribute SET under the depth and value bounds, read each
   entry's type, decode only the value of the first type 12. No usable
   date means the chain is judged at the `Config` clock. This step never
   rejects. The Rust core takes it only once a `SignerInfo` names an
   embedded certificate, since only a chain needs the date.
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

The module has no clock of its own. A wrapper reads the `Config` clock once
per call, before it looks at the input, and passes the value as `now-ms`;
the module uses it only where the rule above says, so a caller still cannot
move the validity instant of an input that carries its own date. A clock
that throws, or answers a time before 1970, is `INTERNAL_ERROR`.

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
package README shows it (PLAN.md D4). Optional because requiring it forces a
client change; sound because each device carries its own receipt with its
own id. *Proof:* `receipt/return-device-hash-inputs` pins the three octet
strings the hash is computed from.

### 3.7 Hostile bytes: bounds, no unbounded recursion, no trailing garbage

Both implementations apply the same bounds (docs/design/0.7-api.md,
Bounds): ASN.1 nesting depth 32; JSON depth 64; at most 10 certificates
embedded in a receipt, 10 CRLs and 4 SignerInfos; at most 100,000 values in
the envelope or in one attribute SET; constructed strings at most six
levels deep; and fixed input caps of 3,145,728 UTF-8 bytes for receipt
base64 and request bodies and 262,144 for a JWS. Readers refuse bytes after
the outermost value. Before the signer is trusted the payload is read only
as far as attribute 12 (§3.3), so the attacker's bytes reach the full
payload grammar only under a trusted signature; a bound hit there is
`UNREADABLE_PAYLOAD`, since only a trusted signer could have put the bytes
in front of it.

In the Rust core OpenSSL decodes, and a walk over the headers alone
(`rust/openssl/src/walk.rs`) runs first: over the whole CMS envelope,
before anything is decoded, it applies the depth bound to constructed
values of every class, the value budget, and the primitive rules OpenSSL's
own decoder would apply. Only then does a shallow decode count the
certificates, CRLs and SignerInfos, and only then does
`d2i_CMS_ContentInfo` build any certificate's key; no envelope reaches
either decode over a bound. The caps are the core's alone: a wrapper
copies at most one byte more than the cap into the module, so an oversized
input costs the module no memory, and adds no cap of its own. Failures
surface as the library's own result, never as a language-level crash.

*Proof.* Trailing bytes: `receipt/reject-one-trailing-byte-after-the-der`;
in Rust `CmsError::Trailing` (`rust/openssl/src/cms.rs`, from the header
walk) with `rust/tests/receipt_negative.rs`
(`trailing_bytes_after_the_cms_blob_are_rejected`).
Amplification, size bounds and certificate flooding:
`rust/tests/envelope_bounds.rs` (a full-decode counter proves the flood,
behind a trailing byte or a broken envelope too, never reaches
`d2i_CMS_ContentInfo`), `rust/tests/hostile.rs`,
`rust/tests/input_size_caps.rs`,
`rust/tests/unauthenticated_key_cost.rs`, and in Java
`java/src/test/.../HostileReceiptInputTest.java`. Depth, as shared vectors:
`receipt/unreadable-signed-content-nested-33-deep`,
`receipt/reject-an-envelope-nested-33-deep`,
`receipt/reject-an-envelope-nested-33-deep-in-context-tags`,
`receipt/reject-digest-algorithm-parameters-nested-33-deep`,
`receipt/reject-a-crls-entry-nested-33-deep`,
`receipt/reject-an-embedded-certificate-with-parameters-nested-33-deep`,
`receipt/unreadable-signed-content-nested-33-deep-in-context-tags` and
`signed-data/unreadable-payload-nested-65-deep`; constructed strings and
CRLs, bounds of the core's decoder that the shared vectors leave
port-defined (Java, whose nesting bound of 32 counts chunk levels and
which never decodes a CRL, verifies them; DECISIONS.md R20):
`receipt/reject-econtent-rechunked-into-7-constructed-levels`,
`receipt/unreadable-attribute-value-rechunked-into-7-constructed-levels`
and `receipt/reject-eleven-embedded-crls`. Malformed structure, as shared
vectors: `receipt/reject-attribute-type-above-int32-max`,
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

*Fuzzing.* [`rust/fuzz/README.md`](./rust/fuzz/README.md) lists six
targets: five over the core's operations, the receipt path and the C ABI,
and one over the module's canonical ABI in Wasmtime. The nightly
`rust-fuzz-openssl` job runs them over an OpenSSL built with
AddressSanitizer and coverage instrumentation, so the fuzzer follows edges
inside OpenSSL's own CMS, X.509 and ASN.1 code. [`java/fuzz/README.md`](./java/fuzz/README.md)
fuzzes the Java implementation with Jazzer. Each core target that can
accept an input carries an anchor-set invariant as well as "no crash": an
input the fuzzer gets accepted must fail against an unrelated anchor set.
Without that, an input that verifies says nothing about why. The wrappers'
fuzz jobs drive their public API through the module and check the
wrapper's own boundary.

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
both implementations accept them too. The core decodes with the `base64`
crate behind a shape check, Java with the JDK's decoder behind one; no
wrapper decodes base64 at all.

The rule this replaced accepted everything Foundation's
`base64EncodedString(options:)` can emit. It was reasoned from Apple's
documentation and never measured, and Apple refuses base64url, omitted padding
and line breaks alike.

An `x5c` entry follows the same rule and fails as `INVALID_CERTIFICATE`.

*Proof:* the nineteen `receipt-base64/*` cases, three accepting and sixteen
rejecting, plus `endpoint/receipt-data-urlsafe-padded`,
`endpoint/receipt-data-junk-after-padding`, `endpoint/receipt-data-empty` and
`endpoint/receipt-data-noncanonical-trailing-bits`; the 33 `decodeBase64`
groups; for `x5c`,
`transaction/reject-x5c-leaf-with-junk-character`,
`transaction/reject-x5c-leaf-in-base64url-alphabet`,
`transaction/reject-x5c-leaf-with-line-breaks`,
`transaction/reject-x5c-leaf-without-padding` and
`transaction/reject-x5c-leaf-with-extra-padding`.

### 3.9 Two implementations, one contract, and roots do not move

Goal 6 of §2 needs two verifiers that disagree. In 0.8.0 there are two
implementations, the Rust core and the Java implementation, and every
other package runs the core's one module, so a wrapper cannot disagree
with the core about a verdict. Both implementations answer the whole of
`fixtures/cases.json` on every change. Every fixture's SHA-256 is re-hashed
before any case runs, so a quietly edited fixture fails loudly everywhere.
`node tools/lint-cases.mjs` validates the file against
`fixtures/cases.schema.json`, and the `conformance` job in
[`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs the same
check. The nightly `java-differential` job runs both implementations over
every input it collects; every difference kept on purpose is recorded with
its reason in docs/rust-core/DECISIONS.md R20, and one that changes an
Apple-signed input's verdict, or accepts something unsigned, is a bug.

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

  What that leaves open: the chain is judged valid at the payload's own
  date (`signedDate`, or the receipt's creation date), so if a historical
  Apple leaf key ever leaked, a payload back-dated into that certificate's
  validity window would verify, in both implementations. Apple's own
  library does the same with its online checks off. A consumer's defence
  today is the weekly `apple-root-watch` workflow and owning the root set
  in `Config`. If that day comes, the answer is a per-certificate distrust
  list in `Config`; it is deliberately not built (ROADMAP.md, "Later /
  hardening").
- **Observability.** No logging, metrics or callbacks: machine-readable reason
  codes and nothing else, with alert policy left to the integrator
  (PLAN.md D11).
- **Client-side validation, and any call to an Apple endpoint** (INTENT.md).
- **A malicious integrator**: caller-supplied anchors and clocks are trusted,
  and so is anyone who can write where the package is installed.
- **Protecting the verdict with isolation.** The sandbox around the module
  protects the caller's process, never the answer (§6).

## 5. Residual risks in the algorithm

- **No parser differential is open.** Both of the ones this section used to
  list are pinned. Resource bounds: the contract states a floor of 1 MiB and
  20,000 ASN.1 nodes, and `receipt-byte-floor` and `receipt-node-floor` hold
  it from within 2% each. `x5c[2]`: every implementation parses all three
  entries, none trusts the third, and
  `transaction/reject-x5c-root-that-is-not-a-certificate` holds it. The
  certificate checks pinned for `x5c` entries — an unknown X.509 version, a
  repeated extension, an extension value that stops decoding, a public key
  on a curve the implementation does not have — hold on the receipt path
  too: `receipt/reject-signer-*` pins all four as rejected before the
  signature is checked, the signer that does not decode as
  `INVALID_CERTIFICATE` or `MALFORMED` (implementations may choose between
  them, docs/design/0.7-api.md), and the key on an unimplemented curve as
  `INVALID_CERTIFICATE`. An embedded certificate that is not the signer is
  a defect of the receipt (`MALFORMED`), not of a certificate. A public key
  is decoded only once a pinned root vouches for its certificate, so a
  stranger whose only defect is its key is never read and the receipt is
  judged without it (`receipt/verify-with-a-stranger-whose-key-is-unreadable`);
  a receipt naming a signer it does not carry is told apart from a
  defective certificate by
  `receipt/reject-signer-absent-beside-a-malformed-stranger`.
- **Known differences between the core and Java are recorded, not
  closed.** OpenSSL decodes at most six levels of constructed string
  (`ASN1_MAX_STRING_NEST`), OpenSSL re-encodes signedAttrs (§3.3), and a
  few encodings deep in unsigned or payload values answer differently.
  docs/rust-core/DECISIONS.md R20 lists each with its reason; none changes
  the verdict of an Apple-signed input or accepts anything unsigned.
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
  platform caveat: BouncyCastle, not the JDK's PKIX"). The Wasm packages are
  in the same position for a different reason: the module carries its own
  OpenSSL, so the host's OpenSSL configuration never reaches it.
- **SHA-1 is accepted for legacy receipts**, and the device-hash binding is
  SHA-1, because Apple signs them that way. Neither can be chosen differently
  and still verify genuine receipts.

## 6. Where the core runs: isolation

A hostile receipt meets the Rust core in one of five settings. Each class
names what separates the core from the caller's process
(docs/rust-core/THREAT-MODEL.md §2):

| Class | Where the core runs | What bounds it | Packages |
|---|---|---|---|
| A | Wasm in the caller's process, interpreted | software bounds checks in the interpreter; no machine code generated | Swift (WasmKit) |
| B | Wasm in the caller's process, compiled to machine code | the runtime's compiled code, with its bounds checks, guard pages and signal handlers | Node and the JS runtimes, Go (wazero), Python (wasmtime-py), Ruby (the `wasmtime` gem), .NET (Wasmtime) |
| C | JVM bytecode compiled from the module, in the caller's JVM | the JVM's memory safety; no native code | Java `-wasm` on the Endive engine |
| D | a separate process, with class B inside it | the operating system's process boundary | Java `-wasm` on the server engine, PHP, any client of `aprv-server` |
| E | native code in the caller's process | nothing | not shipped by default: the Rust crate and the C ABI, for callers who choose them |

**What the module can reach.** `aprv.wasm` imports exactly one function,
`random-get`, which returns random bytes the module copies into its own
memory; OpenSSL uses them for ECDSA blinding. The link-time C file inside
the module answers the clock from the call's `now-ms` and traps on every
other system call wasi-libc would make: no file, directory, environment,
argument or exit function works. CI lists the module's imports and fails
on anything else, and every host refuses to instantiate a module that asks
for more. A parser bug that a hostile receipt reaches stays in the
instance's linear memory; to reach the caller's process it needs a second
bug, in the runtime (classes A and B), in the JVM (class C), or in
Wasmtime and then the server's user's rights (class D).

**What isolation does not protect: the verdict.** The core computes the
answer inside the sandbox. A core compromised by a hostile input could
return "verified" for a forged receipt. The defences for the verdict are
§3's: the shared cases, fuzzing into OpenSSL, the reviews, and the Java
implementation as a second opinion on every case and, nightly, on the
corpus.

**What a compromised instance keeps.** An instance that is attacked and
does not trap keeps its state, so a later call on the same instance runs
in the attacker's state. The in-process pools reuse instances;
`aprv-server`'s default, a fresh instance per request, removes that
carry-over, and `--lifecycle pool` brings it back. Every host discards an
instance that trapped.

**No wrapper decides anything.** A wrapper reads the clock, copies the
input in, reads the JSON answer back and maps it; it has no parser, no
crypto and no trust decision. The `one-implementation` CI job fails on a
crypto, X.509, ASN.1 or CMS API in any non-Java wrapper outside its tests,
allowing only a CSPRNG for `random-get` and a SHA-256 to check a module or
binary against its pin. A trap, a result pointer outside the module's
memory, or an answer that is not the wire shape is `INTERNAL_ERROR` for
that call, never a verdict, and the instance is discarded.

**Per host.** WasmKit stops the whole process, rather than throwing, on an
out-of-range access by the host, so the Swift wrapper checks every range
before it touches the module's memory; it asks for software bounds
checking so that it installs no process-wide signal handler in its
caller's process. Endive's compiler does no post-compilation verification;
it compiles only our module, at build time, and the corpus runs through
the built jar in CI byte for byte against native. The Java `-wasm`
artifact on Java 8 never loads native code into the JVM.

## 7. The module, the binaries and the supply chain

- **`aprv.wasm` is built once per release, by our release job, with no
  cache,** from our source, with rustc, wasi-sdk, wasm-tools, wit-bindgen
  and the OpenSSL tarball pinned by version and SHA-256, and paths remapped
  so a second build reproduces the hash. `tools/reproduce-wasm.sh` rebuilds
  a tag's module in a fresh clone and compares it; the release job runs it
  against its own artifact.
- **One hash everywhere.** The module's SHA-256 is published with the
  release, with SLSA build provenance and a CycloneDX SBOM that names the
  toolchain and OpenSSL. Every package checks its copy against a pinned
  SHA-256 before it runs it: Go and Swift commit the module, the other
  packages pack the file the release built, and no library reads an
  environment variable or a path that could make it load another module.
- **The WIT is the contract.** CI reads the interface back from the built
  module and diffs it against `rust/bindings/abi/wit/aprv.wit`. The export
  names carry the ABI version, so a wrapper built for one version finds no
  export in a module of another and fails at `Verifier` creation instead of
  misreading its arguments.
- **Precompiled code is trusted like a binary.** Wasmtime runs a
  precompiled module as machine code without validating it. `aprv-server`
  runs only the precompiled component embedded in the binary at build
  time, and its runtime-only build has no compiler to accept anything
  else. Python's compile cache is the one other place compiled code lives
  (§10).
- **Server binaries are pinned where they are fetched.** The Java server
  engine takes a binary from a classifier jar, our GitHub Release or a
  mirror the user names, and runs it only if its SHA-256 matches the pin in
  the jar (or the one the user gave): written to an owner-only cache
  directory as a temporary file, hashed while it streams, made executable
  and renamed only on a match, hashed again before every start. PHP's
  `aprv-install` checks the SHA-256 in `php/binaries.json` and installs
  nothing on a mismatch; nothing downloads at request time.
- **Runtimes we do not build.** wasmtime-py, the `wasmtime` gem, Wasmtime
  .NET, wazero, WasmKit, jco and Endive are dependencies with a floor, and
  their fixes reach users through the users' own updates. Each is a large
  runtime the package did not carry in 0.7; we raise a floor when an
  advisory makes the old range unsafe. Runtimes have bugs: the security
  review of Wasmi, done while it was a Python candidate, is the example —
  one issue reported privately upstream on 2026-09-27; not reachable for
  aprv.wasm. Wasmi is not shipped.
- **Publishing** never uses a cache, attests every artifact, and the
  post-publish smoke installs from the real registries.

## 8. Resource limits

Every host inherits the core's input bounds (§3.7). A hostile 3 MiB
receipt of tiny attributes used to cost 145 MiB of process memory in Node;
since the header walk it is refused before the payload is read, and the
module's linear memory grows to about 16 MiB (docs/evidence/2026-09-29-core-review-fixes.md).
The signed-payload path reaches the full payload decode after the walk and
the signature, and has not been re-measured.

| Host | Memory | CPU and time |
|---|---|---|
| `aprv-server` | 256 MiB of linear memory and one instance per store; a larger grow traps | 10 s of guest time per call by default (epoch interruption); a semaphore of one worker per CPU; the 3 MiB body cap, answered with 413 |
| Go, Python, Ruby, .NET | 256 MiB of linear memory per instance; an instance past it traps and is discarded (.NET also drops an instance that grew past 64 MiB) | no guest time limit |
| Swift | no per-instance limit in WasmKit's public API; an instance whose memory grew past 64 MiB is dropped | no guest time limit |
| Node | the engine's limit for a 32-bit memory; workerd's 128 MB isolate | the platform's own CPU limits |
| Endive (Java 11+) | none of its own: the module declares no maximum, so memory can grow to the JVM heap | no guest time limit |
| Java 8 server engine, PHP | as `aprv-server` | as `aprv-server`; PHP's CLI process ends with each call |

A looping input would hold an in-process worker until the call returns;
the core's bounds are what keep every call short (§3.7). Only
`aprv-server` enforces a guest time limit today.

## 9. `aprv-server`

- **Binding.** `127.0.0.1` unless `APRV_LISTEN` says otherwise, in and out
  of Docker. Inside the image the server listens on `127.0.0.1:8080`, so a
  published port reaches nothing until the operator sets
  `APRV_LISTEN=0.0.0.0:8080`, preferably published as
  `-p 127.0.0.1:8080:8080`.
- **Token.** With a token configured (`--token-file` or `APRV_TOKEN`), a
  `/v1/` request without the right `X-Aprv-Token` gets 401. A server bound
  beyond loopback should always have one. The health, readiness and
  OpenAPI routes need no token.
- **Plain HTTP.** The server speaks HTTP without TLS. It is meant for
  loopback, a sidecar or a private network; TLS termination belongs to the
  deployment.
- **Managed mode** (the Java 8 child): the child binds `127.0.0.1:0`
  whatever `APRV_LISTEN` says. The parent sends a fresh 256-bit token and
  the roots on the child's stdin, never in argv (world-readable under
  `/proc`) or the environment. The child exits on stdin EOF, so it ends with
  the JVM, even after `kill -9`. The parent refuses a server whose roots'
  fingerprints differ from its `Config`.
- **The image** is distroless, runs as a non-root user, has no shell, and
  its bases are pinned by digest.
- **The one-shot CLI** has no socket: stdin in, stdout out, exit codes 0,
  2, 3 and 70. PHP runs it with an argv array and no shell.
- **Errors that are not results** (401, 413, a trap, an ABI fault) are RFC
  9457 problem documents; a verification result is always HTTP 200 with
  the module's JSON, so a client cannot mistake a server failure for a
  verdict.

## 10. Java artifacts and Python's cache

- **Two Java artifacts, one class name each.** The main artifact is the
  independent implementation; `-wasm` runs the module. They expose the same
  class names, so each ships a marker resource and fails fast when it finds
  both on the classpath, and the Gradle metadata declares a capability
  conflict: a consumer never runs one believing it runs the other.
- **No configuration from the environment.** The Java libraries read no
  system property and no environment variable of their own, so nothing
  outside the code can switch the engine or point it at another binary.
  `noexec` directories block an extracted binary; such hosts use `url()` or
  `executable()`, which extract nothing.
- **Python's compile cache holds native code.** wasmtime-py compiles the
  module at start and, with the cache on, stores the result on disk, where
  the next process runs it. Anyone who can write that directory can plant
  code. The cache lives in the user's own cache directory, created private;
  it is off, silently, when the directory is read-only, not owned by the
  running user, writable by group or others, or under a parent someone else
  could swap; `APRV_WASM_CACHE_DIR` moves it and an empty value turns it
  off (python/README.md, "The compile cache").

## 11. What the reviews found

Before 0.8.0 five adversarial reviews, by agents that did not write the
code, read every line of the OpenSSL adapter, the core's policy layer, the
fixes of the first round and the ABI crate, and tried to break each with
crafted input. The full record, finding by finding, is
[docs/rust-core/REVIEW-LOG.md](./docs/rust-core/REVIEW-LOG.md).

- Three rounds reported 61 findings: 2 blocking, 23 to fix before merge,
  36 notes. Nothing in memory safety, isolation or trust broke in any
  round: no
  double free, no per-call leak, no panic path, valgrind clean, no input
  verified without a valid signature under a pinned root, and none could
  move the instant at which the chain is judged.
- What broke in the first round was the set of cheap checks before the
  full CMS decode, which covered less than the 0.7 reader had. The fix is
  the header walk of §3.7, with 0.7's depth, value, certificate,
  SignerInfo and CRL bounds, run before OpenSSL decodes anything. The
  second round found the first fix incomplete in three places (a decode
  still ran before the walk, anchor order still decided two custom-root
  cases, the walk checked fewer primitive rules than OpenSSL) and, in the
  ABI crate, an unpinned compiler in the release build, over-cap inputs
  copied whole into the module's memory, and a C ABI that read C strings.
  All are fixed; the input cap is applied in every wrapper. The third
  round read the second round's own fixes and found two more gaps, both
  failing closed: with custom anchors, a same-named decoy certificate
  placed first in the unsigned bag still refused a genuine receipt (the
  bag is now filtered by signature link before the per-anchor runs;
  Apple's roots carry key identifiers and were never affected), and the
  walk refused chunked strings that OpenSSL joins (it now joins them
  too). It also added the guest-side range guard, tighter wire schemas
  and tests for the compiler pin.
- 51 shared cases came from the three rounds, and ten rows of R20's
  divergence table record the differences from Java they exposed.
- **Still open.** The third round's own fixes have had no reader but
  their author (REVIEW-LOG.md §11.9 says what closes the gate). No review
  ran the interpreter hosts' timings, and no fuzz campaign has run since
  the fixes.

## 12. Residual risks of the 0.8 architecture

- **Monoculture.** A bug in the core or in OpenSSL reaches every Wasm
  package at once. The Java implementation is the second opinion, not a
  fallback: a caller runs one or the other.
- **Isolation does not protect the verdict** (§6).
- **Endive is young** (1.0 on 2026-06-26, 1.1.0 on 2026-09-03) and does no
  post-compilation verification; JDK 17 and earlier run with its
  workaround for a C2 miscompilation. The corpus run through the built jar
  is the guard.
- **No guest time limit** in the in-process hosts (§8).
- **Python's cache** is native code on disk (§10).
- **Downloaded server binaries** move trust to our release process; the
  pin inside the jar or `php/binaries.json` is what makes a replaced GitHub
  asset fail.
- **The C ABI and the Rust crate run the core natively** in the caller's
  process (class E). The C ABI also moves memory discipline to the caller:
  a handle freed twice, or freed while another thread is inside a call on
  it, is undefined behaviour, and a string the ABI returned that is
  released with `free()` rather than `aprv_string_free()` corrupts the
  allocator. What is closed from inside: a null argument is a status code
  and never a dereference, the `_bytes` calls take a pointer and a length
  so an embedded NUL cannot truncate an input (the older C-string calls
  read up to the first NUL), no input pointer is retained past the call, and every exported function runs inside `catch_unwind`. No
  verification logic lives in the ABI.
- **Temurin 8 builds end in late 2026.** The Java 8 CI legs move to Zulu
  or Corretto; Java 8 security then depends on the consumer's JVM vendor.
