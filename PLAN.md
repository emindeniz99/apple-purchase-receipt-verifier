# Plan — apple-purchase-receipt-verifier

Read [INTENT.md](./INTENT.md) first for the "why". This file records the
research, the verification algorithms every implementation must follow, and
the shared API shape.

## 0. Decisions (design grill, 2026-08-05)

Settled with the project owner; treat as ADRs — changing one needs a reason
recorded here.

- **D1 — Published libraries, not internal-only.** Each implementation will
  be published (Maven Central, npm, PyPI) when the project graduates.
  Consequences: stable API, semver, dependency-light ("vendoring is ok"),
  license: **MIT, confirmed by the owner 2026-08-05** (LICENSE at the
  project root).
- **D2 — Enterprise-reality version floors**, not upstream-support floors:
  **Java 8**, **Node ≥20**, **Python ≥3.10** (raised from ≥3.9 after 3.9
  reached EOL 2025-10; owner approved), **Swift 6** (server-side Swift
  has no Java-8-style long tail; Apple's own Swift library requires 6). Java is built `--release 8`
  (no records/`var`/`List.of`; ES256 raw-signature conversion done manually
  since `SHA256withECDSAinP1363Format` is Java 9+). CI should matrix-test
  oldest + current LTS. **Amended in 0.8.0** by D25: the Wasm runtimes set
  Swift's floor to 6.3 with macOS 15 and iOS 18; the other floors stand.
- **D3 — Environment routing is an accept-set** (grill Q4, option A): the
  verifier takes a *set* of accepted environments and reports which one
  matched. Rationale: App Review runs production builds against sandbox —
  a single-environment hard fail would reject purchases during review
  (the old `verifyReceipt` 21007 retry-on-sandbox problem, solved locally).
  **Superseded in 0.7** ([docs/design/0.7-api.md](./docs/design/0.7-api.md),
  principle 2): the verifier takes no environment. The caller reads it off
  the payload, with `Environment.fromJwsEnvironment` or
  `Environment.fromReceiptType` in 0.7 and with the payload's own
  `environment()` from 0.8, where the verifier states it
  ([DECISIONS.md R42](./docs/rust-core/DECISIONS.md)); only
  `verifyReceiptEndpoint` takes one, per call, to answer 21007 or 21008
  as Apple would.
- **D4 — Device-hash check stays optional, off by default.**
  The device GUID (the raw bytes of `identifierForVendor` on iOS, iPadOS,
  tvOS and watchOS, including an iOS app running on an Apple silicon Mac,
  or the primary network interface's MAC address from `copy_mac_address`
  on macOS and Mac Catalyst) differs per device but each device carries
  its own receipt with its own GUID, so the check is sound — still,
  requiring it would force client changes. Replay defense = server-side
  transaction-id bookkeeping (owner confirmed the server can keep them).
  **Superseded in 0.7**: the verifier takes no device GUID. The receipt
  payload exposes `opaqueValue`, `sha1Hash` and `bundleIdBytes`, and each
  port README shows the caller-side hash.
- **D5 — Subscriptions supported**: payloads expose `expiresDate` /
  `revocationDate`; whether they entitle a user is the caller's rule. The
  `isActiveAt(now)` helper was removed (2026-09-24): Apple's libraries have
  none, and it could not see a billing grace period (renewal info) or
  `isUpgraded`, so it could answer "expired" while Apple still grants
  access, or "active" for an upgraded-away subscription. How old a signed
  payload may be is the caller's decision, made on `signedDate` or the
  receipt creation date: the optional max-signed-age policy the JWS
  verifier used to take was removed (2026-09-24), because Apple's own App
  Store Server Libraries have none and the right limit depends on the
  endpoint (Apple retries server notifications for days; a device may
  present an old but genuine payload). Refund/renewal
  *state* still requires Apple's server API — out of scope (INTENT.md).
- **D6 — Real receipt corpus pending**: owner will supply real production +
  sandbox receipts as fixtures later; until then generated fake-Apple-PKI
  fixtures carry the tests (tracked in ROADMAP.md).
- **D7 — Full type safety** (2026-08-05): Node is strict TypeScript
  (compiled to `dist/` with declarations; still zero runtime deps), Python
  ships annotations + `py.typed`, Java and Swift are typed by language.
- **D8 — Dependencies stay minimal, hand-rolled parsers stay** (2026-08-05):
  evaluated replacing the Node DER/BER parser with `pkijs`/`node-forge` and
  the JWS handling with `jose` — rejected. `jose` cannot do x5c chain
  validation to a custom pinned root (the security-critical part stays
  manual either way), `node-forge` is effectively unmaintained, and `pkijs`
  pulls a large dependency surface into a security library to replace ~300
  audited lines that Apple's own fixture bytes exercise. Java (BouncyCastle),
  Python (`cryptography`+`asn1crypto`) and Swift (apple/swift-*) already sit
  on the strongest maintained options for their ecosystems.
  **Superseded in 0.8.0 for the eight non-Java packages** by D17 and D18:
  no package keeps a parser of its own; the Rust core parses through
  OpenSSL. Java keeps BouncyCastle. DECISIONS.md R41 (2026-10-02) also
  moved .NET's JSON reader and writer onto `System.Text.Json`.
- **D11 — Observability is the caller's job** (owner decision,
  2026-08-05): this is a library; it exposes machine-readable reason codes
  and nothing else — no logging, no metrics, no callbacks. Integrators wire
  the failure `Reason` values into their own
  telemetry and decide reject/alert policy.
- **D12 — Trust anchors are NEVER fetched at runtime** (owner question,
  2026-08-05): periodic runtime download of Apple's roots was considered
  and rejected — it would convert pinned trust into trust-the-network (a
  MITM on the fetch could inject a root), couple verification availability
  to apple.com, and Apple's PKI page is not an API. Policy instead:
  (1) roots ship pinned with each release (current roots are valid to
  2035/2039 — rotation is a once-a-decade event announced years ahead);
  (2) the scheduled `apple-root-watch` CI workflow diffs Apple's published
  certs weekly and fails loudly on change → cut a release; (3) constructors
  accept caller-supplied anchors, so an integrator who wants their own
  rotation pipeline can inject roots from config — at their own risk.
- **D10 — Forward-compatible ("dynamic") receipt parsing** (2026-08-05):
  attribute types the library does not model are exposed raw on
  `unknownAttributes` (type → verified-but-undecoded value bytes) in every
  language, so fields Apple adds later remain accessible without a library
  update. The JWS side was already dynamic (0.6's `verifyRaw` returned all
  claims; 0.7's `verifySignedData` returns the payload JSON as signed).
  Endpoint environment routing fails closed: only `Production` /
  `ProductionVPP` receipt types count as production; sandbox variants
  (incl. `ProductionVPPSandbox`), `Xcode`, and a missing attribute route
  as non-production — a VPP-sandbox misroute found by the adversarial
  review drove this tightening.
- **D13 — Receipt signer-purpose OID is mandatory** (adversarial review,
  2026-08-06): the legacy PKCS#7 path now requires OID
  `1.2.840.113635.100.6.11.1` on the signer leaf (all four languages),
  checked after chain validation. Verified against genuine production +
  sandbox + legacy receipts (all carry it) and a no-OID negative fixture
  (rejected). This closed a CRITICAL forgery hole: chain-to-pinned-root
  alone let any developer certificate sign an accepted receipt. Also
  hardened the same review's findings: Swift CMS parsing is now
  bounds-checked (was an uncatchable out-of-bounds trap → DoS), and the
  cross-language anti-forgery test matrix (marker-OID rejection, Production
  appAppleId binding, receipt signing-time validity) is now covered in all
  four languages, not just Java.
- **D9 — verifyReceipt wire-compat endpoint** (2026-08-05): each language
  ships a `verifyReceiptEndpoint` (a class of its own until 0.7) speaking Apple's exact request/response/
  status-code contract, with 21007/21008 routing reproduced locally from
  the receipt's `receipt_type` attribute. Fidelity and unavoidable gaps:
  [COMPARISON.md](./COMPARISON.md).
- **D14 — Published as `apple-purchase-receipt-verifier`** (owner decision,
  2026-08-11): one registry name on all four registries, replacing the
  working name `apple-purchase-verifier`. Two constraints settled it.
  Maven Central indexes only groupId and artifactId, matching whole tokens
  with AND, so a developer searching "apple receipt" finds this library
  only if both words sit in the coordinates. And a store-neutral name
  (covering Google Play as well) would over-promise, because Play's
  offline verification cannot express expiry or revocation, so nothing
  here generalizes past Apple.
  - Coordinates: `io.github.emindeniz99:apple-purchase-receipt-verifier`
    (Maven Central), `apple-purchase-receipt-verifier` (npm, PyPI), and a
    SwiftPM repository of the same name shipping the
    `ApplePurchaseReceiptVerifier` product.
  - Import namespaces drop the trailing `verifier`: Java package
    `io.github.emindeniz99.applepurchasereceiptverifier`, Python import package
    `apple_purchase_receipt_verifier`, Swift module `ApplePurchaseReceiptVerifier`. The
    types inside already say `JwsVerifier` and `ReceiptVerifier`, and
    Python callers would otherwise type 31 characters per import.
  - Version is `0.1.0` in all four manifests. The pom said
    `0.1.0-SNAPSHOT`; no release automation exists yet that needs a
    SNAPSHOT cycle, and the other three manifests already declared 0.1.0.
    Whoever wires up the Maven release flow decides then whether to move
    the working version back to SNAPSHOT between releases.
- **D15 — All three published Apple roots are pinned, superseding the
  two-root choice inside D12** (owner decision, 2026-08-16, after a
  primary-source research pass): both `jwsRoots`/`receiptRoots` sets now
  contain Apple Inc. Root, Apple Root CA - G2, and Apple Root CA - G3.
  What forced the change: Apple deliberately does not commit to a
  specific root for either verification path, and G2 is already
  published — if Apple ever issued a WWDR intermediate under it, the
  `apple-root-watch` workflow would see no change on the PKI page and
  our fail-closed verifiers would start rejecting genuine receipts with
  zero warning. Evidence:
  - JWS: the `JWSDecodedHeader` doc specifies the intermediate by OID but
    calls the third element only "An Apple root certificate"
    (<https://developer.apple.com/documentation/appstoreserverapi/jwsdecodedheader>),
    and an App Store Commerce Engineer answered the "always G3?" question
    directly with "use all Apple Root CAs"
    (<https://developer.apple.com/forums/thread/742525>). WWDC23 session
    10143 uses the same set-membership framing ("one of the certificates
    you stored as an Apple Root Certificate Authority").
  - Legacy receipts: Apple's Dec 2022 signing-certificate notice names the
    Apple Inc. Root and warns against hardcoding the *intermediate*
    (<https://developer.apple.com/news/?id=ytb7qj0x>). Real Mac App Store
    receipts verify against it (and fail against G2/G3).
  - Today's chains: no published WWDR intermediate is signed by G2 — the
    ones checked chain to Apple Inc. Root (WWDR G3/G4/G5/G7/G8 and the
    expired original) or to Apple Root CA - G3 (WWDR "- G2" and "- G6";
    the WWDR names do not track their root's name). So G2 anchors nothing
    *currently* — pinning it is insurance against re-anchoring, at zero
    trust cost since it sits at the same assurance level on the same page.
  - Contrast that shows the omission is deliberate: where Apple wants a
    single-root guarantee it writes one — the Apple Pay payment-token doc
    says "Ensure that the root CA is the Apple Root CA - G3". No such
    sentence exists for App Store JWS or receipts.
  What still holds from D12: anchors ship pinned (never fetched at
  runtime), the weekly watch diffs both the pinned bytes and the PKI
  page's root listing, and callers can inject their own anchors. 0.7
  merged the two sets into the one `Config.defaults()` holds.
- **D16 — Hand-written ASN.1/CMS readers stay, and are fuzzed; library
  parsers are used where a maintained one fits** (owner decision,
  2026-09-05, after a per-language research pass; extends D8 to every
  port). The question was whether the six ports that read hostile bytes
  with their own code — rust, go, dotnet (JSON only), php, node, ruby —
  should move to a library. The answer is no, for reasons that were
  measured rather than assumed:
  - Apple's own Xcode and StoreKit-test receipts are BER with *indefinite*
    lengths (10 of 11 receipt fixtures; `openssl asn1parse` shows `l=inf`
    down to depth 5), and the strict-DER libraries reject them:
    RustCrypto `der`/`cms` (open issue since 2022-11), Go `encoding/asn1`
    and `cryptobyte`. The Go PKCS#7 forks (mozilla, smallstep, fullsailor)
    accept BER by converting the whole structure to DER first and then
    verify the signature over bytes *they* produced, not the bytes Apple
    signed.
  - Libraries that do read BER have no bounds. phpseclib3's `decode_ber`
    takes no depth parameter and carries CVE-2024-27355 on exactly that
    axis; spomky-labs/pki-framework 1.6.1 turns 400 KB of nested SEQUENCEs
    into a 208 MB decode (a `memory_limit` fatal, not a `Throwable`, at
    the php.ini-production default) and, worse, silently mis-decodes the
    indefinite-length `[0]` that every CMS `ContentInfo` in an Xcode
    receipt uses — wrong tree, no error. Ruby's `OpenSSL::ASN1.decode`
    recurses in C and escapes `rescue` with `SystemStackError`;
    `OpenSSL::PKCS7` accepts trailing bytes and does not expose the digest
    OID the SHA-1/SHA-256 allow-list needs.
  - Signature checks need the exact bytes that were signed. Every
    candidate that re-encodes (pki-framework's `toDER()`, the Go forks'
    `ber2der`) verifies a normalised view instead; the hand-written
    readers keep input slices.
  - Trust isolation: PHP's `ext-openssl` CMS/PKCS#7 verifiers consult the
    process's `openssl.cafile`; `OpenSSL::X509::Store` and `X509Chain`
    reach the platform store unless carefully disabled. The pinned-anchor
    rule is easier to prove over code that cannot reach a store at all.
  - The web Node build must run on WebCrypto-only runtimes (workerd,
    Fastly); `node-forge`, `crypto.X509Certificate` and `jsrsasign` (end
    of support 2026-08-14) are out on that alone.
  What each port uses from a library is therefore the arithmetic — RSA,
  ECDSA, digests — from the ecosystem's standard option (RustCrypto,
  Go stdlib, Microsoft's `System.Security.Cryptography.Pkcs` and
  `System.Formats.Asn1` for the whole CMS layer in dotnet, `ext-openssl`,
  WebCrypto/Node `crypto`, the `openssl` default gem), and the structure
  walk is a few hundred bounded lines per port. Consequence, and the
  price of the choice: every hand-written reader has a coverage-guided
  fuzz target in CI (`go-fuzz`, `rust-fuzz`, and the per-port jobs added
  with them), seeded from the shared fixtures, with the anchor-set
  invariant — an accepted input must fail against an unrelated anchor
  set — so a fuzzer can find wrong acceptances, not only crashes.
  Python's `asn1crypto` is the one exception to "maintained": last
  release 1.5.1, 2022-03, though at ~155M downloads a month it is about
  as widely exercised as a parser gets. Owner decision: keep it, pin the
  tested range, and let the python fuzz target run through it. Java kept
  `jackson-databind` until 0.7: maintained, widely deployed, and the
  payloads are small and flat; the CVE history it carries is scanner
  noise, not a weakness in how it is used here. **Superseded in 0.7**
  ([docs/design/0.7-api.md](./docs/design/0.7-api.md), "Removed in 0.7"):
  Java dropped `jackson-databind` and `jackson-annotations` and keeps only
  `jackson-core`'s streaming parser and generator. **Superseded in 0.8.0
  for the eight non-Java packages** by D17 and D18: their hand-written
  readers are deleted, and they run one Rust core whose ASN.1, CMS and
  X.509 work is OpenSSL's. **Kept for Java**, the independent
  implementation (D27): BouncyCastle for the structures, `jackson-core`
  for JSON, and the Jazzer fuzz targets.

The records below settle the 0.8.0 architecture. Each is the outcome of a
record in [docs/rust-core/DECISIONS.md](./docs/rust-core/DECISIONS.md)
(named in brackets), which carries the options, the evidence and the
rejected alternatives with their measured reasons.

- **D17 — One Rust core, run as one `aprv.wasm`, under eight packages; one
  Java implementation beside it** (owner, 2026-09-25, rewritten on the
  Wasm-first basis 2026-09-28; R1, R22). The Rust core in `rust/` is the
  only implementation behind npm, the Go module, PyPI, SwiftPM, RubyGems,
  NuGet, Packagist and the Java `-wasm` artifact. It ships in one form, a
  `wasm32-wasip1` module built once per release, and each language runs it
  in a Wasm runtime it already has: jco's bindings on the JS engines,
  wazero (Go), wasmtime-py (Python), the `wasmtime` gem (Ruby), WasmKit
  (Swift), Wasmtime .NET, Endive on Java 11+. Java 8 and PHP reach the
  same module through `aprv-server` (D22). Wrappers read the clock, move
  bytes in and JSON out, pool instances and map the outcome; they parse,
  verify and decide nothing, and the `one-implementation` CI job holds
  them to it. Why: one build artifact carries every security decision to
  every language, with one hash to check, and a memory-safety bug in the
  parser stays inside the module's sandbox instead of the caller's
  process. The cost is speed, above the owner's floor of about 10
  verifications per second per core on every host (BENCHMARKS.md), and
  monoculture, which D27 answers. The C ABI (`rust/ffi`) stays, source
  only, for platforms no runtime reaches. Fastly Compute JS and Akamai
  EdgeWorkers are dropped: neither runs WebAssembly (R5).
- **D18 — The core's substrate is OpenSSL 4 with the CMS API** (owner,
  2026-09-26; R21). The risk the owner named is code we write ourselves
  for generic security protocols, and speed does not matter. OpenSSL
  parses the ASN.1, CMS and X.509 and does the signature arithmetic
  (`CMS_SignerInfo_verify` and `X509_verify_cert` over a store of the
  pinned roots only, never `CMS_verify`); the receipt payload is decoded
  with OpenSSL's ASN.1 templates; the Rust code keeps Apple's policy
  (roots, markers, the chain instant, the bounds, the reasons and their
  order) under `#![forbid(unsafe_code)]`, and `unsafe` lives only in the
  adapter (`rust/openssl`), the ABI crate, the C ABI and the server. One
  header walk (`rust/openssl/src/walk.rs`) applies 0.7's depth, value,
  certificate, SignerInfo and CRL bounds before OpenSSL decodes anything
  (the review, THREAT-MODEL.md §11). OpenSSL loads no configuration and no
  default trust path. The core's own `asn1`, `x509`, `cms`, `chain` and
  `crypto` modules and the RustCrypto dependencies are gone, and
  `tools/check-layering.mjs` keeps them gone.
- **D19 — The module's ABI is the canonical ABI over one WIT file**
  (owner, 2026-09-29; R23). `rust/bindings/abi/wit/aprv.wit`
  (`aprv:verifier@0.1.0`) declares four operations (`init`,
  `verify-receipt`, `verify-signed-data`, `verify-receipt-endpoint`),
  inputs as `list<u8>`, the environment as a `u32` the guest checks,
  `now-ms` as a `u64`, outputs as JSON strings, and one import,
  `random-get`. Component runtimes bind it with generated code (jco,
  Wasmtime `bindgen!`); the others call the core exports by hand in 35 to
  66 lines. The WIT is the contract: CI diffs the interface read back from
  the built module against the file, and the export names carry the
  version, so a wrapper of another version fails at `create`. The
  instance model: `Verifier.create(config)` owns a small pool, each
  instance gets `init` once with the roots, one call at a time per
  instance, a trapped instance is discarded, no handles cross the API.
  Node holds one instance. `aprv-server` makes a fresh instance per
  request; `--lifecycle pool` keeps them, and the `init` measurement of
  2026-09-29 met R23's rule for making the pool the default.
- **D20 — Time crosses as `now-ms` on every call; the module has no clock**
  (owner, 2026-09-28; R24, superseding R10). The wrapper reads its
  `Config` clock once per call and passes the value. The core uses it
  where 0.7 does: the chain instant when the input carries no usable date,
  and `request_date`. No public per-call time is added.
- **D21 — Java ships two artifacts, both on Java 8** (owner, 2026-09-28;
  R25, R26). `apple-purchase-receipt-verifier` stays the independent
  BouncyCastle implementation, unchanged in API. `-wasm` has the same
  package, class names and `Config`, and runs the module on Endive
  (compiled to JVM bytecode at build time, no native code) on Java 11+ or
  through `aprv-server` as a supervised child on Java 8. The engine is
  chosen in code only, `Engine.endive()` or
  `Engine.server(ServerSource...)` with `url`, `executable`, `maven`,
  `github` and `download` sources in the user's order; the library reads
  no system property and no environment variable of its own. A classpath
  guard refuses both artifacts at once. The static Linux server binaries
  ship as `linux-x86_64` and `linux-aarch64` classifier jars of `-wasm`,
  each pinned by SHA-256 inside the jar; macOS and Windows binaries come
  from the GitHub Release. The artifact lives in `java-wasm/` beside
  `java/` rather than as a module of one reactor, so no path moved.
- **D22 — `aprv-server` is a product and an engine** (owner, 2026-09-25
  and 2026-09-28; R17, R31). One Rust binary, `aprv`, runs the released
  component on Wasmtime 49 runtime-only, precompiled at build time for an
  explicit baseline target and embedded: an HTTP server, the managed child
  of a Java 8 or PHP parent, and a one-shot CLI. It adds no verification
  logic. It binds `127.0.0.1` unless `APRV_LISTEN` says otherwise, takes a
  token, refuses a body over 3 MiB with 413, limits each store to 256 MiB
  and each call to 10 s of guest time. Linux builds are fully static musl
  for x86_64 and aarch64; macOS and Windows builds ship for x86_64 and
  arm64; a distroless, non-root image goes to GHCR, and to Docker Hub once
  the owner creates the namespace. Exotic CPUs without a Cranelift backend
  stay open.
- **D23 — Python runs the plain module on wasmtime-py and compiles it at
  start** (owner, 2026-09-28; R27, R28). wasmtime-py at or above the
  current major with no pin to one major; Wasmtime's compile cache on by
  default in the user's own cache directory, silently off when the
  directory is read-only or not the user's, moved by
  `APRV_WASM_CACHE_DIR`. A precompiled module in the wheel was rejected
  because it ties the wheel to one Wasmtime major. On a platform with no
  wasmtime-py wheel, installation stops with a pointer to `aprv-server`
  or the C ABI.
- **D24 — PHP calls `aprv-server`** (owner, 2026-09-28; R29). One `aprv`
  process per call by default, or a server URL the user runs; an
  `aprv-install` command downloads the binary from the GitHub Release and
  checks a SHA-256 pinned in the package. Nothing downloads at request
  time, and no PHP code touches a certificate, so `ext-openssl` is no
  longer needed.
- **D25 — Floors for 0.8.0** (owner, 2026-09-28; R30). Java 8 (both
  artifacts; Endive needs 11), Python 3.10, Swift 6.3 with macOS 15 and
  iOS 18 (raised from 6.1 and macOS 13, because WasmKit declares them),
  Ruby 3.3, .NET netstandard2.0 tested on .NET 8 and later, Node 20, Go
  1.22 (wazero v1.9.0 is the newest release that builds on it), PHP 8.2.
  Go moved to 1.25 on 2026-09-30 (owner), because wazero 1.12 needs it.
  The Java 8 CI legs move from Temurin to Zulu or Corretto before Temurin
  8 builds end. SUPPORT-MATRIX.md lists what each floor rests on.
- **D26 — The isolation invariant** (owner, 2026-09-28; R32). Every
  shipped host puts at least one boundary between a hostile receipt and
  the caller's process: a Wasm sandbox in process, or a separate process
  that runs the sandbox too. Native in-process verification is not
  shipped by default; the Rust crate and the C ABI are for callers who
  choose it. THREAT-MODEL.md §6 classifies every package.
- **D27 — The Java implementation is maintained as the second opinion,
  and a behaviour change moves both** (owner, 2026-09-28; R33, superseding
  R8's frozen jar). The Java implementation stays in the repository,
  maintained. A verification behaviour change touches the Rust core, the
  Java implementation and `fixtures/cases.json` in the same PR; every
  package runs every case as one test. The nightly differential job runs
  both implementations over every input it collects. A frozen jar was
  rejected because every intended change in the core would have become a
  recorded divergence.
- **D28 — Apple compatibility is the goal, and differences are recorded**
  (owner, 2026-09-26; R20). `fixtures/cases.json` is the contract. The
  core accepts any signer and chain signature algorithm the pinned Apple
  chain vouches for. Differences between the core and Java are listed in
  docs/rust-core/DECISIONS.md R20 with their reasons; one that changes an
  Apple-signed input's verdict, or accepts something unsigned, is a bug,
  and no check is added to the core only to match Java.
- **D29 — Standards** (owner, 2026-09-29; R34). The canonical ABI over WIT
  (D19); JSON Schema 2020-12 for the wire shapes
  (`rust/bindings/wire/schema/`), against which CI validates every answer;
  OpenAPI 3.1 for `aprv-server` (`rust/server/openapi.yaml`), linted by
  Spectral and exercised by Schemathesis; RFC 9457 problem documents for
  the server's non-result errors; SLSA build provenance and a CycloneDX
  SBOM per release artifact; `tools/reproduce-wasm.sh` for the module's
  hash; OCI annotations on the image; cbindgen for the C header.
  `wasi:random` was measured as the module's import and not adopted; JCS
  was considered and not adopted, since no signature is computed over our
  JSON.
- **D30 — One release, 0.8.0, and what is built or committed** (owner,
  2026-09-25 and 2026-09-28; R14, R19). Every package moves to the core in
  one release under the 0.7 API. `aprv.wasm` is built once per release and
  every package's copy is checked against its SHA-256; only Go and the
  Swift package commit it, because their registries build from the git
  tree, and the release branch refreshes both copies and every pin
  together. The core's crate stays at 0.7 on crates.io until `openssl-sys`
  accepts OpenSSL 4; a crates.io build would get OpenSSL 3, which the
  adapter refuses.

## 1. Existing solutions (research, 2026-08)

| Solution | Local verify? | Notes |
|----------|--------------|-------|
| [apple/app-store-server-library-java](https://github.com/apple/app-store-server-library-java) (also [-node](https://github.com/apple/app-store-server-library-node), [-python](https://github.com/apple/app-store-server-library-python), [-swift](https://github.com/apple/app-store-server-library-swift)) | **Yes** (JWS only) | Official. `SignedDataVerifier` validates JWS `x5c` chains against caller-supplied Apple roots, offline by default (optional OCSP "online checks"). Does **not** validate legacy PKCS#7 receipts — `ReceiptUtility` only *extracts* a transaction ID from a receipt, unverified. Heavy: bundles the full App Store Server API client. |
| `node-apple-receipt-verify`, `itunes-iap`, `django-receipt-validator`, … | No | All wrappers around the deprecated `verifyReceipt` endpoint — the thing we're replacing. |
| [SilentCircle/iap-local-receipt](https://github.com/SilentCircle/iap-local-receipt) (Python) | Yes (PKCS#7 only) | The one prior server-side local validator we found. Abandoned (~2016, Python 2 era; relies on the PKCS7 API modern pyOpenSSL removed), no JWS; does offer the optional GUID device-hash check. Proves demand; not usable today. |
| [tikhop/TPInAppReceipt](https://github.com/tikhop/TPInAppReceipt) (Swift), [SwiftyLocalReceiptValidator](https://github.com/andrewcbancroft/SwiftyLocalReceiptValidator) | Yes (PKCS#7, on-device) | Client-side focus (`identifierForVendor`, bundle receipt URL); TPInAppReceipt is maintained. Same crypto, different deployment target. **Taken**: the attribute-name table in `Sources/Core/AppReceiptField.swift` — app-level 0, 8, 9, 10, 11, 15, 16, 18 and in-app 1707, 1713, 1721, the only published enumeration that names any of them (RECEIPT-FIELDS.md attributes them line by line); two of the genuine receipts in `fixtures/public-receipts/` come from its test assets; and the device UUID its `Tests/Validation/Verifiers/HashVerifierTests.swift` publishes, which reproduces attribute 5 of `receipt-sandbox-g5` and so pins the hash order against Apple-signed bytes. **Not taken**: its `unknown_NNNN` and "reserved for future use" labels, which this repository leaves unnamed rather than importing as meaning; its verifier-builder API shape and Security-framework (`Sec*`) verifier split, both on-device concerns; and its intro-offer-eligibility and purchase-query helpers, which are entitlement policy that INTENT.md puts out of scope. |
| [Faisal Bin Ahmed, "All the wrong ways to persist in-app purchase status in your macOS app"](https://medium.com/@Faisalbin/all-the-wrong-ways-to-persist-in-app-purchase-status-in-your-macos-app-ce6eb9bcb0c3), March 2023 | No (client-side persistence, StoreKit 1) | A macOS developer's write-up of four storage schemes for an entitlement flag, three of which he breaks himself: a UserDefaults bool (the sandboxed container plist is user-writable once `cfprefsd` is killed), a Keychain application password (the owner can edit it, and can create one with a known account name), and the two combined behind a per-user UUID salt ("achieves nothing" — the attacker writes both halves). **Taken**: the negative result as the argument for INTENT.md's position that a signature, not a stored flag, is the only durable client-side artefact — and the observation that its recommended fix, `TPInAppReceipt.localReceipt()` plus `containsPurchase(ofProductIdentifier:)`, parses without verifying, the same "extract, don't validate" shape as Apple's own `ReceiptUtility` and the reason this library exists. It is also where the macOS device-GUID correction above came from: on macOS the hash input is the MAC address, not `identifierForVendor`. **Not taken**: everything it proposes or breaks is on-device entitlement caching, out of scope per INTENT.md; its `cfprefsd` framing as a deliberate integrity guard (it is a write-through preferences cache, not a security control); and its single deferred sentence about validating and refreshing the receipt, which is the part a server actually performs. It names no ASN.1 attribute and cites no Apple field, so RECEIPT-FIELDS.md gains nothing from it. |
| Apple, [Validating receipts on the device](https://developer.apple.com/documentation/appstorereceipts/validating-receipts-on-the-device) and the archived [Receipt Fields](https://developer.apple.com/library/archive/releasenotes/General/ValidateAppStoreReceipt/Chapters/ReceiptFields.html) chapter (last revised 2017-12-11) | Yes (on-device, OpenSSL) | The primary source: the payload ASN.1 module and the attribute-number table. Types 0 and 18 are not on it; they are community-established. |
| objc.io ["Receipt Validation"](https://www.objc.io/issues/17-security/receipt-validation/), Laurent Etiemble, issue 17, October 2014 | Yes (on-device, C/OpenSSL) | The worked example this repository's device-hash example is ported from. **Taken**: the concatenation order `SHA1(device GUID ‖ opaque value ‖ bundle id)` and — the part that decides whether an implementation works at all — its rule that the hash runs over "the ASN.1 attribute's raw values (i.e. the binary data of the OCTET-STRING), and not on the interpreted values", which is why `ReceiptPayload.bundleIdBytes()` exists beside `bundleId()`; also the "ignore unlisted attributes" rule that RECEIPT-FIELDS.md quotes. It names app-level types 2, 3, 4, 5 and 21 and no in-app numbers at all. **Not taken**: its chain-validity instant — `PKCS7_verify` with no date argument validates at the current time, whereas we anchor at attribute 12, the case Apple's own guidance warns about and that both genuine fixtures now exercise; its type 21 expiry comparison against the wall clock, which is a VPP device-policy decision a server cannot make for the caller; and everything from "Handling the Validation Result" onward (exit code 173, receipt refresh, string obfuscation, anti-debugging), which presumes the validator runs inside the app being protected. |
| [Kodeco tutorial](https://www.kodeco.com/9257-in-app-purchases-receipt-validation-tutorial), [nick.zoic.org PKCS#7 notes](https://nick.zoic.org/art/apple-signed-receipt-verification-pkcs7/) | Yes (on-device, Swift/Python) | Secondary: worked examples of the PKCS#7 + ASN.1 receipt format we port to server-side. Neither carries an attribute number beyond Apple's own list. |
| [fluffy.es, "Local receipt validation"](https://fluffy.es/in-app-purchase-receipt-local/) | Yes (on-device, Swift) | Found through TPInAppReceipt's README. Cited only as an independent statement of the hash order — "concatenate the GUID value with the Opaque value, then concatenate with the Bundle Identifier", matching objc.io. It names no ASN.1 attribute numbers, so it settles nothing about the field table. |

**Conclusion** (re-verified 2026-08): no maintained library covers both
paths (JWS + legacy PKCS#7) server-side in any language, let alone across
our four. Server-side legacy validation appears to simply not exist for
Java and Node; the only Python attempt is a decade stale. The official
libraries are the reference for the JWS algorithm (we mirror their checks,
and verify their exact test fixtures); the PKCS#7 path we implement from
Apple's on-device validation spec. Building it ourselves also keeps each
implementation dependency-light and auditable — appropriate for
security-critical code we must be able to reason about.

## 2. Verification algorithms (normative for every language)

Since 0.7 the library applies no policy: it checks that Apple signed the
input and returns the payload, and the caller checks bundle id,
environment, app Apple id and device binding on what it returns.
[docs/design/0.7-api.md](./docs/design/0.7-api.md) is the full 0.7
contract; where the two differ, it wins.

### 2.1 JWS signed data (StoreKit 2 / Server Notifications V2)

Input: compact JWS string, and the `Config`: trusted roots (Apple Root CA –
G3 among them) and a clock.

1. Split `header.payload.signature`; base64url-decode the header JSON.
2. Require `alg == "ES256"` and an `x5c` array of **exactly 3** certificates
   (leaf, intermediate, root).
3. Marker OIDs (rejects any non-App-Store Apple-issued cert):
   - leaf must carry extension OID `1.2.840.113635.100.6.11.1`
     (Apple in-app-purchase / receipt signing marker);
   - intermediate must carry OID `1.2.840.113635.100.6.2.1`
     (Apple WWDR CA marker) and `CA: true`.
   Checked **after** the path validation of step 4, so a chain that does
   not reach a pinned root is `UNTRUSTED_CHAIN` whatever markers it
   carries.
4. Path-validate leaf → intermediate → **our pinned root** (standard PKIX:
   signatures, issuer/subject chaining, basic constraints, validity window),
   **revocation disabled** (no OCSP — offline by design). The chain must
   terminate at a pinned trust anchor; the x5c-supplied root (`x5c[2]`) is
   **not** trusted or byte-compared — only the intermediate being signed by
   one of our pinned anchors counts, so an attacker swapping in their own
   `x5c[2]` changes nothing.
   - Validity is checked at the payload's `signedDate` (the `Config` clock
     when it is missing or not a representable instant), so historical payloads
     signed with since-rotated certs still verify — same model as Apple's
     official libraries in offline mode.
5. Verify the ES256 signature over `ASCII(header + "." + payload)` with the
   leaf public key (P-256, SHA-256, raw r‖s per RFC 7515 → DER for JCA-style APIs).
6. Confirm the payload is a JSON object, under the depth and size bounds;
   one that is not is `UNREADABLE_PAYLOAD`. No claim is checked: bundle id,
   environment and app Apple id are the caller's to compare.
7. Return the payload JSON exactly as signed. Any failed step returns a
   failure with one of the eight reasons of the 0.7 design — never a
   partially-verified result.

### 2.2 Legacy PKCS#7 app receipt

Input: the receipt's base64 (the exact blob apps send to `verifyReceipt`),
and the `Config`: trusted roots (Apple Inc. Root CA among them) and a clock.

1. Parse as CMS `SignedData`; require signed content present (the payload).
   Present but zero bytes long counts as present.
2. Extract the embedded certificate chain; identify the signer cert; build
   and PKIX-validate signer → WWDR CA → pinned Apple Inc. Root CA,
   revocation disabled.
   - Validity is checked at the receipt's **creation date** (attribute 12) —
     Apple's receipt-signing certs expire and rotate; a receipt is valid if
     its chain was valid when Apple signed it. Only that date is read before
     trust: walk the top-level attribute SET, read each entry's type, decode
     the value of type 12 alone. Missing, empty, unreadable, or a walk that
     fails on any entry: judge the chain at the `Config` clock instead.
     Reading the date never rejects a receipt. Since 0.7 the first copy of a
     repeated attribute 12 is used.
   - The chain is checked before the signature (step 4) on purpose: the
     signature check would otherwise run the attacker's own key, with an
     RSA size and exponent of their choosing, before anything is trusted.
3. **Signer purpose check (critical):** require the signer leaf to carry
   extension OID `1.2.840.113635.100.6.11.1` (the Apple receipt-signing
   marker, present on the genuine "Mac App Store and iTunes Store Receipt
   Signing" leaf, absent on developer certs). Without this, any certificate
   chaining to the pinned Apple root — including any Apple developer's own
   "Apple Distribution"/"Apple Development" leaf, which chains through the
   same WWDR intermediate — could sign a fully forged receipt. This mirrors
   the JWS leaf marker check (§2.1 step 3). Checked **after** chain validation
   so a foreign chain still reports `UNTRUSTED_CHAIN` first. Since 0.7 the
   WWDR intermediate must also carry `1.2.840.113635.100.6.2.1`, as on the
   JWS path.
4. Verify the CMS signature over the content with the signer's public key
   (Apple signs receipts with SHA-1/RSA or SHA-256/RSA — accept what the CMS
   `SignerInfo` declares, but only after the chain anchored at our pinned root
   and the signer-purpose check). Since 0.7 (#160) the signer's key type,
   digest and signature algorithm are not restricted.
5. Parse the whole payload, now that its signer is trusted. Any failure here
   is `UNREADABLE_PAYLOAD` (status 21009 at the endpoint), never
   `MALFORMED`: a trusted signer signed content this library
   cannot read, which is the library's gap or a new Apple format and not a
   malformed client request. Grammar: `SET OF ReceiptAttribute ::= SEQUENCE {
   type INTEGER, version INTEGER, value OCTET STRING }`. App-level attributes:
   | type | field | value encoding |
   |------|-------|----------------|
   | 2 | bundle id | UTF8String (keep raw bytes too — needed for hash) |
   | 3 | app version | UTF8String |
   | 4 | opaque value | raw bytes |
   | 5 | SHA-1 hash | raw bytes |
   | 12 | receipt creation date | IA5String, RFC 3339 |
   | 17 | in-app purchase | nested `SET OF ReceiptAttribute` (repeats) |
   | 19 | original app version | UTF8String |
   | 21 | expiration date | IA5String |
   In-app attributes: 1701 quantity, 1702 product id, 1703 transaction id,
   1704 purchase date, 1705 original transaction id, 1706 original purchase
   date, 1708 subscription expiration date, 1711 web order line item id,
   1712 cancellation date, 1719 is-in-intro-offer-period.
6. Check nothing else. Since 0.7 the bundle id and the device binding
   (`SHA1(guid ‖ opaqueValue ‖ bundleIdRawBytes) == attribute 5`) are the
   caller's checks, made on the fields the payload returns.
7. Return the typed receipt (app fields + list of in-app purchases), or a
   failure, as in 2.1.

### 2.3 Threat model notes

- **Pinned anchors, not system trust store** — a cert chain to any public CA
  must fail; only `certs/*.cer` count.
- **Marker OIDs** stop "valid Apple-issued cert, wrong purpose" attacks on
  **both** paths: the JWS leaf must carry `…6.11.1` and the intermediate
  `…6.2.1`; the receipt signer leaf must carry `…6.11.1` and, since 0.7, its
  intermediate `…6.2.1`. Without the receipt check, any developer cert
  chaining to the pinned root could sign a forged receipt (a real hole
  found by adversarial review, 2026-08-06, now closed).
- **No revocation checking** is the accepted trade-off for offline
  verification (Apple's official offline mode does the same). Compromised
  signing certs are handled by Apple rotating them; consumers concerned
  about revocation can layer OCSP later (roadmap).
- **Replay / refunds are not detectable by signature** — see INTENT.md;
  callers must track transaction IDs and purchase status themselves.
- Parse untrusted bytes defensively: bounded sizes, no recursion on
  attacker-controlled depth, reject trailing garbage.

## 3. Shared API shape (adapt idiomatically per language)

The 0.7 shape; [docs/design/0.7-api.md](./docs/design/0.7-api.md) has the
types and each port's idiom.

```
Environment = { PRODUCTION, SANDBOX }

Config.defaults()                      // the bundled Apple roots + the system clock
Config.builder().roots(...).clock(...) // tests replace both

Verifier.create(config)
  .verifyReceipt(base64)                         -> VerificationResult<ReceiptPayload>
  .verifySignedData(jws)                         -> VerificationResult<JsonPayload>
  .verifyReceiptEndpoint(environment, requestJson) -> response JSON string

VerificationResult { verified, payload | failure }
Failure { reason, message, cause }
Reason = MALFORMED | TOO_LARGE | INVALID_SIGNATURE | UNTRUSTED_CHAIN |
         INVALID_CERTIFICATE | INVALID_CERTIFICATE_PURPOSE |
         UNREADABLE_PAYLOAD | INTERNAL_ERROR
```

0.6's `JwsVerifier`, `ReceiptVerifier`, `VerifyReceiptEndpoint`, the typed
JWS models and the bundle id, environment and device-guid parameters are
gone; each port README's "Upgrading from 0.6" maps them.

Apple root certs are **not** hard-wired: a `Config` takes trust anchors,
and `Config.defaults()` means the three roots of `certs/`, compiled into
the Rust core (and so into `aprv.wasm`) and into the Java implementation. Tests inject a
generated fake "Apple" PKI (root → intermediate-with-OID → leaf-with-OID)
and sign fixtures with it — the same technique Apple's own libraries use —
so tests need no real Apple secrets and prove the anchor pinning works.

## 4. Milestones

1. **Docs** — this folder: INTENT / PLAN / ROADMAP / README / THREAT-MODEL. ✅
2. **Java** (`java/`, Maven, Java 8+, BouncyCastle + Jackson):
   JWS verifier + PKCS#7 receipt verifier + test PKI + full test suite. ✅
3. **Node** (`node/`, Node ≥20, ESM, zero runtime deps — hand-rolled
   bounded DER/BER parser + `node:crypto`; plus a `/web` build on
   WebCrypto alone). ✅
4. **Python** (`python/`, ≥3.10, `cryptography` + `asn1crypto`). ✅
5. **Swift** (`swift/`, SwiftPM, Swift 6, swift-certificates +
   swift-crypto + swift-asn1 only). ✅
6. **Five more ports** — `go/` (1.22+), `ruby/` (3.3+ since 0.7), `rust/`
   (1.85+), `php/` (8.2+ since 0.7) and `dotnet/` (netstandard2.0 +
   net8.0), nine in all. ✅
7. **Cross-language fixture parity**: one shared fixture set
   (`fixtures/generated/` and `fixtures/generated-0.7/`, the vendored Apple-official set in
   `fixtures/apple-official/`, and the genuine Apple receipts in
   `fixtures/public-receipts/`) driven by `fixtures/cases.json`, every
   vector verified byte-identically by all nine suites. ✅
8. **CI per language**: `.github/workflows/ci.yml` carries a test job per
   port plus its runtime, lint, format and fuzz legs; alongside it sit
   `release.yml`, `release-please.yml`, `post-publish-smoke.yml` and the
   scheduled `apple-root-watch.yml`. ✅
9. **0.7: one API** — one `Verifier`, no policy parameters, the eight
   reasons, the shared cases ([docs/design/0.7-api.md](./docs/design/0.7-api.md)). ✅
10. **0.8.0: one core** (D17 to D30) — the Rust core on OpenSSL 4 as
    `aprv.wasm`, eight wrappers over it, `aprv-server`, the Java `-wasm`
    artifact, and the Java implementation kept beside them; the plan and
    its evidence are in [docs/rust-core/](./docs/rust-core/README.md). 0.8.0
    is the first release of this design.
