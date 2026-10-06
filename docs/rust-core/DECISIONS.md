# Decisions for the Rust-core migration

Each record gives its status with a date, the options, the evidence and
the decision. Status is one of:

- **Accepted**: the owner decided it, or accepted the recommendation.
- **Superseded**: a later record replaced it; the record says which, and
  keeps one paragraph of history.

Every record is settled as of 2026-09-29. The owner's brief of
2026-09-28 rewrote the plan on the Wasm-first basis (R22) and settled the
last open questions (R23 to R33); on 2026-09-29 the owner reopened the
export ABI and chose the canonical ABI after two spike rounds (R23), and
adopted the standards of R34. Phase 7 moves the outcomes into PLAN.md as
D17 onward and marks D16 superseded for the eight non-Java ports. After
0.8.0 merged into `main`, the owner's decisions of 2026-09-29 and
2026-09-30 added R35 to R37 and amended R5, R19, R20, R23 and R30, the
owner's decisions of 2026-10-01 added R38 to R41 and rows to R20, and
those of 2026-10-02 amended R17, R25, R31, R34, R39, R40 and R41 and
added R42 and R43 (recorded 2026-10-03);
on 2026-10-03 the owner amended R17 again, reversing its 2026-10-02
client change, and amended R41 for .NET's `Config`; on 2026-10-04 the
owner amended R41 for Go's, Swift's and Node's `Config`, and R23 for the
form of `init`'s configuration (Q30).

The evidence is the 23 notes of 2026-09-25 to 2026-09-29 under
[../evidence/](../evidence/), plus the 2026-09-30 note on the upstream
`vendored-4` feature ([vendored-4][vendored4]) and the 2026-10-01
notes on time-zone crates ([Pacific time-zone crates][pactz]) and on
the JSON reader ([serde_json][jsonserde]). Links use
the short names defined at the end of this file. Rejected alternatives
are in one table at the end, each with its measured reason and its note.

---

## R1. One Rust implementation under eight languages, one Java beside it

**Status: accepted** (owner's brief of 2026-09-25; amended 2026-09-28:
the Java implementation stays, R25 and R33).

Nine hand-written implementations repeat one security algorithm today
(INVENTORY.md). In 0.8.0 the Rust core is the only implementation behind
npm, the Go module, PyPI, SwiftPM, RubyGems, NuGet, Packagist and the
`-wasm` Maven artifact, and it rests on OpenSSL for the generic ASN.1,
CMS, X.509 and signature work (R21). The 0.7 Java implementation over
BouncyCastle stays as a second, independent, maintained implementation:
the main Maven artifact and the live differential oracle (R33).

PLAN.md D16 (hand-written readers per port, each on its ecosystem's
crypto) is superseded for the eight non-Java ports.

**Trade-off accepted: monoculture.** A bug in the Rust core or in OpenSSL
reaches every Wasm-hosted package at once. The maintained Java
implementation, run against the core on every change, is the check
(R33).

---

## R2. Binding toolset

**Status: superseded by R22 on 2026-09-28.**

Final state: no binding generator. Each language runs `aprv.wasm` in a
Wasm runtime it already has, or reaches it through `aprv-server`; the C
ABI with cbindgen stays for everything else (R22).

History: on 2026-09-25 the owner chose UniFFI for Swift, Python and a
Kotlin-over-JNA Java artifact, one plain `aprv.wasm` for JavaScript and
Go, and the C ABI for the rest. On 2026-09-26 Endive took the Java 11+
artifact. The 2026-09-28 brief moved every language onto `aprv.wasm`.
UniFFI, JNA and the other generators are in the rejected table.

---

## R3. Where binding annotations live

**Status: accepted** (recommended 2026-09-25; final form 2026-09-28).

Option C, one generator-free `aprv-surface` crate, holds. Since R22 no
adapter annotates it: the ABI crate and the C ABI call it as plain Rust.
The options A (annotate core types) and B (a mirror per adapter) stay
rejected for the reasons first given: A couples the reviewed core to a
generator, B converts dates, bytes and ids once per adapter.

---

## R4. npm on Node

**Status: accepted** (option C on 2026-09-25; the speed trigger dropped on
2026-09-26; napi-rs rejected on 2026-09-28).

- **Decision:** the plain `aprv.wasm` with a hand-written façade, zero
  runtime dependencies, one package for every JS runtime. No native addon.
- **Evidence:** through ABI v1 on Node 22, 1,343 µs per g5 receipt and
  4,819 µs per JWS ([ABI v1][abi]), against 683 and 732 µs for the 0.6
  `node:crypto` build ([rust-core spikes][spikes], timings; different
  runs, so the ratio is rough).
- **Why no napi-rs:** it would run the core and OpenSSL as native code
  inside the Node process (class E, R32) and add per-platform packages.
  The 2026-09-26 record kept it as a trigger on a user's throughput
  report; the 2026-09-28 brief rejects it. Throughput beyond one Node
  process comes from more processes, or from `aprv-server`.

**Performance guideline (owner, 2026-09-26), for every host.** What
matters is throughput that scales across cores and instances. About 10
verifications per second per core is the floor, 40 to 50 comfortable. The
floor is a guideline, not a gate: a host below it is discussed with the
owner. Every measured host clears it (README.md).

---

## R5. JS runtimes that cannot run WebAssembly

**Status: accepted** (owner, 2026-09-25): drop Fastly Compute JS and
Akamai EdgeWorkers. Amended 2026-09-30: the list of unsupported runtimes
grows, below.

Fastly's JavaScript runtime builds SpiderMonkey without a JIT and
documents no `WebAssembly` object; Akamai lists WebAssembly as removed
([rust-core spikes][spikes], "Findings from outside the container").
Keeping them would mean a second implementation (R1). The npm README and
SUPPORT-MATRIX drop both, the `node-runtimes-fastly` job goes, and the
CHANGELOG marks it breaking. A Fastly user who writes Rust can depend on
the core crate.

**2026-09-30 (owner).** SUPPORT-MATRIX.md also lists LLRT, CloudFront
Functions, Hermes, GraalJS and Nashorn as unsupported, each with its
reason: no WebAssembly, or an embedded engine without the APIs the npm
package loads the module with. Nobody measured them; the reasons come
from each runtime's documented feature set. The rule stays the same: no
second implementation for a runtime that cannot run the module.

---

## R6. Go

**Status: accepted** (owner, 2026-09-25: wazero, plus an opt-in cgo path
on request).

- **Decision:** the Go module embeds `aprv.wasm` and runs it with wazero,
  cgo-free (ARCHITECTURE.md §7.3). An opt-in `-tags aprv_native` build
  over the C ABI is built only when a user asks for it; it is class E, the
  user's choice (R32).
- **Evidence:** the CMS module answered 1,179 of 1,179 rows on wazero
  1.12.0 ([CMS everywhere §2][cms]). An OpenSSL module took 2,495 µs per
  receipt and 8,110 µs per JWS there on the PKCS7 path
  ([substrate bake-off §13][substrate]). BENCHMARKS.md records 207 µs per
  receipt for the hand-written Go port.
- **Rejected options,** kept from 2026-09-25: cgo with committed static
  libraries (loses `CGO_ENABLED=0` and `FROM scratch`); keeping the Go
  port (breaks R1); deprecating the module.

---

## R7. Swift on Linux

**Status: superseded by R30 on 2026-09-28.**

Final state: Swift runs `aprv.wasm` through WasmKit on Linux and on Apple
platforms, with the floors Swift 6.3, macOS 15 and iOS 18 (R30). No
prebuilt Rust library, no SE-0482 artifact bundle, no XCFramework.

History: on 2026-09-25 the owner raised the floor to Swift 6.2 so that
SwiftPM could link a prebuilt UniFFI static library on Linux (SE-0482);
the spike ran on 6.2.4 and 6.4 ([rust-core spikes][spikes] row 14). R22
made the static library unnecessary.

---

## R8. What independent checking survives the migration

**Status: superseded by R33 on 2026-09-28.**

History: on 2026-09-25 the owner chose a test-only Java oracle; on
2026-09-26 the owner revised it to the published 0.7.x jar, pinned by
version and checksum, with no Java verifier source kept in the
repository. R33 keeps the Java implementation maintained instead, so the
oracle follows every intended change. "A frozen jar as the only oracle"
is in the rejected table.

---

## R9. Ruby, PHP and .NET

**Status: superseded on 2026-09-28** by R22 (Ruby and .NET hosts) and R29
(PHP).

Final state: the three packages stay, as thin wrappers: Ruby over the
`wasmtime` gem, .NET over the `Wasmtime` NuGet package, PHP over
`aprv-server`. Their hand-written verifiers are deleted in Phase 7. They
reach their registries once the owner's bootstrap steps are done
(BOOTSTRAP.md); none has been published yet (INVENTORY.md).

History: on 2026-09-25 the brief said "unpublished → remove", and the plan
deleted the three ports after Phase 1. The Wasm hosts made keeping them
cheap: each passed the corpus and the ABI tests ([Ruby][ruby],
[.NET][dotnet], [aprv-server §7][server]).

---

## R10. Clock source on Wasm

**Status: superseded by R24 on 2026-09-28.**

Final state: the module has no clock import; `now_ms` arrives with every
verify call (R24).

History: the 58 `wasm32-unknown-unknown` rows that trapped were exactly
the rows that read the missing clock ([wasm bake-off §4][wasmbake]). The
2026-09-25 record chose a `js-sys` feature, then an installable hook; the
2026-09-26 record chose the `aprv.clock_now_ms` import (option E).
Option C of that record, "take `now` as a parameter", was rejected then
because a caller could move the validity instant; R24 takes `now_ms`
from the wrapper's own `Config` clock, which is the 0.7 contract, and
still offers no public per-call time.

---

## R11. Crypto dependencies and speed

**Status: superseded by R21 on 2026-09-26.** OpenSSL does the signature
arithmetic; the RustCrypto crates, the `std`-feature work and the Marvin
advisory ignore leave with `crypto.rs`.

---

## R12. Native artifacts: targets and trust

**Status: superseded on 2026-09-28** by R22, R26 and R31.

Final state: the core ships as one `aprv.wasm`. The only native
artifacts of this project are the `aprv-server` binaries: static musl for
Linux x86_64 and aarch64, and macOS and Windows builds for x86_64 and
arm64 on GitHub Releases (R31), two of them also as Maven classifier jars
(R26). OpenSSL is compiled once, for `wasm32-wasip1`; a native OpenSSL
build remains only for the C ABI, which ships as source, and for tests.
The native runtimes underneath (wasmtime-py, the wasmtime gem, Wasmtime
.NET) are their projects' artifacts, not ours (SUPPORT-MATRIX.md).

History: on 2026-09-25 and 2026-09-26 the owner accepted 26 C ABI
archives, 19 Python wheels, nine natives in a Java 8 jar and Java 8
libraries on GitHub Releases, under a three-part rule (stable Rust
builds it, CI can test it, someone runs it). The platform research of
that record (Temurin, Alpine, JNA, PyPI tags) stays in the evidence
([rust-core spikes][spikes]).

**Kept from R12:** every artifact gets a SHA-256 and a build-provenance
attestation; release builds pin the toolchain and remap paths; every
package that carries `aprv.wasm` or a server binary ships OpenSSL's
Apache-2.0 licence and NOTICE and the texts of wasi-libc and Rust std
([wasm bake-off §16][wasmbake]); none is copyleft; the library stays MIT.

---

## R13. How much of today's API survives

**Status: superseded by R18 on 2026-09-25**, and the question itself by
0.7: the 0.7 API is the surface for every package (SURFACE.md).

---

## R14. Generated and built outputs: committed or built

**Status: accepted** (recommended 2026-09-25; revised 2026-09-28).

| Output | Committed? | Why |
|---|---|---|
| C header | yes, as today | Consumers read it from the repository; CI regenerates and diffs it |
| `aprv.wasm` in `go/` | yes | The Go module is the git tree at a tag; CI rebuilds it and compares the SHA-256 |
| `aprv.wasm` in the Swift package | yes | SwiftPM builds from git with no build step; same check as Go |
| `aprv.wasm` in npm, PyPI, RubyGems, NuGet | no | Each release job takes the one file the release built, and checks its hash |
| Endive's generated classes | no | The Maven build compiles them from the release's `aprv.wasm` with the pinned plugin |
| `aprv-server`'s `.cwasm` | no | Built per target inside the server's release build |
| Wrapper façades and type declarations | yes, as source | Hand-written; nothing generates them |

Every toolchain is pinned in one place. Bumps of the OpenSSL crates,
wasi-sdk, `wasmtime` (the server), Endive, wazero, WasmKit and the
runtime floors of wasmtime-py, the wasmtime gem and Wasmtime .NET must
pass the full cross-host run before merging.

---

## R15. Order of migration

**Status: superseded on 2026-09-28** by MIGRATION.md's seven phases: the
core, `aprv-server`, the Java `-wasm` artifact, Node and Go, then Python,
Swift, Ruby and .NET, then PHP, then the deletions and 0.8.0. History:
the 2026-09-25 order was Python, Java, npm, Swift, Go.

---

## R16. aprv-surface is generator-neutral

**Status: accepted** (owner, 2026-09-25).

`aprv-surface` depends on the core only and names no binding generator,
runtime or wire format. Since 2026-09-28 it models the 0.7 API exactly,
and no generator exists anywhere in the target. SURFACE.md holds the
contract and its enforcement.

---

## R17. The sidecar: a verifyReceipt server

**Status: accepted** (owner, 2026-09-25: both a product and a Java mode);
carried by R25 and R31 since 2026-09-28.

`aprv-server` is a product of its own (a binary, a Docker image, a
one-shot CLI) and the engine of the Java 8 `-wasm` artifact and of PHP.
It runs the released `aprv.wasm` and adds no verification logic.

**Image registries (owner, 2026-09-25):** GitHub Container Registry, and
Docker Hub once the owner creates its namespace and access token
(BOOTSTRAP.md). GHCR publishes from `release.yml` with the workflow
token.

**Constraints kept from the 2026-09-25 spike:** the Java client sends each
request in one write with `TCP_NODELAY`, because `HttpURLConnection` costs
about 1.5 ms extra per POST; a `noexec` directory blocks an extracted
binary, so `url` and `executable` sources exist; the server binds
`127.0.0.1` and exits when its parent's stdin closes
([rust-core spikes][spikes], "Sidecar"). Executing from memory is in the
rejected table.

**Amended 2026-10-02 and 2026-10-03 (owner): the server engine's HTTP
client.** On 2026-10-02 (Q17) the owner replaced the hand-written
client, `HttpConn`, with the JDK's `HttpURLConnection`: a buffered body,
`Proxy.NO_PROXY`, a pinned TLS socket factory and host name verifier,
and framed bodies only ([HttpURLConnection][huc]). On 2026-10-03, before
that change merged, the owner reversed it on the same pull request, so
no release carried it. The reasons:

- The JDK client brings JVM-wide state the engine cannot switch off. On
  Java 8, where the server engine is the default, a 401 `Basic`
  challenge is answered with the default `Authenticator`'s credentials:
  20 connections an attempt, 19 of them with `Authorization`, 60 sends
  in a call. Java 8 has no per-connection `Authenticator` to stop it.
  A SOCKS proxy from a `ProxySelector` or `socksProxyHost` still carried
  the connection on Java 8, and on JDK 21 for `https`.
- The JDK resends a POST inside each of the engine's attempts. A server
  that closes before the status line got the request 6 times where the
  engine means 3, and one call could open 9 connections.
- The swap added 8 lines net, where its aim was less hand-written code.

The comparison that followed ran `HttpConn`, Apache HttpClient 5.6.4 and
`java.net.http` against the same misbehaving servers and JVM-wide
settings ([HTTP client options][httpopt]). It found six gaps in
`HttpConn`'s own lines. Once they are closed, no JVM-wide proxy, default
TLS context, `Authenticator` or logging setting reaches the engine. Some
JVM-wide state still does: the security provider order
(`SSLContext.getInstance("TLS")` takes the first provider that offers
it), the `jdk.tls.*` properties, `ssl.TrustManagerFactory.algorithm`, a
factory passed to `Socket.setSocketImplFactory`, and the
`javax.net.ssl.trustStore` properties, through which a caller chooses
the roots. The engine keeps `HttpConn`, hardened:

- The socket is opened with `Proxy.NO_PROXY`, so no `ProxySelector` or
  `socksProxyHost` routes it.
- A response is framed by one `Content-Length` of digits, at most
  64 MiB, or by a `Transfer-Encoding` of exactly `chunked`, once. Both
  together, any other coding, a second length, and whitespace before a
  header's colon or at a line's start are refused (RFC 9112 §5.1, §6.3).
  A chunk size is hex digits only, and a line that does not end in CRLF
  is refused (§2.2, §7.1).
- TLS comes from an `SSLContext` built for each connection over the
  JVM's default trust managers: `javax.net.ssl.trustStore` with its type
  and password, else the JDK's `lib/security/jssecacerts`, else its
  `lib/security/cacerts`. `SSLContext.setDefault` and the
  `ssl.SocketFactory.provider` security property do not reach it, so
  other code that installs a trust-all default cannot make the engine
  accept a forged server. The host name is checked inside the handshake
  (endpoint identification `HTTPS`), so a server with the wrong name
  reads no byte of the request. The cost: a private CA trusted only in
  code (a context passed to `setDefault`, with no trust store file) is
  not followed, and no client certificate from `javax.net.ssl.keyStore`
  is sent. A caller who needs either would need a `ServerSource.url`
  overload that takes an `SSLContext`, which does not exist. The owner
  may still choose to follow `setDefault` instead; that change is a
  commit of its own on the pull request. The context is not cached, so
  a change to `javax.net.ssl.trustStore` reaches the next connection
  (the tests rely on that). Building one costs at most about 0.05 ms
  warm and 1.2 ms on first use on JDK 21, and a new pooled connection
  cannot resume an earlier one's TLS session, so each pays a full
  handshake.
- The `Host` header puts an IPv6 literal in brackets and leaves out its
  zone id (RFC 9112 §3.2, RFC 6874 §4).

What `HttpConn` already did right stays: one write per request with
`TCP_NODELAY`, no `Authenticator`, no redirect, no resend inside an
attempt, no content decoding, no logging, a body framed by neither
length nor chunks refused, and an over-cap length refused from the
headers. Two limits stay open, as for every client compared: nothing
bounds a call's total time, so a body that arrives a byte at a time
under the 60 s read timeout is waited for; and a declared length is
allocated (up to 64 MiB) before its first byte arrives.
`ServerHttpTest` checks each framing, proxy and TLS property against
servers that misbehave on purpose, and `HttpConnTest` checks the `Host`
header, on JDK 21 and Java 8. With the hardening reverted, the six tests
for the gaps the comparison found fail, and so do the tests for the
checks added after it.

---

## R18. The Java binding

**Status: superseded by R25 on 2026-09-28.**

History: on 2026-09-25 the owner chose UniFFI's Kotlin over JNA behind a
thin Java façade on the Java 8 floor; on 2026-09-26 the owner split Java
into a Java 11+ artifact on Endive and a Java 8 `-java8` artifact on
UniFFI and JNA with nine natives. The Endive half survives as one engine
of the `-wasm` artifact. The measured costs of the JNA path (a Cleaner
thread and two native copies leaked per Tomcat redeploy, JNA 5.17.0 and
5.19.1) are in the rejected table.

---

## R19. Versions and the crates.io debut

**Status: accepted** (owner, 2026-09-25; restated 2026-09-28).

- 0.7.0 shipped from `main` on 2026-09-28 (tags `v0.7.0` and `go/v0.7.0`)
  and is merged into `rust-core`. It is not part of the
  migration.
- Every package moves to the Rust core in one release, **0.8.0**, under
  the 0.7 API. The phases run one after another with their gates, and
  none of them cuts a release of its own.
- The phases land on a long-lived `rust-core` integration branch. `main`
  keeps taking 0.7.x fixes and is merged into `rust-core` after each one;
  `rust-core` merges into `main` once, when every gate has passed.
- Everything stays 0.x; 1.0 is a separate decision.
- The first crates.io publish waits until something needs it.
- **crates.io after 0.8 (owner, 2026-09-30).** The core crate stays at
  0.7 on crates.io until an `openssl-sys` release can vendor OpenSSL 4.
  The owner opened
  [rust-openssl#2692](https://github.com/rust-openssl/rust-openssl/pull/2692),
  an opt-in `vendored-4` feature that builds `openssl-src` 400.x and
  leaves `vendored` as it is. On the fork's CI the same seven jobs fail
  with and without the change, for reasons outside it, and all six new
  `vendored-4` legs pass ([vendored-4][vendored4]).
- **Open item:** a release with the `-wasm` upload enabled deploys two
  artifactIds and two classifier jars to Maven Central. Whether Central's
  Usage Center counts that as one release event is unconfirmed; the owner
  checks after the first such deployment (BOOTSTRAP.md, "Maven Central";
  the upload is held until `APRV_PUBLISH_JAVA_WASM` is `true`, R41).

---

## R20. Apple compatibility, the algorithm policy, and recorded divergences

**Status: accepted** (owner, 2026-09-26; restated 2026-09-28; the rule
amended 2026-09-30; Java's nesting bound and the core's JSON bounds,
2026-10-01; Java's JSON bounds, 2026-10-05; the core's header walk and
Java's parse before trust, 2026-10-06).

- **The goal:** Apple compatibility and failing closed. `fixtures/cases.json`
  schema v2, 388 cases, is the contract. The Java implementation is a
  reference that is itself held to that contract (R33).
- **Algorithm policy:** accept any signer and chain signature algorithm
  the pinned Apple chain vouches for. With OpenSSL's CMS API the core
  answers as Java does on 22 of 22 algorithm rows
  ([follow-up §3.2][followup]).
- **The rule** (amended by the owner on 2026-09-30): divergences between
  the core and the Java implementation are recorded. A divergence is fixed
  only when it changes an Apple-signed input's verdict or accepts
  something unsigned; that is a bug. Any other divergence makes its case
  port-defined (`oneOf` in `fixtures/cases.json`, listing both answers),
  and nobody writes code in either implementation to imitate the other.
  No prescan or other check is added only to match Java, and none is
  added to Java only to match the core.
- **The 2026-09-30 audit** classified four Java rules that lane J-align
  added on 2026-09-29 as imitation: the six-level cap on constructed
  strings (`Asn1Depth`, `ReceiptCore`, `ReceiptDecoder`), the ten-CRL
  cap, the rule that keeps a five-octet length raw, and the
  `ConstructedStrings` rewriter. Each exists only because OpenSSL refuses
  those BER encodings, on inputs Apple never emits: Apple's receipts and
  certificates are DER, with primitive strings, minimal lengths and no
  CRLs. That matches the OD-17 precedent (STATUS.md). Their removal, the
  eight cases that become port-defined, and the rewritten rows below land
  in their own pull request. The audit examined two core rules and kept
  them on their own grounds: `keyless_target_path` reports path problems
  at the depths `X509_verify_cert` would; `signature_names_digest` kept
  the 0.7 core's `INVALID_SIGNATURE` for a signatureAlgorithm whose hash
  differs from the digestAlgorithm, which is continuity and not a
  security boundary, and its case is already `oneOf`. The owner dropped
  that comparison from the core on 2026-10-05: the core now leaves the
  label to OpenSSL, as Java leaves it to BouncyCastle, which refuses a
  mismatch. OpenSSL checks the signature under the digestAlgorithm. For
  an RSA key it reads the signatureAlgorithm only to choose PKCS#1 v1.5
  or RSASSA-PSS, and compares a hash only in the PSS parameters; for an
  ECDSA key it does not read the signatureAlgorithm at all. An RSA
  PKCS#1 v1.5 signature binds its hash in the DigestInfo, so a relabelled
  one still fails; an ECDSA signature binds none, so one made over the
  digestAlgorithm's hash verifies whatever hash the label names.
  The core's own ten-CRL cap went the same day (owner, 2026-10-05).
  The envelope's value budget bounds how many CRLs there are: the most
  it lets through, 11,092 minimal ones, cost about 0.1 s and 10 MiB in
  the test profile. It does not bound the work inside one: `crl_cb`
  decodes each CRL's extensions eagerly (the AuthorityKeyIdentifier's
  GeneralNames, the issuing distribution point, each entry's
  certificateIssuer; `crypto/x509/x_crl.c:247-316`, 80-163), and an
  `extnValue` is one value to the walk. Only the receipt's size cap
  bounds that: one CRL whose AuthorityKeyIdentifier holds 1,000,000
  empty names (2 MB) costs about 0.6 s and 100 MiB. That is not new,
  since one CRL always fit under the cap (527 ms at 352f0d1), and an
  embedded certificate with a 2 MB subjectAltName costs the same: the
  core's `same_as` (`X509_cmp`) caches every bag certificate's
  extensions before any signature is checked ([redundant
  bounds][redundant]; THREAT-MODEL.md §3.7). Eleven CRLs now verify in
  the core, as in 0.7 and Java, and
  `receipt/reject-eleven-embedded-crls` moves from `MALFORMED` to `ok`
  within its `oneOf`.
  On 2026-10-05 the owner also replaced `keyless_target_path` with
  Java's order. A target a pinned anchor vouched for whose key OpenSSL
  cannot build is `INVALID_CERTIFICATE` before its path is built: the
  receipt signer once `authenticated_top_down` holds it
  (`ReceiptCore.validateChain` checks `authenticated.contains` and then
  the key), the JWS leaf right after the intermediate's signature over
  it (`JwsCore.authenticateTopDown`). A target nobody pinned vouched for
  is `UNTRUSTED_CHAIN` before its key is looked at, as before. The
  removed code was a hand-written half of `X509_verify_cert`, which
  stops on such a target in `X509_get_pubkey_parameters`
  (`crypto/x509/x509_vfy.c:264`, `2531-2535`) before it judges anything
  else. The answer moves only for a vouched-for keyless target that
  also has a validity, CA, critical-extension or marker defect: it is
  now the key's, as in Java. `receipt/reject-signer-on-an-unimplemented-curve`
  and `transaction/reject-x5c-unimplemented-curve` keep
  `INVALID_CERTIFICATE`, and `rust/tests` pins the new order on both
  paths with a signer and a leaf that lack their marker. One input
  moves the other way, failing closed either way: a custom anchor whose
  key OpenSSL cannot build, embedded as the receipt's signer, is
  vouched for without a signature check (an embedded copy of an anchor
  is the anchor), so the core now answers `INVALID_CERTIFICATE`; the
  core before and Java answer `UNTRUSTED_CHAIN`. No case pins it.
- **What stays different under OpenSSL,** measured against the 0.6 Java
  verifier: the CMS build answers as Java does on 1,028 of the 1,048 rows
  the C ABI can express ([ASN.1 payload §3][payload]). Of the other 20, one
  is an acceptance Java refuses, of a signature the key holder really made
  over signed attributes sent in non-DER order; none is a forgery or an
  acceptance of anything unsigned ([CMS everywhere §5][cms]). Two rows
  with 2,000- and 100,000-deep nesting inside unsigned attributes answer 9
  in Java and 0 in OpenSSL; not a bug (owner, 2026-09-26), since nothing
  returned or trusted comes from unsigned attributes.
- **How the plan checks:** Phase 1's differential campaign runs the
  corpus through the 0.7 Java implementation and the core; each
  difference gets a row here with its reason, and the rule above decides.
  The 2026-09-26 divergence table from the Native Image spike stays in git
  history; Phase 1 re-derives the list against 0.7.
- **New Apple fields** land in `unknownAttributes`, which the 0.7 rules
  keep raw. The private-receipt drift check (MIGRATION.md 1.9) reports
  new type numbers.
- **Recorded divergences from the core review** (2026-09-29,
  [core review fixes][corefix]). "0.7" is the Rust core before the
  migration; Java is the 0.7 Java implementation. Rows where all three now
  agree are in the note, not here.

  | Input | 0.7 | Java | Core | Why the core answers so | Case |
  |---|---|---|---|---|---|
  | eContent as an `OCTET STRING` of 7 or more constructed levels | ok | ok (port-defined 2026-09-30; BouncyCastle joins the chunks within its own nesting bound) | `MALFORMED` | OpenSSL decodes six (`ASN1_MAX_STRING_NEST`); changing it means patching OpenSSL. Substrate divergence, fails closed. Apple's receipts are DER and never chunk a string, and the chain is judged either way, so the case allows both (the rule OD-17 applied) | `receipt/reject-econtent-rechunked-into-7-constructed-levels` |
  | A payload attribute value of 7 or more constructed levels | ok | ok (port-defined 2026-09-30) | `UNREADABLE_PAYLOAD` | The same bound, under a verified signature. It holds wherever OpenSSL decodes a string: the value, the version field, a later field, the Xcode wrap (`UNREADABLE_PAYLOAD`), and an unsigned attribute value in the envelope (`MALFORMED`), all read by 0.7. Both cases allow ok | `receipt/unreadable-attribute-value-rechunked-into-7-constructed-levels`, `receipt/unreadable-double-wrap-rechunked-into-7-constructed-levels` |
  | More than 100,000 values in the envelope, or in one attribute SET | `MALFORMED` / `UNREADABLE_PAYLOAD` | ok | as 0.7 | 0.7's node budget, restored: without it a 3 MiB receipt cost 0.3 to 0.7 s before any signature. Inputs are 200 KB or more, so Rust tests pin it, not a shared case | `rust/tests/envelope_bounds.rs`, `receipt_payload.rs` unit tests |
  | A payload string whose length takes more than four octets | kept raw | read (port-defined 2026-09-30; BouncyCastle reads the length) | kept raw | The payload is DER; 0.7's header rules restored. Both verify, and the case pins only the raw octets, which both keep | `receipt/bundle-id-with-a-five-octet-length-is-kept-raw` |
  | A fourth attribute field that is, or holds, an invalid primitive (BOOLEAN of two octets, padded INTEGER, UTCTime under 13 or GeneralizedTime under 15 octets, a constructed INTEGER, a primitive SEQUENCE, an end-of-contents in a definite length) | ok | `UNREADABLE_PAYLOAD` | as Java | Not valid ASN.1 in BER either (X.690 8.1.5, 8.2, 8.3, 8.9.1; a time that short names no time). OpenSSL's `ANY` decoder refuses each as the field itself and keeps a SEQUENCE around it whole, so the header walk applies the same rules at every depth (round-2 review F3): the primitives OpenSSL checks, constructed BOOLEAN, INTEGER, NULL, OID and ENUMERATED, strings of seven levels, and each outermost constructed string handed to OpenSSL whole. The chunks inside a constructed string are joined unchecked, as `asn1_collect` joins them, and not judged one by one (round-3 review F2) | `receipt/unreadable-fourth-field-boolean-of-two-octets`, `receipt/unreadable-fourth-field-sequence-holding-a-padded-integer`, `receipt/unreadable-fourth-field-sequence-holding-{a-short-utctime,a-short-generalizedtime,a-constructed-integer,a-primitive-sequence,an-end-of-contents}` |
  | An invalid primitive inside an unsigned envelope value | ok | `MALFORMED` for a short UTCTime one SEQUENCE deep; others not measured | `MALFORMED` | As above, over the envelope | `receipt/reject-an-unsigned-value-sequence-holding-a-short-utctime`, `rust/tests/envelope_bounds.rs` |
  | A string of 7 or more constructed levels one SEQUENCE deep, in a fourth field or an unsigned envelope value | ok | ok (port-defined 2026-09-30) | `UNREADABLE_PAYLOAD` / `MALFORMED` | OpenSSL refuses the string as a value and keeps the SEQUENCE around it whole; the walk refuses it at every depth, so the verdict does not follow the depth. Fails closed, not Apple-signed; both cases allow both | `receipt/unreadable-fourth-field-sequence-holding-a-7-level-octet-string`, `receipt/reject-an-unsigned-value-sequence-holding-a-7-level-octet-string` |
  | An embedded certificate's outer signature `BIT STRING` in constructed form, two primitive chunks joined to the same signature (BER, outside the signed TBS) | not measured | `MALFORMED` (kept, lane J-align round 3) | ok | OpenSSL joins the chunks and verifies the same signature; the walk used to judge each chunk alone and answered by the signature's first octet (round-3 review F2). The chain is still signed under a pinned root. Java keeps `MALFORMED` on purpose: the second chunk has no initial octet of its own, so under X.690 8.6.4 the value is not a valid BER BIT STRING (it claims 150 unused bits). OpenSSL's `asn1_collect` joins the chunks' raw contents instead. The X.690 spelling of the same signature, each segment with its own initial octet, verifies in Java and is `UNTRUSTED_CHAIN` in the core ([Java round 3][javar3]) | `receipt/accept-a-certificate-whose-signature-bit-string-is-in-two-chunks` |
  | A constructed UTCTime of 13 joined octets one SEQUENCE deep in a fourth field (BER) | ok | `UNREADABLE_PAYLOAD` (port-defined 2026-09-30; BouncyCastle builds no constructed string other than a BIT STRING or an OCTET STRING) | ok | BER allows a constructed string; OpenSSL joins it and the walk agrees. Apple's receipts are DER, so the case allows both | `receipt/accept-fourth-field-sequence-holding-a-constructed-utctime` |
  | Signed content nested 33 deep, with SEQUENCEs or `[0]` context tags | `UNREADABLE_PAYLOAD` | ok (port-defined 2026-10-01; BouncyCastle's bound, 64 by default) | `UNREADABLE_PAYLOAD` | The core's depth bound is 32 (owner, 2026-09-27), counting constructed values of every class. Apple's receipts nest 9 deep, so the case allows both | `receipt/unreadable-signed-content-nested-33-deep`, `receipt/unreadable-signed-content-nested-33-deep-in-context-tags` |
  | An envelope nested 33 deep: in an unsigned attribute value (SEQUENCEs or `[0]` context tags), the digestAlgorithms parameters, a `crls` entry, an embedded certificate's parameters | `MALFORMED` | ok (port-defined 2026-10-01; BouncyCastle's bound, 64 by default) | `MALFORMED` | The same bound over the whole envelope, before any decode. None of these values is signed or Apple's, so the cases allow both | `receipt/reject-an-envelope-nested-33-deep`, `receipt/reject-an-envelope-nested-33-deep-in-context-tags`, `receipt/reject-digest-algorithm-parameters-nested-33-deep`, `receipt/reject-a-crls-entry-nested-33-deep`, `receipt/reject-an-embedded-certificate-with-parameters-nested-33-deep` |
  | A clock past 9999-12-31T23:59:59.999Z, or before -9999-01-02T01:59:59Z, at the endpoint | rendered, a five-digit year with no sign (`10000-01-01 00:00:00 Etc/GMT`) | rendered, with a `+` sign past 9999 (`uuuu`) | `{"status":21009}` (port-defined 2026-10-01) | Such a clock is broken, answered like one that panics; jiff's calendar ends at 9999 and every receipt date the grammar accepts renders (R38) | none: no case pins a clock out there; `rust/tests/endpoint.rs` |
  | A genuinely signed JWS whose header nests 65 deep, or carries a member name of 50,001 characters or an integer of 1,001 digits | `MALFORMED` | `MALFORMED` for the name and the integer (Jackson's defaults: names 50,000, numbers 1,000); ok for the nesting since 2026-10-05 (Jackson's default depth, 1,000; `BoundedJson`'s 64 before) | ok (port-defined 2026-10-01) | The core reads a document into a map of raw member values and skips what nobody reads, with no nesting or length bound of its own (R40); the size caps bound the work. An Apple header carries `alg` and `x5c`, two levels deep, so the cases allow both | `signed-data/reject-a-header-nested-65-deep`, `signed-data/reject-a-header-member-name-of-50001-characters`, `signed-data/reject-a-header-number-of-1001-digits` |
  | A genuinely signed JWS payload nested 65 deep | `UNREADABLE_PAYLOAD` | ok since 2026-10-05 (Jackson's default depth, 1,000; `UNREADABLE_PAYLOAD` before) | ok (port-defined 2026-10-01) | The same reader: the payload is read, `signedDate` with it, and the signature verifies. Nothing unsigned is accepted; the case allows both | `signed-data/unreadable-payload-nested-65-deep` |
  | A `verifyReceipt` request body nested 65 deep around a genuine receipt | `{"status":21002}` | `{"status":0}` since 2026-10-05 (Jackson's default depth, 1,000; 21002 before) | `{"status":0}` (port-defined 2026-10-01) | The same reader over the body: `receipt-data` is read and the receipt verifies. An endpoint case lists the `/status` values it allows with `oneOf` since 2026-10-01 | `endpoint/request-body-nested-65-deep-answers-21002` |
  | A lone surrogate escape (`\ud800` with no low surrogate) in a JWS header or payload member name, in `alg`, in an `x5c` entry or in `receipt-data` | read as U+FFFD, so an unknown name is ignored and a value fails later (an `x5c` entry as `INVALID_CERTIFICATE`) | reads on: Jackson keeps the lone surrogate in the `String` | `MALFORMED` for a header or a request body, `UNREADABLE_PAYLOAD` for a signed payload (port-defined 2026-10-01) | `serde_json` refuses a lone surrogate escape in a name or in a string it decodes (R40); the document is then not the object that was signed for, and nothing unsigned is accepted. Apple's documents are ASCII | none: no case pins it |
  | A SignerInfo whose digestAlgorithm names an OID BouncyCastle has no digest for (`1.2.3.4`, or SHAKE256 `2.16.840.1.101.3.4.2.12`), over an otherwise genuine chain | not measured | `MALFORMED` (`unexpected java.lang.IllegalArgumentException` from `DefaultSignatureAlgorithmIdentifierFinder`, status 21002; recorded 2026-10-04) | `INVALID_SIGNATURE` (status 21003) | The core's signature check fails under that digestAlgorithm; BouncyCastle throws an unchecked exception while building the verifier, which Java files as `MALFORMED` with the cause kept. Both refuse, the input is not Apple-signed, and no shared case pins it; a digest BouncyCastle does know but Apple never used (MD5) is `INVALID_SIGNATURE` in both | none: measured by a review probe, not a case |
  | A lone surrogate escape in a member name inside `data` or `summary` of a genuinely signed JWS payload | not measured (the 0.7 answers carry no environment) | reads on: Jackson keeps the name, and the container's `environment` is read | ok, without that container's environment (port-defined 2026-10-03) | The core reads `data` and `summary` for the environment alone, and `serde_json` refuses the name (R40), so the container states none; the payload and the signature are unchanged. Apple's documents are ASCII | none: no case pins it; R42 |
  | A genuine receipt whose eContent is re-encoded as a constructed `OCTET STRING` with a chunk of another tag (a `UTF8String`, an `INTEGER`), the joined octets unchanged | `MALFORMED` | `MALFORMED` (BouncyCastle 1.86's parser refuses it, "unknown object encountered in constructed OCTET STRING", measured 2026-10-05; the verdict is read from `ReceiptCore.verifySignature`, which maps that `IOException` to `MALFORMED`, not run; [duplicate checks][dupchecks]) | ok (owner, 2026-10-05) | X.690 8.7.3 allows only `OCTET STRING` chunks, but OpenSSL joins chunks of any tag or class, and the joined octets are both what the signature covers and what the payload is read from, so nothing unsigned is accepted. The core dropped its own chunk check on the eContent; payload attribute values and the Xcode wrap keep theirs (`UNREADABLE_PAYLOAD`). Apple's receipts are DER and never chunk a string | none: no case pins it; `rust/tests/receipt_negative.rs` |
  | A receipt whose outer `ContentInfo.contentType` is not `signedData` (`id-data`, or an OID nobody assigned) around a genuine SignedData, or whose `digestAlgorithms` SET carries another tag byte (`0x58` for `0x30`) | not measured | ok: BouncyCastle decodes the content as SignedData without reading the OID, and reads the SET whatever its tag | `MALFORMED` (`not a CMS SignedData`; the tag, from the envelope walk) | Neither field is under the signature. The core reads the OID so that OpenSSL's SignedData accessors are only called on a SignedData; Java needs no such guard. Apple sends `signedData`, and nothing unsigned is accepted either way (recorded 2026-10-05, owner: no code in either implementation) | none: measured by a review probe, not a case |
  | An `x5c` entry that decodes to a certificate followed by more bytes: trailing octets, a second certificate, PEM text or a PKCS#7 certs-only bundle holding the leaf | not measured | ok: `CertificateFactory.generateCertificate` reads one certificate from a stream and stops | `INVALID_CERTIFICATE` | The header is signed, so an Apple-signed JWS never carries one, and a foreign one still chains to no pinned root. `transaction/reject-x5c-leaf-with-line-breaks` is refused by both for its base64, before the bytes are read (recorded 2026-10-05, owner: no code) | none: measured by a review probe, not a case |
  | A leaf whose AuthorityKeyIdentifier names a key other than the issuing intermediate's SubjectKeyIdentifier, in a JWS `x5c` chain that otherwise verifies | not measured | ok: BouncyCastle's PKIX validator matches issuer by name and signature, not by key identifier | `UNTRUSTED_CHAIN` (OpenSSL checks the identifiers) | The signature still has to verify under the intermediate's real key, and Apple's chains carry matching identifiers (recorded 2026-10-05, owner: no code) | none: measured by a review probe, not a case |
  | An ES256 JWS whose leaf key is on a curve other than P-256 with a 32-byte order (secp256k1, brainpoolP256r1) | not measured | ok: the 64-byte signature verifies under whatever curve the leaf names | `INVALID_SIGNATURE` | RFC 7518 ties ES256 to P-256. Apple's leaves are P-256 and a foreign leaf chains to no pinned root; a P-384 leaf is `INVALID_SIGNATURE` in both (recorded 2026-10-05, owner: no code) | none: measured by a review probe, not a case |
  | A version 1 or 2 certificate that carries extensions, on the path | not measured | refused at parse (BouncyCastle: "version 1 certificate contains extra data") | ok | OpenSSL and the core accept any version from 1 to 3 and read the extensions whatever it says. Apple's certificates are v3, and the path is signed either way (recorded 2026-10-05, owner: no code) | none: measured by a review probe, not a case |
  | An authorityInfoAccess or certificatePolicies extension whose value does not decode, on a certificate on the path | not measured | refused at parse: BouncyCastle decodes both | ok | OpenSSL does not cache either (`crypto/x509/v3_purp.c:443-733`) and the core asks for no policy check, so nothing decodes them. The certificate is still signed by its issuer, and Apple's certificates carry extensions that decode (recorded 2026-10-05, owner: no code) | none: measured by a review probe, not a case |

  The four rows recorded on 2026-10-05 above the last two came out of
  the Java round-3 review ([probes][javabc3]): Java accepts four
  shapes the core refuses, none of them in a signed field or producible
  by Apple. The owner chose to record them rather than write code in
  either implementation to match the other, the rule above.

  The core's own X.509 reader (`Certificate::is_readable`: version 1 to
  3, signature bits in whole octets, no extension OID twice, a
  basicConstraints and a keyUsage that decode) was examined on
  2026-10-05 and kept (owner, Q57, revised on that evidence). Under the
  adapter's verify flags OpenSSL checks no version (`x509_vfy.c:700`
  reads it only under `X509_V_FLAG_X509_STRICT`), judges a repeat or a
  decode failure only among the extensions it caches, and reads a
  signature's bits only when it verifies that signature; removing the
  reader made refusals verify, and removing only its decode check moved
  four cases where the core and Java agreed into divergences ([reader
  kept][reader]). Its version is now compared as OpenSSL's `long`, as
  every build reads it. The last two rows of the table came out of that
  review.

  The core's ASN.1 header walk (`rust/openssl/src/walk.rs`) was examined
  on 2026-10-06 and kept (owner, Q63). It carries the bounds, 32 levels
  and 100,000 values, nothing after the outermost value, each
  constructed string handed to OpenSSL at its outermost level, and
  0.7's grammar rules: a primitive of a constrained type must decode
  wherever it stands, no end-of-contents inside a definite length, no
  high-tag-form header or five-octet length in a payload, only OCTET
  STRING chunks in a constructed OCTET STRING. OpenSSL applies none of
  those rules inside a SEQUENCE it keeps whole (an unsigned attribute,
  algorithm parameters, a Name value, the fields after a receipt
  attribute's value), reads a high-tag form for any tag number and joins
  chunks of any type, so the rules duplicate nothing ([walk
  counter][walk]). Reduced to a counter the walk would move ten pinned
  cases, one of them a refusal before the signature, to port-defined; a
  middle shape keeping the envelope rules would move four pinned
  payload cases where the core, 0.7 and BouncyCastle agree today, and
  reverse the 2026-09-30 choice above, for 214 lines and no other gain.
  Reopen only on new evidence: an OpenSSL release that decodes inside a
  kept SEQUENCE or refuses high-tag forms or foreign chunks itself
  (rerun the note's probe through `aprv.wasm`, since it ran on a 64-bit
  native build and `asn1_lib.c` reads lengths up to `sizeof(long)`),
  Apple observed emitting one of those forms, or Java's answer on those
  four cases changing.

  Java's parse before trust was measured on 2026-10-05 and accepted as
  it is (owner, Q62, 2026-10-06). Java reads every top-level attribute
  of the payload into its type and octets before any signer is matched,
  with no value budget; the 3 MiB cap bounds it. At the cap, 195,562
  tiny attributes cost about 0.2 s, 144 MiB of allocation and about
  66 MiB more peak heap than a genuine receipt, roughly twice what a
  genuine receipt of that size allocates; one unsigned attribute of a
  million empty values, which BouncyCastle's own CMS parse builds,
  costs about 0.19 s and 14 MiB ([parse cost][javaparse];
  THREAT-MODEL.md §3.7; java/README.md sizes the heap by the
  concurrency limit, an estimate from that first-call figure). A value
  budget or a streaming date reader in Java was rejected: each is a
  second ASN.1 reader beside BouncyCastle, the kind removed on
  2026-10-01, and neither reaches the unsigned-attribute cost. Reading
  the date only after the signature would remove the pre-trust read in
  both implementations, but it reorders §3.3 and changes which failure
  a receipt that is both unsigned and expired reports, in the core,
  Java and the fixtures together; it was not measured. Reopen only if a
  shape is measured well above that cost at the cap, the input cap
  rises, a BouncyCastle release changes the tree it builds, or §3.3 is
  reordered.

  Lane J-align (2026-09-29) had aligned Java on the four rows marked
  port-defined above, and its round 2 on two more, in Java's own code.
  On 2026-09-30 the owner applied the rule above to that code: each
  rule fired only on a BER form Apple never emits, and each commit
  named OpenSSL's behaviour as its reason, so it imitated the core.
  The code was removed (Java is back to its 0.7 reading, whose nesting
  bound counts chunk levels too), the eight cases list both
  answers, and `tools/differential/recorded.json` names them under one
  group. Divergences that lane found and left for the
  differential campaign (MIGRATION step 1.13) to measure and case: a
  five-octet length on a SET, SEQUENCE or field header inside the payload
  (the core answers `UNREADABLE_PAYLOAD`, Java reads it); a `crls` entry
  that is not a CRL (the core `MALFORMED`, Java verifies
  because it never decodes CRLs); constructed strings of more than six
  levels elsewhere in the envelope (a messageDigest value, a signature,
  an extension value); and a receipt whose path to the eContent uses a
  length of more than four octets, which BouncyCastle reads. (Java's
  byte walk used to give up on such a length and skip its own checks;
  the 6-level check went on 2026-09-30 and the walk itself on
  2026-10-01, so Java has no check left to skip.)
  Round 2 (2026-09-29) aligned Java on two rows above, undone on
  2026-09-30 as said; one more divergence stays open for the
  differential campaign: a constructed
  string of a type other than OCTET or BIT STRING inside the envelope
  (an unsigned attribute value holding a constructed UTCTime), which
  Java answers `MALFORMED` because BouncyCastle cannot build it and the
  core accepts; proposed case: an unsigned attribute value SEQUENCE
  holding a constructed UTCTime, port-defined (ok or `MALFORMED`).
  Round 3 (2026-09-29) ran lane P7-code's 76 proposed cases through Java
  and the G1d module ([Java round 3][javar3]). Two answers are not
  recorded yet: a `signingTime` in month 13 verifies in the core, and
  Java answers `MALFORMED` because BouncyCastle refuses the UTCTime while
  it parses the envelope; a signer validity in month 13 is
  `INVALID_CERTIFICATE` in the core and `MALFORMED` in Java, for the same
  reason. An RSA leaf under ES256 is `INVALID_SIGNATURE` in the core and
  `INVALID_CERTIFICATE` in Java ("x5c[0] does not decode"); the probe's
  leaf carries a made-up 16,384-bit modulus, so the input tests key
  decoding as much as the algorithm mismatch.

  On 2026-10-01 the owner removed Java's own ASN.1 nesting walker
  (`Asn1Depth`), which refused a 33rd nested constructed value in the
  envelope, the payload, each attribute value and each x5c entry. Java's
  bound is now BouncyCastle's (`org.bouncycastle.asn1.max_cons_depth`,
  64 by default; it refuses the 65th constructed value, or the 66th when
  the innermost is empty, and the existing catch sites map its
  `ASN1Exception` to `MALFORMED`, `UNREADABLE_PAYLOAD` or
  `INVALID_CERTIFICATE`). Four reasons: the walker was a second ASN.1
  parser beside BouncyCastle; it had the recorded gap above at lengths
  of more than four octets; it only ever refused input BouncyCastle
  would have parsed, the direction that never weakens a verdict, on
  nesting Apple's receipts (9 deep) never reach; and BouncyCastle's
  property is read from `java.security` and the system properties on
  every parse, so a library cannot pin it from code and the walker
  only added a second bound. The core keeps 32. The seven 33-deep cases
  in the two rows above list both answers, and
  `tools/differential/recorded.json` names them under the group
  `nesting-between-33-and-bouncycastle`.

  The same day the core's JSON reader became `serde_json` (R40) and the
  core lost its three JSON bounds, which Java's `BoundedJson` kept. The
  rule above applies in the other direction: none of the five inputs is
  Apple's, each is genuinely signed, and the core accepts nothing
  unsigned, so the cases list both answers and
  `tools/differential/recorded.json` names them under the group
  `json-bounds-java-only`. On 2026-10-05 Java dropped `BoundedJson` for
  Jackson's default constraints (depth 1,000, names 50,000, numbers
  1,000), which the size caps make sufficient. The three inputs nested
  65 deep now read in both, so the group names only the member name and
  the integer.

---

## R21. Security substrate: OpenSSL 4 with the CMS API

**Status: accepted** (owner, 2026-09-26). The adapter's clock import went
with R24 on 2026-09-28; nothing else changed.

**The owner's reasons:** the risk is code we write ourselves for generic
security protocols, and speed does not matter.

**Decision.**

- **CMS:** OpenSSL's CMS API with our own chain policy:
  `CMS_SignerInfo_cert_cmp`, `CMS_SignerInfo_verify` and
  `CMS_SignerInfo_verify_content`, never `CMS_verify`, and never a store
  built from anything but the pinned roots ([follow-up §3.2][followup]).
- **Chain:** `X509_verify_cert` over a store holding only the pinned
  roots, `X509_V_FLAG_PARTIAL_CHAIN`, the check time set to the signing
  instant, and our historical-time verify callback
  ([substrate bake-off §4][substrate]).
- **Receipt payload:** OpenSSL's declarative ASN.1 templates, a 14-line C
  file decoded with `ASN1_item_d2i` ([ASN.1 payload §2][payload]). No
  hand-written tag or length parsing remains.
- **Isolation:** `OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG)`, no
  default trust paths, `OPENSSL_CONFIG_DIR` set to a path that does not
  exist ([substrate bake-off §7][substrate]).
- **Deleted in Phase 1:** `asn1.rs`, `x509.rs`, `cms.rs`, `chain.rs`,
  `crypto.rs` (1,067 code lines), the RustCrypto dependencies, the public
  modules of those names, and the fuzz targets `parse-der`,
  `parse-certificate`, `parse-cms` ([ASN.1 payload §6][payload]).

**Options measured.**

| Option | What the evidence showed | Verdict |
|---|---|---|
| **OpenSSL 4.0.2, CMS API** | Same answers as its native build on 1,179 of 1,179 rows in 33 Wasm runs on 9 hosts ([CMS everywhere §2][cms]); Java-equal on 1,028 of 1,048 without a prescan ([ASN.1 payload §3][payload]) | **Chosen** |
| OpenSSL 4.0.2, PKCS7 API | Refuses Ed25519, RSA-PSS and SKI-identified SignerInfos Java accepts ([follow-up §3.1][followup]) | Replaced by the CMS API |
| AWS-LC 1.73.0 and 5.7.0 | Fastest natively, smaller, no randomness on Wasm; no CMS API, so Ed25519, RSA-PSS and SKI signers stay unsupported ([follow-up §3.3][followup]) | Not chosen |
| LibreSSL 4.3.2 | No `wasm32-wasip1` build; its CMS API refuses ECDSA-signed receipts ([substrate bake-off §13][substrate], [follow-up §3.3][followup]) | Not chosen |
| Pure Rust, the 0.6 core | 1,069 lines of our own ASN.1, CMS, X.509, path and crypto code; RustCrypto `der` refuses BER spellings ([substrate bake-off §10][substrate], [ASN.1 payload §5][payload]) | Not chosen: the hand-written code the owner wants gone |
| BoringSSL, wolfSSL, Botan, Mbed TLS, NSS, GnuTLS | Research only ([substrate bake-off §15][substrate]) | Not built |

**Numbers that matter.**

- Corpus: 1,179 rows (`cases` 153, `substrate` 193, `hostile` 811,
  `algorithms` 22), plus 5,000 mutants in the later rounds.
- Fuzzing with ASan and libFuzzer, OpenSSL instrumented, no finding in
  any campaign: 4 × 45 min, 28,983,241 executions
  ([follow-up §4.2][followup]); 2 × 45 min on the CMS path, 9.33 million
  ([CMS everywhere §4][cms]); 45 min without `asn1.rs`, 2,999,045
  ([ASN.1 payload §4][payload]).
- `unsafe`: the security path goes from 2,100 code lines with 0 `unsafe`
  and 0 C to 2,207 lines with 402 inside `unsafe` and 14 lines of C
  ([ASN.1 payload §6][payload]). The Phase 1 goals (owner, Q40 a,
  2026-09-26): rust-openssl's safe wrappers wherever they exist; each
  remaining raw call in one small safe function with a `// SAFETY:`
  comment; best effort, the missing CMS SignerInfo wrappers contributed
  upstream.
- Memory (owner, Q32 a): a hostile 3 MiB payload of tiny attributes peaks
  at 92 MiB in the template reader against 33 MiB for a tiny one; a whole
  such receipt at 145 MiB in Node against 67 MiB ([ASN.1 payload §2,
  §3][payload]). Accepted, bounded by the 3 MiB cap. The figure predates
  the header walk of the core review; the unsigned and signerless forms
  now peak near 16 MiB ([core review fixes][corefix]).

**Build.** Native: `openssl-src` 400.x through a one-line
`[patch.crates-io]` of `openssl-sys` 0.9.117's manifest, or
`OPENSSL_DIR`; the two gave identical rows ([CMS everywhere §1][cms]).
Wasm: OpenSSL compiled by wasi-sdk, through `OPENSSL_DIR`.

**Open items.**

1. `openssl-sys` and `openssl-src` 400.x: the patch applies only inside
   our workspace; a crates.io user of the core gets OpenSSL 3.x until
   upstream widens the requirement.
2. OpenSSL 4.1.0 final needs its own corpus run; the beta changed nothing
   ([follow-up §2][followup]).
3. Memory in workerd (128 MB isolate): Phase 4 measures it.

**Maintenance.** OpenSSL's advisories join RustSec. A fix in OpenSSL
means rebuilding one `aprv.wasm` and the server binaries, the full
cross-host run, and a release; that is a security bump of a shipped
dependency, which CLAUDE.md's release budget counts as release-worthy.

---

## R22. Wasm first everywhere

**Status: accepted** (owner, 2026-09-28).

**Decision.** One canonical `aprv.wasm` is the only form in which the
Rust core ships. Each language runs it in a runtime it already has; where
none fits, `aprv-server` runs it in a separate process. By default no
native parser runs inside a caller's process (R32).

| Language | Host | Evidence |
|---|---|---|
| Java 11+ (`-wasm` artifact) | Endive 1.1.0 build-time compiler to JVM bytecode, no native code | [Endive][endive], [ABI v1][abi] |
| Java 8 (`-wasm` artifact) | `aprv-server` as a managed child, pure-Java client | [aprv-server §6][server] |
| Java 8+ (main artifact) | the pure-Java BouncyCastle implementation, unchanged | 0.7.0 |
| Node and every JS runtime | native WebAssembly through jco's generated bindings, a thin façade over them | [CMS everywhere §2][cms], [canonical ABI final][cabifinal] |
| Go | wazero | [CMS everywhere §2][cms] |
| Python | wasmtime-py, plain `.wasm` compiled at start, disk cache on (R27) | [Python wasmtime][pywt], [runtime options][pyopt], [final Python round][pyfinal] |
| Swift 6.3 | WasmKit 0.4.0 | [Swift WasmKit][swift] |
| Ruby 3.3 | the `wasmtime` gem, `gvl: false` | [Ruby][ruby] |
| .NET (netstandard2.0, net8+) | Wasmtime .NET | [.NET][dotnet] |
| PHP 8.2 | `aprv-server`: one-shot CLI per call by default, optional server URL (R29) | [aprv-server §5, §7][server] |
| Anything else, HTTP | `aprv-server` (binary, Docker image), or the C ABI | [aprv-server][server], [static musl][musl] |

**Why.** One build artifact carries every security decision to every
language, with one hash to check. Each host passed the corpus
byte-identically and the ABI tests (README.md). A memory-safety bug in
OpenSSL's parsing, reached by a hostile receipt, stays inside the guest's
linear memory instead of the caller's process ([aprv-server §10][server]).
The measured cost is speed, above the floor on every host (R4).

---

## R23. The canonical ABI and the instance model

**Status: accepted** (owner, 2026-09-29 for the ABI; 2026-09-28 for the
instance model, Q49 option d). Supersedes the ABI v1 export list of the
2026-09-28 record. Amended 2026-09-30: the WIT package version moves from
`1.0.0` to `0.1.0` (R36); done on 2026-10-01, and the export names below
carry it. Amended 2026-10-04: one form for the built-in roots in `init`'s
configuration (Q30, below).

**The ABI.** `aprv.wasm` exports its four operations through the
canonical ABI, the Component Model's calling convention, from one WIT
file (ARCHITECTURE.md §4):

```wit
init: func(config-json: list<u8>) -> string;
verify-receipt: func(now-ms: u64, receipt-base64: list<u8>) -> string;
verify-signed-data: func(now-ms: u64, jws: list<u8>) -> string;
verify-receipt-endpoint: func(env: u32, now-ms: u64, request-json: list<u8>) -> string;
import random-get: func(len: u32) -> list<u8>;
```

Inputs are bytes, so any input reaches the core and a non-UTF-8 JWS is
a value; outputs are the guest's own JSON. `env` is a `u32` the guest
matches, trapping on anything but 0 and 1. `now-ms` is a `u64` argument
on every verify call. A verify before `init`, and a second `init` after a
successful one, trap. The export names carry the package version
(`aprv:verifier/verify@0.1.0#init`), so a wrapper of another version
finds no export and fails at `create`. The WIT file is the contract and
CI diffs it against the built module. Output is aprv-wire JSON. Six
outcomes stay distinct: verified, verification failure, caller misuse,
ABI mismatch, trap or internal failure, server process failure.

**Why the canonical ABI rather than our own export list.** The owner's
reasons, in order:

1. It is a written rulebook rather than a convention of ours: the
   argument flattening, the return area, `cabi_realloc` and post-return
   are the Component Model's canonical ABI, specified and versioned, so a
   new host has a document to bind against and not a spike to read.
2. Hosts with a component runtime write no ABI code: jco on Node, Deno
   and Bun, Wasmtime `bindgen!` in `aprv-server`, wasmtime-py's typed
   API. Hosts without one call the same core exports by hand in 35 to 66
   lines (Endive 35, WasmKit 37, wazero 66), about what ABI v1's bridges
   cost.
3. Nothing about it needs the Component Model at run time: the core
   module stays core Wasm 2.0 on `wasm32-wasip1`, and the component is
   the same module wrapped by `wasm-tools component new` with no adapter,
   2,442 bytes larger, for the hosts that want it.
4. Typed exports replace operation numbers, a handle table and a byte
   prefix for `now_ms`, three conventions each wrapper would have had to
   get right by hand.

**Evidence.** Round 12 ran the interface with `string` inputs and an
`enum` on wazero, Endive, jco, wasmtime-py and a Rust host: PASS WITH
CAVEATS, 5,933 of 6,179 rows identical, the 246 differences all from the
interface (243 non-UTF-8 JWS rows that a WIT `string` cannot carry), and
wit-bindgen's release-mode lifts found to trust the caller
([canonical ABI][cabi]). Round 13 changed inputs to `list<u8>` and `env`
to `u32` and ran eight hosts: PASS, 6,176 rows identical on every host
plus the 3 intended differences (two `injected-clock` endpoint rows under
the 0.7 `now-ms` rule, one `init` refusal of a root that is not a
certificate), 0 traps, every misuse trapping on every host, trap
isolation holding, and `aprv-server`'s runtime-only Wasmtime loading an
embedded precompiled component in 14 ms to the first result, the same as
the core module ([canonical ABI final][cabifinal]). Size +0.47% stripped;
start-up within noise except jco's glue at +8%.

**Findings carried into the plan** ([canonical ABI final][cabifinal]):
generated bindings do not range-check the `u32` (the wrapper's
`Environment` type keeps callers on 0 and 1; the guest traps otherwise);
wasmtime-py 49.0.0 lowers `list<u8>` byte by byte, so Python calls the
core exports by hand (ARCHITECTURE.md §7.2); a precompiled Wasmtime file
records the engine's Wasm features and a mismatch is refused at load
(§7.7); component runtimes refuse a trapped instance while hand-rolled
hosts must discard it; a double post-return is silent on hand-rolled
hosts, so no wrapper exposes a result pointer; Deno needs
`--allow-env=JCO_DEBUG` for jco's glue.

**The instance model.** `Verifier.create(config)` owns a small pool; each
new instance gets `init` once, so the roots are parsed once per instance;
one instance serves one call at a time; a trapped instance is discarded
with everything in it; instances die with the `Verifier`; no handles,
nothing to free. Node: one instance. `aprv-server`: a fresh instance and
`init` per request by default. Phase 1 measures `init`; if it exceeds 10%
of a call, the server's default flips to `--lifecycle pool`.

**Amended 2026-10-04 (owner, Q30): one form for the built-in roots.**

- **Decision:** `{}`, with `roots` left out, is the one spelling of the
  three built-in Apple roots in `init`'s configuration, and every wrapper
  sends it. An empty `roots` list is refused:
  `{"ok":false,"message":"roots must not be empty"}`, the message the
  core's `Config` gives an empty root set. No bytes at all still mean the
  built-in roots, as the WIT's comment says.
- **Before:** the module read an empty list, `{}` and no bytes alike as
  the built-in roots, and the wrappers split: Node, Python, Ruby, Swift
  and Go sent `{"roots":[]}`; .NET, the Java `-wasm` artifact and
  `aprv-server` sent `{}`, and `aprv-server` already refused an empty
  list on its managed roots line.
- **Why:** fail loud. A list is the form a caller's own roots take, so an
  empty one is a root set that came up empty; read as the Apple roots,
  that mistake passed silently. Refused, it fails at `create`, and a
  verifier with no roots cannot exist, as in the Rust crate.
- **No caller sees a change.** Every package already refuses a caller's
  empty root list at `create`, before the module is reached; the module's
  refusal is a second line behind it. `fixtures/cases.json` does not
  change. The WIT does not change, so the ABI version stays;
  `init-config.schema.json` states the refusal (`minItems: 1`).

**Options rejected** (table at the end): ABI v1's `aprv_call` with
operation numbers and result handles; `now_ms` as an 8-byte prefix; one
generic `call(op, ...)` export; WIT `string` inputs and a WIT `enum`;
WASI 0.2 as the build target; memory64; DER input; Protobuf, CBOR or
FlatBuffers as the encoding.

---

## R24. Time: `now_ms` per call, no clock import

**Status: accepted** (owner, 2026-09-28; Q51 option b). Supersedes R10.

- The wrapper reads its `Config` clock once per call and passes the value
  as `now_ms`. The core uses it for the chain instant when the receipt or
  JWS carries no usable date, and for `request_date` (the 0.7 rule).
- The module therefore imports only `random-get`; the clock import
  goes. The guest defines the C clock symbol `wasi-none.c` calls to
  return the call's `now-ms` ([canonical ABI][cabi]).
- No public per-call `now`: 0.7 dropped it ([0.7 API][api07], Dropped).
  The ABI carries `now-ms: u64` on every verify call anyway, so an
  override later is additive.

---

## R25. Java: two artifacts, both Java 8, and the Engine API

**Status: accepted** (owner, 2026-09-28). Supersedes R18.

- **`apple-purchase-receipt-verifier`** (main): pure Java over
  BouncyCastle, Java 8+, the independent implementation. Kept and
  maintained; its deprecation is decided later.
- **`apple-purchase-receipt-verifier-wasm`**: Java 8+, the same package
  and class names, `Config` exactly 0.7's. Its engine is Endive in-process
  on Java 11+ and the `aprv-server` managed child on Java 8 by default.
  A classpath guard refuses both artifacts at once.
- **Engine choice** is programmatic and explicit, with no system
  properties and no environment variables of ours:
  `Verifier.create(config)` chooses by JVM version;
  `Verifier.create(config, Engine.endive())`;
  `Verifier.create(config, Engine.server(ServerSource...).cacheDirectory(path))`.
  `ServerSource` is `url(uri, token)`, `executable(path)`, `maven()`,
  `github()` or `download(url, sha256)`. The user owns the order, the
  first source that works wins, and `Engine.server()` with no sources
  means `[maven, github]`. Java 11+ may choose the server engine too.
- **Managed mode** (tested on Temurin 8): loopback `127.0.0.1:0`, a 256-bit
  token over stdin, supervised, restarted at most 10 times a minute, gone
  when the JVM is. `noexec` directories use `url` or `executable`
  ([aprv-server §6][server]).
- **Why two artifactIds:** a classifier jar cannot replace the main jar,
  since it shares the artifact's POM and dependencies.
- **CI:** the 388 cases against the main artifact and against both engines
  of `-wasm`; the `java-runtime-8` leg runs the server engine on real
  Temurin 8. Temurin 8 builds end in late 2026; the leg moves to Zulu or
  Corretto 8 by then.
- **Rejected for Java 8,** with measured reasons in the rejected table:
  every in-process native binding (over JNA, JNI or FFM), the other JVM
  Wasm runtimes (wasmtime4j, wasmtime-java, Chicory's runtime compiler and
  interpreter, GraalWasm), `memfd` execution, and a frozen 0.7 jar as the
  only oracle.

The spike's client resolved its server through system properties and
environment variables (`-Daprv.server.url`, `APRV_SERVER_URL`,
[aprv-server §6][server]); the `Engine` API replaces them.

**Amended 2026-10-02 (owner, Q11): one source for the shared classes.**
Nine public classes were byte-identical in the two artifacts:
`ReceiptPayload`, `InAppPurchase`, `VerificationResult`, `ClasspathGuard`,
`Environment`, `AppleStatus`, `Reason`, `JsonPayload` and `RawAttributes`.
They live once, in `java/src/shared/java`, and both poms add that
directory as a source root (`build-helper-maven-plugin`). It is a source
directory and not a Maven module, so it publishes no artifact and spends
nothing of the Central budget. It sits under `java/` because spotless
reads only below a pom's own directory, and `java/pom.xml`'s spotless is
the one CI runs. Both jars hold the same class files, byte for byte, as
before the move. A class that differs between the artifacts in any way
(`Version`, `AppleRootCerts`, `Verifier`, `package-info`) keeps one copy
in each. `Config` and `Failure` differed only in Javadoc and joined the
shared directory on 2026-10-03, with Javadoc true for both engines; what
each engine's runtime probe checks moved to its own `Verifier.create`.

---

## R26. Server binaries on Maven Central

**Status: accepted** (owner, 2026-09-28; Q44).

- **Decision:** classifier jars of the static musl `aprv-server` for
  `linux-x86_64` and `linux-aarch64`, attached to the `-wasm` artifact
  and found by `ServerSource.maven()`. macOS and Windows binaries come
  from GitHub Releases (`ServerSource.github()`).
- **Evidence:** the static binaries gzip to 3,656,734 B (x86_64) and
  3,390,574 B (aarch64) ([static musl §1][musl]). With the `-wasm` jar,
  1,762,214 B in the Endive spike ([Endive §4][endive]), that is about
  8.8 MB per release, before the main artifact's own jars (not
  re-measured).
- **Budget:** Maven Central allows 7 releases, about 80 MB and about 1,000
  files per calendar month (CLAUDE.md). At about 9 MB per release the
  release count binds first. The 2026-09-26 server note found that six
  platforms in the jar would cost about 21.5 MB per release and allow 3 a
  month ([aprv-server §10][server]); two Linux classifiers stay well
  inside.

---

## R27. Python runtime and compiled code

**Status: accepted** (owner, 2026-09-28; Q52 option a, Q45/Q53 option a).

- **Runtime:** wasmtime-py, at or above the current major, with no pin to
  one major.
- **Compiled code:** the plain `.wasm`, compiled at start: 934 ms on 4 CPUs
  and 2,923 ms on one ([runtime options][pyopt]).
- **Cache:** Wasmtime's `Config.cache`, on by default; silently off when
  the cache directory is read-only; its path overridable by an
  environment variable. A warm start took 95 ms ([runtime options][pyopt]).
  THREAT-MODEL.md §8 has the directory rules.
- **Amended 2026-10-04 (owner, Q27): the cache's default directory comes
  from platformdirs**, `user_cache_dir()` plus `wasmtime`, instead of
  platform logic written by hand. Every check that makes the directory
  safe stays in the package. The floor is 4.12.0, the oldest release that
  names this directory as every newer one does: it honours an absolute
  `XDG_CACHE_HOME` on macOS too (4.6.0), ignores a relative one (4.11.8)
  and raises when no home directory resolves (4.12.0)
  ([platformdirs floor][pydirs]). It still returns a relative path for a
  relative `HOME`, so the package keeps its own check that the directory
  is absolute, and any exception from platformdirs turns the cache off
  rather than reaching the caller. Python's runtime dependencies are now
  the Wasm runtime plus platformdirs (SECURITY.md). Three defaults moved:
  an absolute `XDG_CACHE_HOME` now holds the cache on macOS as on Linux; a
  relative one falls back to the platform default instead of turning the
  cache off; and an empty `HOME` resolves through the password database
  instead of putting the cache under `/.cache` (`/Library/Caches` on
  macOS).
- **Lambda** pays the compile per new container, about 3 s on one vCPU;
  the README documents it.
- **Winch** is a later improvement, once wasmtime-py exposes it: 468 ms
  and 834 ms to the first result, half the speed ([runtime options][pyopt]).
- **Rejected,** in the table: a precompiled `.cwasm` in the wheel (62 to
  72 ms, but pinned to one Wasmtime major), Wasmi with our own cdylib as
  the default, Wasmi's C API, WAMR in every mode, Pulley, pywasm,
  wasmer-python, pywasm3, WasmEdge and Extism.

Round 11 recommended Wasmi 2.0 behind our own cdylib and named the
precompiled `.cwasm` the runner-up ([final Python round][pyfinal]); the
owner chose neither.

---

## R28. Python platforms without a wasmtime-py wheel

**Status: accepted** (owner, 2026-09-28; Q54).

- **Decision:** on a platform wasmtime-py ships no wheel for, installing
  the package fails with a clear message that points to `aprv-server` or
  the C ABI. The floor is Python 3.10.
- **Evidence:** wasmtime-py 49.0.0 ships wheels for x86_64 and aarch64 on
  manylinux, musllinux, macOS and Windows, plus Android. Of the 19 wheel
  tags R12 planned, 11 have none: manylinux armv7l, i686, ppc64le, s390x
  and riscv64; `linux_armv6l`; musllinux armv7l, i686, ppc64le and
  riscv64; win32 ([Python wasmtime][pywt]).
- **The mechanism** is Phase 5's: today pip installs wasmtime-py's
  `py3-none-any` wheel there, which holds only a Windows DLL, and the
  failure comes at `import wasmtime` ([Python wasmtime][pywt]).

---

## R29. PHP

**Status: accepted** (owner, 2026-09-28).

- The PHP 8.2 package calls the one-shot `aprv` CLI per call by default,
  or a server URL the user configures.
- An `aprv install` command downloads the binary from GitHub Releases and
  checks it against a pinned SHA-256; nothing downloads at request time.
- **Evidence:** 11.6 ms per g5 through the CLI and 3.56 ms over HTTP; a
  200-row corpus slice identical to Node on both ([aprv-server §7][server]).
  A static musl CLI with `cli-fast-exit` exits in 15.2 ms
  ([static musl §3][musl]).
- Packagist publishes from the root `composer.json` once the owner
  submits the repository (BOOTSTRAP.md).

---

## R30. Floors

**Status: accepted** (owner, 2026-09-28; Q54). Amended 2026-09-30: the
policy and Go's floor, below.

Java 8 (both artifacts); Python 3.10; Swift 6.3 with macOS 15 and iOS 18;
Ruby 3.3; .NET netstandard2.0, tested on net8+; Node 20; Go as today; PHP
8.2. SUPPORT-MATRIX.md lists what each floor rests on. Two moves against
0.7.0: Swift from 6.1 and macOS 13 to 6.3 and macOS 15, because WasmKit
0.4.0 declares them ([Swift WasmKit][swift]); and the Java 8 CI leg moves
from Temurin to Zulu or Corretto before Temurin 8 builds end. Go moved
from 1.22 to 1.25 on 2026-09-30 (owner), because wazero 1.12 needs it.

**2026-09-30 (owner).** A floor moves only when a dependency, a security
fix or CI forces it; a new language line or a vendor's end of support
does not move it. Go moves from 1.22 to 1.25, because wazero 1.12 needs
1.25 and the 1.22 floor held wazero at 1.9.0. Node 20, Python 3.10, PHP
8.2, Ruby 3.3, .NET 8 (netstandard2.0), Swift 6.3 and Java 8 stay. The
Go change (the `go` directive, wazero and the CI legs) landed with the
dependency sweep (#204).

---

## R31. aprv-server: build and lifecycle

**Status: accepted** (owner, 2026-09-28).

- **Build:** Rust, axum and tokio; Wasmtime 49 runtime-only with the
  module precompiled to a Cranelift `.cwasm` for an explicit baseline
  target and embedded. Runtime-only starts in 9.8 ms instead of 900 ms and
  idles at 20.7 MiB instead of 115.6 MiB ([aprv-server §2][server]).
- **Linux:** fully static musl for x86_64 and aarch64 with musl's own
  malloc, tested from an empty chroot and on Alpine; 6 to 8% slower than
  glibc ([static musl][musl]). The one-shot CLI carries `cli-fast-exit`
  (the runtime in `ManuallyDrop`), which removes a 55 ms libunwind
  teardown.
- **Lifecycle:** a fresh instance per request, with `--lifecycle pool` as
  the flag R23's `init` measurement may make the default.
- **Surface:** managed mode, the CLI (`aprv verify-receipt |
  verify-signed-data | verify-receipt-endpoint <env>`, stdin to stdout,
  exit codes 0, 3 and 70, about 12 ms per process), HTTP; binds `127.0.0.1`
  unless `APRV_LISTEN` says otherwise; a token; a 3 MiB body cap answered
  with 413 (since 2026-10-02 the 413 carries the module's own answer and
  exit 3 prints it; R34); `StoreLimits` of 256 MiB.
- **Docker:** a multi-stage, distroless, non-root image on GHCR, and on
  Docker Hub after the owner creates the namespace and token.
- **Open: exotic CPUs** where Wasmtime has no compiler (ppc64le,
  loongarch64 and others). Pulley ran 4.6 JWS per second and Wasmi 2.0
  12.5 ([execution modes][modes]). Not decided.

---

## R32. The isolation invariant

**Status: accepted** (owner, 2026-09-28).

Every shipped host puts at least one isolation boundary between a hostile
receipt and the caller's process: a Wasm sandbox in process (classes A, B
and C) or a separate process (class D), which in `aprv-server` also runs
the Wasm sandbox. Native in-process verification (class E) is not
shipped: the C ABI is for users who choose it. THREAT-MODEL.md defines the
classes and classifies every host.

---

## R33. The maintained Java implementation is the live differential oracle

**Status: accepted** (owner, 2026-09-28). Supersedes R8.

- **Decision:** the 0.7 Java implementation stays in the repository,
  maintained. CI runs it and the Rust core over the 388 cases on every
  change, and the differential job runs the full corpus through both
  nightly. Its differences go to R20.
- **The one-product rule, restated for the plan** (CLAUDE.md's "Behavior
  changes" section changes to this text in Phase 7): a verification
  behaviour change touches the Rust core, the Java implementation and
  `fixtures/` in the same PR. The 388 cases keep them in step, and every
  host runs all of them as one test each.
- **Why not the frozen jar of R8:** a frozen jar answers differently
  wherever the core changes on purpose, so every intended change becomes
  a recorded divergence; a maintained implementation changes with the
  contract.

---

## R34. Standards adopted for 0.8.0

**Status: accepted** (owner, 2026-09-29: "all of them").

Each is a published standard with tooling that checks it, chosen so a
consumer or auditor reads a document they already know instead of one of
ours. None changes a verdict. Where each lands is in MIGRATION.md.

| Standard | Where | What it replaces | Checked by |
|---|---|---|---|
| The canonical ABI over WIT (Component Model) | `aprv.wasm`'s exports (R23) | ABI v1's own export list | `wasm-tools component wit` diffed against the file |
| JSON Schema 2020-12 | the three wire shapes of `aprv-wire`: the verify-receipt result, the verify-signed-data result, `init`'s configuration and answer; the endpoint response is Apple's format and keeps 0.7's description | prose in `0.7-api.md` alone | every corpus answer from the core, the C ABI and `aprv.wasm` validated in CI |
| OpenAPI 3.1 | `aprv-server`'s HTTP API, referencing the schemas above; 3.1 because it takes JSON Schema 2020-12 unchanged, and every generator and linter in use supports it, PHP's included | the route list in the evidence note | Spectral (lint) and Schemathesis (property tests against the running server) in the `aprv-server` job |
| RFC 9457 Problem Details | `aprv-server`'s non-result errors: 400, 401, 404, 405, 500 `WASM_TRAP`, `ABI_ERROR`, `INTERNAL_ERROR`, as `application/problem+json` with the code in a `code` member; verification results stay HTTP 200 with the module's JSON, and a body over the cap is HTTP 413 with the module's JSON (amended 2026-10-02, below) | ad hoc error bodies | the OpenAPI document and Schemathesis |
| SLSA build provenance | every release artifact: `aprv.wasm`, the component, the server binaries, the classifier jars, the image | the "build-provenance attestation" already planned, now named by its level and format | `gh attestation verify` in the post-publish smoke |
| CycloneDX SBOM | one per artifact, from `cargo cyclonedx` plus the components Cargo cannot see, named by version and hash: OpenSSL, wasi-sdk and wasi-libc, rustc, Wasmtime (server), Endive (Java) | the licence texts alone | the SBOM attested with the artifact; a script checks it names the pinned versions |
| Reproducible build | `tools/reproduce-wasm.sh`: rebuild `aprv.wasm` from a tag in the pinned toolchain and compare the hash; the same for the server binaries where the platform allows | THREAT-MODEL.md §4's "paths remapped so a second build can reproduce the hash" as a claim | run once in the release job against its own artifact; documented for anyone to rerun |
| OCI image annotations | `org.opencontainers.image.source`, `.revision`, `.version`, `.licenses`, `.description` on the Docker image | none | inspected in the image smoke |
| cbindgen | the C ABI's header, generated from the source | a hand-maintained header | regenerated and diffed in `rust-ffi`, as today |
| `wasi:random/random@0.2` | the module's one import, if Phase 1 confirms `get-random-bytes` can replace our `host.random-get` without a size or speed cost; a WASI 0.2 host then supplies it with no code of ours | our own `host` interface | the import list check either way |

**Amended 2026-10-02** (owner; Q12). The size refusal comes from the
module; HTTP 413 stays.

- **Decision:** `aprv-server` no longer answers a body over 3,145,728
  bytes with a `PAYLOAD_TOO_LARGE` problem of its own. It hands the module
  the body's first 3,145,729 bytes, as every Wasm host cuts an input, and
  sends the module's answer (`TOO_LARGE`, or `{"status":21002}` at the
  endpoint) as the 413's `application/json` body, with the 200's schema.
  A body announced over 16 MiB (`Content-Length`) is read only to
  3,145,729 bytes, answered, and the connection closed, and so is one that
  streams past 16 MiB; one between the cap and 16 MiB is read and
  discarded to its end, so the client sees the answer rather than a reset
  and keeps its connection. The CLI feeds the
  module the same bytes, prints its answer, and keeps exit status 3 so a
  script can still tell the input was over the cap.
- **Why:** with the refusal made by the server, the Java `-wasm` server
  engine and PHP had to forge the core's answer to a 413 or an exit 3,
  copying its messages and caps into wrapper code, which the
  one-implementation rule forbids. Now both read a 413 or an exit 3 as
  they read a 200 or an exit 0, and the cap's wording lives in the module
  alone.
- **Compatibility:** a client of an older server gets a problem document
  with its 413, which these clients now report as a server problem
  (`INTERNAL_ERROR`, 21009 at the endpoint) instead of `TOO_LARGE`. The
  Java and PHP packages pin the server binary they start, so only a
  caller who points them at a server of their own, older than this
  change, sees that.

**Considered and not adopted.** JCS (RFC 8785, JSON canonicalisation):
the 0.7 contract compares JSON by value (`cases.json`), the endpoint
answer is Apple's bytes, and no signature is computed over our JSON, so
canonical form buys nothing here; recorded so it is not proposed again.

---

## R35. The parity corpus: a release asset, pinned in git

**Status: accepted** (owner, 2026-09-29). Replaces the repository
variables of OD-05 (STATUS.md).

- **Where it lives:** a GitHub Release of this repository, tag
  `corpus-2026-09-29` (a pre-release), file `corpus-2026-09-29.tar.gz`,
  28,591,520 B, SHA-256
  `89b599c52f0448dae22298972db5841a795991edf52df520bea7c545774b956d`.
  Its layout is the one `.github/CI-NOTES.md` describes for the nightly
  `corpus` job.
- **What is in it:** rows generated from `fixtures/` and the test keys
  only. It holds no production receipt.
- **The pin:** `fixtures/corpus.json` names the asset's URL and SHA-256,
  and `nightly.yml` reads it and checks the hash before it unpacks
  anything. The repository variables `APRV_CORPUS_URL` and
  `APRV_CORPUS_SHA256` go. #200, merged on 2026-09-30 (86ff162),
  introduced the file and the workflow change.
- **What follows:** the pin changes through a reviewed commit, like any
  other file, and `git log` shows which archive each nightly used. The
  rows belong to one module, so a release that changes the module needs
  a new archive under a new tag and a new pin.
- **Later, perhaps:** a separate corpus repository. Nothing is decided.

---

## R36. The public API in 0.8, and the WIT package version

**Status: accepted** (owner, 2026-09-30). The WIT package version item
is done (2026-10-01). The items still open are in ROADMAP.md, "Decisions
of 2026-09-29 and 30"; R39 and R41 settled the API items listed there
(2026-10-01), all but Node's two factory names.

- **The shape stays as 0.7 defined it** in all nine packages
  ([0.7 API][api07]): `Verifier.create(Config)`, `verifyReceipt(base64)`,
  `verifySignedData(jws)`, `verifyReceiptEndpoint(env, json)`, and a
  result with `verified`, `payload` and `failure`.
- **Settled:** Java keeps `runtimeProbe`. Roots keep the language's own
  certificate type where it has one (Java, .NET and Go) and are bytes
  elsewhere; the one-implementation allowlist already names the .NET and
  Go types (OD-04, STATUS.md).
  Java's `Environment.value()` becomes public.
- **The WIT package version moves from `aprv:verifier@1.0.0` to
  `aprv:verifier@0.1.0`,** because the product is pre-1.0. The export
  names carry the version (R23), so this renames the ABI: the WIT file,
  the guest, every binding and wrapper, and the `abi` string
  `aprv-server` reports move in one pull request. The Go and Swift CI
  jobs test the module the same run builds, so the committed copies in
  `go/` and `swift/` can keep the old names until the release refreshes
  them (R14). **Done 2026-10-01.**
- **Later, not in 0.8.0:** an optional `expect {bundleId, environment}`
  argument on the verify calls. The core would check it and answer a
  mismatch as a verdict. Today every README leaves that check to the
  caller.

---

## R37. Fuzz findings and supply-chain scoring

**Status: accepted** (owner, 2026-09-30). Wired 2026-10-01, waiting on
the owner's key and secrets: the nightly sealing and notice, the
Scorecard workflow and the OSS-Fuzz draft are in the repository, and
BOOTSTRAP.md lists the three owner actions.

- **OSS-Fuzz:** apply with the six existing targets (`rust/fuzz`: five
  targets over the core and the C ABI, and `abi-call` over the module's
  exports).
- **Nightly findings:** the job encrypts any finding to the owner's age
  or PGP public key and sends a notice through a Telegram bot. The public
  log shows only the target name and a hash. This answers lane D's
  hand-back (STATUS.md): the repository is public, so an auto-opened
  issue would disclose a memory-safety crash.
- **OpenSSF Scorecard** joins the checks.
- **Attestation is unchanged:** SLSA provenance and a CycloneDX SBOM per
  artifact (R34).
- BOOTSTRAP.md lists the owner's one-time actions: the public key, the
  bot and its secret, and the OSS-Fuzz project submission.
- **As wired (2026-10-01):**
  - The nightly `rust-fuzz-openssl` job runs each target with its output
    in a file on the runner. A finding prints the target and the
    input's SHA-256; `.github/scripts/fuzz-finding.sh` seals the input
    and the fuzzer's report with age (v1.3.2, pinned by SHA-256) to
    `.github/fuzz/findings-recipient.txt` and the job uploads the sealed
    file for 30 days. Without that file nothing is uploaded. Telegram
    gets the repository, target, hash and run URL when
    `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are set. The run fails
    in every case.
  - age only, no PGP path: one pinned binary, and age also takes an SSH
    public key.
  - Scorecard runs weekly and on pushes to `main` with
    `publish_results`, and uploads its SARIF to code scanning.
  - The OSS-Fuzz draft in `docs/oss-fuzz/` builds five targets.
    `abi-call` reads the module from `APRV_WASM` and compiles it on its
    first input (86 s instrumented), which OSS-Fuzz's runner cannot
    supply or wait for; it joins after a harness change. OSS-Fuzz's Rust
    support is AddressSanitizer only.
  - Closed 2026-10-01: the eight per-push fuzz jobs in ci.yml
    (`go-fuzz`, `rust-fuzz`, `dotnet-fuzz`, `php-fuzz`, `ruby-fuzz`,
    `python-fuzz`, `swift-fuzz`, `java-fuzz`) handle a finding as the
    nightly job does. `.github/scripts/fuzz-quiet.sh` (an inline loop in
    `go-fuzz`) runs each target with its output in a file, and a
    separate failure step holding the
    Telegram secrets runs `fuzz-report.sh`, which hands each failed
    target to `fuzz-finding.sh`; only the sealed files are uploaded, as
    `fuzz-findings-sealed-<job>`.

---

## R38. Calendar and US Pacific time from `jiff`

**Status: accepted** (owner, 2026-10-01; option B the same day).

- The core takes its calendar and the `America/Los_Angeles` offset behind
  every `_pst` date from `jiff` 0.2 (`default-features = false`, feature
  `static`). `jiff::tz::get!` compiles that one zone into the binary from
  `jiff-tzdb`'s copy of the IANA database; nothing reads
  `/usr/share/zoneinfo` at run time, and the module carries no database.
- Reason: the project does not maintain calendar code. The hand-written
  rules (a 1918-1966 table, closed-form rules from 1967 and the civil-date
  arithmetic) were the one part of the core that encoded law rather than
  Apple's policy; a change in US daylight-saving law is now a dependency
  bump and a module rebuild.
- jiff's answers are taken as they are. Before 1883-11-18T20:00:00Z the
  database gives local mean time, −07:52:58, where the hand-written code
  answered PST; Java's `ZoneId` gives the same local mean time, so the
  core now agrees with Java there and R20 gains nothing for it.
- The renderings cover jiff's first instant (-9999-01-02T01:59:59Z) to the
  receipt grammar's last second, 9999-12-31T23:59:59Z. jiff's last
  timestamp is 26 hours earlier, 9999-12-30T22:00:00Z; the seconds past it
  are carried in the UTC offset jiff renders with (jiff allows offsets to
  ±25:59:59 for this), and their Pacific offset is the one at jiff's last
  second, which is exact because the zone's rule puts all of 9999-12-30 and
  -31 in PST. No 400-year cycle arithmetic.
- A clock outside that range is broken: the endpoint answers it with its
  INTERNAL_ERROR body, `{"status":21009}`, as it answers a clock that
  panics (R20 row). Every receipt date `parse_receipt_date` accepts
  renders, so only `request_date` can reach that answer.
- What stays in `rust/src/datetime.rs`: the receipt-date grammar, checked
  byte by byte, since it is the contract with Java and `jiff`'s parsers
  accept more. Within the range above the renderings are byte-identical to
  the hand-written code from 1883-11-18 on: 0 disagreements at 182,918,657
  instants (`rust/tests/datetime.rs`).
- The civil fields are printed with `format!`, as jiff's own
  `%Y-%m-%d %H:%M:%S` prints them (a test holds the two equal over the
  whole year range); `strftime` itself would add 236,960 bytes to the
  module.
- Cost: `aprv.wasm` +48,736 bytes (2,764,700 to 2,813,436; gzip +9,752).
  `jiff` and `jiff-core` link; `jiff-static` and `jiff-tzdb` run at build
  time only. 12 new lockfile packages; `cargo deny check` passes.
- Measured against chrono-tz, tz-rs with tzdb_data, time-tz and jiff's
  other constructors ([Pacific time-zone crates][pactz]). tz-rs with
  tzdb_data is smaller; jiff was chosen for one crate covering the calendar
  and the zone with no build-time environment or file.

---

## R39. Roots are DER in every package

**Status: accepted** (owner, 2026-10-01). Settles the PEM item that R36
left open in ROADMAP.md.

- **Decision:** a caller's root reaches every package as DER: a native
  certificate object in Java, .NET and Go (R36), DER bytes everywhere
  else. Node's `RootInput` is `Uint8Array` only, and Ruby's
  `Config.new(roots:)` takes `#to_der` objects or DER Strings. Both
  deleted their hand-written PEM unwrapping. A PEM string is refused at
  config time with an error that points at the README, which gives the
  conversion: `new X509Certificate(pem).raw` from `node:crypto`, or
  `OpenSSL::X509::Certificate.new(pem).to_der`.
- **Why:** the module's `init` takes base64 DER only
  (`Verifier::new(roots: &[Vec<u8>])`), Apple's PKI page ships `.cer`
  files that are already DER, and every fixture root is DER. Python,
  Swift and PHP already took DER bytes, and PHP already refused PEM.
  Two wrappers decoding a text format by hand was code the
  one-implementation rule asks wrappers not to hold, for an input no
  one has to start from.
- **The core's ABI takes DER only**, and the WIT does not change.
- **Exceptions, both outside the wrappers:** the Rust crate's
  `TrustAnchor::from_pem` stays, for Rust callers holding PEM, until the
  owner decides otherwise; `aprv-server`'s `--roots` file keeps reading
  PEM blocks beside base64 DER lines, because an operator writes that
  file by hand and PEM is what certificate tools print.
- **The gate is unchanged:** the error messages name no crypto API, so
  neither the one-implementation allowlist nor either package's own scan
  needs an exception for them.

**Amended 2026-10-01** (owner, the same day; Q6). Wrappers pass a
caller's root bytes as they are, and the core reads DER or PEM.

- **Decision:** after base64 decoding `init`'s configuration, the core
  reads each root entry by its bytes (`TrustAnchor::from_der_or_pem`). A
  first byte of `0x30`, an ASN.1 SEQUENCE, is one DER certificate, read as
  before. Bytes that start with `-----BEGIN`, after any ASCII whitespace,
  go to OpenSSL's PEM reader (`PEM_read_bio_X509` until the input
  ends), and every certificate in them becomes an anchor, so a PEM
  bundle is one entry. Each one is held to the DER reader's bar through
  the DER OpenSSL encodes from it; OpenSSL does not check that a
  certificate fills its block, so bytes after it inside the block are
  dropped where DER input with them is refused. No certificate, a block
  OpenSSL refuses, or anything else is the existing refusal, with the
  existing message. No format parameter, no new error kind, no WIT
  change: the ABI version stays, and the WIT's comment that a root is
  `<base64 DER>` waits for the next ABI change, since CI diffs that file.
- **PEM is read as OpenSSL reads it.** A block starts at the start of a
  line. Text around the blocks, and blocks of other types (a key, a
  `TRUSTED CERTIFICATE`, a CRL), are passed over, so a bundle with a key
  in it yields its certificates; such a block on its own is refused.
  `X509 CERTIFICATE` is read as `CERTIFICATE`. The reader passes OpenSSL
  a password callback that refuses: OpenSSL's default one prompts on the
  terminal, or reads stdin, for an encrypted block (`Proc-Type:
  4,ENCRYPTED`), which would block a native caller and could open the
  block with a typed passphrase. An encrypted block is refused instead. The module was never
  exposed: its OpenSSL is built with `no-ui-console`.
- **Why:** the format is decided in one place, by OpenSSL, and no
  wrapper or caller has to convert anything. A PEM file read from disk
  is a root as it stands in every package that takes bytes.
- **Wrappers:** Node's `RootInput` stays `Uint8Array`, and a string is
  still a `TypeError`: PEM text goes in as its bytes. Ruby's `Config`
  drops its check for `-----BEGIN` and passes every String on. Python,
  Swift and PHP already passed bytes on. Java, .NET and Go take
  certificate objects and pass their DER, unchanged. No wrapper reads
  either format, and the one-implementation allowlist is unchanged.
- **`TrustAnchor::from_pem`** is no longer an exception: it goes through
  the same OpenSSL reader and returns the first certificate.
- **`aprv-server`'s `--roots` file stays an exception, without a reader
  of its own** (owner, 2026-10-02; Q10). The server still unwraps PEM
  `CERTIFICATE` blocks to DER before `init`, because `GET /v1/info`
  reports each root's SHA-256 and the Java and PHP clients compare those
  with the DER they hold. The `pem` crate now reads each block: it matches
  the END label to the BEGIN label and decodes the base64. The server
  keeps only the file's line rules (base64 lines, `#` comments, blank
  lines, where a block starts and ends) and its existing refusals
  (docs/evidence/2026-10-02-server-roots-pem.md). It does
  not link OpenSSL, so `Certificate::all_from_pem` was not an option
  there. A base64 line in that file may now carry PEM bytes, which reach
  `init` unchanged; `GET /v1/info` then reports the SHA-256 of those PEM
  bytes, one fingerprint however many certificates they hold, so a
  client holding the DER fails closed against it. Give such a client a
  file of DER lines or PEM blocks.
- **`--roots` also takes a DER certificate file, and repeats** (owner,
  2026-10-02; Q14). A file whose first byte is `0x30`, the rule the core
  applies to a root entry, is one DER certificate, so Apple's `.cer`
  files go in as they are; any other file is read as above. The server
  does not parse the DER: it passes it to `init` whole, so a truncated or
  otherwise broken `.cer` is the module's refusal at start (exit 2), and
  `/v1/info` reports the SHA-256 of the file's bytes, which is the DER's.
  Each `--roots` flag adds its file's roots, in order; managed mode, which
  takes its roots on stdin, is unchanged.

---

## R40. JSON from `serde_json`, each document as a map of raw values

**Status: accepted** (owner, 2026-10-01; variant B the same day;
amended 2026-10-02).

- The core reads its three JSON documents, a JWS header, a JWS payload and
  the `verifyReceipt` request body, with `serde_json` (its `raw_value`
  feature on the dependency the core already had; no new crate), each into
  a `BTreeMap<String, &RawValue>`. A member nobody reads is checked against
  the grammar and skipped without being built, iteratively, on a heap
  stack of one byte per nesting level. `alg`, `x5c`, `signedDate` and
  `receipt-data` are then parsed from their raw text. The endpoint reads
  the first value and nothing after it (`StreamDeserializer::next`); a JWS
  header or payload allows only whitespace after its object (`from_str`).
- Reason: the owner's rule that a well-maintained library replaces
  hand-written code. `rust/src/json.rs` was 370 lines of grammar
  (566 with its tests), the one parser the core kept beside OpenSSL and
  `serde_json`; it is about 95 lines of glue now (230 with tests).
- What was deleted: the reader, and its three bounds, `MAX_NESTING_DEPTH`
  64, `MAX_NAME_LENGTH` 50,000 UTF-16 units and `MAX_NUMBER_LENGTH` 1,000
  characters; `rust/tests/input_size_caps.rs` lost the two tests of those
  bounds (`a_body_nested_past_the_limit_answers_21002`,
  `jws_json_nested_past_the_limit_is_refused`), and its two at-the-limit
  tests became `a_deeply_nested_body_verifies` and
  `deeply_nested_jws_json_reaches_the_signature_check`, which pin that
  nesting within the size caps changes no verdict.
- What the core still refuses, in skipped values too: comments, trailing
  commas, leading zeros, `+`, `NaN`, unescaped control characters, escapes
  RFC 8259 does not define, a byte order mark, bytes that are not UTF-8,
  and anything but whitespace after a JWS object. A duplicate name keeps
  its last value. `signedDate` keeps the reference conversion from its
  raw text: an integer must fit an `i64`, a number with a fraction or an
  exponent is truncated within that range, and anything else, an integer
  past `i64` included, is no instant, so the clock stands in. One reading
  changed beside the bounds: a lone surrogate escape is refused in a name
  or in a value the core reads, where the old reader made it U+FFFD and
  Jackson keeps it (R20 row). No shared case reaches it.
- The bounds the core no longer has, and why that is acceptable: the
  input caps (3,145,728 bytes for a body, 262,144 for a JWS) already bound
  the work, and the three bounds prevented no blow-up. Measured natively
  on the worst 3 MiB body each reader admits, best of five
  ([serde_json][jsonserde]): 321,563 distinct members cost the old reader
  26 ms and 46 MB and this one 83 ms and 26 MB; an array of 63-deep
  objects 11 ms and 240 B against 6 ms and 521 B; 1.5 million levels of
  nesting, which the old reader refused, 5 ms and 3.1 MB. A 3 MiB name,
  number or string is read in linear time by both and copied at most
  once. `serde_json`'s own recursion limit (128) applies to the values the
  core builds, the one-level map and the `x5c` array, and not to the
  values it skips.
- Five shared cases crossed the deleted bounds with genuinely signed
  inputs and are port-defined now, each listing Java's answer and the
  core's (R20 rows of 2026-10-01). An endpoint case lists `/status` values
  with `oneOf`, a schema form added for it; every runner that evaluates
  endpoint cases reads it.
- Java kept `BoundedJson` and its three bounds until 2026-10-05; it now
  reads under Jackson's default constraints and the same size caps
  (docs/design/java-notes.md). The R20 rule forbids code in either
  implementation written to imitate the other.
- Rejected: variant A, `Map<String, Value>`, which builds a tree of
  unsigned input at up to 126 times its size (396 MB for one 3 MiB
  request; a pooled Wasm instance keeps the memory it grows).
- Cost: `aprv.wasm` −6,285 bytes (2,813,436 to 2,807,151; gzip −631),
  no new lockfile package, `cargo deny check` passes.

**Amended 2026-10-02: `aprv-wire` writes its JSON with `serde_json` too.**
The bindings' writer (`rust/bindings/wire`) was a hand-written string
escaper and object builder beside a `serde_json` already in the graph. It
is now `Serialize` impls over the surface types and derived envelopes,
and `init`'s configuration is read as a `serde_json` map, with a derived
struct refusing a repeated `roots`. The bytes do not change: `serde_json`
escapes the set 0.7's writer did (`"`, `\` and U+0000 to U+001F, with
`\b`, `\f`, `\n`, `\r`, `\t` and lower-case `\u00XX`), writes everything
else raw, and writes members in the order they are serialised. A test in
`aprv-wire` pins a fully populated receipt answer, controls, raw
non-ASCII, negative and repeated attribute keys and `i64` extremes
included, to the text the old writer produced for it. `serde_derive` is a
build-time proc macro, outside the core's graph that
`tools/check-layering.mjs` inspects. One message moves: a configuration
with two faults now names a stray member before a `roots` that is not a
list, where the old reader took them in document order. Hosts write the
configuration themselves, so only a hand-made one carries two faults.

---

## R41. The public API in 0.8: internals hidden, one way to build a Config, two Java artifactIds

**Status: accepted** (owner, 2026-10-01; amended 2026-10-02,
2026-10-03 and 2026-10-04). Settles the API items R36 left open in
ROADMAP.md (item 5) and the Java artifact naming (item 11).

0.8.0 is the first release of the Wasm-backed packages. A public name
removed now breaks no one who has built on those packages; removed after
the release, it is a breaking change for every caller. So the audit of
2026-10-01 trimmed each package to what a caller needs, in two buckets.

- **Bucket A: internals that leaked into the public surface are hidden.**
  - Rust: the top-level `decode_receipt_data` becomes `pub(crate)` in
    `receipt.rs`. `aprv-surface`, built in lockstep with the core, reads
    the configuration's base64 roots through the `doc(hidden)`
    `__internal` hook the tests already use.
  - Go: `(*ReceiptPayload).String` and `(*JSONPayload).String` repeated
    `ToJSON()` and `JSON()`, and go. `Environment.String` and
    `Reason.String` stay: each is the `fmt.Stringer` of a string type,
    not a second rendering.
  - Swift: `Environment.appleValue` returned `rawValue`, and goes.
  - Node: `VerificationError` was exported from both entry points but
    never thrown, and goes. The failure is the result's `failure`.
  - PHP: `ReceiptPayload::idJson`, `ReceiptPayload::attributesJson` and
    `InAppPurchase::jsonValue` move to `Internal\PayloadJson`.
  - Ruby: `Guest`, `InstancePool`, `Runtime`, `Wire` and `PayloadJson`
    become private constants of the gem's module, and so does
    `RootsRejected`, which `Verifier.create` turns into an
    `ArgumentError` before a caller can see it.
- **Bucket B, option (a): one way to build a `Config` per language, in
  that language's idiom.** The Java-shaped duplicates go.
  - Python: `Config(roots=..., clock=...)`. `Config.create` and
    `Config.defaults` go; the constructor takes any iterable of roots,
    and `None` for either argument means its default, as `create` did.
  - Ruby: `Config.new(roots:, clock:)`. `Config.builder` and
    `Config::Builder` go, and on 2026-10-02 so does `Config.defaults`,
    which only called `Config.new`.
  - PHP: `new Config(roots: ..., clock: ...)`, both arguments defaulted
    and `roots` any iterable. `ConfigBuilder` and `Config::builder()` go,
    and on 2026-10-02 so does `Config::defaults()`, which only returned
    `new Config()`.
  - .NET: `new Config(roots: ..., clock: ...)`, both arguments defaulted
    and `roots` any `IEnumerable<X509Certificate2>`; `null` for either
    means its default, and the constructor refuses what `Build()`
    refused. `Config.Defaults()`, `Config.CreateBuilder()` and
    `Config.Builder` go (owner decision Q21, 2026-10-03).
  - Go, Swift and Node followed on 2026-10-04 (owner decision Q26).
    Go: `NewConfig(ConfigOptions{...})`, where the zero `ConfigOptions`
    is the defaults; `DefaultConfig()` goes, and an explicitly empty,
    non-nil `Roots` is still refused by `NewVerifier`. Swift:
    `Config(roots:clock:)`, both arguments defaulted to `nil`, which
    cannot fail and stores what it is given; `Config.defaults()`,
    `Config.builder()` and `ConfigBuilder` go, and `Verifier(config:)`
    now throws the `ConfigError`s `roots(_:)` and `build()` threw (an
    empty root set; a root the module refuses, found by initialising a
    fresh instance with it), as Go's `NewVerifier` and .NET's
    `Verifier.Create` refuse them. Node: `createConfig()`,
    an option left out taking its default; `defaultConfig()` goes from
    both entry points.
  - Rust: `Config::default()`. `Config::defaults()` goes.
    `Config::builder()` stays: it is the fallible build, and the one
    place a bundled root that did not load is a `ConfigError`.
  - Go and Swift: the byte caps (`MaxReceiptBytes`, `MaxRequestBytes`,
    `MaxJWSBytes`; `maxReceiptBytes`, `maxEndpointRequestBytes`,
    `maxJwsBytes`) only restated the core's numbers, and Go's three JSON
    bounds named limits the core no longer has (R40). Nothing in either
    package read them, so made private they would be dead code; they are
    deleted, and each README states the caps. The module's `TOO_LARGE`
    tells a caller a cap was exceeded.
  - Python, on 2026-10-02, for the same reason: `receipt.MAX_RECEIPT_BYTES`,
    `endpoint.MAX_REQUEST_BYTES` and `jws.MAX_JWS_BYTES` go, and with them
    the `endpoint` and `jws` modules, which held nothing else.
    `receipt.MAX_EMBEDDED_CERTIFICATES` and `receipt.MAX_SIGNER_INFOS`
    stay.
  - .NET: `JsonPayload.Create` stays. The constructor is private, so
    `Create` is the payload's one public way to be built, not a
    duplicate.
  - Kept as they are: the result and payload types' public constructors,
    which callers use to build values in their own tests; Java's
    `Config`, `Config.defaults()` included: it is the shape the others
    came from, and Java has no default arguments. (On 2026-10-01 Ruby's
    and PHP's `defaults` were kept here too; the next day's decision
    above removed them.)
- **.NET reads and writes JSON with `System.Text.Json` (2026-10-02).**
  The package's hand-written reader and writer (`Internal/Json.cs`, 610
  lines, and `OrderedMap`) existed because `System.Text.Json` is a
  package, not part of the framework, on netstandard2.0, and an assembly
  built against a newer copy than a .NET Framework or Unity host carries
  needs binding redirects. The owner chose the package over maintaining a
  parser. The module's answers are read with `JsonDocument` (`MaxDepth`
  128; the deepest answer is six levels, and a verified JWS payload is a
  string inside it), `ToJson` is written with `Utf8JsonWriter`, and no
  reflection serializer is used, so the trimmed build stays clean.
  `ToJson` escapes with the library's `UnsafeRelaxedJsonEscaping`: less
  hand-written code beats byte-identical output (the owner's decision
  Q20, 2026-10-02), so a custom `JavaScriptEncoder` that kept 0.7's
  escaping was dropped the same day. The text can differ from 0.7's in
  escaping only: upper-case hex in `\u` escapes, and `\u` escapes for
  U+007F to U+009F, U+2028 and U+2029, private-use, U+FEFF, noncharacter
  and unassigned code points, and every character outside the BMP (as a
  surrogate pair), which 0.7 wrote as themselves. Old and new were
  compared on the 187 `verifyReceipt` and 114 `verifySignedData` cases
  of `fixtures/cases.json` and 14 hand-built payloads, on both assets:
  every verdict and every `verifySignedData` payload text is the same,
  and of the 81 verified receipts' and 14 payloads' `ToJson` texts, 10
  differ, each with the same JSON value. The 50 `verifyReceiptEndpoint` cases were
  not compared (their answers carry the wall clock), nor the 33
  `decodeBase64` cases (no JSON output). A lone surrogate in a hand-built
  payload, which has no UTF-8 form, is now written as `\uFFFD`
  ([.NET JSON][stjout]). net8.0 gains no dependency; netstandard2.0 takes
  `System.Text.Json` 10.0.12, which brings `Microsoft.Bcl.AsyncInterfaces`,
  `System.IO.Pipelines`, `System.Text.Encodings.Web` and
  `System.Threading.Tasks.Extensions` and raises `System.Buffers`,
  `System.Memory`, `System.Numerics.Vectors` and
  `System.Runtime.CompilerServices.Unsafe` (dotnet/README.md, "How it
  runs").
- **Java: two artifactIds at one version, unchanged.**
  `apple-purchase-receipt-verifier` (BouncyCastle) and
  `apple-purchase-receipt-verifier-wasm` stay, with no qualifier. The
  `-wasm` POM description and README say that it is the newer engine,
  offered as a preview whose public API may still change before 1.0, and
  that the BouncyCastle artifact is the long-standing one. A `-wasm`
  version qualifier on one artifactId would sort below the plain release,
  so Dependabot and Renovate would propose the BouncyCastle build to every
  Wasm user as an upgrade. Two artifactIds keep the engines apart, and a
  release stays one of the month's Maven Central releases, where a
  second version per release would spend two. **Amended 2026-10-04:** the
  `-wasm` upload is held behind the repository variable
  `APRV_PUBLISH_JAVA_WASM` until the owner judges the preview API settled,
  because a version on Central is permanent (Central does not delete or
  replace a published release); the artifactId, the
  shared version and the release-please wiring are unchanged, and the
  main artifact deploys on every release (BOOTSTRAP.md, "Maven Central").
- **The shared cases do not change.** The Python and PHP conformance
  runners build their `Config` with the constructor now; no case and no
  fixture moved.
- **Still open:** Node's `createConfig()` and `createVerifier()` names
  (ROADMAP.md, item 5).

## R42. The module states its input length and the environment

**Status: accepted** (owner, 2026-10-02; decisions 2a A and Q19 A,
recorded 2026-10-03). Two facts every host needs that only the core can
know move into the module's answers, and each copy outside the core and
the Java implementation goes.

- **Decision, the input length (2a A):** `init` answers
  `{"ok":true,"max_input_bytes":N}` where it answered `{"ok":true}`;
  `{"ok":false,"message":"..."}` is unchanged. `N` is the most bytes of
  one input a host needs to hand the module: a longer input may be cut to
  this length, and the module answers `TOO_LARGE` for it (21002 from
  `verify-receipt-endpoint`). The core computes it from its caps, the
  largest plus one (`MAX_INPUT_BYTES` in `rust/src/lib.rs`, 3,145,729
  today), so no second literal exists; `aprv-wire` writes it, and
  `init-result.schema.json` requires it.
- **Why:** seven wrappers kept the number (Node's `MAX_INPUT_BYTES`, Go's
  `maxInput`, Python's `MAX_INPUT_COPY`, Swift's `maxInputBytes`, .NET's
  `MaxLoweredInputBytes`, Java `-wasm`'s `MAX_INPUT_BYTES`, PHP's
  `Input::MAX_BYTES`), and `aprv-server` kept the cap itself
  (`MAX_BODY`). A cap change in the core was a change in eight places
  that no test tied together.
- **What reads it:** each host reads `max_input_bytes` after `init` and
  deletes its copy. `aprv-server` reads it from its first `init`, cuts a
  body or stdin to it, and answers HTTP 413 (CLI exit 3) for a body of
  that length or longer, the behaviour of #219 with the module's number;
  `GET /v1/info` and `aprv info` report it as `limits.max_input_bytes`,
  which replaces `max_body_bytes`. The Java `-wasm` artifact reads it
  from `init` on Endive and from `GET /v1/info` on the server engine,
  where a server that states none is refused as a source. An accepting
  answer without the number comes from a module older than its host, and
  every host treats it as a module failure, never as a verdict.
- **The WIT does not change.** `init(config-json) -> string` keeps its
  signature; only the string's shape moved. The WIT's doc comment, which
  still quotes `{"ok":true}`, waits for the next ABI change, since CI
  diffs that file.
- **Decision, the environment (Q19 A):** a verified answer of
  `verify-receipt` and of `verify-signed-data` carries a top-level
  `environment` beside `payload`:
  `{"verified":true,"payload":...,"environment":"Sandbox"}`, the value
  `"Production"`, `"Sandbox"` or `null`. The payload's own JSON
  (`ReceiptPayload.toJson`, the C ABI's `receipt_payload`) does not
  change, and neither does `verify-receipt-endpoint`, whose response
  already writes Apple's `environment`.
  - A receipt's comes from `receipt_type`: `Production` and
    `ProductionVPP` are Production, `ProductionSandbox` and
    `ProductionVPPSandbox` Sandbox, anything else (`Xcode`, absent) null.
  - A JWS's comes from the first of the three places Apple documents
    that is present: the top-level `environment` (transaction and renewal
    info), `data.environment` (App Store Server Notifications V2) and
    `summary.environment` (summary notifications). `Production` and
    `Sandbox` map; anything else there, a value that is not a string
    included, is null, and so is a payload with none of the three. The
    first one present decides even when it names neither environment. A
    repeated name keeps its last value, a repeated `data` or `summary`
    included, as everywhere in a payload. The core reads the three in the
    one parse it already made for `signedDate`, reading the members of
    `data` and `summary` from their raw text.
- **Why:** nine languages carried a copy of the mapping
  (`Environment::from_receipt_type` and `from_jws_environment` in Rust and
  their twins in Java, Go, .NET, Swift, Ruby, Python, PHP and Node), and
  none of the seven Wasm packages may hold a rule (ARCHITECTURE.md §9).
  A notification's environment sits one level down, where a caller who
  read only the top-level claim found nothing.
- **Every language exposes it on the result's payload**
  (`ReceiptPayload::environment()` and `JsonPayload::environment()` in
  Rust, `ReceiptPayload.environment()` and `JsonPayload.environment()` in
  Java), and the public helpers are deleted in all nine before 0.8
  ships. In Rust the two functions become `pub(crate)`; `JsonPayload::new`
  reads the environment from the JSON it is given, as a verified payload
  is read. Java's two payload constructors take the environment as their
  last argument, since the shared classes the `-wasm` artifact ships must
  hold no rule; the `-wasm` artifact takes the module's member, and
  refuses a verified answer without it, as it refuses one without
  `payload`. The seven Wasm packages follow on the same branch.
- **The rule lives in two places,** as every verification rule does: the
  core (`rust/src/environment.rs`, `rust/src/jws.rs`) and the
  BouncyCastle implementation (`ReceiptDecoder.environment`,
  `JwsCore.Payload`). `fixtures/cases.json` proves they agree: every
  `status: ok` case of `verifyReceipt` and `verifySignedData` states
  `expected.environment` (113 cases: 74 receipts, 60 Sandbox, 1
  Production and 13 null; 39 JWS, 30 Sandbox, 3 Production and 6 null),
  derived from each fixture's own bytes. `EnvironmentFixtures` writes
  four JWS under a root of their own, one per place with `Production`
  and one whose top-level `Xcode` hides `data.environment`'s `Sandbox`;
  Apple's own test notification covers `data` with `Sandbox`.
- **Port-defined:** a member name with a lone surrogate escape inside
  `data` or `summary`. The core's reader refuses such a name (R40), so
  the container holds no environment for it; Jackson reads on. Apple's
  documents are ASCII, and no case pins it.
- **Rejected for the input length:** B) a new WIT function `limits()`:
  the WIT moves to 0.2.0 and all eight hosts move with it in one PR, for
  a number `init`'s answer can carry. C) a CI check that the seven copies
  equal the core's number: it keeps the copies, and the check is one
  more place to keep in step.
- **Rejected for the environment:** B) only the top-level `environment`:
  every App Store Server Notification would answer null, where Apple puts
  the environment in `data` or `summary`. C) keep the nine helpers: nine
  copies of one rule, seven of them in packages that may hold none.

---

## R43. The Rust tests read ASN.1 with `asn1-rs`

**Status: accepted** (owner, 2026-10-02, decision Q18; recorded
2026-10-03).

- **Decision:** the core's tests take fixtures apart with `asn1-rs` 0.7
  (the parser under `x509-parser`), a dev-dependency of the core crate
  only. `rust/tests/common/ber.rs` keeps the tests' `Tlv` shape over its
  `Any`; the DER writer in `rust/tests/common/mod.rs` writes lengths,
  integers and OIDs through it. The library parses nothing with it, and
  `cargo tree -e normal` does not list it.
- **Why:** the reader the tests used was the core's own pre-OpenSSL BER
  reader, 391 lines kept in `rust/tests/common/der.rs` for the tests
  alone. The project does not maintain an ASN.1 parser.
- **What stays hand-written:** each deliberate fault (a wrong length, an
  indefinite length with or without its end-of-contents, a retagged
  value) is written as bytes in the test that states it, since no library
  writes malformed encodings; and the join of a constructed
  `OCTET STRING`'s chunks, which `asn1-rs` 0.7 does not do.
- **Measured:** every fixture the old reader parsed reads into the same
  tree, the writer's output is byte-identical, and the suite lists and
  passes the same 668 tests ([asn1-rs in the tests][asn1rs]).
- **Rejected:** A) RustCrypto `der`: DER only, so it cannot open Apple's
  or Xcode's receipts, which are BER. B) OpenSSL's ASN.1 API from the
  tests: raw FFI with no safe Rust API over it, `unsafe` code in the tests
  for a job a safe crate does. C) Keep the hand-written reader: the
  parser this decision removes.

---

## Rejected alternatives

One table for everything the plan measured or considered and rejected.
"Reopen when" names the trigger where one exists.

| Alternative | Measured reason | Evidence | Reopen when |
|---|---|---|---|
| UniFFI (Kotlin over JNA for Java 8, Swift, Python) | Native core and OpenSSL inside the caller's process, class E (R32); the owner's constraint for Java 8 is that hostile receipts are never parsed by native code inside the JVM. It worked: 701 µs per receipt on JDK 21, typed errors in Python | [rust-core spikes][spikes] rows 5, 6; [aprv-server][server], owner constraint | — |
| JNA | Under Tomcat hot redeploy it leaked a Cleaner thread and two native copies per redeploy, on JNA 5.17.0 and 5.19.1, with no public API to stop the thread; native code in the JVM | [rust-core spikes][spikes], "Enterprise deployment shapes" | — |
| jni-rs with hand-written Java | Native code in the JVM (class E); 472 hand-written Java lines and 2 `unsafe` blocks to maintain | [rust-core spikes][spikes], "Java binding bake-off" | — |
| FFM (Panama) | Final only in Java 22 (JEP 454); the floor is 8 | R2 addendum of 2026-09-25 (git history of this file); no evidence note | the Java floor reaches 22 |
| wasmtime4j | JNI; 13 stars; two Wasmtime majors behind; extracts natives; no signal-handler story. Not built | The owner's brief of 2026-09-28; no evidence note | — |
| kawamuray/wasmtime-java | JNI; work in progress; no Linux ARM64. Not built | The owner's brief of 2026-09-28; no evidence note | — |
| Chicory's runtime compiler and interpreter | 18,546 µs and 974,602 µs per receipt on JDK 21, against 701 µs native; Java 11 floor. Endive's build-time compiler replaced it | [rust-core spikes][spikes], timings | — |
| GraalWasm | Java 21 floor; needs JVMCI for speed. Not built | R2 rejected table of 2026-09-25 (git history of this file); no evidence note | — |
| Wasmi 2.0 behind our own cdylib, as the Python default | 11.7 to 12.2 JWS per second per core, just above the floor, against 177 for wasmtime-py in round 8; a 280-line cdylib with 13 `unsafe` blocks and a wheel build per platform that we would own; CPU bounded only by fuel. The security review: one issue reported privately upstream on 2026-09-27; not reachable for `aprv.wasm` | [final Python round][pyfinal]; [Wasmi review][wasmi] | — |
| Wasmi through its C API | Fuel unusable (every call traps with metering on), no memory or instance limiter, malformed modules rejected with no reason | [final Python round §2, §4][pyfinal] | — |
| WAMR, every mode | Fast interpreter 9.4 JWS per second, under the floor; Fast JIT 486 ms cold on one CPU and a JIT inside the boundary; LLVM JIT 153 s cold and about 1 GB RSS; its Python binding is not on PyPI, stale for 12 months and debug-built | [execution modes][modes]; [runtime options][pyopt] | — |
| Pulley | 4.6 to 7.5 JWS per second, under the floor, on every measurement | [execution modes][modes]; [runtime options][pyopt]; [aprv-server §9][server] | reconsidered only for exotic CPUs (R31) |
| pywasm | 0.006 JWS per second (170 s for one JWS); traps are `assert` statements, so `python -O` changes behaviour | [final Python round §1][pyfinal] | — |
| wasmer-python | Abandoned: last release 1.1.0 on 2022-01-07, wheels for CPython 3.7 to 3.10 only | [runtime options][pyopt] | — |
| pywasm3 | 0.5.0 from 2021, sdist only; an interpreter | [runtime options][pyopt] | — |
| WasmEdge | No Python binding: the repository's bindings are Java and Rust | [runtime options][pyopt] | — |
| Extism | A plugin framework with its own calling convention over Wasmtime: `aprv.wasm` would need rebuilding, and it cannot start faster than Wasmtime | [runtime options][pyopt] | — |
| A precompiled `.cwasm` in the Python wheel | 62 to 72 ms to the first result, but a per-platform native-code artifact pinned to one Wasmtime major (48.0.0 refuses a 49 module) and +2.7 MB per wheel | [runtime options][pyopt]; [execution modes][modes] | — |
| mimalloc in `aprv-server` | No throughput gain; 11 MiB more peak RSS in the CLI and 17 MiB in the server; the first verification 18 ms instead of 6 ms; C built by a second compiler | [static musl §4][musl] | — |
| Cosmopolitan (one binary for every OS) | Not measured; rejected by the owner | The owner's brief of 2026-09-28; no evidence note | — |
| napi-rs (native Node addon) | Native core in the Node process (class E), per-platform npm packages; the Wasm module reaches every JS runtime at 1,343 µs per g5 and 4,819 µs per JWS | [ABI v1][abi]; [rust-core spikes][spikes] | — |
| ABI v1: `aprv_call(version, op, ptr, len)` with result handles and our own alloc/dealloc | Worked on every host and cost nothing; rejected by the owner on 2026-09-29 for a specified calling convention with generated bindings where a runtime has them (R23). Operation numbers, a handle table and a byte prefix are three conventions per wrapper that the canonical ABI's typed exports remove | [ABI v1][abi]; [canonical ABI][cabi]; [canonical ABI final][cabifinal] | — |
| `now_ms` as an 8-byte little-endian prefix on the input | A private framing rule inside a byte string; the canonical ABI passes `now-ms` as a typed `u64` argument at no cost | [canonical ABI][cabi] | — |
| One generic `call(op, args...)` export | Loses the per-function signature; a hand-rolled host would have to encode an argument list, which is what the canonical ABI's flattening already specifies | the owner's discussion of 2026-09-29; no evidence note | — |
| WIT `string` for the inputs | A WIT `string` must be UTF-8 and the release-mode lift is unchecked, so 243 non-UTF-8 JWS rows could not cross; `list<u8>` carries any bytes and the core answers as ABI v1 did | [canonical ABI][cabi]; [canonical ABI final][cabifinal] | — |
| A WIT `enum` for the environment | Lifted with an unchecked `transmute` in release builds; a `u32` the guest matches traps on every out-of-range value on every host | [canonical ABI][cabi]; [canonical ABI final][cabifinal] | — |
| WASI 0.2 (`wasm32-wasip2`) as the build target | The canonical ABI is independent of the WASI version; the p1 module with the link-time C file has no WASI imports left to adapt, and the component wrapper needs no adapter. p2 would add the adapter and the `wasi:*` imports the C file exists to remove | [canonical ABI][cabi] | a host needs WASI 0.2 interfaces from the guest |
| memory64 | A 3 MiB input and a 256 MiB limit fit 32-bit addressing with room; memory64 costs bounds checks and is unsupported on Endive | the owner's discussion of 2026-09-29; no evidence note | inputs approach 4 GiB |
| JCS, RFC 8785 canonical JSON | No signature is computed over our JSON and the fixtures compare by value; canonical form has no consumer here (R34) | [0.7 API][api07] | our JSON is ever signed or hashed |
| jco's WASI 0.2 glue as the JS package | 202,031 to 236,337 B of generated glue for the WASI shims; with no WASI imports left, jco's glue for the component is 63,523 B minified and costs 8 to 11 ms at start | [wasm bake-off §8, §9][wasmbake]; [canonical ABI final][cabifinal] | — |
| Protobuf, CBOR or FlatBuffers as the ABI encoding | Not measured. The 0.7 contract is already JSON (canonical JSON, compared by value in `cases.json`); ABI v1's JSON out cost nothing measurable against the earlier bridge, and a binary codec would add a decoder to every host | [ABI v1][abi]; [0.7 API][api07] | — |
| Executing the server from memory (`memfd_create` + `fexecve`) | Pure Java cannot do it, and security tools treat fileless execution as malware behaviour | R17 of 2026-09-25 (git history of this file); no evidence note | — |
| `HttpURLConnection` as the server engine's client | Tried on 2026-10-02 and reversed on 2026-10-03 (R17). On Java 8 a 401 `Basic` challenge gets the default `Authenticator`'s credentials, 20 connections an attempt, with no per-connection switch; the JDK resends a POST inside each attempt (6 requests where the engine means 3); SOCKS from a `ProxySelector` still applies on Java 8 and for `https`; 8 lines more than the hand-written client | [HttpURLConnection][huc]; [HTTP client options §1, §4][httpopt] | — |
| Apache HttpClient 5 (5.6.4) as the server engine's client | The strictest parser compared, but Spring Boot pins httpclient5 for every app that uses it: 5.1.4 in Boot 2.7, the Java 8 line, lacks `ConnectionConfig` and `DetachedSocketFactory`, and Boot 3.5's versions are inside two advisories' ranges. Only a shaded copy avoids that, and then each HttpClient 5 advisory is a release of this artifact against Central's five a month. Unsafe defaults to turn off: a 307 carried the token to another host, content decoding loads JNI codecs found on the classpath, a body read to the close is accepted; SLF4J debug logging prints the token and the receipt; `NO_PROXY` only through `@Internal` API; 2.3 MB of classes | [HTTP client options §1, §4][httpopt] | the hand-written client's parsing outgrows one server's wire contract |
| A stdio transport for the managed child | Saves the transport's share only: a pipe round trip costs 25 to 32 µs against 52 to 63 µs for a loopback HTTP exchange, about 30 µs of a 2.2 ms g5 call. Costs a framed protocol with request ids and its own status codes in Rust and Java, and `ServerSource.url` still needs HTTP, so two transports would do one job | [HTTP client options §3][httpopt] | — |
| A public per-call `now` | Dropped in 0.7: the `Config` clock covers the chain fallback and `request_date`. The ABI carries `now-ms` per call, so adding it later is additive | [0.7 API][api07], Dropped | a user needs it |
| A handle-based ABI (verifier handles across the boundary) | Handles are state a caller can double-free or share across threads; the measured ABI passed with no verifier state at all, and the instance is the verifier (R23) | [ABI v1][abi]; root THREAT-MODEL.md §5 (C ABI handles) | — |
| DER input | Apple's endpoint and clients carry base64; ABI v1 took base64 only, and 0.7 dropped the DER overload. The cap then admits at most 2,359,296 bytes of DER | [ABI v1][abi]; [0.7 API][api07], Dropped | an overload is wanted; it is additive |
| Fastly Compute JS and Akamai EdgeWorkers as targets | Neither can run WebAssembly | [rust-core spikes][spikes], "Findings from outside the container" | they gain WebAssembly |
| Pruning the pinned roots back to two | Apple commits to no single root for either path; the third root is insurance against re-anchoring | PLAN.md D15 | — |
| A WIT `limits()` function for the input length | Moves the WIT to 0.2.0 and all eight hosts with it, for a number `init`'s answer carries (R42) | the owner's decision 2a, 2026-10-02; no evidence note | — |
| A CI check that the hosts' copies of the input length equal the core's | Keeps seven copies and adds one more place to keep in step (R42) | the owner's decision 2a, 2026-10-02; no evidence note | — |
| Reading a JWS's environment from the top-level claim only | Every App Store Server Notification would answer null: Apple puts its environment in `data` or `summary` (R42) | the owner's decision Q19, 2026-10-02; no evidence note | — |
| Keeping the per-language environment helpers | Nine copies of one rule, seven in packages that may hold none (R42) | the owner's decision Q19, 2026-10-02; no evidence note | — |
| RustCrypto `der` for the tests' ASN.1 reading | Reads DER only, so it cannot open Apple's or Xcode's receipts, which are BER (indefinite lengths, constructed `OCTET STRING`s) (R43, option A) | the owner's decision Q18, 2026-10-02; [asn1-rs in the tests][asn1rs] | — |
| OpenSSL's ASN.1 API from the tests | Raw FFI with no safe Rust API over it: `unsafe` code in the tests, heavier than a parser crate for a job a safe crate does (R43, option B) | the owner's decision Q18, 2026-10-02; no evidence note | — |
| Keeping the tests' hand-written BER reader | 391 lines of the core's pre-OpenSSL reader kept for the tests alone, an ASN.1 parser the project would maintain (R43, option C) | the owner's decision Q18, 2026-10-02; [asn1-rs in the tests][asn1rs] | — |
| A frozen 0.7.x jar as the only oracle | Diverges from the core wherever the core changes on purpose; superseded by the maintained implementation (R33) | R8 history | — |
| wasm-bindgen | Needs `wasm32-unknown-unknown`, where `openssl-sys` 0.9.117 fails with 20 × E0432 | [CMS everywhere §3][cms] | the core stops linking C |
| Emscripten | Works on 7 hosts, with legacy exceptions, about 18 MB of initial memory and 12.8 to 78.9 KB of glue | [wasm bake-off §7][wasmbake] | — |
| `wasm-opt` in the release | 25% smaller raw, no speed change beyond noise, a second optimiser to re-prove every release | [wasm speed §4][speed] | module size matters |
| OpenSSL `enable-ec_nistp_64_gcc_128` | JWS 35% faster on Node, 2.4 to 3.4 times slower on Endive; one module serves every host | [wasm speed §2][speed] | — |
| AWS-LC, LibreSSL, pure Rust as the substrate | See R21's options table | [substrate bake-off][substrate]; [follow-up][followup] | — |
| Keeping the hand-written US Pacific rules and calendar | Correct (0 disagreements with five IANA-derived sources, 1900-2100), but it is calendar code the project maintains, and a change in US daylight-saving law would be a code change (R38) | [Pacific time-zone crates][pactz] | — |
| chrono-tz for `_pst` | Its zone filter reaches the build script only from the shell environment, never from `.cargo/config.toml` under `--manifest-path`, nor for a crates.io consumer: 935 KB unfiltered with an opaque `Tz` | [Pacific time-zone crates][pactz] | — |
| A POSIX TZ rule (`PST8PDT,M3.2.0,M11.1.0`) | Wrong for every daylight-saving season 1900-2006 (19.8 million minutes) | [Pacific time-zone crates][pactz] | — |
| A TZif file through `include_bytes!` (jiff or tz-rs) | A 2.8 KB binary in git, refreshed by hand from each tzdata release, and a TZif parser in the module: +31 KB with tz-rs, +303 KB with jiff's `TimeZone::tzif` | [Pacific time-zone crates][pactz] | — |
| Keeping the hand-written JSON reader | 370 lines of grammar and three bounds the project maintains, for documents `serde_json`, already in the build, reads; the bounds prevented no blow-up, since both readers take a long name, number or string in linear time (R40) | [serde_json][jsonserde] | — |
| Keeping .NET's hand-written JSON reader and writer | 610 lines of grammar and escaping the package maintains, for answers `System.Text.Json` reads; it existed only to keep netstandard2.0 free of a package dependency (R41) | [.NET JSON][stjout] | — |
| Keeping `aprv-wire`'s hand-written JSON writer | An escaper and object builder the project maintains, for output `serde_json`, already in the build, writes byte for byte the same; a test pins a fully populated answer to the old writer's text (R40, amended 2026-10-02) | `rust/bindings/wire/src/lib.rs`, its tests | — |
| `serde_json` variant A, `Map<String, Value>` | Builds a tree of unsigned input at up to 126 times its size: 396 MB for one 3 MiB request and 25 MB for one JWS segment, against 521 bytes for the map of raw values (R40) | [serde_json][jsonserde] | — |

[abi]: ../evidence/2026-09-26-wasm-abi-v1.md
[cabi]: ../evidence/2026-09-29-canonical-abi-spike.md
[cabifinal]: ../evidence/2026-09-29-canonical-abi-final.md
[api07]: ../design/0.7-api.md
[cms]: ../evidence/2026-09-26-openssl-cms-everywhere.md
[dotnet]: ../evidence/2026-09-26-dotnet-wasmtime.md
[endive]: ../evidence/2026-09-26-endive-build-time-jvm.md
[followup]: ../evidence/2026-09-26-substrate-followup.md
[modes]: ../evidence/2026-09-27-wasm-execution-modes.md
[musl]: ../evidence/2026-09-27-static-musl-server.md
[payload]: ../evidence/2026-09-26-openssl-asn1-payload.md
[pyfinal]: ../evidence/2026-09-27-python-runtime-final.md
[pyopt]: ../evidence/2026-09-27-python-runtime-options.md
[pydirs]: ../evidence/2026-10-04-python-platformdirs-floor.md
[pywt]: ../evidence/2026-09-26-python-wasmtime.md
[ruby]: ../evidence/2026-09-26-ruby-wasmtime.md
[server]: ../evidence/2026-09-26-aprv-server.md
[speed]: ../evidence/2026-09-26-wasm-speed.md
[spikes]: ../evidence/2026-09-25-rust-core-spikes.md
[substrate]: ../evidence/2026-09-26-security-substrate-bakeoff.md
[swift]: ../evidence/2026-09-26-swift-wasmkit.md
[wasmbake]: ../evidence/2026-09-26-wasm-architecture-bakeoff.md
[wasmi]: ../evidence/2026-09-27-wasmi-security-review.md
[corefix]: ../evidence/2026-09-29-core-review-fixes.md
[javar3]: ../evidence/2026-09-29-java-align-round3.md
[javabc3]: ../evidence/2026-10-05-java-bc-round3.md
[vendored4]: ../evidence/2026-09-30-rust-openssl-vendored-4-upstream.md
[pactz]: ../evidence/2026-10-01-pacific-tz-crates.md
[jsonserde]: ../evidence/2026-10-01-json-serde.md
[stjout]: ../evidence/2026-10-02-dotnet-stj-output.md
[huc]: ../evidence/2026-10-02-java-httpurlconnection.md
[httpopt]: ../evidence/2026-10-02-java-http-options.md
[asn1rs]: ../evidence/2026-10-03-rust-tests-asn1-rs.md
[dupchecks]: ../evidence/2026-10-05-core-drop-duplicate-checks.md
[redundant]: ../evidence/2026-10-05-core-drop-redundant-bounds.md
[reader]: ../evidence/2026-10-05-x509-reader-kept.md
[walk]: ../evidence/2026-10-06-core-walk-counter.md
[javaparse]: ../evidence/2026-10-05-java-presignature-parse-cost.md
