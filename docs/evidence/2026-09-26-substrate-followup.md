# Substrate follow-up: OpenSSL packages, newest toolchains, the CMS API, fuzzing

Date: 2026-09-26. Code, scripts and raw results:
`2026-09-26-substrate-followup/` (its `README.md` has the file table and
the commands).

This round follows two notes of the same day:
- `2026-09-26-security-substrate-bakeoff.md` ("the substrate bake-off");
- `2026-09-26-wasm-architecture-bakeoff.md` ("the wasm bake-off").

It reuses their adapter, policy, corpora, Java oracle rows, runners and
artifacts unchanged, and edits neither folder.

Every claim carries one label: TESTED (ran here), DOCUMENTED (read in a
source file, manifest or vendor document), EXPECTED (inferred, not run) or
UNKNOWN. Nothing in `rust/`, `docs/rust-core/` or any other production
path changed. `DECISIONS.md` is untouched.

## The question

The owner asked five follow-up questions after the wasm bake-off. Their
answers feed the substrate choice (R20/R21):

1. Do the untested gaps hold up? Namely the OpenSSL npm packages under
   `wrangler dev`, and the WASIp1 modules in browsers.
2. Does anything change on today's newest toolchain and libraries?
3. Can OpenSSL's CMS API close the Java gaps the legacy PKCS7 API left
   open?
4. Has any input ever crashed the native process, and does a real
   coverage-guided fuzz campaign find anything?
5. What are the answers, one line each?

## Answers

| Question | Answer | Label | Source |
|---|---|---|---|
| OpenSSL npm packages, including `wrangler dev` | Yes. 4 new tarballs (core, Emscripten and component for OpenSSL; Emscripten for LibreSSL), installed from the tarball, 32 of 32 smoke runs pass. That covers Node, Bun, Deno, Chromium, Firefox, WebKitGTK, the Lambda-like run and `wrangler dev --local` | TESTED | `results/npm-smoke.jsonl` |
| WASIp1 modules in the three browsers | Yes. `awslc-w1` and `ossl-w1` with the minimal JS host (no `node:wasi`) give 1,179 of 1,179 rows the same as native, in Chromium, Firefox and WebKitGTK | TESTED | `results/parity.txt` |
| Does Rust 1.98.1 change any verdict | No. Native and Route C, OpenSSL and AWS-LC: 1,179 of 1,179 rows each, identical to the rustc 1.94.1 builds | TESTED | `results/parity.txt` |
| Does OpenSSL 4.1.0-beta1 change any verdict | No. 1,179 of 1,179 rows identical to OpenSSL 4.0.2 (native; the beta is informational only) | TESTED | `results/parity.txt` |
| Newest AWS-LC | aws-lc-sys 0.45.0 (AWS-LC 5.7.0) builds and gives 1,179 of 1,179 rows identical to AWS-LC 1.73.0. It needs one manifest line in a local copy of openssl-sys 0.9.117 (`aws-lc-sys` requirement `^0.41` changed to `^0.45`) and no code change. The only blocker is that published requirement | TESTED | `results/parity.txt`, `scripts/newest.sh` |
| Which Java gaps the CMS API closes | All three that the PKCS7 API caused: the Ed25519 SignerInfo, the RSA-PSS SignerInfo, and the SignerInfo identified by subjectKeyIdentifier. OpenSSL goes from 1,025 to 1,028 Java-equal rows of 1,048, or 1,030 with the prescan. The 18 that remain are policy, parser-strictness or encoding choices (section 3.4), not missing library support | TESTED | `results/java-tallies.txt` |
| Any crash ever found | None, in any run on record. This includes the four new 45-minute ASan and libFuzzer campaigns (section 4) | TESTED | `results/fuzz-campaign.txt` |

**A correction to the wasm bake-off** (found here, TESTED): its
`$SCRATCH/em/ossl-em/aprv-em.mjs` had been overwritten by the web-only link
of the same `.wasm`. As a result:

- The wasm bake-off's note and `results/loc.txt` list OpenSSL's node+web
  glue as 12,857 bytes. That is actually the web-only glue's size.
- Relinked from the same static library, the node+web glue is **13,882
  bytes**, with a byte-identical `.wasm` (sha256 `5abf1625df711348...`).
- With that glue, OpenSSL Emscripten again gives 1,179 of 1,179 rows the
  same as native on Node (`results/parity.txt`, `ossl-em-nodeglue`).
- The wasm bake-off's `ossl-em` Node/Bun/Deno parity runs are unaffected.
  Its harness hands the glue a compiled module, so either glue works there.
- The npm package is affected. It lets the glue load its own `.wasm`, which
  the web-only glue cannot do in Node. The first smoke run here failed for
  exactly that reason, before the relink.

## 1. The untested gaps

### 1a. OpenSSL and LibreSSL npm packages (TESTED)

`scripts/npm-pack.sh` builds four packages the way the wasm bake-off built
the AWS-LC ones. They use the same facade files and the artifacts that
bake-off built, and all are `"private": true`:

| Package | Tarball | Inside |
|---|---|---|
| `aprv-spike-core-openssl` | 987,857 B, 9 files | `ossl-c.wasm` (Route C: imports `aprv.clock_now_ms`, `aprv.random_get`) |
| `aprv-spike-emscripten-openssl` | 902,280 B, 10 files | `ossl-em` wasm, node+web glue (13,882 B) and web-only glue (12,857 B) |
| `aprv-spike-emscripten-libressl` | 480,507 B, 10 files | `libressl-em` wasm, both glues (78,886 and 76,340 B) |
| `aprv-spike-component-openssl` | 1,034,252 B, 22 files | jco 1.35.0 output of `ossl-comp` (4 core modules) and the 41-line `wasi-p2-min.mjs` |

The OpenSSL component needs two changes to the AWS-LC component package:

- **Its facade** passes the WASI 0.2 import object. That is
  `npm/component-wasi/facade.js`; the calls are otherwise identical.
- **Its workerd entry** imports four core modules instead of three
  (`npm/component-wasi/workerd.js`).

The core and Emscripten packages needed no change beyond the `.wasm` they
carry: the core facade already forwards `random_get` to
`crypto.getRandomValues`.

**Smoke matrix** (`scripts/npm-smoke.sh`). The wasm bake-off's vectors are
a genuine sandbox g5 receipt against the pinned Apple roots, a generated
JWS, and three rejections. All four packages passed on all eight hosts, 32
of 32 runs:

- Node 22.22.2, Bun 1.3.11 and Deno 2.9.7;
- Chromium 141, Firefox 156 and WebKitGTK 2.52.6, loading straight from
  `node_modules`;
- the Lambda-like run under `node --permission`: 200 repeated and 64
  concurrent calls with 0 mismatches, with file writes and `child_process`
  denied;
- `wrangler dev --local` 4.141.0, the Worker importing the installed
  package. Nothing was deployed.

`results/npm-smoke.jsonl` has every row.

### 1b. WASIp1 modules in browsers (TESTED)

The wasm bake-off ran the Route A modules (`wasm32-wasip1`, WASI answered
by the ~40-line import object in its `js/hosts.mjs`) on Node, workerd,
wazero and Wasmtime, but not in browsers. Here, through the same browser
page and runner, with the `trap` policy (any WASI call outside the answered
set traps):

| Module | Chromium 141 | Firefox 156 | WebKitGTK 2.52.6 | WASI calls made |
|---|---|---|---|---|
| `awslc-w1` | 1,179 same | 1,179 same | 1,179 same | `clock_time_get` 58 |
| `ossl-w1` | 1,179 same | 1,179 same | 1,179 same | `random_get` 1, `clock_time_get` 1,257 |

No `node:wasi`, no WASI runtime, no polyfill.

## 2. Newest toolchain and libraries

### 2a. rustc 1.98.1 (TESTED)

Stable was 1.98.1 on 2026-09-26 (`channel-rust-stable.toml`, dated
2026-09-03). It was installed under `$SCRATCH/rustup` with its own
`CARGO_HOME`, and the system toolchain was not touched. `scripts/rust198.sh`
rebuilt four artifacts through the bake-offs' own build scripts, with the
same `Cargo.lock` (checked byte-equal) and the same C libraries:

- native `ossl402`;
- native `awslc`;
- Route C `ossl-c`;
- Route C `awslc-c`.

| Artifact (rustc 1.98.1) | Compared with | Rows the same |
|---|---|---|
| native OpenSSL 4.0.2 | native, rustc 1.94.1 | 1,179 / 1,179 |
| native AWS-LC 1.73.0 | native, rustc 1.94.1 | 1,179 / 1,179 |
| Route C OpenSSL, Node | native, rustc 1.94.1 and 1.98.1 | 1,179 / 1,179 each |
| Route C AWS-LC, Node (`strict` host) | native, rustc 1.94.1 and 1.98.1 | 1,179 / 1,179 each |

The binaries differ, as expected with a new compiler: `ossl402.so` is
8,428,112 B on 1.94.1 and 8,453,576 B on 1.98.1, and `awslc-c.wasm` is
1,406,386 B and 1,428,341 B (`results/sizes.txt`). The Route C import sets
and call counts are unchanged.

### 2b. OpenSSL 4.1.0-beta1 (TESTED, a beta, informational)

4.0.2 is the newest stable release. The 4.1.0-beta1 tarball (GitHub
release, sha256 matching its published `.sha256`) builds with the same
Configure line (`scripts/build-libs.sh`). openssl-sys 0.9.117 accepts it:
it refuses only versions of 5.0 and later (DOCUMENTED, `build/main.rs`).

Under the unchanged adapter and policy, built with rustc 1.98.1, all 1,179
rows are identical to OpenSSL 4.0.2. The binary reports "OpenSSL
4.1.0-beta1 23 Sep 2026". Its Java tallies are identical too
(`results/java-tallies.txt`).

### 2c. Newest AWS-LC (TESTED)

- **aws-lc-sys 0.45.0** (2026-09-01) is the newest on crates.io. It
  carries AWS-LC 5.7.0 (`AWSLC_VERSION_NUMBER_STRING`, DOCUMENTED). The
  0.41.0 used so far carries 1.73.0.
- **The blocker** is openssl-sys 0.9.117, still the newest (2026-06-12).
  It declares `aws-lc-sys = "^0.41"`, so no `[patch]` of aws-lc-sys alone
  can reach 0.45: `^0.41` does not match 0.45 under Cargo's 0.x rules.
- **The workaround.** `scripts/newest.sh awslc045` copies openssl-sys
  0.9.117, changes that one manifest line to `^0.45`, and wires the copy in
  with `[patch.crates-io]`. It builds with no source change: openssl-sys
  finds the prefixed AWS-LC through the version-agnostic `DEP_AWS_LC_*`
  variables. The binary holds 1,643 `aws_lc_0_45_0` symbols and no
  `aws_lc_0_41` ones.
- **Result:** all 1,179 rows are identical to AWS-LC 1.73.0, and so are
  the Java tallies.

The blocker is therefore a version requirement in a published manifest,
not an API change. A production build would wait for an openssl-sys
release that widens it (EXPECTED), or carry a one-line `[patch]`.

## 3. Java gaps and the CMS API

### 3.1 Why the PKCS7 API left gaps (DOCUMENTED and TESTED)

The substrate bake-off's adapter verifies through the legacy PKCS7 API. On
OpenSSL that is `PKCS7_signatureVerify` on the first SignerInfo; on AWS-LC,
`PKCS7_verify`. Three signer shapes Java accepts are out of that API's
reach:

| Row | Java | Rust | OpenSSL, PKCS7 | Why |
|---|---|---|---|---|
| `algorithms/receipt/ed25519` | 0 | 9 | 5 | PKCS7's digest-then-sign flow has no pure EdDSA; the signature fails |
| `algorithms/receipt/rsa-pss-sha256` | 0 | 5 | 5 | the SignerInfo's signatureAlgorithm (id-RSASSA-PSS with parameters) is not applied; the check uses PKCS#1 v1.5 padding |
| `substrate/cms/signer-identified-by-ski` | 0 | 9 | 9 | PKCS#7's SignerInfo ASN.1 has only issuerAndSerialNumber, so `d2i_PKCS7` refuses a CMS version 3 SignerInfo (subjectKeyIdentifier) |

### 3.2 The CMS path (TESTED)

The adapter gains a `cms` feature (`adapter-cms/`). With it on,
`SignedData` is backed by `CMS_ContentInfo` with the same API, so the
policy (`substrate.rs`) is unchanged:

- **Signer lookup:** `CMS_SignerInfo_cert_cmp` matches the embedded
  certificate by issuer and serial or by SKI.
- **Signature over the signed attributes:** `CMS_SignerInfo_verify`.
- **Content check:** `CMS_SignerInfo_verify_content`, over a digest BIO
  built for the SignerInfo's own digestAlgorithm, as the PKCS7 path does.
- **Trust.** It never builds a store and never calls `CMS_verify`. The
  pinned-roots-only path validation, the top-down pre-check and the
  historical-time callback all stay in the policy and `verify_path`, as
  before.

Size: `cms_path.rs` is 266 code lines, 106 of them inside `unsafe` across 19
sites. It replaces the PKCS7 `SignedData` section of `lib.rs`, which is 341
code lines with 165 inside `unsafe` across all its per-library `cfg`
variants. OpenSSL compiles only part of those. The switch in `lib.rs` is 8 lines: four `cfg` attributes, plus the
module and its re-export (`adapter-cms/adapter-cms.patch`).

| Build | cases | substrate | hostile | algorithms | Java-equal / 1,048 |
|---|---|---|---|---|---|
| OpenSSL 4.0.2, PKCS7 (bake-off) | 153 | 187 | 665 | 20 | 1,025 |
| OpenSSL 4.0.2, **CMS** | 153 | 188 | 665 | **22** | **1,028** |
| OpenSSL 4.0.2, **CMS + prescan** | 153 | **190** | 665 | 22 | **1,030** |
| LibreSSL 4.3.2, PKCS7 (bake-off) | 153 | 186 | 671 | 20 | 1,030 |
| LibreSSL 4.3.2, CMS | 153 | 187 | 671 | 19 | 1,030 |
| AWS-LC 1.73.0 and 5.7.0, PKCS7 | 152 | 185 | 671 | 19 | 1,027 |

Source: `results/java-tallies.txt` (agree + cand=java per corpus). "1,048"
is 1,179 rows minus the 131 hostile rows the C ABI cannot express.

**What changed, row by row** (`results/cms-vs-pkcs7-ossl402cms.txt`):
exactly three rows, all to Java's answer:

- `signer-identified-by-ski`: 9 → 0;
- `rsa-pss-sha256`: 5 → 0;
- `ed25519`: 5 → 0.

All other 1,176 rows are identical to the PKCS7 path. The prescan adds two
more (`unsigned-attribute-nesting-2000` and `-100000`: 0 → 9, Java's
answer; `results/cms-vs-pkcs7-ossl402cmspre.txt`).

**The 5,000-mutant smoke corpus** (`results/fuzz-cms.txt`):

- The PKCS7 row reproduces the substrate bake-off's `fuzz.txt` exactly
  (4,565 / 85 / 129 / 46 / 175).
- The CMS path changes 4 rows, all mutants of the SKI receipt, and all 4
  move to Java's answer (cand=java 85 → 89).
- It still accepts the 3 mutated-unsigned-attribute rows that Java and Rust
  reject. With the prescan it accepts none. No new acceptance anywhere.

### 3.3 LibreSSL and AWS-LC

- **LibreSSL 4.3.2's CMS API** (TESTED) closes the same three rows, but
  breaks three that pass today: the ECDSA-signed receipts
  `ec-p256-sha256`, `ec-p384-sha384` and `ec-p521-sha512` go from 0 to 5.
  - `c/cms-probe.c` isolates it: LibreSSL's `CMS_SignerInfo_verify`
    returns 0 (`CMS_R_VERIFICATION_FAILURE`, `cms_sd.c:850`) on exactly
    those three. OpenSSL 4.0.2 returns 1 on all 16 `algorithms` receipts,
    and LibreSSL's own PKCS7 path verifies the three
    (`results/cms-probe.txt`).
  - The root cause inside LibreSSL is UNKNOWN; it was not pursued. Net for
    LibreSSL: 1,030 either way. It is not a candidate for the CMS switch.
- **AWS-LC** (DOCUMENTED) has no CMS API in either version:
  - There is no `cms.h` in the headers of aws-lc-sys 0.41.0 (AWS-LC 1.73.0)
    or 0.45.0 (AWS-LC 5.7.0).
  - Its PKCS7 SignerInfo models issuerAndSerialNumber only (`pkcs7.c`
    around line 1526, signer lookup).
  - Its `pkcs7_signature_verify` calls `EVP_VerifyFinal` with the key's
    default padding and does not read the SignerInfo's signatureAlgorithm
    (`pkcs7.c` lines 1575 to 1660, 5.7.0).
  - So the three rows stay as they are on AWS-LC (TESTED on both
    versions: `ed25519` 5, `rsa-pss-sha256` 5, `signer-identified-by-ski`
    9).

### 3.4 Every remaining non-Java row for OpenSSL (CMS + prescan)

There are 18 rows. `results/tri-ossl402cmspre-<corpus>.txt` has them all.
None is an acceptance of a forged or untrusted receipt. One is an
acceptance Java refuses, and it is a matter of encoding (row 1).

| # | Row | Java | Rust | OpenSSL | Class and reason |
|---|---|---|---|---|---|
| 1 | `substrate/cms/attributes-unsorted-signed-as-sent` | 5 | 0 | 0 | **Encoding.** The signed attributes are sent in non-DER order and the signature covers those bytes. OpenSSL (both APIs) and the Rust core verify the bytes as received: `CMS_Attributes_Verify` and `PKCS7_ATTR_VERIFY` re-encode as SEQUENCE OF, which keeps the order (DOCUMENTED, `cms_asn1.c:403`, `pk7_asn1.c:249`). Java re-encodes as a DER SET, which sorts, and fails. A genuine signer made this signature; no key is bypassed. A policy that wants Java's answer can refuse SignedAttrs that are not in DER order, a check the prescan could make (EXPECTED, not built) |
| 2 | `substrate/cms/attributes-unsorted-signed-sorted` | 0 | 5 | 5 | **Encoding, mirror of 1.** Sent unsorted, signed over the sorted DER. Java accepts, OpenSSL and Rust reject. Conservative; keep |
| 3 | `substrate/cms/crls-garbage` | 0 | 0 | 9 | **Library stricter.** `d2i_CMS_ContentInfo` parses the unsigned `crls` field and refuses garbage there. Java and Rust ignore it. Rejects, no risk |
| 4, 5 | `hostile/endpoint/m3-184626924`, `hostile/endpoint/trailing-garbage` | status 0 | 21002 | 21002 | **Policy code, not the substrate.** The endpoint's JSON layer (Rust, shared by every build) refuses trailing bytes that Java's JSON reader tolerates |
| 6-9 | `hostile/jws/m0-534728031`, `m0-672945841`, `m0-718123265`, `m1-160010987` | 1 | 2 | 2 | **Order of checks.** Java fails at header JSON parsing (1); the Rust JWS front end, shared with the substrate build, first decodes `x5c` and fails there (2). Both reject |
| 10-14 | `hostile/receipt-der/g5-m0-701123523`, `g5-m1-236749769`, `g5-m1-324520034`, `g5-m1-853597831`, `gen-m1-933684943` | 9 | 4 | 4 | **Parser strictness.** Bouncy Castle refuses the mutated encoding; OpenSSL and Rust parse it and then fail the chain (4). Both reject |
| 15 | `hostile/receipt-der/gen-m1-619385370` | 4 | 9 | 9 | **Outer contentType.** The mutation changes the ContentInfo type OID. OpenSSL and Rust refuse it as not signedData; Java does not check that OID and fails later at the chain. Both reject |
| 16, 17 | `hostile/receipt-der/g5-m1-127707244`, `g5-m1-233102848` | 4, 2 | 4, 2 | 9 | **Library stricter.** An embedded certificate with a broken name or a non-OCTET STRING extension value fails the whole `d2i_CMS_ContentInfo`. Java and Rust reject later. Both reject |
| 18 | `hostile/receipt-der/gen-m1-280546414` | 9 | 2 | 4 | **Library more lenient on one mutation.** OpenSSL parses a structure BC and Rust refuse, then fails the chain. Rejects |

On the PKCS7 path, the three rows of section 3.1 add to these. Without the
prescan, `unsigned-attribute-nesting-2000` and `-100000` add two
acceptances Java refuses: nesting inside unsigned attributes, which no
signature covers (the substrate bake-off, section 6).

## 4. Crash hunting

### 4.1 The evidence before this round (TESTED, substrate bake-off)

Every earlier run had 0 crashes. Precisely:

- **valgrind memcheck** 3.22.0, one process per row, `--leak-check=full`,
  definite leaks counted as errors (`$SPIKE/results/memcheck.txt`).
  - Rows: all of `cases` (93 runs), `algorithms` (22), `substrate` (193),
    and every 4th `hostile` row (151). That is 459 runs per variant.
  - Variants: rust, OpenSSL 4.0.2, LibreSSL 4.3.2 and AWS-LC 1.73.0.
  - Result: 0 flagged, 0 crashed.
- **ASan + UBSan** (`$SPIKE/results/asan-ubsan.txt`) covered only the C
  side.
  - Build: OpenSSL 4.0.2 compiled by clang 18 with
    `-fsanitize=address,undefined` (minus UBSan's `function` check, which
    fires on OpenSSL's own `sparse_array.c:93` cast before any input is
    read). It was linked into a C harness built by gcc 13 with both
    sanitizers. The Rust code was not instrumented.
  - Runs: 5,902. That is 93 + 22 + 193 + 594 corpus rows, plus 5,000
    mutants.
  - Result: 0 crashes. One report was the harness's own leak on an early
    exit, with no library frame in it.
  - AWS-LC and LibreSSL were not built with sanitizers.
- **Deep nesting** (TESTED on all three libraries): the `substrate/parse`
  rows (100,000 levels of indefinite length, unterminated, 2,000 definite,
  9-octet lengths, high tag numbers) are all refused with 9. No crash and no
  stack overflow.
- **The 5,000-mutant smoke fuzz** (`py/mutate.py`, seed 20260926) ran
  through the differential for every library and through the ASan build.
  No crash and no hang. It is seeded mutation, not coverage guidance.
- **Leak loop:** 100,000 calls in one process grew VmRSS by 16 to 104 KB
  (`$SPIKE/results/leak-loop.txt`).

### 4.2 Coverage-guided campaigns (TESTED, this round)

**Setup** (`scripts/fuzz.sh`):
- **Tooling:** cargo-fuzz 0.13.2, libFuzzer through libfuzzer-sys 0.4.13,
  and AddressSanitizer with leak detection, on rustc 1.100.0-nightly
  (2026-09-25).
- **Targets:** the repository's own `rust/fuzz` targets `verify-receipt`
  and `verify-transaction`, unchanged, over the substrate bake-off's
  patched core. Receipts and JWS therefore go through `substrate.rs` and
  the adapter. Their invariants hold too: no panic, no configuration error,
  and an accepted input must fail under an unrelated anchor set.
- **Instrumentation:** the C library is instrumented as well, compiled by
  clang 18 with `-fsanitize=address,fuzzer-no-link`. Coverage therefore
  guides the fuzzer into the library, not only into Rust.
  - OpenSSL 4.0.2 `no-asm`.
  - AWS-LC 1.73.0 through aws-lc-sys (its assembly stays uninstrumented).
- **Seeds:** every receipt and JWS input of the five corpora. That is
  3,835 unique receipts and 2,062 unique JWS, all from `fixtures/` or test
  keys.
- **Limits:** `-max_len=65536`, `-timeout=10` s, `-rss_limit_mb=2048`,
  45 minutes per target, four targets, one core each, in parallel.

The campaigns ran from 11:11:18Z to 11:56:19Z (`results/fuzz-campaign.txt`):

| Library, target | Seconds | Executions | exec/s | Coverage at start → end | Corpus units added | Peak RSS | Crashes / leaks / timeouts / OOM |
|---|---|---|---|---|---|---|---|
| OpenSSL 4.0.2, `verify-receipt` | 2,701 | 2,650,534 | 981 | 6,527 → 7,090 | 3,241 | 614 MB | 0 / 0 / 0 / 0 |
| OpenSSL 4.0.2, `verify-transaction` | 2,701 | 4,142,588 | 1,533 | 7,536 → 8,079 | 5,560 | 550 MB | 0 / 0 / 0 / 0 |
| AWS-LC 1.73.0, `verify-receipt` | 2,701 | 3,734,008 | 1,382 | 3,213 → 3,577 | 3,510 | 573 MB | 0 / 0 / 0 / 0 |
| AWS-LC 1.73.0, `verify-transaction` | 2,701 | 18,456,111 | 6,833 | 3,222 → 3,828 | 11,769 | 553 MB | 0 / 0 / 0 / 0 |

In total that is 28,983,241 executions. There were:
- no AddressSanitizer report, no leak report and no deadly signal;
- no timeout (the slowest unit took under a second in every campaign);
- no out-of-memory, and no violation of the targets' invariants (panic,
  configuration error, acceptance under unrelated anchors);
- nothing in any of the four artifact directories.

So there is no reproducer to report, and nothing to attribute to OpenSSL,
AWS-LC, the adapter or the policy.

"Coverage" is libFuzzer's count of covered counters over every instrumented
module, Rust and C together. Coverage was still rising slowly when each
campaign stopped, so these runs are not saturated. The AWS-LC numbers are
lower partly because its assembly carries no counters. Coverage is not
comparable across libraries. Neither campaign is proof of absence. They
extend the "no crash ever" record from 5,902 sanitizer runs to about 29
million guided executions.

**The answer to the owner's question.** No input in any run on record has
crashed the native process. That covers:
- valgrind (1,836 runs);
- ASan + UBSan (5,902 runs, OpenSSL);
- the deep-nesting rows;
- the 5,000 mutants on every library;
- these four ASan + libFuzzer campaigns.

## 5. Where these results stop holding

- **Builds:** Linux x86_64 only. R12's other targets were out of scope for
  this round, as asked.
- **Parity scope:** "identical" means the same code and payload on the
  1,179 corpus rows (and 5,000 mutants where stated). Other inputs are
  covered only as far as the fuzzing reaches.
- **The OpenSSL 4.1.0 row is a beta.** A final 4.1.0 needs its own run.
- **The AWS-LC 5.7.0 build needs an openssl-sys that is not published.**
  Only its manifest differs (`$SCRATCH/fu/openssl-sys-awslc045`, one
  line). The Route C (wasm) AWS-LC artifact was not rebuilt on 5.7.0.
- **The CMS path** was built and measured natively only; Route C with
  `cms` was not built (EXPECTED to work: the same OpenSSL builds for wasip1).
  It was not built for AWS-LC, which has no CMS API.
- **LibreSSL's CMS ECDSA refusal:** the cause is UNKNOWN.
- **The fuzzing** is 4 × 45 minutes on one core each, a campaign rather
  than a continuous one. Of the libraries only OpenSSL's C is instrumented
  without assembly. AWS-LC's assembly and LibreSSL were not fuzzed.
- **Side effects outside `$SCRATCH` this round:** the Ubuntu package
  `libclang-rt-18-dev`. Installing it upgraded `libc6`, `libc6-dev` and
  `libc-bin` from 2.39-0ubuntu8.7 to 2.39-0ubuntu8.9, which apt pulled in
  as a dependency.
- **Data:** every corpus and seed is from `fixtures/` or generated from test
  keys. No production receipt was used.
