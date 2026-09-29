# Security substrate bake-off: OpenSSL, LibreSSL, AWS-LC under the Rust policy

Date: 2026-09-26. Code, scripts and raw results:
`2026-09-26-security-substrate-bakeoff/` (its `README.md` has the file
table and the commands). Every claim carries a label: TESTED (ran here),
DOCUMENTED (read in a source file, manifest or vendor document), EXPECTED
(inferred, not run), UNKNOWN.

## The question

Can the Rust core keep its policy (reason codes, Java's order of checks,
R20) while a mature native library replaces its own ASN.1, CMS, X.509, path
validation and crypto code (`rust/src/asn1.rs`, `cms.rs`, `x509.rs`,
`chain.rs`, `crypto.rs`)? The preferred shape was one rust-openssl adapter
over OpenSSL, LibreSSL and AWS-LC. The answer feeds the substrate choice in
`docs/rust-core/` (R20, R12 and the npm/Go wasm path).

Short answer. Yes for native targets: one adapter builds against all three
libraries with 23 library `cfg` lines, parses every genuine receipt, keeps
the pinned-root isolation, and agrees with Java more often than the current
Rust core does. The price is 287 lines inside `unsafe`, a C library in the
trusted base, 2.4 to 6.7 times the artifact size, and a build per target.
For wasm the adapter reaches `wasm32-wasip1` with OpenSSL and AWS-LC, but no
rust-openssl substrate can build for `wasm32-unknown-unknown`, the target
the npm package uses today. So a native substrate cannot be the one core
for every package; pure Rust stays on the wasm path at least.

## 1. Executive table

Counts are rows of the request corpora (section 4). "Java-equal" means the
same reason code as the Java oracle (and the same payload on success).

| | OpenSSL 4.0.2 | LibreSSL 4.3.2 | AWS-LC 1.73.0 | Pure Rust (today) | Java/BC |
|---|---|---|---|---|---|
| Parses the genuine g5, legacy and Xcode receipts | yes (TESTED) | yes (TESTED) | yes (TESTED) | yes (TESTED) | yes |
| Exposes what the policy needs | yes, one raw FFI call (`PKCS7_signatureVerify`) | yes, same | partly: no public `PKCS7_signatureVerify`, no rust-openssl `pkcs7` module; worked around (TESTED) | n/a | n/a |
| `cases`, 153 rows, Java-equal | 153 | 153 | 152 | 153 | 153 |
| `substrate`, 193 rows, Java-equal | 187 | 186 | 185 | 170 | 193 |
| `hostile`, 680 non-ABI rows, Java-equal | 665 | 671 | 671 | 657 | 680 |
| `algorithms`, 22 rows, Java-equal | 20 | 20 | 19 | 8 | 22 |
| fuzz, 4,825 non-ABI mutants, Java-equal | 4,650 | 4,683 | 4,681 | 4,607 | 4,825 |
| Accepts what Java and Rust reject (fuzz) | 3 rows, unsigned attributes only; 0 with the prescan | 2, same class | 2, same class | 0 | 0 |
| Historical-time fixtures, 39 rows | 39 | 39 | 39 | 39 | 39 |
| Isolation: ambient root ignored, no config or cert path opened | yes | yes | yes | yes | n/a |
| Lines inside `unsafe` | 287 (shared adapter) | 287 | 287 | 0 | 0 |
| C ABI `.so`, stripped + gzip -9 | 2,733,498 B | 969,580 B | 1,301,167 B | 408,286 B | n/a |
| Receipt p50, 1 thread | 399 µs | 471 µs | 430 µs | 546 µs | n/a |
| JWS p50, 1 thread | 479 µs | 1,135 µs | 355 µs | 841 µs | n/a |
| Throughput, 16 threads, receipt | 9,458/s | 5,248/s | 11,728/s | 7,192/s | n/a |
| `wasm32-wasip1` (Go path) | yes, own wasi-sdk build + 2 link fixes (TESTED) | no, does not compile (TESTED) | yes, 5 build flags (TESTED) | yes (TESTED) | n/a |
| `wasm32-unknown-unknown` (npm path) | no (TESTED) | no (EXPECTED, same cause) | no (TESTED) | yes, but 58 of 1,179 rows trap on the clock (TESTED) | n/a |
| R12's 26 C ABI targets | 26 mapped by openssl-src (DOCUMENTED) | no s390x port (DOCUMENTED); rest EXPECTED | 11 with pregenerated bindings (DOCUMENTED); rest need bindgen, illumos and Solaris UNKNOWN | 26 (R12) | n/a |
| License of the linked C code | Apache-2.0 | OpenSSL + SSLeay + ISC | ISC, Apache-2.0, MIT, BSD-3-Clause mix | MIT/Apache crates | n/a |

Sources: `results/tri-<variant>-<corpus>.txt`, `results/fuzz.txt`,
`results/isolation.txt`, `results/loc.txt`, `results/sizes.txt`,
`results/bench.jsonl`, `results/wasm-*.txt`.

## 2. Versions

| Component | Version | Source |
|---|---|---|
| OpenSSL | 4.0.2, static, assembly on (the sanitizer build alone uses `no-asm`), sha256 `736b4675…543a8` | GitHub release tarball |
| OpenSSL (vendored leg) | 3.6.3 in openssl-src 300.6.1+3.6.3 | crates.io |
| LibreSSL | 4.3.2, static, sha256 `edf01aee…0847b5`, signed SHA256 file | cdn.openbsd.org |
| AWS-LC | 1.73.0 in aws-lc-sys 0.41.0, symbols prefixed `aws_lc_0_41_0_` | crates.io |
| rust-openssl | openssl 0.10.81, openssl-sys 0.9.117 | crates.io |
| Rust | rustc 1.94.1 stable | rustup |
| C toolchains | clang 18.1.3, gcc 13.3.0, cmake 3.28, wasi-sdk 34.0 (clang 23.1.0), sha256 `b761e3a0…984b2c4` | Ubuntu 24.04, GitHub release |
| Java oracle | JDK 25.0.4.1, Bouncy Castle 1.86, the previous spike's `OracleCli` | |
| Wasm runtimes | Node 22.22.2 (`node:wasi`), Bun 1.3.11, Deno 2.9.7, wazero 1.12.0 on Go 1.25.0 | |
| Checkers | valgrind 3.22.0, ASan and UBSan (clang 18 objects, gcc 13 runtime) | |

Newer releases exist and were not usable (DOCUMENTED): aws-lc-sys 0.45.0
(openssl-sys 0.9.117 requires `^0.41`), openssl-src 400.0.1+4.0.2
(openssl-sys requires openssl-src 300.x).

Machine: Linux x86_64, 4 vCPUs, 15 GB RAM, shared cloud VM. Timings are
from that machine only.

## 3. Build commands

Full list in the folder README. The variants differ only in features and
environment:

```sh
scripts/build-libs.sh openssl            # OpenSSL 4.0.2 static: 3.5 min
scripts/build-libs.sh libressl           # LibreSSL 4.3.2 static: 15.6 s
OPENSSL_DIR=$SCRATCH/inst/openssl-4.0.2 OPENSSL_STATIC=1 scripts/build-variant.sh ossl402 substrate
OPENSSL_DIR=$SCRATCH/inst/libressl-4.3.2 OPENSSL_STATIC=1 scripts/build-variant.sh libressl432 substrate
scripts/build-variant.sh awslc substrate-aws-lc          # AWS-LC from source: 51 s
scripts/build-variant.sh ossl36v substrate-vendored      # OpenSSL 3.6 from source: 63 s
scripts/build-wasm.sh ossl402-w wasm32-wasip1 substrate  # 15 s after a 45 s OpenSSL wasm build
```

The adapter (`security-openssl/`) is one source for all three libraries.
`build.rs` turns openssl-sys's metadata into `aprv_openssl`,
`aprv_libressl` or `aprv_awslc`. Of the adapter's 29 `cfg` lines, 23 name a
library (`results/loc.txt`).

## 4. Method

- Four request corpora, 1,179 rows, all from `fixtures/` or generated:
  `cases` (153, `fixtures/cases.json`), `hostile` (811 seeded mutations,
  131 of them not expressible through the C ABI), `algorithms` (22 signature
  algorithms the fixtures do not use), `substrate` (193, new here:
  `py/gen_corpus.py`; time, CMS shapes, path rules, floods, parser stress).
  Plus a 5,000-row mutation corpus for the fuzz (`py/mutate.py`).
- Every candidate is the unchanged `rust/ffi` C ABI over a scratch copy of
  the core, patched (`core-patch/`) so receipts and JWS go through
  `substrate.rs` and the adapter. Same runner (`run_rust.py`) for all.
- `py/tri.py` compares each row three ways: Java oracle, current Rust,
  candidate.

### Experiment A: OpenSSL

A1 (`PKCS7_verify` with `NOVERIFY|NOINTERN|NOCHAIN`, feature `a1`) works
but differs from Java in 5 more `substrate` rows than A2 (162 vs 167
agree, `results/tri-ossl402a1-substrate.txt`). TESTED causes:
`PKCS7_verify` checks every SignerInfo where Java checks the first, and
`PKCS7_dataInit` builds its digests from the SignedData `digestAlgorithms`
set, so an empty or different set fails.

A2 (decomposed) parses with `d2i_PKCS7`, picks the first signer, digests
the content through its own `BIO_f_md` chain with the signer's digest, and
calls `PKCS7_signatureVerify`. The path is `X509_verify_cert` over a store
holding only the pinned anchors, `X509_V_FLAG_PARTIAL_CHAIN`, the check
time set to the signing instant, and a verify callback. A2 is the design
that matches Java best; every later number is A2 unless named.

### Experiment B: LibreSSL

Same source, same results as OpenSSL except (TESTED):
- `X509_VERIFY_PARAM` depth counts one more than OpenSSL's: leaf, CA, root
  at depth 1 gave `CHAIN_TOO_LONG`. One `cfg`; the length rule moved to the
  policy.
- No chain in the store context during the verify callback, so the anchor
  test uses a thread-local list of anchors and `X509_cmp`.
- Rejects a definite-length constructed OCTET STRING as content (9, Java 0).
- JWS is 2.4 times slower than OpenSSL (1,135 vs 479 µs p50).

### Experiment C: AWS-LC capability list

| Capability | Answer |
|---|---|
| `d2i_PKCS7` on BER, indefinite-length receipts | yes (TESTED) |
| `PKCS7_verify` | yes (TESTED, variant `awslca1`) |
| `PKCS7_dataInit` | yes, but fails when eContentType is not `data` (5, Java 0) (TESTED) |
| `PKCS7_signatureVerify` | no public symbol (DOCUMENTED, headers); A2 instead drops extra SignerInfos, replaces `digestAlgorithms` with the signer's, then calls `PKCS7_verify` with `NOVERIFY` (TESTED) |
| rust-openssl `pkcs7` module | no, gated out for `awslc` and `boringssl` (DOCUMENTED); raw FFI with its own `PKCS7_free` owner |
| `X509_verify_cert`, `PARTIAL_CHAIN`, verify callback, `set_time` | yes (TESTED) |
| X.509 version field above v3 | rejected at parse: v11 signer gives 9, Java 2 (TESTED) |
| RIPEMD-160 signer digest | no (5, Java 0) (TESTED) |
| MD5 in the chain | rejected, like the Rust core (Java accepts) (TESTED) |
| Ed25519 or RSA-PSS SignerInfo | no (5), same as OpenSSL and LibreSSL (TESTED) |
| P-521 in JWS chains | yes (TESTED) |
| Symbol prefix, coexists with a system OpenSSL | yes, `aws_lc_0_41_0_*` (TESTED, `nm`) |
| libssl built even though unused | yes, openssl-sys turns on aws-lc-sys `ssl`, which also forces bindgen (DOCUMENTED) |
| `X509_V_ERR_INVALID_CA` | 24, as LibreSSL; OpenSSL 3+ uses 79 (DOCUMENTED, openssl-sys handles it) |

Stopping rule: every candidate parsed the genuine BER receipts and exposed
enough for the policy, so no candidate was stopped.

### Behaviors the policy had to absorb (all TESTED)

- notAfter: OpenSSL 1.1.1 to 3.6 and AWS-LC treat notAfter as exclusive;
  OpenSSL 4.0 and LibreSSL as inclusive, like Java. The verify callback
  waives `HAS_EXPIRED` when notAfter equals the check time, on every
  library.
- OpenSSL does not backtrack among untrusted issuers with the same name;
  LibreSSL does. The policy authenticates embedded certificates top-down
  from the anchors first (Java's order), so the impostor row now matches
  Java everywhere.
- JWS reason order: bottom-up library errors gave 6 where Java gives 4. The
  policy runs Java's top-down steps before calling the library path.
- An anchor's own validity is not checked (Java does not); the callback
  exempts `NOT_YET_VALID`, `HAS_EXPIRED`, `INVALID_CA` and
  `PATH_LENGTH_EXCEEDED` on a certificate equal to a pinned anchor.

## 5. Mismatches

Classes from `tri.py`. Rows listed once for OpenSSL A2; the library
columns say where the others differ.

**cand=java (the library agrees with Java, current Rust does not): 20 in
`substrate`, 12 in `algorithms`, 10 to 16 in `hostile`.** These are the
Rust core's known R20 divergences and a few new ones: unknown critical
extensions accepted, duplicate `contentType`/`messageDigest`,
`contentType` = signedData, missing `contentType`, indefinite-length signed
attributes, name comparison (case, whitespace, PrintableString vs
UTF8String: Rust compares bytes), SHA-224/384/512, SHA3-256, ECDSA signers,
P-521, RSA-PSS chains, MD5 chains (not AWS-LC), and hostile mutations that
Java and the libraries both refuse at parse.

**cand=rust (the library agrees with current Rust against Java): 3 in
`substrate`, 1 in `algorithms`.**
- `attributes-unsorted-signed-as-sent`: signed attributes sent unsorted.
  Rust and the library verify the bytes as sent (0); Java re-encodes the
  SET sorted and fails (5).
- `attributes-unsorted-signed-sorted`: the reverse (library and Rust 5,
  Java 0).
- `signer-identified-by-ski`: a SignerInfo that names its signer by
  subjectKeyIdentifier. The PKCS7 API (OpenSSL, LibreSSL, AWS-LC) cannot
  parse it (9); Java accepts (0). The CMS API (`CMS_verify`) would; not
  tried (section 10).
- `rsa-pss-sha256` signer: 5 on all libraries and Rust, 0 in Java.

**cand-own (differs from both).**

| Row | Java | Rust | OpenSSL | LibreSSL | AWS-LC | Why |
|---|---|---|---|---|---|---|
| `cms/crls-garbage` | 0 | 0 | 9 | 9 | 9 | `d2i_PKCS7` parses the CRL field, Java ignores it |
| `cms/unsigned-attribute-nesting-2000`, `-100000` | 9 | 9 | 0 | 0 | 0 | the libraries skip unsigned attributes; the Rust prescan (`ossl402pre`) restores 9 |
| `cms/content-constructed-octets-definite` | 0 | 0 | 0 | 9 | 0 | LibreSSL refuses a definite constructed OCTET STRING |
| `cms/econtenttype-other` | 0 | 0 | 0 | 0 | 5 | AWS-LC `PKCS7_dataInit` accepts only `data` |
| `receipt/reject-signer-certificate-version-11` | 2 | 2 | 2 | 2 | 9 | AWS-LC rejects the version at parse |
| `algorithms/receipt/ed25519` | 0 | 9 | 5 | 5 | 5 | PKCS7 has no Ed25519 |
| `algorithms/receipt/rsa-ripemd160` | 0 | 9 | 0 | 0 | 5 | AWS-LC has no RIPEMD-160 |
| `hostile/receipt-der/g5-m1-127707244` | 4 | 4 | 9 | 9 | 9 | an embedded certificate with a broken name fails the whole PKCS7 parse |
| `hostile/receipt-der/g5-m1-233102848` | 2 | 2 | 9 | 9 | 9 | same, an extension value that is not an OCTET STRING |
| `hostile/receipt-der/gen-m1-280546414` | 9 | 2 | 4 | 9 | 9 | OpenSSL 4 parses a mutation the others refuse |

Summary: no row where a library accepts a receipt whose signature or chain
Java rejects. The only acceptances Java refuses are in unsigned attributes,
which no signature covers. The rest is "rejects for a different reason", or
an algorithm the PKCS7 API does not carry.

**Fuzz (`results/fuzz.txt`).** 5,000 mutants, 175 not expressible through
the ABI. cand-own: OpenSSL 46, LibreSSL 45, AWS-LC 47; of these, library
accepts while Java and Rust reject: 3, 2, 2, all mutated unsigned
attributes, 0 with the prescan. One row the libraries reject and both
references accept (`flood/digestalgorithms-1000` mutated). The largest
group (24 to 25 rows) is 4 in Java and Rust, 9 in the library: a mutated
embedded certificate fails the whole PKCS7 parse. In JWS, 6 rows are 4 in
Java and 2 in the library: the libraries' X.509 parser refuses mutated
certificates that Java's accepts.

## 6. BER, parse safety and the prescan

- BER: all three libraries parse the indefinite-length Xcode receipt and
  the generated BER receipts (TESTED, `cases` 153/153). RustCrypto's `cms`
  0.2.3 with `der` 0.7.10 parses the g5 and legacy sandbox receipts (they
  are DER) and refuses the Xcode receipt and `generated/receipt.der`:
  "indefinite length disallowed" (TESTED, `results/probe-rustcrypto.txt`).
- Deep nesting: `parse/nesting-100000-indefinite`, `-unterminated`,
  `nesting-2000-definite`, 9-octet lengths, high tag numbers: 9 on every
  library, no crash, no stack overflow at 100,000 levels (TESTED). OpenSSL's
  decoder has its own depth limit (`ASN1_MAX_CONSTRUCTED_NEST` 30, DOCUMENTED
  in `crypto/asn1/tasn_dec.c`).
- Unsigned attributes are not parsed as ASN.1 by any of the libraries, so
  2,000 or 100,000 levels of nesting there verify (0) where Java and Rust
  refuse (9).
- Prescan (`substrate-prescan`): the Rust `asn1.rs` reader walks the whole
  input first and refuses what it refuses today. It fixes both nesting rows
  and all 3 fuzz acceptances (`ossl402pre`: `substrate` 169/20/3/1, fuzz
  cand-own 42). Cost: `asn1.rs` (265 code lines) stays, and one more pass.

## 7. Trust-store isolation (TESTED)

`scripts/isolation.sh`: the chain's real root planted in `SSL_CERT_FILE`
and `SSL_CERT_DIR`, a hostile `OPENSSL_CONF`, `OPENSSL_MODULES`,
`OPENSSL_ENGINES`; an unrelated root pinned; strace on files and sockets.

- rust, ossl402, libressl432, awslc, ossl36v: 4 for both inputs under the
  unrelated root, 0 for the controls, no planted path opened, 0 network
  syscalls (`results/isolation.txt`). ossl36v opened `/etc/localtime` once
  per run (openssl-src's build, time zone lookup), nothing else.
- Negative control (`ossl402neg`: loads the default config and trust
  paths): opened `$ISO/openssl.cnf` and `$ISO/ambient.pem`
  (`results/isolation-negative-control.txt`), so the check can see a leak.
  It still answered 4 because the policy authenticates top-down from the
  pinned anchors before the library path runs.
- Wasm (`results/wasm-isolation.txt`): no preopened directories and an
  empty guest environment; host variables set to the planted files. 4 4 0 0
  for rust, ossl402 and awslc modules. WASI calls made: none (rust, AWS-LC);
  1 `random_get` and 20 `clock_time_get` (OpenSSL). The OpenSSL module
  imports `path_open` and `fd_readdir` but never called them.

## 8. Historical time and algorithms

- Time: all 39 `substrate/time` rows agree with Java on every library
  after the notAfter waiver: validity judged at the signing instant, at
  whole seconds and ±1 ms around notBefore and notAfter, before 1970, and
  across the UTCTime/GeneralizedTime switch in 2050 (TESTED).
- Algorithms against R20 (`algorithms`, 22 rows): the libraries accept 12
  that Java accepts and the Rust core rejects (SHA-224/384/512, SHA3-256,
  ECDSA P-256/384/521 signers, P-521 and RSA-PSS chains, MD5 and RIPEMD-160
  signer digests; AWS-LC not RIPEMD-160). If R20 keeps today's narrow Rust
  list, the policy must refuse these itself before the library sees them;
  the adapter already reports the signer's digest and key algorithm, so this
  is a table lookup (EXPECTED, not built).

## 9. Performance and size

Native C ABI, same harness as the Native Image spike, 8 s per point
(`results/bench.jsonl`). µs; "tput" in calls per second.

| Variant | receipt p50 / p99 / mean | JWS p50 / p99 / mean | receipt tput 1 / 4 / 16 threads | RSS after load |
|---|---|---|---|---|
| rust | 546 / 730 / 555 | 841 / 1,301 / 858 | 1,720 / 6,885 / 7,192 | 5.9 MB |
| ossl402 | 399 / 779 / 439 | 479 / 805 / 497 | 2,448 / 9,560 / 9,458 | 10.2 MB |
| libressl432 | 471 / 745 / 490 | 1,135 / 1,574 / 1,117 | 2,168 / 6,280 / 5,248 | 8.9 MB |
| awslc | 430 / 766 / 442 | 355 / 551 / 370 | 3,045 / 12,275 / 11,728 | 7.1 MB |
| ossl36v | 403 / 706 / 415 | 511 / 796 / 536 | 2,580 / 9,278 / 9,285 | 9.6 MB |

Every threaded point compared every output with the first: 0 mismatches
in 45 runs (TESTED concurrency). First call: 0.4 to 2.4 ms.

Size of the C ABI `.so` (`results/sizes.txt`), bytes:

| Variant | raw | stripped | stripped + gzip -9 |
|---|---|---|---|
| rust | 1,068,760 | 877,568 | 408,286 |
| ossl402 | 8,428,112 | 7,328,168 | 2,733,498 |
| ossl36v | 6,423,864 | 5,611,904 | 2,006,604 |
| libressl432 | 2,645,256 | 2,250,320 | 969,580 |
| awslc | 3,049,096 | 2,707,984 | 1,301,167 |

All link statically: `NEEDED` is libgcc_s, libc and ld-linux only; 20
exported symbols, all `aprv_*` (TESTED).

## 10. Line counts (`results/loc.txt`)

| | code lines | lines inside `unsafe` | `unsafe` sites |
|---|---|---|---|
| Today: `asn1` 265, `cms` 148, `x509` 374, `chain` 82, `crypto` 200 | 1,069 | 0 | 0 |
| Adapter `security-openssl/src/lib.rs` | 823 | 287 | 62 |
| Policy `substrate.rs` + `build.rs` | 198 | 0 | 0 |
| Wasm shim (host allocation only) | 16 | 6 | 2 |

After a switch (EXPECTED): `cms.rs`, `chain.rs`, `crypto.rs` go (430);
`x509.rs` goes once `roots.rs` parses anchors through the adapter (374);
`asn1.rs` stays for the receipt payload and the prescan (265). New code:
823 + 198. Net: about +220 code lines, and 0 to 287 lines inside `unsafe`,
plus the C library in the trusted base.

## 11. Security ownership

| Concern | Today (pure Rust) | With a native substrate |
|---|---|---|
| ASN.1/BER parsing of attacker bytes | this repository (`asn1.rs`, `cms.rs`) | the C library; `asn1.rs` still owns the payload and the prescan |
| X.509 parsing and extensions | this repository | the C library; policy owns the marker OIDs and critical-extension rule |
| Path building and validity | this repository (`chain.rs`) | C library, constrained: only anchors in the store, top-down pre-check, a verify callback owned here |
| Signature arithmetic | RustCrypto `rsa`, `p256`, `p384` | the C library |
| Memory safety of the glue | none needed (0 `unsafe`) | 287 lines inside `unsafe`, one crate |
| Trust store and config isolation | no ambient store exists | owned here: `NO_LOAD_CONFIG`, no default paths; proven by the negative control |
| Algorithm policy (R20) | enforced by what is implemented | must be enforced by an explicit allow-list, since the libraries accept more |
| Advisories to follow | RustSec for 9 crates | the library's security advisories plus RustSec for rust-openssl |
| Patch cadence | a crate bump | a library rebuild on every target and a release (R12 budget) |

## 12. FFI security checks

- `unsafe` isolated in one crate (`security-openssl`); the policy
  (`substrate.rs`) has none (TESTED, `loc.txt`).
- valgrind memcheck, one process per row, `--leak-check=full`, definite
  leaks as errors: 459 runs per variant (all of `cases`, `algorithms`,
  `substrate`, every 4th `hostile` row) for rust, ossl402, libressl432 and
  awslc: 0 flagged, 0 crashed (`results/memcheck.txt`).
- ASan + UBSan: OpenSSL 4.0.2 compiled with both (clang 18), linked into the
  ffi staticlib, harness built with gcc 13's sanitizers. All 1,179 corpus
  rows the harness can drive plus the 5,000 fuzz mutants: 5,902 runs, 0
  sanitizer reports from the library or adapter. One flag was the harness's
  own buffers on its "constructor refused" exit (`results/asan-ubsan.txt`).
  The Rust code was not instrumented: no nightly toolchain here. UBSan's
  `function` check was turned off: it fires on every run inside OpenSSL's
  `sparse_array.c:93` callback cast, before any input is read (TESTED).
- Leak loop: 100,000 calls in one process; VmRSS grew 16 to 104 KB for every
  variant and both operations, under 1.1 bytes per call
  (`results/leak-loop.txt`).
- Brief fuzz: 5,000 seeded mutants through the differential and the
  sanitizer build (sections 5 and above). No crash, no hang.

## 13. Wasm

Built with `scripts/build-wasm.sh`: `wasm/shim` links the unchanged
`rust/ffi` C ABI and adds `aprv_alloc`/`aprv_dealloc`. Run with
`wasm/run.mjs` (Node, Bun, Deno) and `wasm/wazero` (Go). Corpus: the same
1,179 rows, compared row by row with the native run of the same variant
(`py/same.py`, `results/wasm-corpora.txt`).

| Substrate | `wasm32-wasip1` builds? | Toolchain | Size raw / stripped / gzip, bytes | Node | wazero | Bun | Deno |
|---|---|---|---|---|---|---|---|
| Pure Rust | yes | rustc only | 614,635 / 576,156 / 189,000 | 1,179 same | 1,179 | 1,179 | 1,179 |
| OpenSSL 4.0.2 | yes, via `OPENSSL_DIR` | wasi-sdk 34 (clang + wasi-libc sysroot) | 2,941,749 / 2,697,807 / 901,514 | 1,179 | 1,179 | 1,084, 95 trap (Bun bug); 1,179 with a harness `random_get` | 1,179 |
| AWS-LC 1.73.0 | yes, 5 flags | wasi-sdk 34, CMake toolchain file, host libclang for bindgen | 1,414,202 / 1,323,932 / 528,746 | 1,179 | 1,179 | 1,179 | 1,179 |
| LibreSSL 4.3.2 | no | wasi-sdk 34 | n/a | n/a | n/a | n/a | n/a |
| openssl-src 300.6.1 (OpenSSL 3.6) | no | n/a | n/a | n/a | n/a | n/a | n/a |

| Substrate | `wasm32-unknown-unknown` (npm path)? |
|---|---|
| Pure Rust | yes, 620,669 / 586,787 / 186,728 bytes; 1,121 rows same, 58 trap: every call site that falls back to `SystemTime::now()` (endpoint without a pinned clock, receipts and JWS without a date) panics on that target (TESTED, Node and wazero) |
| OpenSSL, LibreSSL, AWS-LC through rust-openssl | no: openssl-sys (20 errors) and openssl (95 errors) do not compile, because the `libc` crate defines no C types (`size_t`, `c_int`, `time_t`, `FILE`) on that target. This holds for any C library behind rust-openssl, whatever the C toolchain (TESTED for OpenSSL and AWS-LC; EXPECTED for LibreSSL) |

Exact errors: `results/wasm-build.txt`. What had to change (all TESTED):

- openssl-src 300.6.1 maps only the old name `wasm32-wasi`, so
  `substrate-vendored` fails: "don't know how to configure OpenSSL for
  wasm32-wasip1". OpenSSL 4.0.2 built directly with wasi-sdk
  (`build-wasm-libs.sh openssl`, openssl-src's own WASI options) works.
- Link fix 1: wasi-libc's emulation libraries (`signal`, `process-clocks`,
  `mman`, `getpid`). Without them the link succeeds and the module imports
  `env.getpid` and `env.munmap`.
- Link fix 2: stable rustc links a wasip1 cdylib as a command, wrapping each
  export with constructor and destructor calls. With OpenSSL inside, the
  first call traps (`unreachable` in `.Lregister_call_dtors`). Linking
  wasi-sdk's `crt1-reactor.o` and exporting `_initialize` fixes it.
- AWS-LC: `BINDGEN_EXTRA_CLANG_ARGS` and the wasi-sdk CMake toolchain file,
  `-DOPENSSL_NO_SOCK`, `-DOPENSSL_NO_TTY`, and hiding wasi-libc's
  `struct iovec` from the C++ files because libssl's `bio_ssl.cc` defines
  its own. libssl is built only because openssl-sys asks for it.
- LibreSSL: 39 of 482 objects fail: no `crypto/arch` headers for wasm32
  (21), no `netdb.h`/`syslog.h` in wasi-libc (6), `getuid`. A port is
  EXPECTED to be feasible; it would be a patch set on LibreSSL, not tried.
- Bun 1.3.11 defect: `random_get(buf, len)` returns `len` instead of errno
  0 and writes random bytes over the whole linear memory
  (`wasm/bun-random-get.mjs`, TESTED). OpenSSL draws 48 random bytes on its
  first JWS call and then traps. With the harness's own `random_get`
  (`APRV_FIX_RANDOM_GET=1`) all 1,179 rows match. AWS-LC and pure Rust
  never call it on these inputs.

Wasm latency, one thread, 1,000 calls after 200 warm-up (`results/wasm-bench.jsonl`), µs:

| Module | receipt, Node | receipt, wazero | JWS, Node | JWS, wazero | memory |
|---|---|---|---|---|---|
| pure Rust wasip1 | 2,954 | 4,974 | 2,977 | 4,479 | 1.2 MB |
| pure Rust unknown-unknown | 3,171 | 5,218 | 3,004 | 4,420 | 1.2 MB |
| OpenSSL wasip1 | 1,046 | 2,495 | 4,076 | 8,110 | 2.1 MB |
| AWS-LC wasip1 | 1,155 | 2,132 | 2,632 | 3,224 | 1.4 MB |

The native build is 5 to 9 times faster than any wasm build. On wasm, the
C substrates are 2 to 3 times faster than pure Rust for receipts (RSA);
for JWS (P-256) OpenSSL is slower and AWS-LC close.

Not run on wasm: headless Chromium, workerd and Emscripten. The first two
are npm-path hosts, and no C substrate builds for that target; Emscripten
needs emsdk, which was not installed.

## 14. Static linking and the 26 R12 targets

- Linux x86_64 glibc: static, TESTED for all four. Other targets were not
  built.
- OpenSSL via openssl-src: all 26 R12 triples appear in its target table
  (DOCUMENTED, `openssl-src` 300.6.1 `src/lib.rs`). Needs perl and a C
  compiler per target; Windows builds use `VC-WIN*` configs (EXPECTED to
  need nasm or `no-asm`). With openssl-src the version is 3.6, not 4.0,
  until openssl-sys accepts openssl-src 400.x.
- LibreSSL: CMake per target, no openssl-src equivalent. Its architecture
  table has no s390x (DOCUMENTED, `CMakeLists.txt`), so Linux s390x is
  EXPECTED to fail like wasm32 did. FreeBSD, Solaris and illumos have CMake
  branches (DOCUMENTED); not built.
- AWS-LC via aws-lc-sys: pregenerated bindings for 11 of the targets
  (DOCUMENTED, `src/*_crypto.rs`); openssl-sys's `ssl` feature forces
  bindgen anyway, so every build host needs libclang. Needs CMake, and
  NASM (or its prebuilt copy) on Windows x86_64 (DOCUMENTED). illumos and
  Solaris: UNKNOWN.
- Licenses: OpenSSL 3+ is Apache-2.0 (NOTICE to carry). LibreSSL carries the
  original OpenSSL and SSLeay licenses (advertising clause) plus ISC.
  aws-lc-sys declares "ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT
  AND BSD-3-Clause AND ..." (DOCUMENTED, `Cargo.toml`). All are compatible
  with MIT distribution with attribution; none is copyleft.

## 15. Secondary candidates (not built unless stated)

| Candidate | Version | Verdict | Label |
|---|---|---|---|
| BoringSSL (`boring`) | 5.2.0 | No PKCS7 signature verification in BoringSSL; rust-openssl gates `pkcs7` out for it | EXPECTED |
| wolfSSL (`wolfssl`) | 7.4.0 | Has PKCS7 verify; GPL-3.0 or commercial license | DOCUMENTED license; API EXPECTED |
| Botan (`botan`) | 0.14.0 | X.509 path validation, no CMS SignedData verification | EXPECTED |
| mbedTLS (`mbedtls`) | 0.13.6 | `pkcs7` module is DER-only and limited; would fail the Xcode receipt | EXPECTED |
| GnuTLS (`gnutls`) | 0.1.3 | `gnutls_pkcs7_verify` exists; LGPL-2.1+ for a static link | EXPECTED |
| NSS | n/a | Full CMS; no maintained Rust binding; heavy build | EXPECTED |
| Platform APIs | n/a | Security.framework (Apple), CryptMsg (Windows); nothing on Linux or wasm | DOCUMENTED |
| RustCrypto `cms` / `x509-cert` / `der` | 0.2.3 / 0.2.5 / 0.7.10 (latest 0.3.0 / 0.8.2) | Parses the DER g5 and legacy receipts, refuses the BER Xcode receipt; no path validation | TESTED (`probe-rustcrypto/`) |
| `rustls-webpki` | 0.103.15 | Path validation for TLS usages; no CMS, no SHA-1 chains (legacy receipts) | EXPECTED |
| `x509-parser` + `der-parser` | 0.18.1 + 10.0.0 | BER-capable parser, no CMS verify, no path validation | EXPECTED |

Hybrids (line counts EXPECTED):

1. Rust parses, the library verifies: keep `asn1.rs` and `cms.rs` (413),
   hand certificates, path and signatures to the adapter. Removes
   `x509.rs`, `chain.rs`, `crypto.rs` (656); adapter shrinks to about 500
   lines with about 200 inside `unsafe`. Keeps today's BER behavior and
   the unsigned-attribute checks; still no wasm32-unknown-unknown.
2. Library for crypto only: replace `crypto.rs` (200) with EVP
   verification; keep parsing and path in Rust. Adapter about 150 lines,
   about 40 inside `unsafe`. Fixes the algorithm gap (section 8) without
   moving parsing into C; the R20 divergences in names, critical extensions
   and attributes stay in Rust.

## 16. Recommendations

- **Best native: AWS-LC through the shared rust-openssl adapter.** Fastest
  (JWS 355 µs p50, 11,728 receipts/s at 16 threads), smallest of the
  OpenSSL family after LibreSSL (1.30 MB gzip), prefixed symbols, and the
  same Java agreement as LibreSSL. Its gaps (RIPEMD-160, non-`data`
  eContentType, version above v3) are all rejections, not acceptances.
  OpenSSL 4.0.2 is the close second and the one with every target mapped.
- **Best native plus wasm: AWS-LC for native and wasip1, pure Rust for
  `wasm32-unknown-unknown`.** No rust-openssl substrate reaches the npm
  target, so two cores would ship. If one core must serve everything, it
  is pure Rust.
- **Best pure Rust: the current core, fixed toward Java.** It agrees with
  Java on 4,607 of 4,825 fuzz rows versus 4,650 to 4,683 for the
  libraries; the gap is the R20 table (names, critical extensions,
  duplicate attributes, algorithms), which is policy code, not substrate.
  RustCrypto `der` cannot replace `asn1.rs` because of BER.
- **Lowest review burden: pure Rust** (0 `unsafe`, 1,069 security lines,
  no C). Among the natives, hybrid 2 (about 40 lines inside `unsafe`).
- **Lowest packaging burden: pure Rust** (one toolchain, 26 targets, one
  wasm file). Among the natives, OpenSSL via openssl-src (one crate
  feature, 26 targets mapped), but that pins OpenSSL 3.6.
- **Best long-term: pure Rust core plus hybrid 2 held in reserve.** Keep
  parsing and path policy where the repository can test and fuzz them in
  every package, including wasm. Revisit a native substrate if the R20
  algorithm list must grow beyond what RustCrypto covers, or if a Rust
  crate cannot be kept current.

## 17. Not done and limits

- Only Linux x86_64 native builds. The other 25 R12 targets are DOCUMENTED
  or EXPECTED above, not built.
- Rust code was not sanitizer-instrumented (no nightly toolchain); valgrind
  covered it instead. No cargo-fuzz run; the fuzz here is 5,000 seeded
  mutants, a smoke test, not a campaign.
- The CMS API (`CMS_verify`, SKI signer identifiers, RSA-PSS and Ed25519
  SignerInfos) was not tried; only the PKCS7 API.
- No Windows, macOS, musl or 32-bit performance numbers. Timings come from
  a shared 4-vCPU VM; treat differences under 10 % as noise.
- LibreSSL on wasm not ported. Chromium, workerd and Emscripten not run.
- wasi-sdk 34 has no published checksum; its hash is first-use.
- The Java oracle is JDK 25 with BC 1.86 only.
- Every corpus is from `fixtures/` or generated from test keys. No
  production receipt was used.
- Newer aws-lc-sys (0.45.0) and openssl-src (400.0.1, OpenSSL 4.0.2) exist
  but openssl-sys 0.9.117 cannot use them yet.
