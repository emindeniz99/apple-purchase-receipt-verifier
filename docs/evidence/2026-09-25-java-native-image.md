# Java verifier as a GraalVM Native Image shared library: spike results

Measured 2026-09-25 on one Linux x86_64 cloud container (4 vCPUs, 15 GB
RAM, Ubuntu 24.04, glibc 2.39). The question: can the unchanged Java
verifier (`java/`, 0.6.0, Bouncy Castle 1.86, Jackson 2.22.2) be compiled
by GraalVM Native Image into a JVM-free shared library with a C ABI, and
serve as the one cross-language core instead of the Rust crate that
[docs/rust-core/](../rust-core/README.md) plans?

Sources and raw outputs: [2026-09-25-java-native-image-spike/](./2026-09-25-java-native-image-spike/README.md).
Nothing under `java/`, `rust/`, `fixtures/` or `certs/` was changed. CI
builds none of it.

Labels used below: **tested** (run here, output in `results/`),
**documented** (upstream documentation, not run here), **expected**
(follows from something tested, not run), **unknown**.

## Result in one table

| Question | Answer |
|---|---|
| Does it build? | **Yes.** Oracle GraalVM 25.4.4.1.1 `native-image --shared`, 2 min 52 s, 3.05 to 3.4 GB peak RSS, 41.8 MiB `.so`. Tested. |
| Does it run without a JVM? | **Yes.** `env -i` (no `JAVA_HOME`, no `PATH`), `NEEDED` is `libz.so.1` and `libc.so.6` only, and strace shows no JDK file opened. Tested. |
| Is it correct? | **Yes, with generated metadata.** 152 of 153 cases pass, 1 explained, 269 fields checked. Identical to the JVM (JDK 25 and Temurin 8) on 986 of 986 requests. Tested. |
| Is the tracing agent enough? | **No.** Traced metadata gave wrong verdicts on 16 of 22 receipts and JWS signed with algorithms the fixtures do not use. No error, just a rejection. Tested. |
| Is it fast? | Close to the JVM, slower than Rust. Receipt: 749 µs (NI), 705 µs (NI with PGO), 692 µs (JDK 25), 676 µs (Rust). 4-thread receipt throughput: 4,785, 5,462, 5,578 and 6,675 per second. Tested. |
| Is it small? | **No.** 41.8 MiB (17.5 MB gzipped) per platform, against 0.88 MB stripped (0.46 MB gzipped) for the Rust C ABI library. Tested. |
| Where does it run? | Documented: Linux x64 and aarch64, macOS aarch64, Windows x64. Each built on its own OS and architecture: Native Image does not cross-compile. The plan's R12 asks for 26 C ABI targets. |
| Can it replace the Rust core? | **No.** It is a sound way to run the Java port without a JVM on four server platforms. It cannot reach the other 22 R12 targets, iOS, Android or `wasm32-wasip1`, and it ships a 42 MB runtime per platform. See section 16. |

## 1. Toolchain

| Item | Value |
|---|---|
| Native Image | Oracle GraalVM 25.4.4.1.1+1.1 (`native-image 25.0.4.1.1 2026-08-18`, JDK 25.0.4.1.1+1-LTS, jvmci-25.4-b23), the newest Oracle build on graalvm.org's download page on 2026-09-25. |
| Community Edition | GraalVM CE 25.0.2+10.1, the newest CE asset whose URL could be found. graalvm.org names CE 25.3.4.1 (2026-08-25) as newest, but the GitHub releases page answers 403 in this container, so its file name stayed unknown. |
| Oracle GraalVM license | GraalVM Free Terms and Conditions (GFTC). Documented (Oracle's FAQ and blog; the license page itself answered 403): production use is free, and native images count as the unmodified Program, so they may be redistributed only if no fee is charged, and search summaries of the text extend that to fees for products that bundle the Program. CE is GPLv2 with the Classpath Exception. This is a reading of public text, not legal advice. |
| JVMs for comparison | Temurin 8u504-b01, Temurin 25.0.4.1+1. |
| Rust | `rust/ffi` release build, unchanged (`libapple_purchase_receipt_verifier_ffi.so`). |
| C | gcc 13.3.0, glibc 2.39, musl 1.2.4 (Ubuntu package). |

**No JVM at run time (tested).** The C harness ran under `env -i`: no
`JAVA_HOME`, no `PATH`. `ldd` lists `libz.so.1`, `libc.so.6`, the vDSO and
the loader. `strings` finds no `libjvm.so`. `strace -f` of the whole smoke
run opened no file whose path mentions java, jdk or jvm
(`results/no-jvm-strace.txt`). The image does read `/etc/passwd`,
`/etc/localtime`, `/usr/share/zoneinfo/Etc/UTC`, `/dev/random`,
`/dev/urandom`, cgroup files and `/proc/self/maps` at start. A minimal
container needs those, or has to be tested without them.

## 2. The wrapper

Three layers, none of them in `java/`:

- `bridge/Bridge.java`: plain Java 8, no GraalVM types. Options JSON in,
  `(code, json)` out. It calls the public API only.
- `bridge/OracleCli.java`: the same `Bridge` on a JVM, reading a JSON-lines
  corpus. The JVM and the image run identical adapter code, so a difference
  between them belongs to the image.
- `native/NativeEntryPoints.java`: 14 `@CEntryPoint` shims (248 lines with
  comments). Pointer and length in, C string out.

`build.sh` copies `java/` into `$SCRATCH`, runs its own `pom.xml`
(`mvn package`), compiles the bridge with `--release 8`, then runs
`native-image --shared -march=compatibility`. `-march=compatibility`
replaces the default `x86-64-v3`, so the library also loads on older x86_64
CPUs.

## 3. C ABI, lifecycle and threads

```c
graal_isolatethread_t* aprvj_runtime_new(void);            /* isolate + attach caller */
graal_isolate_t*       aprvj_runtime_isolate(graal_isolatethread_t*);
graal_isolatethread_t* aprvj_thread_attach(graal_isolate_t*);
int                    aprvj_thread_detach(graal_isolatethread_t*);
int                    aprvj_runtime_free(graal_isolatethread_t*);  /* others detached first */

void* aprvj_receipt_verifier_new(graal_isolatethread_t*, char* options_json, char** error);
void* aprvj_jws_verifier_new    (graal_isolatethread_t*, char* options_json, char** error);
void* aprvj_endpoint_new        (graal_isolatethread_t*, char* options_json, char** error);
void  aprvj_handle_free(graal_isolatethread_t*, void* handle);

int aprvj_verify_receipt(graal_isolatethread_t*, void* h, char* bytes, size_t len,
                         int is_base64, char* guid, size_t guid_len, char** out);
int aprvj_verify_jws(graal_isolatethread_t*, void* h, char* jws, size_t len, int op, char** out);
int aprvj_verify_receipt_json(graal_isolatethread_t*, void* h, char* body, size_t len, char** out);
int aprvj_self_check(graal_isolatethread_t*, char** out);
void aprvj_string_free(graal_isolatethread_t*, char* s);
```

Return codes: 0 success; 1 to 13 the library's `Reason` (the same numbers
as the Rust ABI for 1 to 10 and 12); -1 invalid argument; -2 internal;
-3 configuration (for example a missing root resource). `*out` is always a
`malloc`'d JSON string or NULL, freed by `aprvj_string_free`.

The thread model is Native Image's, and the caller has to follow it:

- One isolate per process is enough. Each OS thread attaches once and passes
  its own `graal_isolatethread_t*` to every call. Passing another thread's
  pointer is undefined (it aborted, section 11).
- Handles are global `ObjectHandles`. Any attached thread may use any handle.
  The Java verifiers are thread-safe once built (their Javadoc says so).
- Attaching an already attached OS thread returns the **same**
  `IsolateThread`. Detaching it then detaches the original too, and the next
  call aborts the process. The harness's first draft hit this. A binding has
  to track attachment per OS thread (a thread-local), exactly as `py/aprvj.py`
  does.

**Concurrency (tested, `c/harness.c bench`).** Every call's JSON is compared
with the first call's. 0 mismatches in every run below.

| Receipts per second, 8 s | 1 thread | 4 threads | 16 threads | 4 threads, shared handles | 16, shared |
|---|---:|---:|---:|---:|---:|
| Native image | 1,218 | 4,785 | 4,490 | 4,525 | 4,195 |
| Native image, PGO | 1,360 | 5,462 | 4,958 | | |
| Rust C ABI | 1,660 | 6,675 | 6,708 | 6,480 | 6,470 |

The image scales 3.9x from 1 to 4 threads on 4 vCPUs. At 16 threads it
loses 6 to 9%, the JVMs 3 to 4%, Rust nothing. The image uses the Serial
GC, which stops every thread for each collection. Oracle GraalVM also offers
G1 on Linux (documented, not tested).

## 4. Bouncy Castle metadata

`BouncyCastleProvider`'s constructor loads about 108 `$Mappings` classes by
name and skips any that is missing without an error. JCA then creates each
algorithm's service class by reflection. Native Image needs every one of
them registered.

1. **Tracing agent (tested).** `native-image-agent` over the 153 cases, the
   811 hostile inputs and a self-check, merged with `native-image-configure`:
   151 reflection entries and 5 resource globs (`config/traced`). The
   conformance suite passes with it. Then a corpus of 22 inputs signed with
   algorithms no fixture uses (`gen/AlgorithmCorpus.java`: RSA with SHA-224,
   384, 512, SHA3-256, MD5, RIPEMD-160 and PSS, ECDSA P-256, P-384, P-521,
   Ed25519, and chains signed with SHA-384, SHA-512 and PSS) verifies on both
   JVMs. The traced image rejected **16 of 22**: `INVALID_SIGNATURE` "CMS
   verifier refused the signer info" or `INVALID_CHAIN`. Nothing reports the
   missing class. A trace covers only the algorithms the traced run happened
   to use, and the library's contract is "any signer algorithm under the
   pinned chain".
2. **Generated metadata (tested, committed).** `gen/MetadataGen.java` reads
   the provider's own name tables and `getServices()` and writes
   `config/minimal/reachability-metadata.json`: 108 `$Mappings` (no-arg
   constructors), 481 service classes of the 8 JCA types the verifier uses
   (Signature, MessageDigest, KeyFactory, AlgorithmParameters,
   CertificateFactory, CertPathBuilder, CertPathValidator, CertStore) with
   their public constructors, `PKIXRevocationChecker`, and the 28 non-BC
   entries plus 5 resources from `config/base.json`. 618 reflection entries
   in all. The output is a function of the Bouncy Castle jar, so it is
   deterministic. It is not "all of BC": ciphers, MACs, KEMs, key agreement,
   key stores, DRBGs and KDFs are left out, and the build reports 956 types
   registered for reflection out of 9,007 reachable. This image agrees with
   both JVMs on all 22.

Workarounds, all of them:

- the `$Mappings` and service lists above (a Bouncy Castle upgrade needs
  `MetadataGen` re-run);
- `base.json`: Jackson payload models (fields and `@JsonCreator`
  constructors), `sun.security` X.509 factory classes for caller-supplied
  roots, `Class.isRecord`, `java.lang.Boolean.getBoolean` (JNI), ICU
  `nfkc.nrm`, time-zone data and the three Apple `.cer` files;
- no custom `@CEntryPoint` exception handler: the public API accepts one only
  with `com.oracle.svm.core.Uninterruptible`, an internal annotation, and the
  build fails without it. Each shim catches `Throwable` instead (section 11).

`--exact-reachability-metadata` (fail on any unregistered lookup instead of
silently skipping it) would have turned the traced image's wrong verdicts
into errors. It was not tried.

## 5. Apple roots in the image (tested)

- The three `certs/*.cer` files are resources in the image. A byte search
  finds each file's exact bytes once in the `.so`.
- `aprvj_self_check` loads them through the library's own `AppleRootCerts`,
  which checks each against its pinned SHA-256. It returns
  `b0b1730e...f024`, `c2b9b042...a050`, `63343abf...9179`, equal to
  `sha256sum certs/*.cer`.
- **Negative control:** the same build with `AppleRootCA-G2.cer` left out
  of the resource list. The build succeeds and nothing warns. The G2 bytes
  are absent from that `.so`. `self_check` answers -3 `IllegalStateException:
  bundled certificate missing: AppleRootCA-G2.cer`, and 37 of the 153 cases
  fail with -3: every case that uses the bundled roots. Cases with custom
  roots still pass. The library fails closed, and a smoke test catches it.
  The build does not.

## 6. Provider behaviour

The verifier never registers Bouncy Castle globally. It holds one private
`BouncyCastleProvider` instance and passes it explicitly to every JCA call
(`CertificateFactory`, `CertPathBuilder`, `CertPathValidator`, `CertStore`,
`Signature`, `MessageDigest`, `X509Certificate.verify`,
`JcaSimpleSignerInfoVerifierBuilder`). It parses ASN.1 and CMS with Bouncy
Castle's lightweight classes. So the image needs the JCA reflection
metadata above, and the JDK's own providers matter only on one path: the
bridge decodes caller-supplied roots with the JDK's X.509 factory, as
`ConformanceCasesTest` does (hence the `sun.security` entries). No refactor
was made. Moving the verifier to Bouncy Castle's lightweight API
(`org.bouncycastle.crypto` signers instead of JCA lookups) would remove most
of the reflection metadata, but it is a rewrite of the verification path and
out of scope.

## 7. Conformance and differential testing (tested)

Corpora (`py/requests_gen.py`, `gen/AlgorithmCorpus.java`):

- `cases`: the 153 non-`decodeBase64` groups of `fixtures/cases.json`. The
  33 `decodeBase64` groups need a decoder entry point, which neither this ABI
  nor the Rust ABI has.
- `hostile`: 811 inputs, seed 20260925. Mutated DER receipts (g5 and the
  generated receipt), device GUID edge cases, base64 text, mutated JWS,
  endpoint bodies, invalid UTF-8, embedded NULs, odd constructor options.
- `algorithms`: the 22 inputs from section 4.

| Comparison | Result |
|---|---|
| Image against `cases.json` expectations | 152 pass, 0 fail, 1 explained, 269 fields checked |
| Image against JDK 25 (`OracleCli`) | 153 + 811 + 22 = 986 identical (code and parsed JSON) |
| Image against Temurin 8 | 986 identical |
| Image with PGO, image built by CE 25.0.2 | 986 identical each |
| Image on hostile input | 0 crashes, 0 internal errors (-2), 5 invalid arguments (-1) |

The explained case: `endpoint/receipt-data-over-the-receipt-cap-answers-21002`
expects `INVALID_RECEIPT_FORMAT`. `ConformanceCasesTest` hands the endpoint a
`Map` and so skips the body cap. Through a body-in ABI the body is over the
3,145,728-byte cap first, so the reason is `REQUEST_TOO_LARGE`. Apple's
wire status is 21002 either way.

**Against Rust (`rust/ffi`, same corpora).** Cases: 0 differences (33
endpoint identical, 44 JWS and 47 receipt failures with the same code, 12
JWS and 17 receipt successes with equal fields). The hostile and algorithm
corpora find differences between the two **ports**. They are not caused by
Native Image: the JVM gives the same answers.

| Difference | Rows | Java | Rust |
|---|---:|---|---|
| Signer or chain algorithm other than RSA SHA-1/SHA-256 or EC P-256/P-384 chains | 14 of 22 algorithm inputs | accepts (any algorithm under the pinned chain) | rejects: 9, 5, 4 or 2 |
| Receipt DER, byte 2178 changed inside the unused third embedded certificate's `tbsCertificate.signature` OID | 1 | accepts | 9 "signatureAlgorithm disagrees with tbsCertificate.signature" |
| Endpoint body with bytes after the JSON object (`{...}xyz`) | 2 | status 0 (Jackson ignores trailing tokens) | 21002 |
| Non-UTF-8 JWS, base64 receipt or endpoint body | 63 + 18 + 39 | answers (JWS 1, receipt 9, endpoint 21002 ×22 and 0 ×17) | ABI refuses with 101 `INVALID_UTF8` |
| Both reject, different reason | 20 | e.g. 9 (BC whole-blob parse) | e.g. 4 (chain checked first) |
| NUL inside a C string | 11 | reachable (pointer and length) | not expressible |

The reason-only rows are listed with the changed byte and its DER path in
`results/java-vs-rust-hostile-explained.txt`. One code comment is wrong:
`rust/src/jws.rs:632-634` says `from_utf8_lossy`'s U+FFFD makes the header
JSON invalid. It does not in general. These are pre-existing Java/Rust
divergences that the plan's shared-fixture rule has not caught. They need an
owner decision (the algorithm policy most of all), whichever core is chosen.

## 8. Performance (tested)

Same machine, same hour, one run at a time. Receipt: the g5 sandbox receipt,
base64, bundled Apple roots. JWS: `fixtures/generated/transaction.jws`
against `jws-root.der`. Endpoint: `{"receipt-data": ...}`, Sandbox, fixed
clock. Every side returns JSON (the JVM runs the same `Bridge`). Warm-up:
3 s for native code, 10 s for the JVMs (JIT). Latency: 2,000 calls on one
thread. Throughput: each worker builds its own verifiers, 8 s.

**Single-thread latency, µs (mean / p50 / p99)**

| | Receipt | JWS | Endpoint |
|---|---|---|---|
| A. Temurin 8, Maven jar via Bridge | 721 / 681 / 1,342 | 1,097 / 1,069 / 1,734 | 742 / 695 / 1,312 |
| A. Temurin 8, library call, no JSON | 723 / 674 / 1,268 | 1,186 / 1,105 / 1,931 | |
| B. Temurin 25, via Bridge | 692 / 642 / 1,085 | 1,062 / 993 / 1,871 | 691 / 659 / 1,109 |
| B. Temurin 25, library call, no JSON | 645 / 615 / 1,107 | 1,057 / 982 / 1,890 | |
| C. Native image | 749 / 723 / 1,374 | 1,238 / 1,121 / 2,686 | 805 / 763 / 1,494 |
| C. Native image, PGO | 705 / 655 / 1,317 | 1,115 / 1,057 / 1,828 | 719 / 680 / 1,366 |
| C. Native image, CE 25.0.2 | 1,399 / 1,327 / 2,465 | 1,376 / 1,305 / 2,341 | 1,516 / 1,437 / 2,569 |
| D. Rust C ABI | 676 / 581 / 1,159 | 861 / 848 / 1,133 | 581 / 573 / 873 |

**Throughput, calls per second, 1 / 4 / 16 threads**

| | Receipt | JWS | Endpoint |
|---|---|---|---|
| A. Temurin 8 | 1,350 / 4,980 / 4,640 | 860 / 3,435 / 3,375 | 1,360 / 5,018 / 4,880 |
| B. Temurin 25 | 1,463 / 5,578 / 5,380 | 958 / 3,730 / 3,395 | 1,470 / 5,435 / 5,135 |
| C. Native image | 1,218 / 4,785 / 4,490 | 810 / 3,085 / 2,798 | 1,188 / 4,620 / 4,215 |
| C. Native image, PGO | 1,360 / 5,462 / 4,958 | 880 / 3,450 / 3,165 | 1,375 / 5,075 / 4,865 |
| C. Native image, CE 25.0.2 (1 / 4) | 650 / 2,565 | 645 / 2,660 | 615 / 2,425 |
| D. Rust | 1,660 / 6,675 / 6,708 | 1,135 / 4,480 / 4,480 | 1,618 / 6,475 / 6,445 |

**Startup and first call**

| | Runtime ready | Build three verifiers | First receipt | First JWS |
|---|---:|---:|---:|---:|
| A. Temurin 8 | JVM start to first verdict 720 to 920 ms | 557 to 656 ms | 157 to 216 ms | 350 to 435 ms |
| B. Temurin 25 | 684 to 933 ms | 520 to 636 ms | 108 to 146 ms | 348 to 551 ms |
| B. Temurin 25 + AOT cache (Leyden) | 438 to 497 ms | 198 to 244 ms | 89 to 106 ms | not run |
| C. Native image | `aprvj_runtime_new` 1.4 to 1.8 ms (0.6 to 0.8 ms for later isolates); whole process, exec to exit, 28 to 30 ms | 22 to 26 ms | 12 to 13 ms | 4 ms |
| D. Rust | nothing to start | 0.12 to 0.18 ms | 0.6 to 0.8 ms | 0.9 to 1.0 ms |

(For the JVMs "build" is the receipt verifier alone and includes loading
the provider; for the image and Rust it is all three verifiers.)

**Resident memory, MB (after start / after warm-up / after the 4- or 16-thread run)**

| | |
|---|---|
| A. Temurin 8, default heap (1/4 of 15 GB) | 30 / 1,010 to 1,250 / 1,010 to 1,210 |
| A. Temurin 8, `-Xmx64m` (receipt, 4 threads: 3,930/s) | 29 / 156 / 157 |
| B. Temurin 25, default heap | 50 / 450 to 560 / 530 to 900 |
| B. Temurin 25, `-Xmx64m` (receipt, 4 threads: 4,648/s) | 50 / 196 / 209 |
| C. Native image | 8.3 / 57 / 77 to 88 |
| C. Native image, PGO | 41 after a 1-thread run / 67 to 75 after 4 or 16 threads |
| D. Rust | 2.1 / 2.9 / 3.1 to 6.5 |

Reading:

- Without PGO the image is 8 to 17% slower than JDK 25's warmed-up JIT and
  4 to 13% slower than Temurin 8. With PGO it is within 2 to 5% of JDK 25
  on every operation. PGO also cut the file to 27.7 MB.
- Rust is faster than every Java path: 22% more receipt throughput than the
  PGO image at 4 threads, 30% more JWS.
- The image's advantages are startup (30 ms against 0.7 to 0.9 s) and
  memory (57 MB against 150 to 1,250 MB). Neither matters to a long-running
  server that verifies after warm-up. Both matter to CLIs and serverless.
- **CE is about 1.9x slower** than Oracle GraalVM on receipts (1,399
  against 749 µs) and 1.1x on JWS. The GPL build is the slower
  one.
- Earlier references (`2026-09-25-rust-core-spikes.md`): Rust 529 µs per
  receipt and 6,444/s at 4 threads; Maven 0.6.0 on JDK 21 678 µs receipt,
  1,077 µs JWS. This run's numbers sit in the same range.

**PGO (tested, Oracle GraalVM only).** A `--pgo-instrument --shared` build
succeeds (58.7 MiB), but the instrumented library knows no
`-XX:ProfilesDumpFile` and writes no `.iprof` on teardown (`c/pgo_train.c`).
The working route: build `bench/JvmBench.java` as an instrumented
**executable** with the same metadata, run receipt, JWS and endpoint
workloads (8.7 to 9.0 MB `.iprof` each), then build the shared library with
`--pgo=receipt.iprof,jws.iprof,endpoint.iprof` (122.5 s, 2.3 GB). That
image answers the 986 requests identically.

## 9. Memory ownership

- Every `char*` the library returns is `malloc`'d (Native Image's
  `UnmanagedMemory`, libc `malloc`) and must go back through
  `aprvj_string_free` exactly once. Freeing it on another attached OS thread
  works (tested).
- Handles are freed with `aprvj_handle_free`. Input buffers stay the
  caller's; the library copies them.
- `aprvj_runtime_free` returns the Java heap. 500 cycles of create, self
  check and teardown in one process: RSS 15,116 kB after the first,
  15,132 kB after the 500th (`results/startup-ni.txt`).

**Leak loop (tested).** 20,000 iterations of receipt + JWS + endpoint, with
a fresh set of handles every 100 iterations (`c/harness.c leak`):

| | RSS at 1,000 | RSS at 20,000 | Range after 2,000 |
|---|---:|---:|---:|
| Native image | 66.4 MB | 57.1 MB | 56.5 to 57.8 MB |
| Rust | 2.9 MB | 2.9 MB | 2.90 to 2.92 MB |

**Valgrind 3.22 and ASan (tested).** Valgrind runs the image. Leak loop
(100 iterations) and smoke test: 0 errors, 0 bytes definitely, indirectly
or possibly lost; 18 to 23 KB still reachable at exit. Rust: the same.
gcc `-fsanitize=address,undefined` harness builds against both libraries:
smoke, leak and a 4-thread benchmark ran with no sanitizer report. Valgrind
and ASan see only `malloc` memory. The Java heap is Native Image's own
`mmap`, checked by the RSS loop above instead.

## 10. Exception mapping

| Java | Code | JSON |
|---|---|---|
| `VerificationException` | its `Reason` (1 to 13) | `{"reason", "exception", "message"}` |
| `IllegalArgumentException`, `ClassCastException` (bad options, wrong handle kind, NULL with length > 0, unknown JWS op) | -1 | same shape |
| `IllegalStateException` (missing or replaced root resource) | -3 | same shape |
| any other `Throwable` | -2 | same shape |
| constructors | NULL handle | `*error` gets the JSON when `error` is not NULL |
| endpoint | the result's `failureReason` code, or 0 | Apple's response JSON (`{"status":21002}` etc.) |

Across the 986 requests no -2 occurred. A `Throwable` that escapes the
shim's own `catch` (for example an `OutOfMemoryError` while building the
error JSON) reaches Native Image's default fatal handler, which ends the
process. That path is not reachable from the public API without an internal
annotation (section 4). Expected, not provoked.

## 11. Crash behaviour (tested)

`c/harness.c smoke` (23 checks, all pass) covers the misuse that returns a
code: NULL handle (-1), NULL bytes with length 5 (-1), NULL bytes with
length 0 (9, the library's own verdict for empty input), empty base64 (9),
NULL GUID with length 7 (treated as no GUID), wrong GUID (10), NULL JWS (1),
unknown JWS operation (-1), a receipt handle passed as a JWS handle (-1),
NULL endpoint body (11, `{"status":21002}`), NULL `out` pointer (code still
returned), NULL or malformed options (NULL handle plus an error),
`string_free(NULL)`, `handle_free(NULL)`, and a second runtime after
teardown.

`c/harness.c hazards` runs each of these in a forked child:

| Misuse | Outcome |
|---|---|
| Attach twice on one OS thread, detach once, call again | abort (SIGABRT, "Must either be at a safepoint or in native mode") |
| `handle_free` twice | returns; nothing happens |
| Call with a freed handle | -1 |
| Call with a made-up handle value | -1 |
| `string_free` twice | abort (glibc "double free or corruption") |
| `string_free` on a stack pointer | abort (glibc) |
| Call after `runtime_free` with the stale thread | SIGSEGV |
| Call from an unattached thread with another thread's `IsolateThread` | abort (fatal StackOverflowError: "wrong IsolateThread") |
| Call with a NULL `IsolateThread` | exit(2), "Failed to enter the specified IsolateThread context" |
| Length larger than the buffer | reads past it (undefined; this run returned 9) |

Handle misuse is safer than in a raw pointer ABI: handles are table
indices, checked on use. Thread misuse is worse: it ends the process, and a
Rust ABI has no thread lifecycle to get wrong. A binding for a
garbage-collected language has to hide attach and detach completely.

## 12. Build facts

| | Value |
|---|---|
| Command | `native-image --shared -march=compatibility -cp <bridge, verifier jar, 7 deps, shims> -H:ConfigurationFileDirectories=config/minimal -o <name>` (`build.sh`) |
| Duration, 4 vCPUs | 2 min 52 s; the rebuild 179.6 s; PGO build 122.5 s; CE 1 min 38 s |
| Peak RSS | 3.05 to 3.4 GB (CE 2.8 GB, PGO 2.3 GB, instrumented executable 4.9 GB) |
| Reachable | 9,007 types, 49,306 methods; 956 types registered for reflection |
| Output | `.so`, `<name>.h`, `<name>_dynamic.h`, `graal_isolate.h`, `graal_isolate_dynamic.h` |
| `.so` size | 43,845,736 B (41.8 MiB, already stripped), 17.5 MB gzip -9, 12.6 MB xz -9 |
| `NEEDED` | `libz.so.1`, `libc.so.6`; no `SONAME` |
| Newest glibc symbol | `GLIBC_2.34` (the `pthread_*` and `dl*` symbols glibc moved into libc.so.6). It will not load on RHEL 8 (2.28) or Ubuntu 20.04 (2.31) as built here. Building on an older distribution should lower it (expected; Oracle lists Oracle Linux 7 and 8 as supported). The Rust library built on this machine also needs 2.34. |
| Exported dynamic symbols | 64: the 14 `aprvj_*`, 7 `graal_*`, `JNI_CreateJavaVM`, `JNI_GetCreatedJavaVMs`, `JNI_GetDefaultJavaVMInitArgs`, SBOM and version data, entry stubs. Two different native images loaded into one process (`RTLD_LOCAL` and `RTLD_GLOBAL`) worked (tested). Loading one into a JVM process, whose `libjvm.so` exports the same `JNI_*` names, was not tested. |
| Embedded | a CycloneDX SBOM; the build notes "Binary includes Java deserialization". |
| Bit-for-bit reproducible? | **No** (tested). Two builds from the same inputs: same size, 37,168,945 differing bytes, and the generated `<name>.h` declares the same functions in a different order. No determinism option found in `native-image --print-options`. Behaviour of the two builds is identical on the 153 cases. |

**musl (tested, with a caveat).** `--shared --libc=musl` is accepted.
With Ubuntu's `musl-gcc` it first failed to link (`cannot find -lz`). With a
static zlib 1.3.1 built by `musl-gcc -fPIC` it produced a 43.9 MB library
(2 min 50 s). A harness built with `musl-gcc` (interpreter
`/lib/ld-musl-x86_64.so.1`) passed all 23 smoke checks and the benchmark
(receipt 749 µs single-thread mean, 4,488/s at 4 threads). The library's `NEEDED` is
`libc.so`, which is how Ubuntu's musl names itself. Alpine's musl uses
`libc.musl-x86_64.so.1`, so an Alpine build has to be linked with Alpine's
toolchain or Oracle's musl bundle. Not tested on Alpine. Oracle documents
musl only for static executables on Linux x64.

## 13. Platforms

Native Image compiles for the machine it runs on. There is no
cross-compilation, so every target needs a CI runner of that OS and
architecture.

| Target (R12 numbering) | Native Image | Rust core (R12) |
|---|---|---|
| 1 Linux x86_64 glibc | **tested** | yes |
| 2 Linux aarch64 glibc | documented (Oracle download and support list) | yes |
| 3 Linux x86_64 musl | tested on Ubuntu's musl only; Alpine unknown | yes |
| 4 Linux aarch64 musl | unknown | yes |
| 5 macOS aarch64 | documented | yes |
| 6 macOS x86_64 | **unsupported**: removed after GraalVM 25.0.1 | yes |
| 7 Windows x86_64 | documented | yes |
| 8 Windows aarch64 | unsupported: no download (the SDK has a `WINDOWS_AARCH64` platform class) | yes |
| 9 Windows x86, 10 Linux i686, 13 ARMv6, 14 ARMv7 | unsupported (no 32-bit targets) | yes |
| 11 ppc64le, 12 s390x, 16 loongarch64 | unsupported | yes |
| 15 riscv64 | not offered as a download; the SDK has a `LINUX_RISCV64` platform class; unknown | yes |
| 17, 18 FreeBSD; 19 illumos; 20 Solaris | unsupported | yes |
| 21 to 26 other musl targets | unsupported | yes |
| iOS, Android (the Swift package's XCFramework) | unsupported by GraalVM itself | yes (Swift R7) |
| `wasm32-wasip1` (Go through wazero) | unsupported (see section 14) | yes |

Four of R12's 26 targets are documented; one is tested. Temurin, the
proxy R12 uses for "where Java users are", also ships ppc64le, s390x, AIX
and macOS x64. The image cannot follow Java users there.

**Other distributions.** GraalVM CE 25.0.2 built the same library
(44.4 MB, 1 min 38 s), passed the same 986 comparisons, and ran 1.9x
slower on receipts (section 8). Mandrel is a CE downstream. Its current
release name could not be read (GitHub releases page 403), and CE already
answers the CE question, so it was not tried. Liberica NIK was not tried
either, for the same reason.

**Project Leyden (tested on JDK 25, briefly).** JEP 483/514/515 are in
JDK 25: `-XX:AOTCacheOutput` on a training run, then `-XX:AOTCache`. It cut
JVM start to first verdict from 690 to 753 ms to 438 to 497 ms, with a
29.5 MB cache file. The cache refuses a directory on the class path
("Cannot have non-empty directory in paths"). Leyden speeds up a JVM. It
does not remove the JVM, so it does not answer this spike's question:
Python, Node, Go and Swift callers would still need a JVM. Documented:
ahead-of-time code compilation is a candidate JEP (544), not in a release.

## 14. WebAssembly: Web Image (experimental)

Oracle GraalVM 25.4 ships Web Image (`native-image --tool:svm-wasm`),
documented upstream as **experimental**. It needs binaryen's `wasm-as`
(version_124 used) and WebAssembly GC, exception handling and typed
function references.

Tested: `web/WebMain.java`, the same `Bridge` calls from a `main`, built
with the same metadata in 1 min 57 s (3.8 GB peak).

| | Value |
|---|---|
| Output | `wasm-main.js` 110,547 B + `wasm-main.js.wasm` 22,627,824 B (8.26 MB gzip -9); also a 695 MiB `.wat` debug file |
| Node 22.22.2 (`--experimental-wasm-exnref`) | all checks pass (self-check hashes, receipt 0, JWS 0, endpoint 0, wrong bundle 6); receipt 3,795 µs, JWS 3,056 µs; construction 192 ms |
| Bun 1.3.11 | all checks pass; receipt 5,206 µs, JWS 4,283 µs |
| Deno 2.9.7 | fails in the generated launcher before `main` (`features.location.data.location.href` is undefined) |
| Cloudflare workerd, browsers | not tried |
| Go via wazero, `wasm32-wasip1` | not possible: Web Image emits a JS-hosted WasmGC module, not WASI; wazero does not implement WasmGC (expected) |

Web Image builds an application with a `main`, not a library with exported
functions. An npm package would need Web Image's JS interop API
(`org.graalvm.webimage.api`), which was not tried. Speed is close to the
Rust wasm build (3,626 µs per receipt on Node), but the module is 60 times
larger (22.6 MB against 0.37 MB). As an npm core this is not usable today.

## 15. Comparison

| Criterion | A. Today's JVM port (Maven jar) | B. Java as a Native Image `.so` | C. Rust core + bindings (the plan) | D. Local sidecar (Rust server, R17) |
|---|---|---|---|---|
| Who can call it | JVM only | any language with a C FFI, on 4 platforms | every registry package, 26 C ABI targets, wasm for npm and Go | anything that speaks HTTP |
| Needs a JVM | yes | no (tested) | no | no |
| Algorithm code to maintain | Java (plus 8 other ports today) | Java | Rust | Rust |
| Agreement with the Java oracle | is the oracle | 986/986 identical (tested) | 0 differences on cases; 14 algorithm policy and 3 verdict differences on hostile inputs (section 7) | as C |
| Receipt µs, 1 thread | 692 (JDK 25), 721 (JDK 8) | 749; 705 with PGO; 1,399 on CE | 676 C ABI; 629 to 742 via bindings (earlier spike) | about 895 over HTTP (earlier spike) |
| Receipts/s, 4 threads | 5,578 (JDK 25) | 4,785; 5,462 with PGO | 6,675 | 3,296 (earlier spike) |
| JWS µs, 1 thread | 1,062 | 1,238; 1,115 with PGO | 861 | not measured |
| Cold start to first verdict | 0.7 to 0.9 s; 0.44 to 0.5 s with Leyden | 30 ms process; 1.5 ms runtime + 23 ms constructors | under 2 ms | 43 ms to healthy (earlier spike) |
| Resident memory | 150 MB (`-Xmx64m`) to 1.2 GB (default heap) | 57 to 88 MB | 3 to 6.5 MB | about 2 MB server + client |
| Artifact per platform | 11.8 MB of jars, one for all | 41.8 MiB (17.5 MB gzip); 27.7 MB with PGO | 0.88 MB stripped (0.46 MB gzip) | 1.43 MB glibc, 1.54 MB static musl |
| Platforms | wherever a JVM runs | Linux x64/arm64, macOS arm64, Windows x64 | 26 C ABI targets, Apple and Windows Swift, wasm | same as C |
| Cross-compiles | n/a | no: one CI runner per OS and architecture | yes | yes |
| iOS, Android | no | no | yes | no |
| wasm | no | Web Image: experimental, 22.6 MB, no WASI | yes: 0.37 MB, Node, Bun, Deno, workerd, wazero | no |
| Error model | Java exceptions | codes + JSON; thread misuse aborts the process | codes + JSON; generated typed exceptions | HTTP status |
| Build | Maven, seconds | 3 min, 3.4 GB RAM per target; not reproducible | cargo, reproducible | cargo |
| License of the toolchain in the artifact | Apache/MIT deps | Oracle GFTC (no-fee redistribution) or CE (GPLv2+CPE, 1.9x slower) | Rust crates' licenses | same as C |
| Metadata burden | none | generated reflection list, regenerate on every Bouncy Castle upgrade; a trace alone gives wrong verdicts | none | none |

## 16. Recommendation

**Do not replace the Rust core with the Native Image library.**

What works, and is worth recording: the Java verifier compiles to a
JVM-free shared library with no source change. With generated metadata it
answers exactly as the JVM does on 986 inputs, with 0 crashes on 811
hostile ones. With Oracle GraalVM and PGO it is as fast as a warmed-up
JDK 25, starts in 30 ms and needs 57 MB.

Why it cannot be the one core:

1. **Reach.** Four documented platforms against R12's 26, no 32-bit, no
   ppc64le or s390x (where Temurin users are), no macOS x64, no iOS or
   Android, no WASI. Every target needs its own runner.
2. **Size.** 42 MB per platform, 50 times the stripped Rust library. The
   four reachable platforms alone come to about 70 MB gzipped, against
   about 0.5 MB gzipped per target for Rust.
3. **Web.** npm and Go are already committed to wasm. Web Image is
   experimental, 22.6 MB, fails on Deno, has no library exports and no WASI.
4. **Fragility.** Correctness depends on a reflection list that must cover
   every algorithm Bouncy Castle can meet. The natural workflow (the
   tracing agent) produced wrong verdicts with no warning. A dropped root
   resource builds without a warning. Thread-lifecycle misuse aborts the
   host process.
5. **License and speed are tied.** The fast build is Oracle's, under a
   no-fee redistribution condition that reaches products bundling it. The
   GPLv2+CPE build is about 1.9x slower on receipts.
6. **It keeps Java as the algorithm language** but still needs a C ABI, a
   thread lifecycle and a binding per language, which is the same binding
   work the Rust plan already has, on a heavier base.

Where it could still help (optional, not recommended as a product):

- The differential harness from this spike (the same corpus through the
  JVM, the image and `rust/ffi`) is useful for Phase 1 whatever the core.
  It already found the Java/Rust differences in section 7.
- Those differences need owner decisions now: whether Rust should accept
  every signer and chain algorithm Java accepts (14 of 22 inputs differ),
  the trailing-JSON leniency, non-UTF-8 input at the ABI, and the wrong
  comment in `rust/src/jws.rs:632-634`.

## Not done, and why

- **Mandrel and Liberica NIK:** not built. CE 25.0.2 stands in for the
  community line; the Mandrel release name could not be read (GitHub
  releases page 403).
- **Newest CE (25.3.4.1):** its asset URL is unknown for the same reason;
  CE 25.0.2 (2026-01-20) was used.
- **Linux aarch64, macOS, Windows:** not built. No cross-compilation and no
  such runner here. Their rows are documented, not tested.
- **Alpine:** the musl library was tested with Ubuntu's musl only.
- **G1 GC, `-march=x86-64-v3`, `--exact-reachability-metadata`:** not tried.
- **`decodeBase64` groups (33):** not reachable through either C ABI.
- **Loading the image into a JVM process** (`JNI_*` symbol overlap): not
  tested.
- **Web Image as an exported library, workerd, browsers:** not tried.
- **Bit-for-bit reproducibility with a single build thread:** not tried.
