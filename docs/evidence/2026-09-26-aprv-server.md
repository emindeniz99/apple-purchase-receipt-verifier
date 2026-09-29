# aprv-server: the canonical aprv.wasm behind HTTP, a CLI, and Java 8

Date: 2026-09-26. Code, scripts and raw results are in
`2026-09-26-aprv-server/`; its `README.md` has the file table and the
commands to reproduce.

**Question.** Can one Rust binary host the canonical ABI v1 module
(`aprv-abi1.wasm`, sha256 `b14e14b2…87b636b3`, 2,952,613 bytes) through the
`wasmtime` crate as an HTTP adapter, a one-shot CLI and a supervised child
of a Java 8 JVM, with process isolation and Wasm isolation, fast enough and
small enough to ship? It feeds R17 (the sidecar), the `-java8` artifact
(R18) and the Maven Central size budget.

**Owner constraint for Java 8:** hostile receipts and JWS are never parsed
by native code inside the JVM. JNI, JNA and UniFFI appear below only as
same-process size and speed references, not as options.

Labels: TESTED (ran here), DOCUMENTED (read in a primary source), EXPECTED
(inferred, not run). Linux x86-64 only unless a line says otherwise.
Versions are in `results/versions.txt`: rustc 1.98.1, `wasmtime` 49.0.1
(the current release on crates.io on 2026-09-26, published 2026-09-24,
MSRV 1.96), axum 0.8.9, tokio 1.53.1, Temurin 1.8.0_504, PHP 8.4.19.
Nothing under `rust/`, `docs/rust-core/` or any other production path
changed.

## Result

- **Both server variants work and agree with Node on every row they can
  answer.** 6,153 of 6,179 corpus rows are byte-identical to the Node rows
  of the same module, under both lifecycles. 25 rows get HTTP 413 because
  their body is over 3 MiB; Node refused all 25 as well. 1 row cannot be
  expressed in ABI v1 (as in Node). 0 differ (TESTED,
  `results/corpus-http.txt`).
- **Variant B is the one to ship:** runtime-only Wasmtime with the module
  precompiled at build time. It starts in 10 ms instead of 900 ms, idles at
  21 MiB instead of 116 MiB, is 3.6 MB gzipped instead of 5.1 MB, and
  verifies as fast as variant A: 240 to 279 receipts and 125 to 142 JWS
  per server CPU-second, 12 to 28 times the 10/s/core floor (TESTED).
- **Lifecycle: a fresh Store and Instance per request.** It meets the
  floor by the same margin, and nothing carries from one hostile input to
  the next request. The pool is 2.3 to 2.5 times faster for receipts and
  1.4 to 1.5 times for JWS, and stays available as `--lifecycle pool`.
- **Java 8 managed mode works on Temurin 8.** The JVM survives a
  deliberate child abort, the next call restarts the child and succeeds,
  and no child outlives the JVM, whether it calls `close()`, exits or is
  killed with SIGKILL. 31 of 31 checks pass (TESTED, `results/java8.txt`).
- **The server binaries do not fit in the Maven Central jar at our release
  rate.** B for six platforms comes to about 21 MB per release (EXPECTED
  from one measured platform). The monthly budget of about 80 MB then
  allows 3 releases, where the plan allows 7. Ship them on GitHub
  Releases and GHCR, and pin their SHA-256 in the 16 KB Java client.
- **Pulley misses the JWS floor.** Where Cranelift has no backend (for
  example ppc64le), Wasmtime runs the module in its Pulley interpreter:
  5.6 to 7.5 JWS per second per core (TESTED on x86-64), under 10.

## 1. What was built

`server/` builds one binary, `aprv`:

- `aprv serve`: routes `POST /v1/receipt/verify` (operation 1; the body is
  the UTF-8 base64 receipt-data text, chosen because it is what clients
  already send and the module decodes it), `POST /v1/signed-data/verify`
  (2, compact JWS text), `POST /v1/verify-receipt/production` and
  `/sandbox` (3 and 4, Apple's request JSON untouched), `GET /healthz`,
  `GET /readyz`.
- The server has no base64, CMS, JWS, certificate or policy code. A route
  picks the operation, and the body goes to `invoke(op, bytes) -> bytes`
  as it arrived. `invoke` is the brief's lifecycle: `aprv_alloc`, copy in,
  `aprv_call(1, op, ptr, len)`, bounds-check the result pointer and
  length, copy out, `aprv_result_free`, `aprv_dealloc`. Any error discards
  the instance (`server/src/abi.rs`).
- Host imports: `aprv.clock_now_ms` returns `SystemTime::now()` in
  milliseconds, and `aprv.random_get` fills guest memory from the OS
  CSPRNG through `getrandom` 0.3. An out-of-bounds range traps. Any other
  import is refused at load.
- Status mapping: every verification result, verified or not, is HTTP 200
  with the module's JSON. A trap is 500 `WASM_TRAP`, an ABI fault is 500
  `ABI_ERROR`, a lost worker is 500 `INTERNAL_ERROR`, and a body over
  3,145,728 bytes is 413, which is Apple's limit and `fixtures/cases.json`'s.
  With a token configured, a missing or wrong `X-Aprv-Token` is 401.
- Each Store is capped at 256 MiB of linear memory (`StoreLimits`) and one
  instance. A worker semaphore allows N concurrent verifications, where N
  is the CPU count by default.
- Spike-only features, never default: `spike` adds `/spike/call/{op}` for
  the corpus's test variants (op + 256: test anchors and a pinned clock,
  parsed by the guest) and an in-process `bench`; `crash` adds
  `POST /spike/crash`, which calls `abort()`.

Code size: 730 lines of Rust (`abi.rs` 303, `server.rs` 237, `main.rs` 190).

## 2. Variant A against variant B, measured

A = `wasmtime` with `runtime`, `std`, `cranelift`, `parallel-compilation`;
the `.wasm` is embedded and compiled at start.
B = `wasmtime` with `runtime` and `std` only. Everything else the 49.0.1
crate lets you turn off is off: `cranelift`, `winch`, `cache`,
`component-model`, `gc*`, `wat`, `async`, `threads`, `stack-switching`,
`profiling`, `coredump`, `addr2line`, `demangle`, `debug-builtins`,
`pooling-allocator`, `wit-parser`, `compile-time-builtins`
(`results/info.txt` shows the resolved feature tree). The module is
precompiled by A (`aprv precompile`) and deserialized by B, either
embedded with `include_bytes!` or read from a side file whose SHA-256 must
equal a hash compiled into the binary.

| | A: full + .wasm | B: runtime + embedded .cwasm | B: runtime + side-file .cwasm |
|---|---:|---:|---:|
| Binary, unstripped | 16,912,600 B | 10,793,512 B | 2,343,904 B + 8,449,864 B file |
| Binary, stripped | 14,455,192 B | 10,315,096 B | 1,865,512 B + 8,449,864 B file |
| gzip -9 (release artifact) | 5,065,681 B | 3,582,068 B | 843,498 + 2,738,871 = 3,582,369 B |
| xz -9 | 3,597,656 B | 2,726,552 B | 659,664 + 2,072,024 = 2,731,688 B |
| Start to listening (median of 5) | 900 ms | 9.8 ms | 21.5 ms |
| First verification (fresh instance) | 5.0 ms | 5.1 ms | 5.7 ms |
| RSS idle | 115.6 MiB | 20.7 MiB | 12.7 MiB |
| RSS peak (4 clients; side file: 21 sequential calls) | 122.0 MiB | 26.5 MiB | 20.2 MiB |
| Receipt per server CPU-second, 1 / 4 clients | 262 / 233 | 279 / 240 | same code as embedded |
| JWS per server CPU-second, 1 / 4 clients | 136 / 131 | 142 / 125 | same code as embedded |

Sources: `results/sizes.txt`, `results/server-a-vs-b.txt` (throughput from
`aprv-spike` for A and `aprv-min-spike` for B, the same builds plus the
spike route the JWS needs). All TESTED on 4 vCPUs (Xeon 2.1 GHz), with the
load generator on the same vCPUs. "Per server CPU-second" is requests
divided by the server's own user and system time. The JWS runs through
`/spike/call/258`. The shared-sandbox JWS verifies only against the
corpus's test anchors, and public operation 2 has no way to pass them.
Through the public route the same JWS is a result value, `INVALID_CHAIN`.

- A's 900 ms and 116 MiB are Cranelift compiling 2.95 MB of Wasm with
  parallel compilation on 4 cores; the compiler's heap stays resident.
- Cranelift costs about 9.6 MB stripped: A minus the embedded `.wasm`,
  against B's side-file binary. The HTTP stack (axum, hyper, tokio)
  costs 0.76 MB stripped, 0.35 MB gzipped: `aprv-min` minus `aprv-cli`.
- Embedding and a side file ship the same compressed bytes. Embedding
  costs 8 MiB more idle RSS here (the `.rodata` copy is touched once when
  it is deserialized). The side file costs 12 ms more at start, spent
  hashing 8.4 MB with the `sha2` crate. Embedding needs no second file to
  keep in step and no pin to check, so it is the default.
- B's release gzip (3.58 MB) is smaller than A's (5.07 MB) although the
  `.cwasm` (8.45 MB) is 2.9 times the `.wasm`, because Cranelift is gone.

**Record for B** (`results/versions.txt`, `results/info.txt`): canonical
`aprv.wasm` sha256 `b14e14b2c3b8a38953c6ac03d941e42647321fdb86cfb0e3629c006687b636b3`;
precompiled `aprv-abi1.cwasm` sha256
`31ca2603abcac8e266e5b55f6fe8fb35ff9ae0e917e5f88ccd725603e6147b28`
(8,449,864 bytes, byte-identical over repeated precompiles); Wasmtime
49.0.1; target `x86_64-unknown-linux-gnu`; `Config::new()` with no
setting changed (the full build adds Cranelift with no custom flags, and
the runtime-only build has no compiler); per Store, `StoreLimits` with
256 MiB of memory, 1 instance and `trap_on_grow_failure`.

**The precompiled artifact is platform-specific, and by default
machine-specific too** (TESTED, `results/baseline-target.txt`). A
Cranelift `.cwasm` is an ELF object for one target. `Config::new()` also
compiles for the build machine's CPU features, and this Xeon has AVX-512.
With an explicit `Config::target("x86_64-unknown-linux-gnu")` the result
is a different, baseline artifact (sha256 `d14a8819…6e13b562`, 8,458,112
bytes). It loaded and ran just as fast here: 266 receipts and 141 JWS per
CPU-second. A release build must precompile with an explicit target.
Otherwise the artifact may refuse to load on a CPU older than the CI
runner's. Wasmtime refuses such a module with "compilation settings are
not compatible with the native host", the error seen here when the
target was wrong. Every OS/ISA pair needs its own `.cwasm`, and so its own
B binary (EXPECTED for OSes other than Linux, which were not tried).

**Trust rule for precompiled code.** `Module::deserialize` is `unsafe`:
per its documentation the bytes are native code, and they are safe only if
they are the unmodified output of `Module::serialize` or
`Engine::precompile_module`. Wasmtime rejects output from other Wasmtime
versions, but it does not validate arbitrary bytes (DOCUMENTED, the
49.0.1 source). So the binary deserializes only two things: bytes embedded
at build time, which are part of the binary we sign and checksum, or a
side file whose SHA-256 equals the hash compiled in (`APRV_CWASM_SHA256`).
It refuses everything else before Wasmtime sees it. A tampered side file
exits with code 70 and never loads, and the runtime-only build refuses a
`.wasm` because it has no compiler (TESTED, `results/info.txt`). Never
load a `.cwasm` from a cache someone else can write, or from the network
without that pin. `deserialize_file` (mmap) also needs the file unchanged
while it is mapped; the spike reads it into memory instead.

## 3. Lifecycle: pool against fresh

HTTP, variant A build, 8 s per point (`results/bench-http.txt`):

| Clients | Receipt per server CPU-s, pool / fresh | JWS per server CPU-s, pool / fresh | Receipt p50, pool / fresh |
|---:|---:|---:|---:|
| 1 | 603 / 258 | 201 / 142 | 1.7 / 3.7 ms |
| 2 | 571 / 248 | 199 / 138 | 1.8 / 4.0 ms |
| 4 | 600 / 242 | 202 / 132 | 2.1 / 4.9 ms |

In-process, without HTTP (`results/bench-inprocess.txt`), one thread
does 793 receipts/s with the pool and 359/s fresh. With Wasmtime's
pooling allocator, fresh does 289/s: no better, so the extra 1.6 ms is
the guest initialising OpenSSL and its roots on the instance's first
call, not Wasmtime allocating the instance. JWS: 189/s pool, 151/s fresh.

**Chosen: fresh (the brief's model B).** It clears 10/s/core 24 to 26
times for receipts and 13 to 14 times for JWS on this host. No state from a hostile input
reaches the next request, and a trap needs no pool bookkeeping. Where
throughput matters more, the pool (the brief's model A) is one flag away.
It destroys a pair on any trap or ABI error and never shares one
instance between two requests.

## 4. Correctness through HTTP

`py/corpus_http.py` sends every call of the ABI round's five calls files
(1,179 rows and 5,000 mutants) to the server. Operations 1 to 4 go through
the public routes and the test variants 257 to 260 through the spike
route. Each answer is compared byte for byte with the Node row of the same
module. As in the ABI round, `request_date*` is masked on endpoint answers
whose clock is not pinned, because it is the wall clock.

| | fresh | pool |
|---|---:|---:|
| Public routes, identical | 384 | 384 |
| Spike route, identical | 5,769 | 5,769 |
| HTTP 413, body over 3 MiB (Node refused each of them too) | 25 | 25 |
| Not expressible in ABI v1 (as in Node) | 1 | 1 |
| Different | **0** | **0** |

The spike route accepts 1 MiB more than 3 MiB for the envelope's test
anchors, so the corpus's receipt at the size cap is compared too. On the
public routes a body over the cap gets 413, as Apple's endpoint gives,
where the module alone answers `21002`/`REQUEST_TOO_LARGE`.

## 5. One-shot CLI (the PHP question)

`aprv verify-receipt | verify-signed-data | verify-receipt-endpoint <env>`
reads stdin (up to 3 MiB), runs one operation in one fresh instance,
writes the JSON and exits. Exit codes: 0 for any result, 3 for input too
large, 70 for a trap, ABI fault or load failure. `results/cli.txt`, g5
receipt, 30 sequential and 200 calls from 4 parallel callers:

| Binary | Latency per process, median / p90 | Calls/s, 4 callers | Calls per child CPU-second |
|---|---:|---:|---:|
| B, CLI only, embedded `.cwasm` (9.55 MB stripped, 3.24 MB gzip) | 12.5 / 17.5 ms | 355 | 102 |
| B, server binary used as CLI | 12.1 / 13.5 ms | 326 | 91 |
| B, side-file `.cwasm` (hash checked) | 24.3 / 29.3 ms | 196 | 52 |
| A, compiling the `.wasm` at each start | 881 / 900 ms | 1.4 | **0.4** |

The CLI only works with a precompiled module. Compiling at each start
gives 0.4 calls per CPU-second, far under the floor.

## 6. Java 8: three ways to reach the server

`java/AprvClient.java` (457 lines, Java 8, no dependencies; 15,779 bytes
of classes) resolves in this order:

1. **A configured URL** (`APRV_SERVER_URL` / `-Daprv.server.url`, token
   `APRV_SERVER_TOKEN`): an external service, a sidecar container or a
   Docker service. The JVM starts nothing and needs no writable or
   executable directory. TESTED against a standalone B with a token: 6/6
   checks pass, 3.6 ms per g5 call.
2. **A configured executable** (`APRV_SERVER_EXECUTABLE` /
   `-Daprv.server.executable`, for example `/opt/aprv/bin/aprv`): the
   client starts `aprv serve --managed` and supervises it. Nothing is
   extracted, so a read-only file system is fine. The binary's own mount
   must allow exec.
3. **Opt-in managed download** (`-Daprv.server.download=true`): see
   below. It needs a writable, exec-allowed cache directory. On a
   `noexec` home or `/tmp` the start fails with EACCES (seen in the
   2026-09-25 sidecar spike). Such hosts use mode 1 or 2.

**Managed mode, TESTED on Temurin 8u504** (`results/java8.txt`, 13/13):

- The child binds `127.0.0.1:0` whatever `APRV_LISTEN` says and reports
  its port as one stdout line. The parent sends a fresh 256-bit
  `SecureRandom` token as the first stdin line, not in argv (world-readable
  under `/proc`) or the environment. Requests without the token, or with a
  wrong one, get 401. stdin stays open: the child exits on its EOF.
- All three operations work: g5 verifies; the shared-sandbox JWS returns
  an `INVALID_CHAIN` value under Apple's roots; the endpoint answers 0 on
  sandbox and 21007 on production.
- **Deliberate crash:** `POST /spike/crash` makes the child `abort()`. The
  JVM carries on, and the next call restarts the child and succeeds: 18.7 ms
  for that call, restart included. A `kill -9` of the child recovers the
  same way. A child that dies 10 times within a minute is not restarted.
- **No orphans:** `close()` closes stdin and the child exits.
  `System.exit` without `close()`: the shutdown hook stops it. `kill -9`
  of the JVM, where no hook runs: the child sees stdin EOF and exits. In
  this container it stays a zombie until PID 1 reaps it, but it has
  exited. All TESTED.
- Child start to port: 76 ms, measured from the JVM. First
  verification: 8.0 ms.
- **Local HTTP round trip** (one write per request, `TCP_NODELAY`, the
  lesson from R17): `GET /healthz` 43.7 µs. g5 verify from Java 8:
  3.87 ms mean, 3.71 ms p50, 6.09 ms p99, 258/s on one thread; 719/s on 4
  threads, with the JVM and the child on the same 4 vCPUs.

**Managed download (mode 3), prototype TESTED** against `python3 -m
http.server` on loopback, standing in for GitHub Releases:

- The expected SHA-256 per platform is pinned in the Java artifact. The
  file downloads into an owner-only (0700) cache directory as a 0600
  temp file, hashed while it streams (64 MiB cap). It becomes 0500 and is
  renamed atomically to `aprv-<sha256>` only if the hash matches. It is
  re-hashed before every start.
- Two JVMs, 4 threads each, empty cache: **one** GET reached the server,
  and all 8 callers got the same verified file. The lock is a `FileLock`
  between processes plus a monitor between threads, since `FileLock` is
  per process.
- A cache entry changed after download is detected at the next start,
  deleted, fetched again and verified before it runs.
- A download whose hash is not the pin is refused with a
  `SecurityException` before it is ever made executable, and the cache
  keeps nothing.
- Production must fetch over HTTPS only. The test allows `http://` for a
  loopback host only, behind an explicit flag. A GitHub asset redirects,
  but the pin still decides.

## 7. PHP

`php/Aprv.php` (92 lines) is one façade (`verifyReceipt`,
`verifySignedData`, `verifyReceiptEndpoint`) over two transports.
`CliTransport` runs `proc_open` with an argv array, so no shell is
involved. `HttpTransport` reuses one curl handle for keep-alive. TESTED
(`results/php.txt`):

| Transport | g5 per call | 200-row corpus slice (public operations): identical to Node | Per row |
|---|---:|---:|---:|
| CLI, one process per call (B, `aprv-cli`) | 11.6 ms | 200 / 200 | 9.6 ms |
| HTTP to a running B | 3.56 ms | 200 / 200 | 2.4 ms |

## 8. Docker

`docker/Dockerfile` has two stages. The first is `rust:1.98.1-slim-trixie`:
it checks the module's SHA-256, builds A, precompiles, then builds B with
the `.cwasm` embedded and strips it. The second is
`gcr.io/distroless/cc-debian13:nonroot`: uid 65532, no shell, entrypoint
`aprv serve`. Inside the container the server listens on `127.0.0.1:8080`,
so a published port reaches nothing until `APRV_LISTEN=0.0.0.0:8080` is
set explicitly: `docker run -e APRV_LISTEN=0.0.0.0:8080 -p
127.0.0.1:8080:8080 …`. Both base tags exist (checked on Docker Hub and
gcr.io); pin them by digest before real use.

**Not built and not run:** `docker info` failed here because no daemon is
listening on `/var/run/docker.sock` (`results/docker.txt`). Per the task,
the daemon was not started. The amd64 image and smoke test
(`scripts/docker.sh`) and arm64 are untested.

## 9. Where Wasmtime runs natively, and where only Pulley runs it

DOCUMENTED ([platform support](https://docs.wasmtime.dev/stability-platform-support.html),
[tiers](https://docs.wasmtime.dev/stability-tiers.html), read 2026-09-26):
"Cranelift supports x86_64, aarch64, s390x, and riscv64. No 32-bit
platform is currently supported." Tier 1 is `x86_64` on Linux, macOS and
Windows (MSVC). Tier 2 is `aarch64` on Linux and macOS, `s390x` Linux,
`x86_64-pc-windows-gnu`, and the Pulley backend. Tier 3 includes
`powerpc64le-unknown-linux-gnu`, `aarch64-pc-windows-msvc`, `armv7`,
`i686`, `riscv64gc` and musl. Pulley is "a portable WebAssembly
interpreter", and Wasmtime falls back to it where Cranelift has no
backend. The 49.0.1 `build.rs` turns Pulley on as the default target when
the host has no compiler backend.

TESTED (`results/pulley.txt`):

- **Pulley on x86-64**, built with the `pulley` feature and target
  `pulley64`, one thread: receipt 31.8/s (pool) and 18.5/s (fresh); JWS
  **7.5/s (pool) and 5.6/s (fresh)**. At 4 threads, fresh: 64 receipts/s
  and 21 JWS/s, about 5 per core. JWS falls under the 10/s/core floor.
  Receipts clear it.
- **ppc64le, variant B, cross-built** (`powerpc64le-linux-gnu-gcc`),
  embedding a `pulley64` `.cwasm` precompiled on x86-64. That artifact is
  6,399,792 bytes, 2,409,608 gzipped, sha256 `060a5fe2…31b6d05e`. Under
  `qemu-ppc64le` 8.2.2 user mode: it starts, deserializes the module in
  38.5 ms, answers `/healthz`, verifies g5 at 2.2/s and the JWS at 0.9/s.
  One `pulley64` artifact serves every 64-bit little-endian host. The
  emulated speed says nothing about real POWER hardware; it proves the
  path works.
- A Pulley platform would get a Java 8 server that verifies receipts
  within the floor and JWS below it. s390x has a Cranelift backend and so
  should not need Pulley (EXPECTED; not run here).

## 10. Size references and the Maven Central budget

| Row | Isolation | Stripped | gzip -9 | Receipt / JWS | Source |
|---|---|---:|---:|---|---|
| (1) Full Wasmtime + `.wasm` (variant A) | process + Wasm | 14,455,192 B | 5,065,681 B | 262 / 136 per CPU-s over HTTP | TESTED, §2 |
| (2) Runtime-only Wasmtime + precompiled `.cwasm` (variant B) | process + Wasm | 10,315,096 B | 3,582,068 B | 279 / 142 per CPU-s over HTTP | TESTED, §2 |
| (3) Native Rust server calling the OpenSSL core directly | process only | ≈ 8.1 MB | ≈ 3.1 MB | ≈ 0.76 ms / ≈ 0.85 ms per call over HTTP | **EXPECTED, not built**: the substrate bake-off's `ossl402` C ABI `.so` (7,328,168 B stripped, 2,733,498 B gzip; receipt p50 399 µs, JWS 479 µs, 2,448 receipts/s on 1 thread) plus this spike's HTTP stack (0.76 MB, 0.35 MB gzip) plus the 2026-09-25 sidecar's ~365 µs per HTTP call |
| (4) In-process native in the JVM (JNI / JNA / UniFFI) | **none: same process, not acceptable for Java 8** | 1.14 MB (jni-rs, pure-Rust core); 7.33 MB for the OpenSSL-core C ABI | 2.73 MB (OpenSSL core) | 552 µs / 862 µs per call on JDK 8 (pure-Rust core) | The 2026-09-25 Java bake-off and the substrate bake-off; reference only |

Row (3) is the fastest process-isolated option, about 5 times faster per
receipt and 8 times per JWS than B at one client. It gives up the Wasm sandbox: a memory-safety bug in
OpenSSL's parsing of a hostile receipt runs code in the server process.
Under B the same bug stays inside the guest's linear memory.

**Budget.** Maven Central allows about 80 MB per calendar month in all
(CLAUDE.md). A jar compresses with deflate, so the gzip column is the
cost. If the `-java8` artifact carried B for six platforms (Linux, macOS
and Windows on x86-64 and arm64) at the measured 3.58 MB, that is about
21.5 MB per release (EXPECTED: the other five platforms were not built).
80 MB then allows 3 releases a month, where the plan allows 7 and keeps
2 in reserve. A costs 5.07 MB per platform, about 30 MB per release. A
side file saves nothing: binary and `.cwasm` gzip to the same total.
Leaving the binaries out of the jar makes the Java artifact about 16 KB
of client classes (this spike's), with a SHA-256 pinned per platform.

## 11. Recommendation for Java 8

1. **Keep both isolations.** The `-java8` artifact becomes a pure-Java
   client with no native code in the JVM. It talks to aprv-server variant
   B, runtime-only Wasmtime with the module precompiled for an explicit
   baseline target and embedded. The parser runs in another process, and
   inside that process in the Wasm sandbox.
2. **Resolution order as built here.** A configured URL first (Docker or
   sidecar deployments, nothing extracted or executed). Then a configured
   executable the operator installed, started and supervised on loopback
   with a stdin token. Then, opt-in only, a download from GitHub Releases
   checked against the SHA-256 in the jar, cached owner-only under a lock.
3. **Publish the binaries outside Central:** GitHub Release assets per
   platform, with the image on GHCR (R17 already plans that). Central
   carries only the client, so it spends one release's budget no matter
   how many platforms exist.
4. **Lifecycle fresh by default,** with `pool` as a documented option.
   CLI mode only with a precompiled module.
5. **Open before production:**
   - The Docker image build and smoke test.
   - arm64, macOS and Windows builds and sizes.
   - A guest time limit (Wasmtime epoch interruption), so a looping input
     cannot hold a worker; the spike caps memory only.
   - Whether Pulley-only platforms get Java 8 support at all, given the
     JWS floor.
   - Release-time precompilation with an explicit target in CI.

## Where this stops holding

- Linux x86-64, 4 vCPUs, glibc. The load generator shared the vCPUs, and
  another agent's builds ran on the same machine; load averages are in
  each result file's header, 0.85 to 3.3. Run-to-run spread was about
  ±10% (compare `bench-http.txt` with the A/B table).
- The JWS numbers use the test-anchor variant (op 258) because no JWS in
  the repository verifies against Apple's roots. It does the same
  signature and chain work.
- One module (`aprv-abi1.wasm`, sha256 above) and Wasmtime 49.0.1.
  Another Wasmtime version needs a new `.cwasm`.
- The ppc64le run is emulated, and the Pulley rows in `results/pulley.txt`
  come from the ppc64le run one source revision earlier, before the
  `StoreLimits` cap; the x86-64 Pulley rows were rerun on the final code.
