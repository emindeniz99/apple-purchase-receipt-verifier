# Threat model of the 0.8 architecture

Status: **accepted plan**, 2026-09-28. The root
[THREAT-MODEL.md](../../THREAT-MODEL.md) covers the verification
algorithm: pinned trust, marker OIDs, signatures over exact bytes, time,
hostile-byte bounds. It holds unchanged for 0.8.0, since the API and the
fixtures do not change. This file covers what 0.8.0 adds: where the one
Rust core runs, what separates a hostile receipt from the caller's
process, and what each package trusts. The decisions it rests on are
DECISIONS.md R22 to R34.

## 1. Assets and inputs

Attacker-chosen, as in the root model: the `receipt-data` base64 string,
the compact JWS with its `x5c` chain, and the verifyReceipt request body.
New in 0.8.0, reachable only by someone who can already write where the
package lives or reach the server:

| Input | Where it enters | Who may supply it |
|---|---|---|
| `aprv.wasm` | every Wasm host | our release build only (§4) |
| A precompiled `.cwasm` | `aprv-server`; wasmtime-py's cache directory | our release build only; the Python cache under §8's rules |
| An `aprv-server` binary | the Java `-wasm` server engine; PHP's `aprv install` | our release build, checked against a pinned SHA-256 (§7, §9) |
| Requests to `aprv-server` | loopback or the network the operator binds it to | holders of the token, when one is set (§6) |

## 2. The isolation classes

| Class | Where the guest runs | What bounds it | Hosts |
|---|---|---|---|
| **A** | Wasm in the caller's process, interpreted | software bounds checks in the interpreter; no machine code generated | WasmKit (Swift). Wasmi would be here |
| **B** | Wasm in the caller's process, compiled to machine code | the runtime's JIT or AOT code, with guard pages and signal handlers | Wasmtime (wasmtime-py, the Ruby gem, Wasmtime .NET, and inside `aprv-server`); wazero (Go); the JS engines |
| **C** | JVM bytecode compiled from Wasm, in the caller's JVM | the JVM's own memory safety; no native code | Endive (Java 11+) |
| **D** | a separate process | the operating system's process boundary, and class B inside it | `aprv-server` as the Java 8 managed child, PHP's CLI per call, any HTTP client |
| **E** | native code in the caller's process | nothing | not shipped; the C ABI, and Go's opt-in native build, for users who choose them |

WasmKit's class is its execution model, an interpreter that generates no
machine code. The Swift note records software bounds checks and an
mprotect-based mode compiled for Linux and macOS ([Swift][swift]); the
shipped configuration uses software bounds checks, so the package installs
no process-wide signal handler (swift/README.md, "How it works").

## 3. What a guest compromise reaches

"Guest compromise" means a hostile input that gains control of the code
inside `aprv.wasm`: a memory-safety bug in OpenSSL's parsing or in our
Rust reached through a receipt, the case the Wasm boundary exists for.

**In every class, the verdict.** The guest computes the answer. A
compromised guest can return "verified" for a forged receipt, or a wrong
payload. Isolation protects the host process, never the verdict. The
defences for the verdict are the root model's: the fixtures, fuzzing into
OpenSSL, the owner's review of the core, and the Java implementation as a
second opinion (R33).

**In every class, the instance.** A compromised instance that does not
trap keeps its state. Where an instance serves more than one call (the
in-process pools, and `aprv-server` with `--lifecycle pool`), a later
call on that instance runs in the attacker's state. `aprv-server`'s
default, a fresh instance per request, removes that carry-over (R23).

Beyond that, per class:

| Class | The guest can reach | To escape it needs |
|---|---|---|
| A | its linear memory; `random-get`, which only returns random bytes the guest copies into its own memory | a bug in the interpreter. WasmKit stops the process with a precondition failure on an out-of-range memory access by the host, so the wrapper checks every range first ([Swift][swift]); a host-side slip there is a crash, not an escape |
| B | the same | a bug in the runtime's compiler, its bounds checking or its signal handling; the prize is the caller's process |
| C | the same, held in a Java `byte[]` or `ByteBuffer` | a miscompile gives wrong answers or exceptions, since the JVM verifies the generated classes for type safety when they load ([Endive §10][endive]); memory corruption would need a JVM bug |
| D | the server process, with the operating-system rights of its user: files and network, not the caller's memory. Inside, class B still holds | an escape from Wasmtime, then whatever the server's user may do |
| E | the caller's process | nothing more |

The server note puts the contrast in one line: a native server calling
the OpenSSL core directly would be about 5 times faster per receipt, and
a memory-safety bug in OpenSSL's parsing of a hostile receipt would run
code in the server process; with the Wasm module the same bug stays
inside the guest's linear memory ([aprv-server §10][server]).

## 4. `aprv.wasm`: our build, one hash

- **Built by our release job, once per release, with no cache,** from our
  source, with rustc, wasi-sdk and the OpenSSL tarball pinned by version
  and SHA-256, paths remapped so a second build can reproduce the hash.
- **Its SHA-256 is published with the release** beside a build-provenance
  attestation. Every package that carries the module checks its copy
  against that hash in its release job; the committed copies in `go/` and
  the Swift package are rebuilt in CI and compared.
- **Its only import is `random-get`.** CI lists the imports and fails
  on anything else, and the link-time C file traps on every other WASI
  function (ARCHITECTURE.md §3). A host refuses to instantiate a module
  that asks for more. The WIT file is the contract: CI reads the
  interface back from the built module and diffs it (ARCHITECTURE.md §9).
- **Its SHA-256 is reproducible and its contents are named.** The
  release job rebuilds the module once with `tools/reproduce-wasm.sh`
  and compares the hash; a CycloneDX SBOM and SLSA provenance travel
  with it (R34).
- **Endive compiles only this module.** Endive's documentation says its
  compiler does no post-compilation verification and to compile only
  trusted modules ([Endive §10][endive]); ours is built by our CI, so the
  assumption holds. The attack surface at run time is the receipt and
  JWS bytes. The byte-for-byte corpus run through the built jar on every
  change is the guard against a miscompile.
- **Precompiled native code is trusted like a binary.** Wasmtime's
  `Module::deserialize` runs its input as machine code without validating
  it. `aprv-server` deserializes only the `.cwasm` embedded at build time,
  inside the binary we attest, and the runtime-only build has no compiler
  to accept anything else ([aprv-server §2][server]). Python's cache is
  the one other place compiled code lives (§8).

## 5. Resource limits per host

Every host inherits the core's input bounds (the root model §3.7, and the
0.7 bounds table). Over the whole corpus the module's linear memory
peaked at 23,789,568 bytes ([final Python round §2][pyfinal]), measured
on the ABI v1 module before the core review's fixes and not repeated on
the current one. A hostile 3 MiB receipt of tiny attributes used to peak
at 145 MiB of process memory in Node ([ASN.1 payload §3][payload]). Since
the review's fixes one header walk bounds the envelope and the payload
before anything is decoded, and the unsigned and signerless forms peak
near 16 to 18 MiB: the signerless receipt grew linear memory from 1.9 to
16.1 MiB in 16.5 to 26 ms through `aprv.wasm` in V8, and the unsigned
one with a signer certificate peaked near 18 MiB ([core review
fixes][corefix]). The signed-payload path (R21) reaches the full payload
decode after the walk and the signature, and was not re-measured, so no
current figure exists for it. The node budget bounds the envelope's walk,
not the cost of every shape under it: one unsigned attribute of about
100,000 OBJECT IDENTIFIERs, which anyone can append to any genuine
receipt outside its signature, is walked, decoded in full and verifies.
With 20-octet identifiers (2.2 MB) it cost 126 to 149 ms natively and
101 to 128 ms through `aprv.wasm` in V8, with 16.9 MiB of linear memory,
against 0.45 ms and 7 to 10 ms for the receipt alone on the same loaded
machine ([core review fixes][corefix], round 3). That is the costliest
anonymous request found under the budget so far; interpreter hosts pay
several times more.

| Host | Memory | CPU and time | Concurrency |
|---|---|---|---|
| `aprv-server` | `StoreLimits`: 256 MiB of linear memory, one instance, `trap_on_grow_failure` | 10 s of guest time per call by default (`--time-limit-ms`), by epoch interruption (rust/server/README.md, "Limits") | a semaphore of N workers, N = CPU count; the 3 MiB body cap, answered with 413 |
| wasmtime-py, the Ruby gem, Wasmtime .NET | Wasmtime's store limits, available in each binding; Phase 5 sets the server's 256 MiB and tests it | epoch interruption and fuel are Wasmtime features; not exercised in the evidence | one instance per call; the pool bounds the count |
| wazero (Go) | wazero's memory page limit; Phase 4 sets and tests it | context cancellation; not exercised in the evidence | the pool |
| JS engines | the engine's limit for a 32-bit memory; workerd's 128 MB isolate, measured in Phase 4 | the platform's own CPU limits | one instance |
| WasmKit (Swift) | not exercised in the evidence | not exercised in the evidence | one instance per thread |
| Endive (Java 11+) | none by default: the module declares no maximum, so memory can grow to the JVM's heap ([Endive §10][endive]) | none by default | one instance per call, from the pool |
| Java 8 server engine, PHP | as `aprv-server` | as `aprv-server`; PHP's CLI process ends with each call | the server's; PHP one process per call |

Where a runtime offers a limit the evidence did not exercise, the phase
that lands the host sets it and adds a hostile-module test like round 11's
(infinite loop, unbounded growth, a 1 GiB `memory.grow`), which only the
Wasmi bindings ran ([final Python round §4][pyfinal]).

## 6. `aprv-server`: token and loopback

- **Binding.** `127.0.0.1` unless `APRV_LISTEN` says otherwise. In the
  Docker image the server listens on `127.0.0.1:8080` inside the
  container, so a published port reaches nothing until the operator sets
  `APRV_LISTEN=0.0.0.0:8080` and publishes it, preferably as
  `-p 127.0.0.1:8080:8080` ([aprv-server §8][server]).
- **Token.** With a token configured, a request without the right
  `X-Aprv-Token` gets 401 ([aprv-server §1][server]). A server bound
  beyond loopback should always have one.
- **Managed mode** (the Java 8 child): the child binds `127.0.0.1:0`
  whatever `APRV_LISTEN` says, and reports its port on stdout. The parent
  sends a fresh 256-bit `SecureRandom` token as the first stdin line, not
  in argv, which is world-readable under `/proc`, and not in the
  environment. The child exits on stdin EOF, so it ends with the JVM,
  even after `kill -9` ([aprv-server §6][server]).
- **Plain HTTP.** The server speaks HTTP without TLS. It is meant for
  loopback, a sidecar or a private network; TLS termination belongs to
  the deployment.
- **The image** is distroless and runs as a non-root user (uid 65532 in
  the spike), with no shell, and its base is pinned by digest.
- **The one-shot CLI** has no socket: stdin in, stdout out, exit codes 0,
  3 and 70.

## 7. Java: two artifacts, two engines

- **The main artifact** is pure Java over BouncyCastle, in the JVM, with
  no Wasm and no native code: the 0.7 model, unchanged.
- **The `-wasm` artifact's engines differ in isolation.** Endive is class
  C, in process. The server engine is class D, with class B inside the
  child. The default depends on the JVM: C on Java 11+, D on Java 8. A
  Java 11+ user who wants the process boundary chooses
  `Engine.server(...)`.
- **Classpath guard.** The two artifacts expose the same class names. Each
  ships a marker resource and fails fast at startup when it finds both,
  so a consumer never runs one implementation believing it runs the
  other. The Gradle module metadata declares a capability conflict.
- **Server binaries.** `maven()`, `github()` and `download()` fetch or
  extract a binary whose SHA-256 is pinned: inside the `-wasm` jar for the
  first two, given by the user for the third. The binary is written to an
  owner-only cache directory as a temporary file, hashed while it
  streams, made executable and renamed only on a match, and hashed again
  before every start; a mismatch is never executed. Downloads use HTTPS
  only; a redirect does not change the pin ([aprv-server §6][server]).
- **`noexec` directories** block an extracted binary. Such hosts use
  `url()` or `executable()`, which extract nothing.
- **No configuration from the environment.** The artifact reads no system
  property and no environment variable of ours (R25), so nothing outside
  the code can switch its engine or point it at another binary.

## 8. Python's cache directory

wasmtime-py compiles `aprv.wasm` at start and, with `Config.cache` on,
stores the compiled native code on disk (R27). Anyone who can write that
directory can plant code the next Python process runs
([runtime options][pyopt], "Trust"). The rules:

1. The default is the running user's own cache directory, as
   platformdirs names it; with no home directory the cache is off.
2. An environment variable can point it elsewhere.
3. The cache is off, silently, when the directory is read-only. The
   process then compiles at start: about 1 s on 4 CPUs, 3 s on one.
4. The plan adds, from the same trust note: the cache is also off when
   the directory is not owned by the running user or is writable by
   group or others. A shared directory such as `/tmp` never holds it.
5. On AWS Lambda the package directory is read-only and nothing survives
   a cold start, so each new container compiles; the README documents it.

## 9. PHP

- The default transport runs the `aprv` binary once per call through
  `symfony/process`, from an argv array that holds only the subcommand,
  the clock and the roots file's path. The input goes on stdin, so
  nothing a caller or a receipt contains reaches a command line
  ([aprv-server §7][server]). How the binary starts depends on the
  release and the platform. On Unix, 7.4 starts it directly and uses
  `/bin/sh -c 'exec …'` only on a PHP built with `--enable-sigchild` or
  when the direct start fails; 6.4 always uses `/bin/sh -c 'exec …'`.
  On Windows it goes through `cmd.exe`. Every argument is quoted for the
  shell that reads it.
- The child's environment holds `PATH` and nothing else (on Windows also
  `SystemRoot` and `ComSpec`, which `cmd.exe` needs), so nothing an
  application loaded into `$_ENV` reaches it. On Unix the answer stays
  in the transport's memory and never touches disk. On Windows
  `symfony/process` routes the child's stdout and stderr through
  `sf_proc_NN` files in the temp directory (its workaround for PHP bug
  #51800), so there the answer, purchase data included, is written to
  disk. Symfony truncates those files when the call ends and does not
  delete them.
- The process boundary is class D and ends with the call.
- `aprv install` downloads the binary from GitHub Releases and checks it
  against the SHA-256 pinned in the Composer package before it installs
  it. Nothing downloads at request time.
- The optional server URL follows §6.

## 10. Runtime supply chain

- **What we build:** `aprv.wasm`, the `aprv-server` binaries, the
  classifier jars and every package. Rust dependencies are locked in one
  `Cargo.lock` and checked by cargo-deny and RustSec advisories; the
  server pins `wasmtime` (49.0.1 in the evidence). wasi-sdk and the
  OpenSSL tarball are pinned by SHA-256. Endive's plugin and runtime are
  pinned by version in the POM.
- **What our users resolve:** wasmtime-py, the `wasmtime` gem, the
  `Wasmtime` NuGet package, wazero and WasmKit are dependencies with a
  floor. Their fixes reach users through the users' own updates; we raise
  a floor when an advisory makes the old range unsafe. Each is a large
  native or compiler-bearing dependency that the package did not have in
  0.7.
- **Runtimes have bugs.** The Wasmi security review, done while Wasmi was
  a Python candidate, is the example: one issue reported privately
  upstream on 2026-09-27; not reachable for `aprv.wasm`
  ([Wasmi review][wasmi]). Wasmi is not shipped.
- **Publishing** never uses a cache, attests every artifact, and the
  post-publish smoke installs from the real registries.

## 11. Residual risks

- **Monoculture.** A bug in the core or in OpenSSL reaches every
  Wasm-hosted package at once. The Java implementation is the second
  opinion, not a fallback: a caller runs one or the other.
- **Isolation does not protect the verdict** (§3).
- **Endive** is young (1.0 on 2026-06-26, 1.1.0 on 2026-09-03) and does
  no post-compilation verification ([Endive §2, §10][endive]); JDK 17 and
  earlier run with its workaround for a C2 miscompilation.
- **No time limit yet** in the in-process Wasmtime hosts
  (§5).
- **Python's cache** is native code on disk (§8).
- **Downloaded server binaries** move trust to our release process; the
  pin inside the jar or the Composer package is what makes a replaced
  GitHub asset fail.
- **Temurin 8 builds end in late 2026.** The Java 8 CI leg moves to Zulu
  or Corretto; until then Java 8 security depends on the JVM vendor.

[swift]: ../evidence/2026-09-26-swift-wasmkit.md
[endive]: ../evidence/2026-09-26-endive-build-time-jvm.md
[server]: ../evidence/2026-09-26-aprv-server.md
[pyfinal]: ../evidence/2026-09-27-python-runtime-final.md
[pyopt]: ../evidence/2026-09-27-python-runtime-options.md
[payload]: ../evidence/2026-09-26-openssl-asn1-payload.md
[wasmi]: ../evidence/2026-09-27-wasmi-security-review.md
[corefix]: ../evidence/2026-09-29-core-review-fixes.md
