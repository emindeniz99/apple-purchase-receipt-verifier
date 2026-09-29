# apple-purchase-receipt-verifier-wasm (Java)

The same verifier as
[`apple-purchase-receipt-verifier`](../java/README.md), with the same
package, class names and API, answered by the shared Rust core instead of
the Java implementation. The core is compiled once to WebAssembly
(`aprv.wasm`), and this artifact runs that module on the JVM. Every
package of this project runs the same module, so a fix in the core
reaches this one with the next release.

Use one artifact or the other, never both. They have the same class names;
`Verifier.create` throws `IllegalStateException` when it finds both on the
classpath, and a Gradle build that asks for both fails at resolution.

```xml
<dependency>
  <groupId>io.github.emindeniz99</groupId>
  <artifactId>apple-purchase-receipt-verifier-wasm</artifactId>
  <version>0.7.0</version> <!-- x-release-please-version -->
</dependency>
```

Java 8 is the floor for the API. Where the module runs depends on the JVM:
see [Engines](#engines).

## Quick start

The main artifact's README applies as written: the three methods, the
results, the reasons, the endpoint and the checks that stay yours. The
only new part is the optional second argument of `Verifier.create`.

```java
// Build once, at startup, and share it: Verifier is immutable and thread-safe.
Verifier verifier = Verifier.create(Config.defaults());

VerificationResult<ReceiptPayload> receipt = verifier.verifyReceipt(receiptBase64);
VerificationResult<JsonPayload> jws = verifier.verifySignedData(signedTransaction);
String response = verifier.verifyReceiptEndpoint(Environment.PRODUCTION, requestBody);
```

## Engines

An engine is what runs `aprv.wasm`. It is chosen in code, and only in code:
this library reads no system property and no environment variable, so
nothing outside your program can switch the engine or point it at another
binary.

| Engine | Where the module runs | JVM | Isolation |
|---|---|---|---|
| `Engine.endive()` | in this JVM, as bytecode compiled from the module when this jar was built | Java 11 and later | the JVM's own memory safety; no native code |
| `Engine.server(...)` | in `aprv-server`, a separate process | Java 8 and later | the operating system's process boundary |

`Verifier.create(config)` picks by the JVM version alone: Endive on
Java 11 and later, the server engine with its default sources on Java 8.
To choose:

```java
Verifier inProcess = Verifier.create(config, Engine.endive());
Verifier separateProcess = Verifier.create(config,
        Engine.server(ServerSource.url(URI.create("http://127.0.0.1:8080"), token),
                      ServerSource.maven(),
                      ServerSource.github())
              .cacheDirectory(Paths.get("/var/cache/aprv")));
```

A verifier on the server engine owns a process or a connection pool, so
it implements `Closeable`: close it when you are done with it. One you
forget is closed when it becomes unreachable, and every open one is
closed when the JVM exits.

### Endive

[Endive](https://endive.run) (`run.endive`, Apache-2.0) compiles every
function of `aprv.wasm` to JVM bytecode when this artifact is built, with
no interpreter fallback. At run time your classpath holds this jar and
Endive's `runtime` and `wasm` jars, and nothing else from Endive: no
compiler, no interpreter, no native library. A test in this module reads
every class file of the three jars and of jackson-core and finds no native
method and no call that loads native code.

- The first verifier in a JVM pays for loading the compiled module and
  starting its first instance: about 1.1 s measured on a busy 4-CPU
  machine (the Endive evaluation measured 335 to 380 ms for the loading
  alone on an idle one). Each later instance takes about 60 ms, and the
  first call about 0.2 s. The JIT then needs some seconds of traffic
  before calls reach full speed: about 9 ms per g5 receipt and 40 ms per
  JWS on one thread, measured on that machine.
- Each instance holds about 2 MiB of linear memory; the JVM's heap held
  about 13 MiB after a GC with the module loaded and one instance live.
- A `Verifier` keeps a small pool of module instances. Each call takes one
  of its own, so calls on several threads run in parallel, and an instance
  never serves two calls at once.
- A trap in the module (a bug in the core, never a verdict on your input)
  answers `INTERNAL_ERROR` (21009 from the endpoint) with the trap in
  `Failure.cause()`, and the instance is thrown away. The next call gets a
  fresh one. The shipped module carries no `name` section, so the
  compiled methods in a stack trace or a JFR recording carry the wasm
  function's index, not its name, as a `wasm-function[N]` frame does;
  `rust/bindings/abi/README.md` says how to map an index to its function.
- On `Engine.endive()`, a Java 8 JVM fails at `Verifier.create` with an
  `IllegalStateException` that says so.

### Server engine sources

`Engine.server(ServerSource...)` tries its sources in the order you give
and uses the first that works. With none, it uses `maven()` then
`github()`. A source that fails gives its reason and the next one is
tried; when none works, `Verifier.create` throws `IllegalStateException`
with every source's reason, in order.

| Source | What it does |
|---|---|
| `url(uri, token)` | an `aprv serve` you run yourself (a sidecar or a container); this JVM starts nothing and needs no writable or executable directory |
| `executable(path)` | starts the binary at `path` and supervises it; nothing is extracted |
| `maven()` | extracts the binary for this platform from this artifact's `linux-x86_64` or `linux-aarch64` classifier jar on the classpath |
| `github()` | downloads the binary for this platform from this project's GitHub Release over HTTPS |
| `download(url, sha256)` | downloads from your mirror and accepts only a file with that SHA-256 |

`maven()` needs the classifier jar for your platform beside this one:

```xml
<dependency>
  <groupId>io.github.emindeniz99</groupId>
  <artifactId>apple-purchase-receipt-verifier-wasm</artifactId>
  <version>0.7.0</version> <!-- x-release-please-version -->
  <classifier>linux-x86_64</classifier> <!-- or linux-aarch64 -->
</dependency>
```

Each classifier jar holds one static Linux binary at
`io/github/emindeniz99/applepurchasereceiptverifier/server/aprv-<target>`
(`x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl`): about
12 MB extracted, 4 MB as a jar. On macOS and Windows use `github()`, `download()`, `executable()`
or `url()`. `github()` fetches the release asset `aprv-<target>` (`.exe`
on Windows) of this version.

**The cache directory.** A binary from `maven()`, `github()` or
`download()` is written to the cache directory as a temporary file,
hashed while it streams, and made executable (owner read and execute
only) and renamed to `aprv-<sha256>` only when the hash is the one pinned
in this jar (`maven()`, `github()`) or given to `download()`. One that
does not match is deleted and never run, and that source fails. The
installed file is hashed again before every start. A file lock makes one
download per machine however many threads and JVMs start at once.

The default directory is `~/.cache/aprv` on Linux,
`~/Library/Caches/aprv` on macOS and `%USERPROFILE%\AppData\Local\aprv\cache`
on Windows; `cacheDirectory(path)` sets another. It is created
owner-only, and one that others can write, that another user owns, or
that is a symbolic link is refused.

**A directory mounted `noexec` cannot run a binary.** On such a host
(many container platforms mount `/tmp` or the home directory that way)
the source fails with a message that says so. Use `url()`, or
`executable()` with a binary on a mount that allows it, or a
`cacheDirectory` on one.

### The server process

For every source but `url()`, this JVM runs `aprv serve --managed` as a
child process and supervises it:

- A fresh 256-bit token and your roots go to the child on its standard
  input, never on its command line or in its environment. The child
  listens on `127.0.0.1` only, on a port it picks and reports.
- A child that dies is started again by the next call. One that died 10
  times within a minute is not; calls answer `INTERNAL_ERROR` until you
  create the verifier again.
- The child stops on `close()`, when the verifier becomes unreachable, and
  when the JVM exits. When the JVM is killed with `kill -9`, the child
  sees its standard input close and exits by itself.
- Each call is one HTTP request on a kept-alive loopback connection. The
  config's clock is read once per call and sent with it.

**Failures.** A verdict answers exactly as on Endive. A problem the
server reports (a trap in the module, an ABI error, a refused token) is
`INTERNAL_ERROR` (21009 from the endpoint) with a `ServerProblem` as
`Failure.cause()`, whose message names the HTTP status and the server's
code. A server that cannot be started or reached is `INTERNAL_ERROR`
with a `ServerProcessFailure` as the cause, so it is never mistaken for
a trap. The server refuses a body over 3 MiB before the module sees it;
the engine answers such an input as the module does, `TOO_LARGE` (21002
from the endpoint) with the core's own message. Both cause classes are
internal; tell them apart by `getClass().getName()` in logs.

## The runtime probe

`Config.runtimeProbe()` is on by default. For this artifact it means that
`Verifier.create` starts the engine before it returns: Endive loads the
compiled module, creates one instance and calls its `init` with your
roots, and keeps that instance for the first call. `create` then throws
`IllegalStateException` if the module cannot run on this JVM or does not
have the interface this library binds, and `IllegalArgumentException` if
the module refuses one of your roots.

On the server engine, the probe resolves the sources: `create` starts
the child (or reaches the `url()` server), asks it for `/v1/info`, and
refuses a server that trusts other roots than your `Config`, since it
would answer for another trust anchor. A root the module refuses stops
the child at start, and `create` throws `IllegalArgumentException` with
the module's reason, as on Endive. On Java 8 the default
`Verifier.create(config)` therefore returns a verifier whose server is
already running.

With the probe off, `create` does none of that and the first call pays
for it; a module that cannot run, a root it refuses, or a server source
that does not work then answers `INTERNAL_ERROR` on every call.

## Differences from the main artifact

- **The same verdicts, and different messages.** Both artifacts run the
  311 shared cases of `fixtures/cases.json`. `Failure.message()` is
  written by the core here and can be worded differently.
- **`Failure.cause()`** is `null` for every reason the core decided,
  `UNREADABLE_PAYLOAD` included. It is set for the `INTERNAL_ERROR`s this
  library raises itself: a trap, a runtime failure, a clock that threw.
- **Dependencies.** `run.endive:runtime` and `run.endive:wasm` (Apache-2.0,
  pure Java 11 bytecode) and `jackson-core`. No BouncyCastle. The server
  engine adds nothing: its HTTP client and JSON reader are in this jar.
- **Class files.** The API, the engine choice and the server client are
  Java 8 bytecode. The Endive engine and its compiled module are Java 11
  bytecode and load only when that engine is chosen, so the jar sits on a
  Java 8 classpath harmlessly.

## Building

`aprv.wasm` is not in git: copy the release's `aprv.wasm` to
`src/main/wasm/aprv.wasm` (the build checks it against
`src/main/wasm/aprv.wasm.sha256`), or pass `-Daprv.wasm=PATH`. The
classifier jars come from `-Daprv.server.linux-x86_64=PATH` and
`-Daprv.server.linux-aarch64=PATH`; see [CI-NOTES.md](CI-NOTES.md).

## Licence

MIT, like the rest of this project. The compiled module contains OpenSSL,
wasi-libc, musl and the Rust standard library, under their own licences;
their texts are in the jar under `META-INF/licenses/aprv-wasm/`, and in
each server classifier jar too, whose binary embeds the module.
