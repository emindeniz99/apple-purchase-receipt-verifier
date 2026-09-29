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

**The server engine is not available yet.** Its API compiles and is
documented, but `Verifier.create` throws
`UnsupportedOperationException("server engine: pending")` for it, and so
does `Verifier.create(config)` on Java 8. It lands in a later step of the
0.8.0 work.

### Endive

[Endive](https://endive.run) (`run.endive`, Apache-2.0) compiles every
function of `aprv.wasm` to JVM bytecode when this artifact is built, with
no interpreter fallback. At run time your classpath holds this jar and
Endive's `runtime` and `wasm` jars, and nothing else from Endive: no
compiler, no interpreter, no native library. A test in this module reads
every class file of the three jars and of jackson-core and finds no native
method and no call that loads native code.

- The first verifier in a JVM pays for loading the compiled module: 335
  to 380 ms in the Endive evaluation, up to about a second on a busy
  machine. Later instances take a few milliseconds each. The JIT then
  needs some seconds of traffic before calls reach full speed.
- A `Verifier` keeps a small pool of module instances. Each call takes one
  of its own, so calls on several threads run in parallel, and an instance
  never serves two calls at once.
- A trap in the module (a bug in the core, never a verdict on your input)
  answers `INTERNAL_ERROR` (21009 from the endpoint) with the trap in
  `Failure.cause()`, and the instance is thrown away. The next call gets a
  fresh one.
- On `Engine.endive()`, a Java 8 JVM fails at `Verifier.create` with an
  `IllegalStateException` that says so.

### Server engine sources

`Engine.server(ServerSource...)` tries its sources in the order you give
and uses the first that works. With none, it uses `maven()` then
`github()`.

| Source | What it does |
|---|---|
| `url(uri, token)` | an `aprv serve` you run yourself (a sidecar or a container); this JVM starts nothing and needs no writable or executable directory |
| `executable(path)` | starts the binary at `path` and supervises it; nothing is extracted |
| `maven()` | extracts the binary for this platform from this artifact's `linux-x86_64` or `linux-aarch64` classifier jar on the classpath |
| `github()` | downloads the binary for this platform from this project's GitHub Release over HTTPS |
| `download(url, sha256)` | downloads from your mirror and accepts only a file with that SHA-256 |

A binary from `maven()`, `github()` or `download()` is checked against a
pinned SHA-256 before it is made executable and again before every start;
one that does not match is never run. They are kept in the cache directory
(`cacheDirectory(path)`). **A directory mounted `noexec` cannot run
them.** On such a host (many container platforms mount `/tmp` that way),
use `url()` or `executable()`, which extract nothing.

## The runtime probe

`Config.runtimeProbe()` is on by default. For this artifact it means that
`Verifier.create` starts the engine before it returns: Endive loads the
compiled module, creates one instance and calls its `init` with your
roots, and keeps that instance for the first call. `create` then throws
`IllegalStateException` if the module cannot run on this JVM or does not
have the interface this library binds, and `IllegalArgumentException` if
the module refuses one of your roots.

With the probe off, `create` does none of that and the first call pays
for it; a module that cannot run, or a root it refuses, then answers
`INTERNAL_ERROR` on every call.

## Differences from the main artifact

- **The same verdicts, and different messages.** Both artifacts run the
  311 shared cases of `fixtures/cases.json`. `Failure.message()` is
  written by the core here and can be worded differently.
- **`Failure.cause()`** is `null` for every reason the core decided,
  `UNREADABLE_PAYLOAD` included. It is set for the `INTERNAL_ERROR`s this
  library raises itself: a trap, a runtime failure, a clock that threw.
- **Dependencies.** `run.endive:runtime` and `run.endive:wasm` (Apache-2.0,
  pure Java 11 bytecode) and `jackson-core`. No BouncyCastle.
- **Class files.** The API, the engine choice and the server client are
  Java 8 bytecode. The Endive engine and its compiled module are Java 11
  bytecode and load only when that engine is chosen, so the jar sits on a
  Java 8 classpath harmlessly.

## Licence

MIT, like the rest of this project. The compiled module contains OpenSSL,
wasi-libc and the Rust standard library, under their own licences.
