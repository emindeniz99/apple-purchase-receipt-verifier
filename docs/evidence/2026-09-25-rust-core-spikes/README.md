# Spike sources, 2026-09-25

Throwaway code behind
[../2026-09-25-rust-core-spikes.md](../2026-09-25-rust-core-spikes.md).
CI builds none of it, and none of it is the design: each adapter exists to
answer one question from the plan in [docs/rust-core/](../../rust-core/README.md).
Paths are relative to this folder. `$SCRATCH` stands for any scratch
directory outside the repository.

| Folder | Question it answered |
|---|---|
| `uniffi/` | Does a UniFFI adapter over the unchanged core give usable Python, and what Kotlin and Swift does it generate? |
| `jvm/` | Can a Java 8 program use the generated Kotlin, endpoint and `toJsonIn` included? How does it compare with the Maven 0.6.0 jar? |
| `wasm/` | Does a wasm-bindgen adapter run on Node, Bun, Deno and Cloudflare workerd, and at what cost? |
| `jni/` | What would a hand-written JNI binding (pure Java API, no Kotlin, no JNA) look like and cost? |
| `swift/` | Can SwiftPM on Linux link the Rust core from an SE-0482 artifact bundle? (Yes, 6.2.4 and 6.4.) |
| `swig/` | What does SWIG over the C ABI give? (It works; results leak without typemaps.) |
| `ruby/` | Does UniFFI's built-in Ruby backend work? (Yes, with weaker enums.) |
| `chicory/` | Could the JVM run the wasm build instead of native libraries? (No: 28x slower, Java 11+.) |
| `wasi-go/` | Can Go run the core through wazero without cgo? |
| `neutral-surface/` | Can adapters annotate a generator-free surface crate from outside (`#[uniffi::remote]`)? (SURFACE.md) |
| `java-bakeoff/` | Java binding bake-off: UniFFI, jni-rs, flapigen, SWIG and Diplomat against one spec (`SPEC.md`). |
| `sidecar/` | Does a local verifyReceipt HTTP server work as a product and as a Java library mode? `server/` is the server, `java/` the Java launcher and clients, `java-http-client/` the `HttpURLConnection` versus one-write client comparison, `loadtest/` the Rust load generator for the throughput table. |
| `enterprise/` | Do the Java finalists survive real deployment shapes? `tomcat/` (Tomcat 9 and 10 hot redeploy, JNA 5.17.0), `tomcat-jna-5.19.1/` (the same rerun on the latest JNA), `spring-boot/` (fat jars), `native-image/` (GraalVM smoke programs and the tracing agent's config). `runs/` holds the output each table row was read from. |
| `stats/` | The scripts behind the download counts, GitHub stars, platform lists and MSRV rows, plus `reg.out` and a JNA platform dump. `pycur.py` times today's PyPI package. |
| `javadoc-screenshot/` | The Playwright script that rendered the Javadoc hover screenshot. |
| `core-no-std-features.diff` | The one core change the wasm builds needed (the `[[test]]` hunks only trimmed the scratch copy and are not part of the change). |

## Reproduce

```sh
# 1. UniFFI: build, generate, run Python
cargo build --release --manifest-path uniffi/Cargo.toml
./uniffi/target/release/uniffi-bindgen generate --library uniffi/target/release/libaprv_uniffi.so \
  --language python --out-dir $SCRATCH/py   # also: kotlin, swift
cp uniffi/target/release/libaprv_uniffi.so uniffi/spike.py $SCRATCH/py/ && python3 $SCRATCH/py/spike.py

# 2. Java 8: copy the generated .kt into src/main/kotlin, the .so into
#    src/main/resources/linux-x86-64/, Smoke.java into src/main/java/spike/,
#    then `mvn package` and run with a Temurin 8 `java -cp target/classes:target/dependency/*`

# 3. wasm: apply core-no-std-features.diff to rust/Cargo.toml first
cargo build --release --target wasm32-unknown-unknown --manifest-path wasm/Cargo.toml
wasm-bindgen --target nodejs --out-dir wasm/pkg-nodejs wasm/target/wasm32-unknown-unknown/release/aprv_wasm.wasm
wasm-bindgen --target web    --out-dir wasm/pkg-web    wasm/target/wasm32-unknown-unknown/release/aprv_wasm.wasm
node wasm/run.mjs; bun wasm/run.mjs; deno run -A wasm/run.mjs web
# workerd: copy pkg-web/* and the three fixtures next to workerd/*, then
npx workerd@1.20260903.1 test wasm/workerd/config.capnp

# 4. Go: build wasi-go for wasm32-wasip1, copy aprv_wasi.wasm next to main.go
go mod init spike && go get github.com/tetratelabs/wazero && CGO_ENABLED=0 go run .
```

Not kept here, on purpose: toolchains (JDKs, Swift, GraalVM, Tomcat),
build outputs, generated bindings (each tool regenerates them from the
sources above) and a copy of the core (the diff above is the only
change it carried).
