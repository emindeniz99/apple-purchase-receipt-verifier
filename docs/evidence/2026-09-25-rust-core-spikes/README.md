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
| `chicory/` | Could the JVM run the wasm build instead of native libraries? (No: 28x slower, Java 11+.) |
| `wasi-go/` | Can Go run the core through wazero without cgo? |
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
