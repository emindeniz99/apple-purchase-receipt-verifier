# Cross-build spike: sources

The note is `../2026-10-31-cross-build-spike.md`. The scripts the spike
workflow runs live in `tools/cross/`, because a workflow can only call
files in the tree; this folder holds the local half, the results, and the
workflow itself, `spike-cross-build.yml`. It ran from
`.github/workflows/` while the spike was open (run 41257197635) and was
parked here once it had answered, so it no longer runs on every change.

| File | Question it answered |
|---|---|
| `local-run.sh` | Does each target cross-build on a Linux x86_64 host, and how long does each step take? Runs `tools/cross/precompile.sh` once and `tools/cross/build.sh` per target, one log each |
| `inspect.sh` | What did the cross build produce: Mach-O minos, code signature and linked dylibs; PE machine, stack reserve and imported DLLs; whether the build path is baked into the test executables |
| `ccwasm-compare.sh` | Does the `.ccwasm` depend on how the precompiler was built (`wasmtime/all-arch` or not, release profile or a cheaper one)? Builds the precompiler each way and hashes one `.ccwasm` per target |
| `release-timings.py` | What do today's native `build-server` legs cost? The `build` step and job time per target over recent successful release.yml runs, from the public API |
| `results/` | The logs and tables the numbers in the note come from |

`tools/cross/`:

| File | Role |
|---|---|
| `precompile.sh` | Candidates B and C: one precompiler build, one `.ccwasm` per target |
| `build.sh` | The final builds for one target around its `.ccwasm`: the runtime-only server, the C ABI library, both crates' test executables; native, cargo-zigbuild or cargo-xwin by target |
| `verify.sh` | On a runner of the target: `aprv info`, every shared case over HTTP and the CLI, the managed mode, the server's and the C ABI's own tests, C++ and ctypes conformance over the C ABI |
| `requirements.txt` | The hash-pinned zig, cargo-zigbuild and cargo-xwin wheels |

## Reproduce

On Linux x86_64 with the repository's pinned toolchain (`rust/rust-toolchain.toml`):

```sh
python3 -m venv "$SCRATCH/venv"
"$SCRATCH/venv/bin/pip" install --require-hashes -r "$REPO/tools/cross/requirements.txt"
mkdir -p "$SCRATCH/bin" && ln -s "$(command -v clang)" "$SCRATCH/bin/clang-cl"   # cargo-xwin wants clang-cl
export PATH="$SCRATCH/venv/bin:$SCRATCH/bin:$PATH"
channel="$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$REPO/rust/rust-toolchain.toml")"
rustup target add --toolchain "$channel" aarch64-apple-darwin x86_64-apple-darwin \
  x86_64-pc-windows-gnu x86_64-pc-windows-msvc

# the component, as ci.yml's rust-wasm job builds it (the toolchain first:
# build.sh needs WASI_SDK_DIR and OPENSSL_WASM_DIR and installs neither)
eval "$("$REPO/tools/wasm-toolchain.sh" "$SCRATCH/wasm-toolchain")"
"$REPO/rust/bindings/abi/build.sh" "$SCRATCH/aprv"

# one precompiler and one .ccwasm per target (B and C), then the cross
# builds (C), from a stable path the verify runners can recreate
ln -sfn "$REPO" /tmp/aprv-src
SCRATCH="$SCRATCH" COMPONENT="$SCRATCH/aprv/aprv.component.wasm" \
  /tmp/aprv-src/docs/evidence/2026-10-31-cross-build-spike/local-run.sh /tmp/aprv-src
"$REPO/docs/evidence/2026-10-31-cross-build-spike/inspect.sh" "$SCRATCH/out/aarch64-apple-darwin" /tmp/aprv-src

# does the precompiler's build change the .ccwasm?
"$REPO/docs/evidence/2026-10-31-cross-build-spike/ccwasm-compare.sh" "$SCRATCH/aprv/aprv.component.wasm" "$SCRATCH/ccwasm-compare"

python3 "$REPO/docs/evidence/2026-10-31-cross-build-spike/release-timings.py" 10
```

The runs on macOS and Windows are the spike workflow's. To run them
again, copy `spike-cross-build.yml` back into `.github/workflows/` on a
branch and open a pull request: it runs on a pull request that touches it
or `tools/cross/`, and by dispatch.
