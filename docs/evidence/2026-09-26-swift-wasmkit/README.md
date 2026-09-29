# aprv.wasm on Swift 6.3 with WasmKit, Linux (2026-09-26)

Sources for `../2026-09-26-swift-wasmkit.md`. The ABI v1 module from
`../2026-09-26-wasm-abi-v1/` runs here on WasmKit 0.4.0, swiftwasm's Wasm
interpreter written in Swift. It builds with Swift 6.3.3 on Ubuntu 24.04
x86_64, through a small Swift package, and a clean consumer package uses it.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory; this round writes under `$SCRATCH/sw7` and reads the ABI v1 module and calls files from `$SCRATCH/abi` |
| `$CORPORA` | the substrate bake-off's request corpora |
| `$SWIFT_TC` | an extracted Swift 6.3.3 toolchain for Ubuntu 24.04 from download.swift.org (the `usr/` parent) |

## Files

| File | What it is for |
|---|---|
| `AprvWasm/Package.swift` | The package: library `AprvWasm` (WasmKit `exact: "0.4.0"`, `aprv.wasm` as a resource) and the harness `aprv-tool` |
| `AprvWasm/Sources/AprvWasm/AprvWasm.swift` | The bridge (`AprvRuntime`, `AprvInstance`) and the facade (`Verifier`) |
| `AprvWasm/Sources/aprv-tool/main.swift` | The harness: `calls`, `startup`, `bench`, `threads`, `isolation` |
| `AprvWasm/Sources/aprv-tool/Tests.swift` | The 33 ABI tests, plus 4 tests of the facade's contract |
| `consumer/` | A clean consumer package: depends on `AprvWasm` by path and resolves WasmKit itself |
| `scripts/env.sh`, `scripts/build.sh` (`package`, `consumer`), `scripts/run.sh`, `scripts/facts.sh` | Settings, builds, runs, primary sources |
| `results/*.txt` | One file per `run.sh` mode, plus `build.txt` and `facts.txt` |

## Reproduce

Run the ABI v1 round's `scripts/build.sh` and `scripts/node.sh` first. Then
get the toolchain and check its signature:

```sh
U=https://download.swift.org/swift-6.3.3-release/ubuntu2404/swift-6.3.3-RELEASE/swift-6.3.3-RELEASE-ubuntu24.04.tar.gz
curl -O $U; curl -O $U.sig
curl -sSL --compressed https://www.swift.org/keys/all-keys.asc | gpg --import
gpg --verify swift-6.3.3-RELEASE-ubuntu24.04.tar.gz.sig
mkdir tc; tar xzf swift-6.3.3-RELEASE-ubuntu24.04.tar.gz -C tc --strip-components=1   # SWIFT_TC=$PWD/tc
```

Then run the round:

```sh
export REPO=... SCRATCH=... CORPORA=... SWIFT_TC=...
SW=$REPO/docs/evidence/2026-09-26-swift-wasmkit
{ sh $SW/scripts/build.sh package; sh $SW/scripts/build.sh consumer; } > $SW/results/build.txt
sh $SW/scripts/facts.sh > $SW/results/facts.txt
sh $SW/scripts/run.sh tests > $SW/results/abi-tests.txt
for m in calls startup bench threads isolation; do sh $SW/scripts/run.sh $m > $SW/results/$m.txt; done
```

Run the timing modes on an otherwise idle machine, one at a time.
