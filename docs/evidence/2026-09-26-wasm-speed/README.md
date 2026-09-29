# Simple speed options for aprv.wasm (2026-09-26)

Sources for `../2026-09-26-wasm-speed.md`. The question is whether simple,
low-risk, documented switches make round 4's Route C module (`new-c.wasm`)
faster in Node and in Endive, without changing a single output byte.

Nothing here touches production code. `scripts/build.sh` is round 4's
recipe with three inputs made variable: the OpenSSL install, cargo's
release opt-level, and a `wasm-opt` pass afterwards. It uses round 4's own
scratch paths, so its baseline reproduces round 4's module byte for byte.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory; this round writes under `$SCRATCH/speed` (and rebuilds round 4's `tree-new-c`, `asn1/adapter-new` and `target-new-c` in place) |
| `$CORPORA` | the substrate bake-off's request corpora (1,179 rows, plus 5,000 mutants in `fuzz.jsonl`) |
| `$WASI_SDK` | wasi-sdk 34.0 |
| `$JDK21`, `$JDK25` | JDK homes |

## Files

| File | What it is for |
|---|---|
| `scripts/env.sh` | Shared settings: the reference module and rows, rustc 1.98.1, wasm-tools and wasm-opt |
| `scripts/build.sh` | `openssl <name> [Configure args]`, `wasm <out> <openssl> [rust opt-level]`, `opt <in> <out> <wasm-opt args>` |
| `scripts/parity.sh` | The gate. Node runs a candidate over all 6,179 rows; every row must match round 4's native rows and Node rows byte for byte, and the imports must be exactly the two `aprv` ones |
| `scripts/bench.sh` | Round 5's method: `node <name>` (1,000 timed calls), `endive <name>` (round 5's library rebuilt on the candidate; JDK 21 and 25, both memory implementations, 1,000 warm-up + 500 timed) |
| `scripts/endive-parity.sh` | Candidate 1 (`ByteArrayMemory`) through the gate on JDK 21 |
| `scripts/nistp-endive.sh` | Why the nistp option is slower on Endive: generated method sizes, and the JWS row with and without `-XX:-DontCompileHugeMethods` |
| `scripts/scale.sh`, `java/spike/consumer/Scale.java` | Throughput with one instance per thread, at 1, 2 and 4 threads, on JDK 21 |
| `scripts/sizes.sh` | Module sizes per candidate |
| `scripts/facts.sh` | OpenSSL's INSTALL.md and `ec_curve.c`, `__int128` on wasm32, and Debian's and Fedora's OpenSSL configuration |
| `py/summary.py` | The benchmark table from the raw lines |
| `results/parity.txt` | The gate, per candidate |
| `results/endive-parity.txt` | `ByteArrayMemory` on JDK 21, all rows |
| `results/bench-raw.txt`, `results/bench.txt` | Every benchmark line, and the summary |
| `results/nistp-endive.txt` | The nistp diagnosis |
| `results/scaling.txt` | Thread scaling |
| `results/sizes.txt`, `results/facts.txt`, `results/versions.txt` | Sizes, primary sources, exact versions |

## Reproduce

These commands assume round 4's inputs in `$SCRATCH`: `inst-wasm` (for
`r4-repro`), `dl/openssl-4.0.2.tar.gz`, and the rows in `asn1/run` and
`asn1/wrun`. They also need round 5's built consumer and local repository
in `$SCRATCH/endive` (round 5's `build.sh lib` and `build.sh consumer`).

```sh
export REPO=... SCRATCH=... CORPORA=... WASI_SDK=... JDK21=... JDK25=...
SPD=$REPO/docs/evidence/2026-09-26-wasm-speed; B=$SPD/scripts/build.sh
$SPD/scripts/facts.sh > $SPD/results/facts.txt
$B wasm r4-repro r4                        # must equal round 4's new-c.wasm byte for byte
$B openssl base; $B openssl nistp enable-ec_nistp_64_gcc_128; $B openssl o2 -O2; $B openssl nopic no-pic
$B wasm base base; $B wasm nistp nistp; $B wasm o2 o2; $B wasm nopic nopic; $B wasm rust2 base 2
$B opt base base-wo2 -O2; $B opt base base-wo3 -O3
for n in r4-repro base nistp o2 nopic rust2 base-wo2 base-wo3; do $SPD/scripts/parity.sh $n; done > $SPD/results/parity.txt
$SPD/scripts/sizes.sh > $SPD/results/sizes.txt
{ for r in 1 2 3; do for n in base nistp o2 nopic rust2 base-wo2 base-wo3; do $SPD/scripts/bench.sh node $n; done; done
  for n in base nistp nopic o2 rust2 base-wo2 base-wo3; do $SPD/scripts/bench.sh endive $n; done; } > raw.txt
# results/bench-raw.txt = a header line + raw.txt; results/bench.txt = a header + py/summary.py's table
$SPD/scripts/nistp-endive.sh > $SPD/results/nistp-endive.txt
$SPD/scripts/scale.sh > $SPD/results/scaling.txt           # rebuilds round 5's library on round 4's module
$SPD/scripts/endive-parity.sh > $SPD/results/endive-parity.txt   # after scale.sh
```

## What is not here

This folder has no binaries (`.wasm`, `.a`, `.jar`, `.class`), no
OpenSSL sources, no local paths and no receipts. Every input row comes
from `$CORPORA`, which is built from `fixtures/` and generated test keys.
