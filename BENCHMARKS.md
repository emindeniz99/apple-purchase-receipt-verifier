# Benchmarks

Every package carries a benchmark that times the same operations on the
same receipts. In 0.8.0 all of them but the Java main artifact run the same
`aprv.wasm`, so the numbers compare the hosts (the Wasm runtime and the
wrapper around it), not nine implementations. Run them on one machine, or
through the `benchmark` workflow on one runner type, and you can compare
across packages. None of them gates anything: a shared machine is too noisy
for that. The owner's guideline is about 10 verifications per second per
core as a floor and 40 to 50 as comfortable (docs/rust-core/DECISIONS.md
R4).

## What is measured

Two genuine Apple-signed sandbox receipts from `fixtures/public-receipts/`,
the same pair `java-bench/` uses, and one StoreKit 2 transaction:

| fixture | in-app purchases | chain | base64 chars | DER bytes |
|---|---:|---|---:|---:|
| `receipt-sandbox-g5` (g5) | 2 | SHA-256 | 7,556 | 5,665 |
| `receipt-sandbox-legacy` (legacy) | 187 | SHA-1 | 105,472 | 79,104 |

Every run verifies them with one `Verifier` built from the package's
default `Config` (the Apple roots) and a fixed clock
(2026-01-01T00:00:00Z), which only reaches `request_date` because both
receipts carry a creation date. The base64 input is the canonical
re-encoding of the DER.

| benchmark | call |
|---|---|
| `verifyReceipt` | `verifier.verifyReceipt(base64)`: decode, chain, signature and full parse |
| `endpointJson` | `verifier.verifyReceiptEndpoint(SANDBOX, requestJson)`, from request JSON to response JSON |
| `rejectTamperedSignature` | `verifyReceipt` on the base64 of the DER with one bit flipped in the middle of the SignerInfo signature |
| `verifySignedData` | `verifier.verifySignedData(jws)` on a StoreKit 2 transaction, where the harness has it |

The names are the Java JMH names; each package spells the calls in its own
casing. 0.7's `decodeBase64` benchmark is gone from the Wasm packages:
they have no base64 decoder of their own, the module decodes. Ruby and
Rust still also emit the 0.6 names `core` and `verifierBase64` (both time
`verifyReceipt`) and `retryViaResult` (a `PRODUCTION` call answering 21007
followed by the `SANDBOX` call). In both receipts the signature is a
256-byte OCTET STRING at the very end of the DER, so every harness flips
the byte 128 from the end, the byte java-bench's `flipSignatureByte` finds
by parsing the CMS.

Before timing, each benchmark runs every call once and stops unless it gets
the answer the conformance suite expects: the bundle id and in-app count
`fixtures/cases.json` pins (`dev.bonzer.weeka.app` with 2,
`com.nutcall.alert` with 187), status 0 with every `in_app` entry, and
`INVALID_SIGNATURE` for the tampered receipt. A benchmark therefore cannot
time a fast failure.

A Wasm host also has a start-up cost the Java main artifact does not:
compiling or loading the module once per process, and creating an
instance (with `init`, which parses the roots) per pooled instance. The
results below report both.

## Tools and output

| package | tool | where | output |
|---|---|---|---|
| Java, main artifact | JMH 1.37, 2 forks, 5 warmup and 5 measured iterations of 1 s | `java-bench/` | JMH JSON, µs/op (mean) |
| Java `-wasm` | the timing step of the parity run | `java-wasm/scripts/g1.sh` | text |
| Go | `testing.B` | `go/bench_test.go`, `go/internal/host/bench_test.go` | Go benchmark text, ns/op, readable by benchstat |
| Rust core, native | an example with `std::time` | `rust/examples/bench.rs` | JSON, µs/op |
| Node | a script with `node:perf_hooks` | `node/bench/bench.mjs`; `startup.mjs` and `memory.mjs` beside it | JSON, µs/op |
| Python | a script with `timeit`, collector on | `python/bench/bench.py` | JSON, µs/op |
| Ruby | a script with the monotonic clock | `ruby/bench/bench.rb`; `startup.rb` and `threads.rb` beside it | JSON, µs/op |
| PHP | a script with `hrtime`, through each transport | `php/bench/bench.php` | JSON, µs/op |
| .NET | a console app with `System.Diagnostics.Stopwatch`, release build | `dotnet/bench/` | JSON, µs/op |
| Swift | an executable with `ContinuousClock`, release build | `swift/bench/` | JSON, µs/op |
| `aprv-server` | a script over the binary: load, start-up, CLI and HTTP per call | `rust/server/scripts/startup.py` | text |

The script harnesses share one method: warm up for one second, size a
sample to at least 100 ms, take ten samples, and report the median,
minimum and maximum µs/op. Their JSON has the same shape: `port`, `tool`,
`settings`, and `results` with `benchmark`, `fixture`, `us_per_op_median`,
`us_per_op_min`, `us_per_op_max` and `ops_per_sample`.

The tools are the ones each package already had, or none. Rust's `#[bench]`
needs nightly, and criterion would add a few dozen crates to the lockfile
the crate publishes. pyperf, benchmark-ips and phpbench are not
dependencies of their packages, and BenchmarkDotNet would add a few dozen
packages to the .NET benchmark. `dotnet/bench` references the library
project and no package, and it sits outside the solution, like
`dotnet/fuzz`, so the shipped package never sees it. `swift/bench` is a
separate package, like `swift/fuzz`, so the root manifest stays as it is.

## Running locally

Run these from the repository root, after putting the module where each
package reads it (CONTRIBUTING.md, "Building the module").

```bash
# Java, main artifact
mvn -B -f java/pom.xml -Dmaven.test.skip=true install
mvn -B -f java-bench/pom.xml -Dlibrary.version="$(cat version.txt)" package
java -jar java-bench/target/benchmarks.jar -rf json -rff jmh-result.json

# Go
go -C go test -run '^$' -bench . -benchtime 3s -cpu 1,4 . ./internal/host | tee go-bench.txt

# Rust core, native
cargo run --release --locked --manifest-path rust/Cargo.toml --example bench > rust-bench.json

# Node
npm ci --ignore-scripts --prefix node && npm run build --prefix node
node node/bench/bench.mjs > node-bench.json

# Python
uv --directory python sync --locked
uv --directory python run --locked python bench/bench.py > python-bench.json

# Ruby
ruby -Iruby/lib ruby/bench/bench.rb > ruby-bench.json

# PHP, through the CLI and over HTTP
composer --working-dir=php install --no-dev --no-scripts
php php/bench/bench.php --aprv "$APRV_BIN" > php-bench.json

# .NET
dotnet run -c Release --project dotnet/bench > dotnet-bench.json

# Swift
swift build -c release --package-path swift/bench --force-resolved-versions
swift/bench/.build/release/bench > swift-bench.json

# aprv-server
python3 rust/server/scripts/startup.py --aprv "$APRV_BIN"
```

The script harnesses print progress to stderr and the JSON to stdout. A run
takes one to five minutes per package.

## Running in CI

The `benchmark` workflow (`.github/workflows/benchmark.yml`) runs only when
you dispatch it by hand: Actions, "benchmark", "Run workflow". It builds the
module and the static server binary once, places them as `ci.yml` does, and
runs one job per package, all on `ubuntu-latest`; each uploads an artifact
named `<package>-bench` (`jmh-result` for Java). No job restores a cache.
Runners differ from run to run, so compare packages within one run, not
across runs.

## Results

**Measured 2026-09-29 by the migration's host lanes, on one shared 4-vCPU
Linux x86_64 guest that five other builds kept busy (load averages of 8 to
20).** Read every number as an upper bound, or an order of magnitude; where
a lane reported CPU time rather than wall time, the table says so. The
module was the 0.7 core's `aprv.wasm` or its review-fixed successor; the
sources are each package's README ("Speed", "Performance" or "Cost per
call"), the evidence notes named below, and the lanes table of
[docs/rust-core/STATUS.md](docs/rust-core/STATUS.md). A blank cell was not
measured. No idle-machine run of the release module has been recorded yet.

One call on the g5 receipt and on a StoreKit 2 JWS, on one thread:

| Host | g5 `verifyReceipt` | `verifySignedData` | First `Verifier` in a process | A later `Verifier` or instance |
|---|---:|---:|---:|---:|
| Node (V8, jco) | about 5 ms | | 135 to 153 ms | |
| Go (wazero v1.9.0) | 5.5 ms | 22 ms | about 2.3 s (compile) | 13 to 20 ms |
| Python (wasmtime-py 49.0.0) | 2.2 to 3.0 ms CPU | 8 ms CPU | about 5 s CPU (compile); 0.1 s from the cache | about 3 ms |
| Ruby (`wasmtime` gem 48.0.1) | 2.3 to 2.5 ms CPU | 8.9 to 9.5 ms CPU | 5.7 to 6.2 s CPU (compile) | 3.3 to 3.6 ms CPU |
| Swift (WasmKit 0.4.1) | 24 to 30 ms CPU | 100 to 110 ms CPU | 45 to 170 ms, then 150 to 380 ms for an instance's first call | |
| .NET (Wasmtime 48.0.2) | 215 to 379 per second | 55 to 95 per second | 7.7 to 12.3 s (compile) | 4 to 7 ms |
| Java `-wasm`, Endive, JDK 21 | about 9 ms | about 40 ms | about 1.1 s | about 60 ms |
| Java `-wasm`, server engine, Temurin 8 | 8.2 ms | | | |
| `aprv-server`, HTTP keep-alive | 7.3 ms | 16.5 ms | 20.1 ms to listening (load 13 to 16 ms) | |
| `aprv-server`, one CLI process per call | 25.1 ms | 31.3 ms | | |
| PHP, through the CLI | 37.7 ms | | | |
| PHP, over HTTP | 9.0 ms | | | |
| Java, main artifact | | | | |
| Rust core, native | | | | |

Sources: node/README.md and STATUS.md (Node); go/README.md "Speed";
[docs/evidence/2026-09-29-python-g1.md](docs/evidence/2026-09-29-python-g1.md)
and python/README.md "Speed"; ruby/README.md "Performance" and
[docs/evidence/2026-09-29-ruby-host.md](docs/evidence/2026-09-29-ruby-host.md);
swift/README.md "Speed"; dotnet/README.md "Speed and start-up" and
[docs/evidence/2026-09-29-dotnet-host.md](docs/evidence/2026-09-29-dotnet-host.md);
java-wasm/README.md "Endive"; STATUS.md lane E (the server engine);
rust/server/README.md "Measured"; php/README.md "Cost per call".

Read with the machine in mind:

- **The load made every figure slower, by different amounts.** The Swift
  lane re-ran the earlier spike's harness in the same minutes and got
  numbers 2.2 times slower than it had recorded on an idle machine. On
  the idle machine of the spikes (the ABI v1 module, before the review's
  fixes), a g5 receipt took 1.3 to 1.8 ms and a JWS 4.5 to 5.2 ms on
  Node, wasmtime-py, the Ruby gem and Wasmtime .NET, 13.3 ms and 54.7 ms
  on WasmKit, and Endive reached 154.7 g5 receipts and 52.6 JWS per second
  on one thread (docs/rust-core/README.md, "The hosts").
- **Swift is the thin margin.** WasmKit interprets, and a JWS at about
  100 ms of CPU is the guideline's 10 per second per core with no margin on
  this machine (1.7 to 1.9 times it on the idle spike machine). It needs a
  re-measure on an idle runner before anyone reads it as a verdict on a
  platform.
- **Python and Ruby pay the compile once per process**, so a process that
  starts for one call (a Lambda cold start, a one-off script) pays seconds.
  Python's cache brings a warm start to about 0.1 s. Build the `Verifier`
  at start-up.
- **Threads.** The Wasm hosts give each call its own instance, so throughput
  grows with cores, except wasmtime-py, which scales past two threads
  badly: use worker processes (python/README.md). The four-thread figures
  were not measurable on the shared machine.
- **Memory.** An instance's linear memory stays near 2 MiB across
  thousands of calls. A hostile 3 MiB receipt of tiny attributes grows it
  to about 16 MiB before the module refuses it (node/README.md, "Input
  limits"; [core review fixes](docs/evidence/2026-09-29-core-review-fixes.md)).

**Earlier runs.** The 0.6.0 run of all nine hand-written implementations
(2026-09-25, `v0.6.0`) is in this file's git history. It explains the
Java main artifact's 0.6 slowdown (BouncyCastle caches neither parsed
certificates nor signature checks, and each chain signature is checked
twice since #161); the fixes are deferred in ROADMAP.md, "Later /
hardening". Neither the Java main artifact nor the native Rust core has
been re-measured for 0.8.0.
