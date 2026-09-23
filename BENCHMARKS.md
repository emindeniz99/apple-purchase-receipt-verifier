# Benchmarks

Each of the nine ports carries a benchmark that times the same operations on
the same two receipts. Run them on one machine, or through the `benchmark`
workflow on one runner type, and you can compare the numbers across ports.
None of them gates anything: a shared machine is too noisy for that.

## What is measured

Two genuine Apple-signed sandbox receipts from `fixtures/public-receipts/`,
the same pair `java-bench/` uses:

| fixture | in-app purchases | chain | base64 chars | DER bytes |
|---|---:|---|---:|---:|
| `receipt-sandbox-g5` (g5) | 2 | SHA-256 | 7,556 | 5,665 |
| `receipt-sandbox-legacy` (legacy) | 187 | SHA-1 | 105,472 | 79,104 |

Every run verifies them against the port's built-in Apple receipt roots, with
the bundle ids `fixtures/cases.json` pins (`dev.bonzer.weeka.app`,
`com.nutcall.alert`). The base64 input is the canonical re-encoding of the
DER, and the endpoints read a fixed clock (2026-01-01T00:00:00Z).

| benchmark | call |
|---|---|
| `decodeBase64` | the library's own receipt-data decoder on the canonical string |
| `core` | `verifyReceiptCore(der, roots)` on pre-decoded DER: chain and signature, no bundle check |
| `verifierBase64` | a `ReceiptVerifier` built in setup, `verify` on the base64 string |
| `endpointJson` | a Sandbox `VerifyReceiptEndpoint`, `verifyReceiptJson` from request JSON to response JSON |
| `retryViaResult` | a Production endpoint, `verifyReceiptResult(request).toJson(Sandbox)`: the 21007 retry without a second verification |
| `rejectTamperedSignature` | `verifyReceiptCore` on the DER with one bit flipped in the middle of the SignerInfo signature |

The names are the Java JMH names. Each port spells the calls its own way
(`VerifyReceiptJSON` in Go, `verify_receipt_json` in Python and Ruby, and so
on). In both fixtures the signature is a 256-byte OCTET STRING at the very end
of the DER, so every port flips the byte 128 from the end, the byte
java-bench's `flipSignatureByte` finds by parsing the CMS.

Before timing, each benchmark runs every call once and stops unless it gets
the answer the conformance suite expects: the right bundle id and in-app
count, status 0 with every `in_app` entry, a Sandbox status 0 from the
Production result, and `INVALID_SIGNATURE` for the tampered receipt. A
benchmark therefore cannot time a fast failure.

`decodeBase64` reaches an internal function in most ports: through the
internal test package in Go, a `dist/` module in Node, a private module in
Python, reflection in Java and .NET. Swift reports no `decodeBase64`. Its
decoder is internal, and reaching it takes `-enable-testing`, which changes
how the whole library compiles.

`java-bench/` also has `endpointMap`, `endpointWrongEnv` and `resultOnly`,
which no other port repeats.

## Tools and output

| port | tool | where | output |
|---|---|---|---|
| Java | JMH 1.37, 2 forks, 5 warmup and 5 measured iterations of 1 s | `java-bench/` | JMH JSON, µs/op (mean) |
| Go | `testing.B`, `-benchtime 1s -count 5` | `go/crossport_bench_test.go` | Go benchmark text, ns/op, readable by benchstat |
| Rust | an example with `std::time` | `rust/examples/bench.rs` | JSON, µs/op |
| Node | a script with `node:perf_hooks` | `node/bench/bench.mjs` | JSON, µs/op |
| Python | a script with `timeit`, collector on | `python/bench/bench.py` | JSON, µs/op |
| Ruby | a script with the monotonic clock | `ruby/bench/bench.rb` | JSON, µs/op |
| PHP | a script with `hrtime` | `php/bench/bench.php` | JSON, µs/op |
| .NET | a console app with `System.Diagnostics.Stopwatch`, release build | `dotnet/bench/` | JSON, µs/op |
| Swift | an executable with `ContinuousClock`, release build | `swift/bench/` | JSON, µs/op |

The seven script ports share one method: warm up for one second, size a sample
to at least 100 ms, take ten samples, and report the median, minimum and
maximum µs/op. Their JSON has the same shape: `port`, `tool`, `settings`,
and `results` with `benchmark`, `fixture`, `us_per_op_median`,
`us_per_op_min`, `us_per_op_max` and `ops_per_sample`.

The tools are the ones each port already had, or none. Rust's `#[bench]` needs
nightly, and criterion would add a few dozen crates to the lockfile the crate
publishes. pyperf, benchmark-ips and phpbench are not dependencies of their
ports, and BenchmarkDotNet would add a few dozen packages to the .NET
benchmark. `dotnet/bench` references the library project and no package,
and it sits outside the solution, like `dotnet/fuzz`, so the shipped
package never sees it. `swift/bench` is a separate package, like
`swift/fuzz`, so the root manifest stays as it is.

## Running locally

Run these from the repository root.

```bash
# Java
mvn -B -f java/pom.xml -Dmaven.test.skip=true install
mvn -B -f java-bench/pom.xml -Dlibrary.version="$(cat version.txt)" package
java -jar java-bench/target/benchmarks.jar -rf json -rff jmh-result.json

# Go
go -C go test -run '^$' -bench '^BenchmarkCrossPort$' -benchtime 1s -count 5 . | tee go-bench.txt

# Rust
cargo run --release --locked --manifest-path rust/Cargo.toml --example bench > rust-bench.json

# Node
npm ci --ignore-scripts --prefix node && npm run build --prefix node
node node/bench/bench.mjs > node-bench.json

# Python
uv --directory python sync --locked
uv --directory python run --locked python bench/bench.py > python-bench.json

# Ruby
ruby -Iruby/lib ruby/bench/bench.rb > ruby-bench.json

# PHP
composer --working-dir=php install --no-dev --no-scripts
php php/bench/bench.php > php-bench.json

# .NET
dotnet run -c Release --project dotnet/bench > dotnet-bench.json

# Swift
swift build -c release --package-path swift/bench --force-resolved-versions
swift/bench/.build/release/bench > swift-bench.json
```

The script ports print progress to stderr and the JSON to stdout. A run takes
one to five minutes per port.

## Running in CI

The `benchmark` workflow (`.github/workflows/benchmark.yml`) runs only when
you dispatch it by hand: Actions, "benchmark", "Run workflow". It has one job
per port, all on `ubuntu-latest`, and each uploads an artifact named
`<port>-bench` (`jmh-result` for Java). No job restores a cache. Runners
differ from run to run, so compare ports within one run, not across runs.

## Results

**Local, shared 4 vCPU cloud VM, noisy, not a baseline.** Measured 2026-09-22
on the library at `bc32534` (0.5.1), one port at a time, nothing else
running. CPU: Intel(R) Xeon(R) Processor @ 2.10GHz, 4 vCPUs (KVM guest),
15 GiB RAM.

Tool versions: OpenJDK 21.0.10 (Ubuntu build) with JMH 1.37; Go 1.24.7;
rustc 1.94.1; Node 22.22.2; CPython 3.11.15; Ruby 3.3.6 and PHP 8.4.19, both
on OpenSSL 3.0.13; .NET 10.0.11 (SDK 10.0.400);
Swift 6.3.3.

Values are µs/op: the JMH mean for Java, the median of five runs for Go,
and the median of ten samples for the rest. The .NET column was re-measured the same
day on the same machine and library, after its benchmark moved from
BenchmarkDotNet to the shared Stopwatch loop.

The Swift column was re-measured on 2026-09-23, after its date and JSON
changes, on a different 4 vCPU KVM guest (Intel(R) Xeon(R) Processor @
2.80GHz, 15 GiB RAM), all ten rows in one run. On that machine, run back to
back with it, the library before those changes (`5d5d74a`) measured
182,511 µs for legacy `core` and 343,070 µs for legacy `endpointJson`, 14%
and 13% above the 160,145 and 304,378 the first run recorded, so the two
machines are close enough to compare, not identical. The other columns were
not re-measured.

| benchmark | fixture | Java | Go | Rust | Node | Python | Ruby | PHP | .NET | Swift |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `decodeBase64` | g5 | 2.4 | 6.9 | 3.3 | 16.3 | 17.9 | 6.6 | 0.4 | 6.0 | n/a |
| `core` | g5 | 356 | 207 | 1,159 | 519 | 589 | 2,108 | 3,882 | 3,018 | 598 |
| `verifierBase64` | g5 | 345 | 205 | 1,130 | 581 | 682 | 1,865 | 3,470 | 2,620 | 525 |
| `endpointJson` | g5 | 366 | 338 | 1,219 | 674 | 914 | 2,264 | 3,842 | 3,030 | 780 |
| `retryViaResult` | g5 | 375 | 248 | 1,202 | 668 | 784 | 2,151 | 3,527 | 2,639 | 786 |
| `rejectTamperedSignature` | g5 | 380 | 201 | 1,191 | 563 | 612 | 2,053 | 3,410 | 2,812 | 614 |
| `decodeBase64` | legacy | 27.3 | 96.3 | 47.4 | 192 | 235 | 80.1 | 5.0 | 76.2 | n/a |
| `core` | legacy | 3,063 | 2,519 | 2,274 | 4,051 | 9,176 | 17,193 | 24,777 | 3,319 | 8,150 |
| `verifierBase64` | legacy | 3,134 | 2,481 | 2,153 | 4,176 | 9,028 | 16,237 | 24,255 | 3,223 | 8,255 |
| `endpointJson` | legacy | 4,401 | 5,758 | 3,969 | 8,170 | 13,659 | 24,503 | 26,855 | 4,929 | 19,273 |
| `retryViaResult` | legacy | 4,061 | 4,655 | 4,103 | 6,187 | 12,421 | 22,131 | 24,997 | 4,800 | 18,660 |
| `rejectTamperedSignature` | legacy | 3,152 | 2,381 | 2,438 | 3,386 | 9,106 | 14,852 | 23,731 | 3,747 | 8,122 |

Read the ratios inside one column before the absolute values. PHP and the
earlier BenchmarkDotNet run of .NET each ran twice, and the same benchmark
moved by up to 12% between those runs.
A few gaps are larger than that. Swift used to take about 50 times as long
as Java on the legacy receipt and about 8 times as long on g5. Each date cost
a new `ISO8601DateFormatter` to parse and two `DateFormatter`s to render, and
`JSONSerialization` with `.sortedKeys` wrote the answer; on Linux that was
nearly all of the time. Foundation's `Date.ISO8601FormatStyle`,
`Date.VerbatimFormatStyle` and `JSONEncoder` now do that work, giving the
same bytes. Swift now takes about 2.7 times as long as Java on legacy `core`
and 4.4 times on legacy `endpointJson`.
PHP and Ruby take about 25 ms
and 17 ms for legacy \`core\`. Rust is the one port whose g5 \`core\` costs half
its legacy \`core\`. The table predates the fix for that: `rsa` was built
without its `u64_digit` feature, so the three RSA-2048 verifies every receipt
needs ran on 32-bit limbs at about 370 µs each. With the feature back, g5
`core` went from 1,187 to about 740 µs, measured on a different machine (Xeon
at 2.80 GHz), and RSA is still about 90% of it. See the Rust entries in
`ROADMAP.md` for the next steps.
