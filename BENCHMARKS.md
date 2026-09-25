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

**Local, shared 4 vCPU cloud VM, noisy, not a baseline.** All nine ports
measured on 2026-09-25 at `v0.6.0` (`b934caa`), one port at a time, nothing
else running, with the commands `benchmark.yml` runs. CPU: Intel(R) Xeon(R)
Processor @ 2.10GHz, 4 vCPUs (KVM guest), 15 GiB RAM. Every number below
comes from this one run; the earlier table, measured on 0.5.1 and partly on
other machines, is gone.

Tool versions: OpenJDK 21.0.10 (Ubuntu build) with JMH 1.37; Go 1.24.7
(the workflow asks for 1.27); rustc 1.94.1; Node 22.22.2; CPython 3.11.15
(the workflow asks for 3.13); Ruby 3.3.6 and PHP 8.4.19, both on OpenSSL
3.0.13; .NET 10.0.11 (SDK 10.0.400); Swift 6.3.3.

Values are µs/op: the JMH mean for Java, the median of five runs for Go,
and the median of ten samples for the rest.

| benchmark | fixture | Java | Go | Rust | Node | Python | Ruby | PHP | .NET | Swift |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `decodeBase64` | g5 | 2.3 | 19.5 | 3.4 | 14.2 | 31.9 | 15.5 | 3.3 | 15.5 | n/a |
| `core` | g5 | 780 | 210 | 567 | 535 | 644 | 1,935 | 3,407 | 2,589 | 627 |
| `verifierBase64` | g5 | 784 | 251 | 567 | 573 | 687 | 2,031 | 3,299 | 2,161 | 549 |
| `endpointJson` | g5 | 849 | 384 | 630 | 712 | 877 | 1,952 | 3,510 | 1,871 | 763 |
| `retryViaResult` | g5 | 830 | 284 | 603 | 670 | 803 | 1,959 | 3,492 | 1,839 | 732 |
| `rejectTamperedSignature` | g5 | 749 | 169 | 562 | 466 | 496 | 1,667 | 2,992 | 2,251 | 485 |
| `decodeBase64` | legacy | 27.7 | 256 | 45.0 | 186 | 433 | 168 | 44.3 | 216 | n/a |
| `core` | legacy | 3,742 | 2,338 | 1,651 | 4,001 | 9,234 | 16,616 | 24,419 | 3,153 | 8,204 |
| `verifierBase64` | legacy | 3,729 | 2,701 | 1,740 | 4,449 | 9,559 | 16,889 | 24,477 | 3,029 | 8,465 |
| `endpointJson` | legacy | 4,661 | 5,939 | 3,419 | 7,737 | 13,615 | 21,240 | 27,477 | 4,403 | 17,583 |
| `retryViaResult` | legacy | 4,638 | 5,054 | 3,373 | 7,441 | 13,824 | 21,483 | 26,616 | 4,105 | 17,147 |
| `rejectTamperedSignature` | legacy | 1,269 | 339 | 668 | 661 | 1,084 | 2,273 | 3,663 | 2,369 | 796 |

Read the ratios inside one column before the absolute values. This machine
is noisy: a second JMH run of Java `core` the same morning gave 819 µs for
g5 with an error of ±372, and the library just before #161 (`918a0eb`) gave
713 ±594 back to back with it, so #161's key-decoding change is within the
noise. The Java column is about twice the 356 µs the 0.5.1 table showed on
the same kind of VM. The move to the pinned BouncyCastle provider (#152)
accounts for about 90 µs of that; the rest is not explained by any change
measured here, and the column should be re-measured on a quieter machine
before anyone reads a trend into it. Rust's g5 `core` fell from 1,159 to
567 µs now that `rsa` is built with its `u64_digit` feature again.

`rejectTamperedSignature` on the legacy receipt is now far cheaper than
`core` in every port, because the signature is checked before the payload
is parsed. PHP and Ruby
remain the slowest, at about 24 ms and 17 ms for legacy `core`.
