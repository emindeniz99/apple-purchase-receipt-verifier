# Fuzz targets

Four coverage-guided [ruzzy][ruzzy] targets over the entry points a consumer
calls. Since 0.8 those are a thin host around `aprv.wasm`: the parsers, the
chain walk and the signature checks run inside the module, which `rust/fuzz`
fuzzes with its own targets. What ruzzy's Ruby branch coverage steers here is
the wrapper: input handling, the instance pool, the canonical-ABI call and the
decoding of the module's answers. `run.sh` pairs each target with the shared
fixtures that seed it, so nothing under `fixtures/` is copied here.

[ruzzy]: https://github.com/trailofbits/ruzzy

```bash
sudo apt-get install -y clang libclang-rt-18-dev      # libFuzzer + sanitizer runtimes
MAKE="make --environment-overrides V=1" \
  CC=/usr/bin/clang CXX=/usr/bin/clang++ \
  LDSHARED="/usr/bin/clang -shared" LDSHAREDXX="/usr/bin/clang++ -shared" \
  gem install ruzzy                                    # or: bundle install with gemfiles/fuzz.gemfile

./run.sh all              # every target, 60 s each
./run.sh verify_receipt 600    # one target, ten minutes
./run.sh list             # the target names
```

| target | what it reaches | invariant beyond "nothing escapes" |
|---|---|---|
| `verify_receipt` | `Verifier#verify_receipt` on base64-encoded fuzz bytes | an accepted receipt fails against an unrelated anchor set |
| `verify_receipt_base64` | `Verifier#verify_receipt`, the string a client sends | never raises; the verdict comes back as a `VerificationResult` |
| `verify_transaction` | `Verifier#verify_signed_data`, the one JWS entry point | a JWS that verifies under the fixture root fails under Apple's roots |
| `endpoint_json` | `Verifier#verify_receipt_endpoint` on a request body | never raises, the answer is always JSON with a numeric `status`, and it is never `21009`/`INTERNAL_ERROR` on unauthenticated fuzz input |

The names are the Rust port's, in snake_case because they are Ruby file
names. The two targets of 0.7 that fuzzed this port's hand-written ASN.1 and
CMS readers (`parse_der`, `parse_cms`) are gone with those readers.

The anchor-set invariant is the one that lets a fuzzer find "accepts what it
should not" rather than only crashes: without it an input that verifies tells
you nothing about *why*. `verify_receipt` pins Apple's three roots (the
repository's `certs/`) plus `fixtures/generated-0.7/receipt-root.der`, so both
the generated fixtures and the two public Apple receipts get past the chain
check and the fuzzer can explore what lies beyond it; the unrelated set it must
then fail against is the fixture *JWS* root. `verify_transaction` is the mirror
image: the fixture JWS root trusted, Apple's roots unrelated.

"Nothing escapes" is stricter than it sounds. Every entry point is called
through `FuzzSupport.call`, which rescues `Exception`, not `StandardError`:
a `NoMethodError` from a nil the wrapper did not expect, a `TypeError`, or a
`SystemStackError` would each end the run with the input that caused it. A
trap in the module is not a finding here: it is answered as INTERNAL_ERROR,
and the `endpoint_json` target treats that answer (21009) as an invariant
violation, since a fuzzer cannot forge a signature and the module should never
trap on unauthenticated input.

## How it works

Ruby has no compile-time instrumentation to hand libFuzzer, so ruzzy uses
Ruby's own branch coverage: `Ruzzy.trace` turns on
`Coverage.start(branches: true)`, hooks `RUBY_EVENT_COVERAGE_BRANCH`, and
feeds each distinct branch into libFuzzer's 8-bit counters. libFuzzer itself
arrives through `LD_PRELOAD` of a shared object ruzzy links at install time
from clang's `libclang_rt.fuzzer_no_main` and `libclang_rt.asan`.

Two consequences worth knowing before editing anything here:

* **Coverage only sees code loaded after the trace starts.** `tracer.rb`
  requires nothing but ruzzy; the target requires `support.rb`, which
  requires the library. Requiring the library any earlier — from the tracer,
  or from a `-r` flag — fuzzes it with no feedback at all and the run looks
  fine while finding nothing.
* **A raised exception ends the process, and libFuzzer records that as the
  crash.** An invariant violation is therefore just a `raise`; the offending
  unit lands under `artifacts/<target>/`.

`ASAN_OPTIONS` carries `use_sigaltstack=0` on purpose: ASAN's alternate
signal stack otherwise displaces the one Ruby installs to turn a stack
overflow into `SystemStackError`, so a deep recursion would kill the process
instead of raising.

There is no `-timeout`. libFuzzer's per-unit watchdog is a `SIGALRM` it
declines to install over an existing handler; under Ruby it never takes
effect and the alarm reaches the default disposition, killing the run at
`timeout / 2 + 1` seconds with exit 142 and no timeout report. A hanging unit
is caught by the caller's budget instead — `timeout` locally, the job timeout
in CI, exactly as the Go and Rust targets rely on.

## Throughput

Not measured for the wasm host. Every call runs the module, so a unit costs
about a millisecond for a receipt (`bench/startup.rb`). `verify_receipt`
passes `-max_len=65536`, as the .NET and Java receipt targets do, because
`fixtures/generated-0.7` seeds it with files of 1 to 3 MB that would
otherwise let libFuzzer grow inputs to its 1 MB ceiling. The other targets
take libFuzzer's default, so seeds that are whole base64 receipts raise their
`max_len` to about 100 KB and cost more.

## Corpus and findings

`corpus/`, `artifacts/` and `.seeds/` are gitignored. A crasher is not
committed here: reduce it and pin it as a test under `../test/`, where it
runs on every Ruby in the matrix rather than only where a libFuzzer-capable
clang happens to be installed.

`endpoint_json` is the one target with no fixture to seed from — no fixture
is a verifyReceipt request body — so `seeds.rb` builds its corpus at run time
from the public receipts and the `receipt-b64` fixtures. Generated rather
than committed, so a receipt fixture is never duplicated into this port where
it could drift from the shared one.

## Licence

ruzzy is AGPL-3.0-only; this project is MIT. It is a development tool run out
of process against the harness in this directory, and neither ruzzy nor
anything under `ruby/fuzz/` is distributed with the gem — the gemspec ships
`lib/`, `sig/`, `licenses/`, `README.md` and `LICENSE` and nothing else. Its
dependency lives in `../gemfiles/fuzz.gemfile`, out of both the gemspec and
the test Gemfile, so a tool that needs clang can never fail the Ruby 3.3
matrix leg.
