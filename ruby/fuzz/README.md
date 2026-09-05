# Fuzz targets

Six coverage-guided [ruzzy][ruzzy] targets over the parsers this port
hand-writes and the entry points a consumer calls. `run.sh` pairs each with
the shared fixtures that seed it, so nothing under `fixtures/` is copied
here.

[ruzzy]: https://github.com/trailofbits/ruzzy

```bash
sudo apt-get install -y clang libclang-rt-18-dev      # libFuzzer + sanitizer runtimes
MAKE="make --environment-overrides V=1" \
  CC=/usr/bin/clang CXX=/usr/bin/clang++ \
  LDSHARED="/usr/bin/clang -shared" LDSHAREDXX="/usr/bin/clang++ -shared" \
  gem install ruzzy                                    # or: bundle install with gemfiles/fuzz.gemfile

./run.sh all              # every target, 60 s each
./run.sh parse_cms 600    # one target, ten minutes
./run.sh list             # the target names
```

| target | what it reaches | invariant beyond "nothing escapes" |
|---|---|---|
| `parse_der` | `Asn1.scan!`, then `Asn1.parse` on bytes it passed | only `Asn1::Error` escapes |
| `parse_cms` | `Cms.parse` and every accessor on what it returns | after a scan that passed, only `VerificationError` escapes |
| `verify_receipt` | `verify_receipt_core`: CMS, payload, chain, signature | an accepted receipt fails against an unrelated anchor set |
| `verify_receipt_base64` | `ReceiptVerifier#verify_base64` and `#verify`, the string a client sends | only `VerificationError` escapes |
| `verify_transaction` | the three `JwsVerifier` entry points | a JWS `verify_raw` accepts under the fixture root fails under Apple's roots |
| `endpoint_json` | `VerifyReceiptEndpoint#verify_receipt_json` on a request body | it never raises, and the answer is always JSON with a numeric `status` |

The names are the Rust port's, in snake_case because they are Ruby file
names; `rust/fuzz/` additionally carries `parse-certificate`, which here
would only fuzz OpenSSL.

The anchor-set invariant is the one that lets a fuzzer find "accepts what it
should not" rather than only crashes: without it an input that verifies tells
you nothing about *why*. `verify_receipt` pins the Apple receipt roots plus
`fixtures/generated/receipt-root.der`, so both the generated fixtures and the
two public Apple receipts get past the chain check and the fuzzer can explore
what lies beyond it; the unrelated set it must then fail against is the
fixture *JWS* root. `verify_transaction` is the mirror image: the fixture JWS
root trusted, Apple's JWS roots unrelated.

"Nothing escapes" is stricter than it sounds. Every entry point is called
through `FuzzSupport.call`, which rescues `Exception`, not `StandardError`:
a `NoMethodError` from a nil the parser did not expect, a `TypeError`, or a
`SystemStackError` from a recursive path that grew back into the bounded
scanner would each end the run with the input that caused it. That last one
is why this port has a hand-written ASN.1 scanner at all.

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
overflow into `SystemStackError`, and the depth bound the scanner exists to
enforce becomes unobservable — the process would just die.

There is no `-timeout`. libFuzzer's per-unit watchdog is a `SIGALRM` it
declines to install over an existing handler; under Ruby it never takes
effect and the alarm reaches the default disposition, killing the run at
`timeout / 2 + 1` seconds with exit 142 and no timeout report. A hanging unit
is caught by the caller's budget instead — `timeout` locally, the job timeout
in CI, exactly as the Go and Rust targets rely on.

## Throughput

Measured here on one core of a 4-core x86-64 box, three targets at a time,
420 s each on a corpus already warmed by an earlier pass:

| target | execs | branch coverage |
|---|---|---|
| `parse_der` | 651 k | 42 |
| `verify_transaction` | 390 k | 81 |
| `parse_cms` | 388 k | 67 |
| `verify_receipt` | 145 k | 156 |
| `endpoint_json` | 70 k | 188 |
| `verify_receipt_base64` | 39 k | 165 |

The two slow ones are slow for a good reason: their seeds are whole base64
receipts, so libFuzzer raises `max_len` to ~100 KB and every unit is a full
decode plus chain build. They buy depth rather than executions.

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
`lib/`, `sig/`, `certs/`, `README.md` and `LICENSE` and nothing else. Its
dependency lives in `../gemfiles/fuzz.gemfile`, out of both the gemspec and
the test Gemfile, so a tool that needs clang can never fail the Ruby 3.1
matrix leg.
