# Fuzz targets

Six coverage-guided targets over the parsers this package hand-writes and the
verifiers a consumer calls. `run.sh` pairs each target with the shared fixtures
that seed it, so nothing under `fixtures/` is committed here.

```bash
./run.sh all               # every target, 60 s each
./run.sh parse-cms 600     # one target, ten minutes
```

The first run downloads the fuzzer (1.3 MB) into `tools/`, verifying it against
a pinned sha256 before it is executed. `tools/`, `corpus/` and `crashes/` are
gitignored.

| target | what it reaches | invariant beyond "nothing but a verdict escapes" |
|---|---|---|
| `parse-der` | `Der::parse` on raw bytes, then every accessor on every node | — |
| `parse-cms` | `Cms::parse`, the embedded certificates, the signer lookup and both signed-attribute readers | — |
| `verify-receipt` | `ReceiptVerifier::verifyReceiptCore`: CMS, payload, chain, signature | an accepted receipt fails against an unrelated anchor set |
| `verify-receipt-base64` | `ReceiptVerifier::verify` on the transport string a client sends | — |
| `verify-transaction` | the three `JwsVerifier` entry points | a JWS `verifyRaw` accepts under the fixture root fails under Apple's roots |
| `endpoint-json` | `VerifyReceiptEndpoint::verifyReceiptJson` on a request body | the answer is always JSON with an integer `status` |

The anchor-set invariant is the one that lets a fuzzer find "accepts what it
should not" rather than only crashes: without it, an input that verifies tells
you nothing about *why* it verified. `verify-receipt` runs against the pinned
Apple receipt roots plus `fixtures/generated/receipt-root.der` — six generated
receipts and both public Apple receipts get past the chain check with that set,
so the branch behind it is reached on nearly every iteration rather than being
decoration — and re-runs anything accepted against `jws-root.der`.
`verify-transaction` is the mirror image: the fixture JWS root accepts three
generated payloads, and each is required to fail under Apple's roots.

## What counts as a crash

The library's contract is that a public entry point raises
`VerificationException` and nothing else, so each target declares exactly the
exception types its entry point documents and **every other `Throwable` is a
finding**:

| target | allowed |
|---|---|
| `parse-der` | `Internal\ParseException` |
| `parse-cms` | `VerificationException`, `Internal\ParseException` |
| `verify-receipt`, `verify-receipt-base64`, `verify-transaction` | `VerificationException` |
| `endpoint-json` | nothing — `verifyReceiptJson` never throws |

That covers more than a segfault would. php-fuzzer installs an error handler
that turns every warning and notice into an `Error`, so an undefined array key
or a `substr()` on a negative offset is caught here even though PHP would let
the call return; an `InvalidArgumentException` counts too, since with a
non-empty anchor set the misconfiguration path is unreachable and reaching it
means a parser handed the wrong thing to a constructor. `TypeError`,
`ValueError` and `ArgumentCountError` are `Error`s and were never allowed.

The one failure mode a `catch` cannot see is a `memory_limit` fatal, which is
not a `Throwable` at all — the reason `Der` has a retained-byte budget on top
of its node and depth budgets (see the port's README, "Defensive bounds").
`run.sh` therefore runs with a finite `memory_limit=512M`: php-fuzzer's
shutdown handler saves the input that caused a fatal error, so an allocation
bomb is a recorded, reducible finding instead of an OOM-killed container.

## The fuzzer: nikic/php-fuzzer, as a pinned phar

`nikic/php-fuzzer` is the only coverage-guided fuzzer for PHP. It is a
libFuzzer-shaped engine written in pure PHP: it instruments each file as it is
included, by rewriting the source through a stream wrapper and recording edge
coverage, then mutates the corpus with libFuzzer's own mutator set and keeps
whatever produces a new edge. Nothing has to be compiled and no extension is
needed — the alternatives all do, and none of them exists for PHP: there is no
`cargo-fuzz`, no `go test -fuzz`, and PHP's own OSS-Fuzz integration fuzzes the
interpreter, not libraries written in it. It needs neither `pcov` nor Xdebug;
those measure line coverage for test reports and cannot drive a mutator.

**It is installed as a phar, deliberately.** Its own README recommends the
phar "because it avoids dependency conflicts with libraries using PHP-Parser",
which it depends on. But the reason it stays out of `composer.json` here is
narrower and this repository's own: this package ships **no lockfile** on
purpose, and its CI resolves `require-dev` twice — once normally and once with
`--prefer-lowest --prefer-stable`. A fuzzer in `require-dev` would join both
resolutions, and its `nikic/php-parser` requirement would then be free to move
the version PHPUnit and PHP-CS-Fixer resolve to on the `--prefer-lowest` leg —
a fuzzing tool silently deciding what the *test* toolchain is. It has no
business in the dependency graph of a library whose entire point is having
almost none. `run.sh` pins the release URL and its sha256 and checks the digest
before running the file, so this is not "curl into a shell": a tampered or
truncated download refuses to execute.

**Maintenance status, recorded because it is a real risk.** The project is at
`v0.0.11` (May 2025), is one author's side project, and has no stable release.
Nothing else in this space exists, so the choice is this or no coverage-guided
fuzzing for the PHP port — but the exposure is worth naming, and it is bounded
by construction: the phar is a build-time tool that no consumer ever installs,
every target is a plain PHP file whose target closure would survive a switch to
another engine, and the crashers it finds land in `../tests/` as ordinary
PHPUnit tests. If it stops working, the regression tests it produced keep
running on all five PHP matrix legs.

## Seeding, and why the corpus is copied

php-fuzzer takes exactly one corpus directory and writes new and reduced
entries into it. libFuzzer's trick — passing `fixtures/` as an extra read-only
corpus, which is what the Rust port's `run.sh` does — is therefore not
available. `run.sh` copies the seed files into `corpus/<target>/` instead,
content-addressed so re-seeding is idempotent, and that directory is
gitignored. `fixtures/` is never written to and nothing from it is committed
under `php/`.

## When a crasher is found

The run exits non-zero and leaves `crashes/<target>/crash-<hash>.txt`. Reduce
it first — the input that reproduces is rarely the smallest one that does:

```bash
php fuzz/tools/php-fuzzer-v0.0.11.phar minimize-crash \
  fuzz/targets/verify-receipt.php fuzz/crashes/verify-receipt/crash-<hash>.txt
php fuzz/tools/php-fuzzer-v0.0.11.phar run-single \
  fuzz/targets/verify-receipt.php minimized-<hash>.txt
```

Then pin the reduced input as a test under `../tests/` rather than committing
it here, so it runs on every PHP version in the matrix instead of only where a
fuzzer happens to be installed. `tests/HostileInputTest.php` is where the
hand-written hostile shapes live and is the right neighbour for one.

## CI

The `php-fuzz` job in `.github/workflows/ci.yml` runs every target for a fixed
budget on each push. Seeds come from `fixtures/`, so a crasher it finds is a
mutation of a genuine Apple-signed receipt or JWS rather than of noise.
