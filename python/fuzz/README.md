# Fuzz targets

Three coverage-guided targets over the boundary between Python and
`aprv.wasm`. `run.sh` pairs each with the fixture directories that seed it,
so nothing under `fixtures/` is copied here.

```bash
./run.sh all             # every target, 60 s each
./run.sh jws 600         # one target, ten minutes
```

There is nothing to install first: `run.sh` builds an ephemeral environment
with `uv`, and it fuzzes the source tree off `PYTHONPATH` rather than an
installed wheel, the same thing the `python` CI job does.

## What is fuzzed, and what is not

The Python package holds no verification logic: no ASN.1, no X.509, no CMS, no
signature check. `aprv.wasm` does all of that, and its parser is fuzzed where
it is written, in `rust/fuzz` (coverage-guided, with OpenSSL instrumented).
What these targets reach is the wrapper: the pool of Wasm instances, the
canonical-ABI call, the mapping of the module's JSON to the 0.7 types, and the
clock handling. Hostile text goes in through the public `Verifier`, and the
invariants are the ones the API promises:

| target | what it reaches | invariant beyond "nothing crashes" |
|---|---|---|
| `receipt-base64` | `Verifier.verify_receipt` on the string a client sends | it never raises, and a receipt accepted under the fixture anchors is refused under an unrelated anchor set |
| `jws` | `Verifier.verify_signed_data` | it never raises, and a JWS accepted under the fixture root fails under Apple's roots |
| `endpoint-json` | `Verifier.verify_receipt_endpoint` on a request body | it never raises, and the answer is always JSON with a numeric `status` |

The anchor-set invariant is the one that lets a fuzzer find "accepts what it
should not" rather than only crashes: without it, an input that verifies tells
you nothing about *why* it verified. `receipt-base64` anchors on the pinned
Apple roots plus `fixtures/generated-0.7/receipt-root.der`, so the shared
fixture receipts and the two public Apple receipts get past the chain check and
the fuzzer can explore what lies beyond it; the unrelated set is the fixture
*JWS* root.

An escape here would be a `wasmtime` error, a `TypeError` or a `KeyError` in
the JSON mapping reaching a caller. A trap inside the module is not an
escape: it is `INTERNAL_ERROR`, by design, and the instance is replaced.

## The fuzzer: atheris

[`atheris`](https://github.com/google/atheris), from Google. It is libFuzzer
driven by coverage counters that atheris writes into Python bytecode as it is
imported, so it takes libFuzzer's corpus directories and flags directly.
`run.sh` here is a near-copy of `rust/fuzz/run.sh` for that reason. The
instrumentation covers the wrapper's own Python; the module's code is
compiled Wasm and gives no Python coverage.

### Why the runs pin CPython 3.13

atheris publishes **only wheels**: 3.1.0 (June 2026) ships three, for CPython
3.12, 3.13 and 3.14 on manylinux x86_64, and no source distribution at all, so
on any other line `pip install atheris` fails outright rather than falling
back to a build. So the fuzzing interpreter is pinned to 3.13, the line covered
by both current releases, and `FUZZ_PYTHON` overrides it. This is a property
of the *fuzzer*, not of the library: the package still claims and tests
3.10 through 3.14, and the `python` job's matrix is what proves that.

The targets are also run without atheris, over the fixtures and a fixed
mutation of them, by `../tests/test_fuzz_targets.py`, so a change that breaks a
target fails on every line of the matrix rather than only where atheris installs.

## Seeds, corpus, crashers

Seeds are the shared fixtures, passed as extra libFuzzer corpus directories.
libFuzzer writes new units only to the first directory, so `corpus/<target>/`
here grows across runs while `fixtures/` stays read-only. `corpus/`,
`artifacts/` and `.seeds-generated/` are gitignored: a corpus is a cache, not a
record.

`seeds/endpoint-json/` holds the four hand-written request bodies that are not
copies of anything. `run.sh` builds one more into `.seeds-generated/`: the
request body carrying a genuine receipt. Building it keeps that receipt at
exactly one copy in the repository.

A crasher lands under `artifacts/<target>/`, which is gitignored **on
purpose**: reduce it and pin it as a test under `../tests/`, where it runs on
every Python line in the matrix rather than only when someone runs the fuzzer.

## Why atheris is not a dependency of anything

`run.sh` installs it into an ephemeral `uv` environment. It is not in
`pyproject.toml`, not in `dependencies` and not in the `dev` extra, so
`uv pip install -e ".[dev]"`, the install every other CI job and every
contributor performs, never pulls a 35 MB native fuzzing runtime. The published
wheel is unaffected either way: `[tool.setuptools] packages` names
`apple_purchase_receipt_verifier` explicitly, so nothing under `fuzz/` has ever
been in it, and `test_trust_isolation.py`'s dependency-set assertion keeps the
runtime set at exactly `wasmtime`.

`python-fuzz` in `.github/workflows/ci.yml` runs each target for a fixed budget
on every push.
