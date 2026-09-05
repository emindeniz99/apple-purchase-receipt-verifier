# Fuzz targets

Five coverage-guided targets over the verifiers a consumer calls and the one
parser this port hand-writes. `run.sh` pairs each with the fixture directories
that seed it, so nothing under `fixtures/` is copied here.

```bash
./run.sh all             # every target, 60 s each
./run.sh jws 600         # one target, ten minutes
```

There is nothing to install first: `run.sh` builds an ephemeral environment
with `uv`, and it fuzzes the source tree off `PYTHONPATH` rather than an
installed wheel — the same thing the `python` CI job does.

## The fuzzer: atheris

[`atheris`](https://github.com/google/atheris), from Google. It is libFuzzer
driven by coverage counters that atheris writes into Python bytecode as it is
imported, so it is the same kind of tool as `cargo fuzz` and `go test -fuzz`,
not a random-input loop, and it takes libFuzzer's corpus directories and flags
directly. `run.sh` here is a near-copy of `rust/fuzz/run.sh` for that reason.

What that instrumentation buys is the point of the whole directory. This port
parses CMS with `asn1crypto`, a pure-Python library, and the owner's decision
is to keep it. Instrumented, its `ContentInfo` / `SignedData` / SET decoding
is inside the coverage signal that steers mutation; without instrumentation a
fuzzer would be guessing at a BER parser from the outside. `cryptography`, the
other dependency, is a compiled extension and contributes no Python coverage
either way — which is why there is no target aimed at certificate parsing on
its own, the way the Rust port has one for its own X.509 reader.

`pythonfuzz`, the alternative, was rejected on maintenance: its last release
is 1.0.3 from November 2019.

### Why the runs pin CPython 3.13

atheris publishes **only wheels** — 3.1.0 (June 2026) ships three, for
CPython 3.12, 3.13 and 3.14 on manylinux x86_64, and no source distribution at
all, so on any other line `pip install atheris` fails outright rather than
falling back to a build. Older releases do carry an sdist (3.0.0, November
2025, wheels for 3.11-3.13; 2.3.0, August 2023, wheels for 3.6-3.11), but
building it needs clang with `-fsanitize=fuzzer-no-link`, which is not
something a CI job should be doing to obtain a linter-grade tool.

So the fuzzing interpreter is pinned to 3.13, the line covered by both current
releases, and `FUZZ_PYTHON` overrides it. This is a property of the *fuzzer*,
not of the library: the package still claims and tests 3.9 through 3.14, and
the `python` job's matrix is what proves that. A bug these targets find is
reproduced as a test under `../tests/`, where it runs on every one of those
lines rather than only where atheris installs.

## The targets

| target | what it reaches | invariant beyond "nothing crashes" |
|---|---|---|
| `receipt-der` | `verify_receipt_core`: the asn1crypto CMS walk, the payload parse, chain building, the RSA signature | an accepted receipt fails against an unrelated anchor set |
| `receipt-attributes` | `receipt.py`'s own DER reader: `_read_tlv`, the attribute SET walk, the string/integer/date decoders | failures are `VerificationError`, never `IndexError`/`UnicodeDecodeError` |
| `receipt-base64` | `ReceiptVerifier.verify` on the string a client sends, through `decode_receipt_base64` | failures are `VerificationError` |
| `jws` | the three `JwsVerifier` entry points: segments, JSON, `x5c`, chain, ES256 | a JWS `verify_raw` accepts under the fixture root fails under Apple's roots |
| `endpoint-json` | `VerifyReceiptEndpoint.verify_receipt_json` on a request body | it never raises, and the answer is always JSON with a numeric `status` |

The anchor-set invariant is the one that lets a fuzzer find "accepts what it
should not" rather than only crashes: without it, an input that verifies tells
you nothing about *why* it verified. `receipt-der` anchors on the pinned Apple
roots plus `fixtures/generated/receipt-root.der`, so the shared fixture
receipts and the two public Apple receipts get past the chain check and the
fuzzer can explore what lies beyond it; the unrelated set is the fixture *JWS*
root. Both accept branches are live, not decorative — the genuine fixtures do
verify under those anchors and are refused under the unrelated ones.

`receipt-attributes` overlaps `receipt-der` on purpose. The attribute reader is
the only ASN.1 code in this port that is ours rather than asn1crypto's, and it
runs on the payload *before* the signature check — the creation date it reads
is what anchors the certificate validity window. Reached only through
`receipt-der`, it sits behind a CMS envelope the fuzzer has to keep
well-formed; here it gets the payload bytes directly.

## What the targets found

Five escapes, all on the JWS path, all fixed and pinned as regression tests in
`../tests/test_verifiers.py::JwsHostileInputTest`. The receipt path had none:
it already contains hostile input by category (`verify_receipt_core` wraps
everything that is not a `VerificationError`), and its own hostile-input tests
predate this directory. The JWS path had no such guard, so each of these
reached a caller raw:

| escape | site | fix |
|---|---|---|
| `TypeError` | `"x5c": [1, 2, 3]` reached `base64.b64decode` | require every entry to be a string, as the typed ports' JSON decoding does |
| `OverflowError`, `ValueError` | `signedDate: 1e300`, `NaN` (which `json.loads` accepts) reached `datetime.fromtimestamp` | an instant no calendar can express is in no validity window: `INVALID_CHAIN` |
| `ValueError` | one corrupt extension in an `x5c` certificate makes the marker-OID lookup raise instead of returning `ExtensionNotFound` | fail closed, as Node's `safeHasExtension` does |
| `UnsupportedAlgorithm` | an EC curve `cryptography` does not implement, out of chain building | fail closed alongside the two exception types already handled there |
| `InvalidVersion` | `load_der_x509_certificate` on a TBSCertificate with version 11 — it derives from `Exception`, not `ValueError` | catch by category at that call site, the verdict is `INVALID_CERTIFICATE` either way |

The last one is the argument for the category guard rather than a longer list
of exception types: `(ValueError, binascii.Error)` was already a considered
list at that call site, and it was still wrong.

## Seeds, corpus, crashers

Seeds are the shared fixtures, passed as extra libFuzzer corpus directories.
libFuzzer writes new units only to the first directory, so `corpus/<target>/`
here grows across runs while `fixtures/` stays read-only. `corpus/`,
`artifacts/` and `.seeds-generated/` are gitignored: a corpus is a cache, not a
record.

`seeds/endpoint-json/` holds the four hand-written request bodies that are not
copies of anything. Two more seed sets are built by `run.sh` into
`.seeds-generated/`: the request body carrying a genuine receipt, and the raw
attribute SETs lifted out of three generated receipts — the payload bytes
`receipt-attributes` takes, which no fixture holds on its own. Building them
keeps each of those receipts at exactly one copy in the repository.

A crasher lands under `artifacts/<target>/`, which is gitignored **on
purpose**: reduce it and pin it as a test under `../tests/`, where it runs on
every Python line in the matrix rather than only when someone runs the fuzzer.
All five findings above went through exactly that path, and none of them is
reproduced by a committed blob.

## Why atheris is not a dependency of anything

`run.sh` installs it into an ephemeral `uv` environment. It is not in
`pyproject.toml` — not in `dependencies`, not in the `dev` extra — so
`uv pip install -e ".[dev]"`, the install every other CI job and every
contributor performs, never pulls a 35 MB native fuzzing runtime. The
published wheel is unaffected either way: `[tool.setuptools] packages` names
`apple_purchase_receipt_verifier` explicitly, so nothing under `fuzz/` has ever
been in it, and `test_trust_isolation.py`'s dependency-set assertion keeps the
runtime set at exactly `asn1crypto` and `cryptography`.

`python-fuzz` in `.github/workflows/ci.yml` runs each target for a fixed budget
on every push.
