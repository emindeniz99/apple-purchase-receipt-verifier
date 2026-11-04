# Fuzz targets

Five `cargo fuzz` targets over the verifiers a consumer calls, two over
the payload decoders that run only once a signature has passed, and one
over the module's canonical ABI (`abi/`, a package of its own). The parsers
underneath are OpenSSL's (`../openssl/`), which OSS-Fuzz fuzzes upstream;
the targets that drove this crate's own DER, X.509 and CMS readers went
with those readers. `run.sh` pairs each with the shared fixtures
that seed it, so nothing under `fixtures/` is copied here.

```bash
cargo install cargo-fuzz --locked
rustup toolchain install nightly --profile minimal   # sanitizer flags
./run.sh all              # every target but abi-call, 60 s each
./run.sh verify-receipt 600    # one target, ten minutes
APRV_WASM=<out>/aprv.wasm ./run.sh abi-call 600   # the module, built by
                                                   # rust/bindings/abi/build.sh
./asan-openssl.sh <dir> 600    # every target but abi-call, over an OpenSSL
                               # built with ASan and coverage instrumentation
```

| target | what it reaches | invariant beyond "no panic" |
|---|---|---|
| `verify-receipt` | `Verifier::verify_receipt` on the base64 of arbitrary DER: CMS, chain, signature, payload | never `INTERNAL_ERROR`; an accepted receipt carries the payload of a seed that verifies, and fails against an unrelated anchor set |
| `verify-receipt-base64` | `Verifier::verify_receipt`, the string a client sends | none |
| `verify-transaction` | `Verifier::verify_signed_data` | a JWS accepted under the fixture root carries the signing input (`header.payload`) of a seed that verifies, and fails under Apple's roots; the clock is fixed |
| `endpoint-json` | `Verifier::verify_receipt_endpoint` on a request body | the answer is always a body that starts with `status` |
| `ffi` | the C ABI's exports (`../ffi`), called as Rust functions: the length-taking calls, the C-string calls, the endpoint | each `_bytes` call answers `aprv-wire`'s document over `aprv-surface`, byte for byte; a C-string call answers what the `_bytes` call answers for the bytes before the first NUL |
| `receipt-payload` | the receipt payload decoder on a receipt's signed content (the eContent), through the `test-seams` hook `__internal::read_receipt_content` | a refusal is `UNREADABLE_PAYLOAD`; a decoded payload's `to_json()` parses as a JSON object; the creation date read before the signature (the chain instant) equals the one the payload reports |
| `jws-payload` | the JWS payload reader on a decoded payload segment, through the `test-seams` hook `__internal::read_jws_payload` | a refusal is `UNREADABLE_PAYLOAD`; an accepted payload's `json()` is the input, byte for byte |
| `abi-call` | `aprv.wasm` in Wasmtime, called through a hand-rolled canonical-ABI host (`cabi_realloc`, the return area, `cabi_post_`), one instance reused across inputs as a pool would | an endpoint call whose `env` has a low byte over 1 traps (the lift reads the low 8 bits, so 256 is production); every other call returns, and its answer has the wire shape (a verdict, or a body starting with `status`). An instance is replaced only after a trap |

`abi-call`'s coverage is the host's and Wasmtime's: the module's own code
is compiled by Cranelift, not instrumented, so libFuzzer mutates blind
inside it (coverage stops growing within a minute). Its job is the
contract between host and module (lowering, lifting, post-return, reuse
after a refusal), not the parsers the other targets reach with coverage.

`asan-openssl.sh` links the targets against OpenSSL built by
`tools/openssl-asan.sh` (AddressSanitizer plus `-fsanitize=fuzzer-no-link`),
so libFuzzer follows edges inside OpenSSL's CMS, X.509 and ASN.1 code, and
ASan sees its memory errors. Without it the targets link the system or
vendored OpenSSL, uninstrumented: coverage stops at the adapter's calls.

The whole-input targets barely reach the payload decoders. A receipt's
payload is decoded only after a signature a pinned root vouches for has
passed, which random bytes never carry; before that only its creation
date is read. A JWS payload is read only once the header and all three
`x5c` certificates parse, and a mutation there lands in base64url. The
payload targets call the same decode the verifier runs after the
signature, with nothing in front of it; `../tests/signed_payload_decode.rs`
checks that each hook answers what the verifier answers for a signed
fixture. Their seeds are bytes no fixture holds as a file, so `run.sh`
has `derive-seeds.py` extract them (each receipt's eContent, each JWS's
decoded payload) into `corpus/<target>/` before the run; nothing derived
is committed. The fuzz crate turns the core's `test-seams` feature on for
these hooks, and so for every target in it; the feature adds no check and
changes no verdict.

The two acceptance invariants are what let a fuzzer find "accepts what it
should not" rather than only crashes. The anchor-set one shows the anchors
decided; the seed one shows the signature covers what is returned, since a
fuzzer cannot forge a signature and so can only get accepted what a seed's
signer signed. Without the seed check, a broken content signature under a
genuine chain would pass the anchor check. The targets read the seeds from
the directories `run.sh` passes them (`SEED_DIRS` in each target), so a run
seeded from other directories must add them there.

CI (`rust-fuzz` in `.github/workflows/ci.yml`) runs each target for a fixed
budget on every push; `CI-NOTES.md` says what the nightly job adds. A crasher lands under `artifacts/<target>/`, which is
gitignored on purpose: reduce it and pin it as a test under `../tests/`,
where it runs on every toolchain in the matrix rather than only when a
nightly is around.
