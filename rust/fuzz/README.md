# Fuzz targets

Five `cargo fuzz` targets over the verifiers a consumer calls, and a sixth
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
| `verify-receipt` | `Verifier::verify_receipt` on the base64 of arbitrary DER: CMS, chain, signature, payload | never `INTERNAL_ERROR`; an accepted receipt fails against an unrelated anchor set |
| `verify-receipt-base64` | `Verifier::verify_receipt`, the string a client sends | none |
| `verify-transaction` | `Verifier::verify_signed_data` | a JWS accepted under the fixture root fails under Apple's roots |
| `endpoint-json` | `Verifier::verify_receipt_endpoint` on a request body | the answer is always a body that starts with `status` |
| `ffi` | the C ABI's exports (`../ffi`), called as Rust functions: the length-taking calls, the C-string calls, the endpoint | each `_bytes` call answers `aprv-wire`'s document over `aprv-surface`, byte for byte; a C-string call answers what the `_bytes` call answers for the bytes before the first NUL |
| `abi-call` | `aprv.wasm` in Wasmtime, called through a hand-rolled canonical-ABI host (`cabi_realloc`, the return area, `cabi_post_`), one instance reused across inputs as a pool would | an endpoint call with `env` over 1 traps; every other call returns, and its answer has the wire shape (a verdict, or a body starting with `status`). An instance is replaced only after a trap |

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

The anchor-set invariant is the one that lets a fuzzer find "accepts what
it should not" rather than only crashes: without it an input that verifies
tells you nothing about *why*.

CI (`rust-fuzz` in `.github/workflows/ci.yml`) runs each target for a fixed
budget on every push; `CI-NOTES.md` says what the nightly job adds. A crasher lands under `artifacts/<target>/`, which is
gitignored on purpose: reduce it and pin it as a test under `../tests/`,
where it runs on every toolchain in the matrix rather than only when a
nightly is around.
