# Fuzz targets

Seven `cargo fuzz` targets over the parsers this crate hand-writes and the
verifiers a consumer calls. `run.sh` pairs each with the shared fixtures
that seed it, so nothing under `fixtures/` is copied here.

```bash
cargo install cargo-fuzz --locked
rustup toolchain install nightly --profile minimal   # sanitizer flags
./run.sh all              # every target, 60 s each
./run.sh parse-cms 600    # one target, ten minutes
```

| target | what it reaches | invariant beyond "no panic" |
|---|---|---|
| `parse-der` | `asn1::parse_exact` on raw bytes | — |
| `parse-certificate` | `x509::Certificate::from_der`, then every accessor | — |
| `parse-cms` | `cms::parse_cms` and the two signed-attribute readers | — |
| `verify-receipt` | `verify_receipt_core`: CMS, payload, chain, signature | an accepted receipt fails against an unrelated anchor set |
| `verify-receipt-base64` | `ReceiptVerifier::verify_base64`, the string a client sends | — |
| `verify-transaction` | the three `JwsVerifier` entry points | a JWS `verify_raw` accepts under the fixture root fails under Apple's roots |
| `endpoint-json` | `VerifyReceiptEndpoint::verify_receipt_json` on a request body | the answer is always JSON with a `status` |

The anchor-set invariant is the one that lets a fuzzer find "accepts what
it should not" rather than only crashes: without it an input that verifies
tells you nothing about *why*.

CI (`rust-fuzz` in `.github/workflows/ci.yml`) runs each target for a fixed
budget on every push. A crasher lands under `artifacts/<target>/`, which is
gitignored on purpose: reduce it and pin it as a test under `../tests/`,
where it runs on every toolchain in the matrix rather than only when a
nightly is around.
