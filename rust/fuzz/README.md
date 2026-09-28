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
| `parse-der` | `asn1::parse_exact` on raw bytes | none |
| `parse-certificate` | `x509::Certificate::from_der`, then every accessor | none |
| `parse-cms` | `cms::parse_cms` and the two signed-attribute readers, for every `SignerInfo` | none |
| `verify-receipt` | `Verifier::verify_receipt` on the base64 of arbitrary DER: CMS, chain, signature, payload | never `INTERNAL_ERROR`; an accepted receipt fails against an unrelated anchor set |
| `verify-receipt-base64` | `Verifier::verify_receipt`, the string a client sends | none |
| `verify-transaction` | `Verifier::verify_signed_data` | a JWS accepted under the fixture root fails under Apple's roots |
| `endpoint-json` | `Verifier::verify_receipt_endpoint` on a request body | the answer is always a body that starts with `status` |

The anchor-set invariant is the one that lets a fuzzer find "accepts what
it should not" rather than only crashes: without it an input that verifies
tells you nothing about *why*.

CI (`rust-fuzz` in `.github/workflows/ci.yml`) runs each target for a fixed
budget on every push. A crasher lands under `artifacts/<target>/`, which is
gitignored on purpose: reduce it and pin it as a test under `../tests/`,
where it runs on every toolchain in the matrix rather than only when a
nightly is around.
