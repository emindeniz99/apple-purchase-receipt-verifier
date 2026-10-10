# OSS-Fuzz project files (draft)

The owner submits these to [google/oss-fuzz](https://github.com/google/oss-fuzz)
(docs/rust-core/DECISIONS.md R37). They live here so they can be reviewed
with the code they build; OSS-Fuzz reads its own copy under
`projects/apple-purchase-receipt-verifier/` in its repository, never this
one.

| File | What it does |
|---|---|
| `project.yaml` | Homepage, repository, language `rust`, the contact OSS-Fuzz reports to, AddressSanitizer and libFuzzer |
| `Dockerfile` | `base-builder-rust` (clang, a nightly Rust, cargo-fuzz), `make`, `perl` and `zip`, and a shallow clone of this repository |
| `build.sh` | `cargo fuzz build -O --debug-assertions` in `rust/fuzz`, the five target binaries copied to `$OUT`, and one seed corpus zip per target from the same fixture directories `rust/fuzz/run.sh` seeds it with |

## What OSS-Fuzz builds

OpenSSL 4.0.3 comes from `openssl-src` (the default `vendored` feature),
built inside the cargo build with OSS-Fuzz's `CC` and `CFLAGS`, so it
carries the sanitizer and coverage flags and libFuzzer is guided into its
CMS, X.509 and ASN.1 code, as `rust/fuzz/asan-openssl.sh` arranges in the
nightly job. That build needs `perl` and `make`, and it is the slow part:
OpenSSL compiles once per build configuration (address, coverage and the
introspector build), several minutes each. Not measured here: OSS-Fuzz's
infrastructure was not run for this draft.

The image's Rust is the nightly OSS-Fuzz pins in `base-builder-rust`
(`RUSTUP_TOOLCHAIN`, `nightly-2025-09-05` when this was written), which
overrides `rust/rust-toolchain.toml`. The core's floor is Rust 1.85, so the
crates here fit it; a dependency that needs a newer compiler shows up as a
failed `build_fuzzers` below.

## The five targets, and why not six

`verify-receipt`, `verify-receipt-base64`, `verify-transaction`,
`endpoint-json` and `ffi` (`rust/fuzz/README.md` lists what each reaches
and its invariant).

`abi-call` (`rust/fuzz/abi/`) is not in this draft, although R37 names six
targets. It reads `aprv.wasm` from the `APRV_WASM` environment variable,
and OSS-Fuzz runs a fuzzer with no environment of its own, so every input
of 13 bytes or more would panic and `check_build` would fail the whole
project. Its first such input also compiles the module, 86 s in an
instrumented build (`rust/fuzz/CI-NOTES.md`), well past OSS-Fuzz's 25 s
per-input timeout. It can join once the harness finds the module without
the environment (beside its own binary, with `build.sh` copying a pinned
module there) and compiles it before the first input. Until then it runs
by hand (`APRV_WASM=<out>/aprv.wasm rust/fuzz/run.sh abi-call 600`); no
workflow runs it yet either.

## Submitting

1. Replace `OWNER_EMAIL_PLACEHOLDER` in `project.yaml` with the owner's
   address. OSS-Fuzz requires an address that appears as a committer in
   this repository's history and belongs to a Google account; an alternate
   address linked to a Google account gets the issue tracker but not the
   ClusterFuzz dashboard. `auto_ccs` may list more people the same way.
2. Fork google/oss-fuzz and copy the three files into
   `projects/apple-purchase-receipt-verifier/` of the fork (`project.yaml`,
   `Dockerfile`, `build.sh`; not this README).
3. Check the build locally from the fork's root with Docker:

   ```sh
   python3 infra/helper.py build_image apple-purchase-receipt-verifier
   python3 infra/helper.py build_fuzzers --sanitizer address apple-purchase-receipt-verifier
   python3 infra/helper.py check_build apple-purchase-receipt-verifier
   python3 infra/helper.py run_fuzzer apple-purchase-receipt-verifier verify-receipt
   python3 infra/helper.py build_fuzzers --sanitizer coverage apple-purchase-receipt-verifier
   ```

4. Open the pull request against google/oss-fuzz with the three files.
   OSS-Fuzz accepts projects with "a significant user base and/or [that
   are] critical to the global IT infrastructure"; the description should
   say what the library verifies, who runs it (the registries it ships to)
   and that the parsers under it are OpenSSL's, reached through the
   targets with the anchor-set invariant.
5. After the merge, OSS-Fuzz files each crash in its own tracker,
   restricted to the contacts until the fix is released or the deadline
   passes (90 days, or 30 days after a fix). That matches SECURITY.md's
   private reporting: a finding from OSS-Fuzz becomes a test under
   `rust/tests/` built from test keys only, as a nightly finding does.

## Keeping it current

A new target in `rust/fuzz/Cargo.toml` joins `targets` and gets a `seed`
line in `build.sh`, here and in the oss-fuzz fork. A fixture directory
moved in `rust/fuzz/run.sh` moves here too.
