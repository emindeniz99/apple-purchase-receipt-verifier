# CI notes for the fuzz targets (lane A3)

What `.github/` needs for MIGRATION.md step 1.12. None of it is applied
here.

## Every push (`rust-fuzz`, as today)

1. **Five targets now, not four.** `./run.sh all <seconds>` runs
   `verify-receipt`, `verify-receipt-base64`, `verify-transaction`,
   `endpoint-json` and the new `ffi`; the job's per-target budget
   multiplies by five. `ffi` builds `../ffi` as an rlib (the crate's
   `crate-type` now lists `rlib` beside `cdylib` and `staticlib`) and
   the surface and wire crates; nothing else in the job changes.
2. **`abi-call` is not in `all`.** It needs the built module and
   Wasmtime; see the nightly job.

## Nightly (new job, or a leg of the existing nightly)

3. **The core over an instrumented OpenSSL, ten minutes per target:**

   ```sh
   rust/fuzz/asan-openssl.sh "$RUNNER_TEMP/openssl-asan" 600
   ```

   It builds OpenSSL with `tools/openssl-asan.sh` into the directory
   when the directory holds no `lib/libcrypto.a`; cache that directory
   keyed on `tools/openssl-asan.sh` and `tools/wasm-toolchain.sh` (the
   tarball pin lives there). Needs clang, a nightly Rust with cargo-fuzz
   0.13 (`FUZZ_TOOLCHAIN` names it), perl and make. Five targets, 50 minutes of fuzzing plus the builds.
4. **`abi-call`, ten minutes, after `rust/bindings/abi/build.sh`:**

   ```sh
   APRV_WASM="$RUNNER_TEMP/aprv/aprv.wasm" rust/fuzz/run.sh abi-call 600
   ```

   `rust/fuzz/abi/` is a package of its own (own `[workspace]` and
   `Cargo.lock`) so that Wasmtime 49.0.1 stays out of the other targets'
   graph; its cold build took 20 minutes here with two jobs. Its target
   directory may be cached in this job (it is not a publish job). The
   first input of 13 bytes or more compiles the module (Cranelift inside
   an instrumented build: 86 s here), and libFuzzer reports that input as
   a `slow-unit-*` artifact (here the 19 bytes `{"receipt-data":""}`);
   it is the compile, not a finding, and the job should not fail on a
   slow unit alone.
5. **Artifacts.** Never upload `rust/fuzz/artifacts/` or
   `rust/fuzz/abi/artifacts/` (gitignored) as they are: the repository
   is public. The nightly job and the per-push `rust-fuzz` job keep each
   target's output on the runner and hand a failed target to
   `.github/scripts/fuzz-finding.sh`, which
   prints only the target and the input's SHA-256 and seals the input
   and report with age to the owner's key (DECISIONS.md R37). A crasher
   becomes a test under `rust/tests/` built from test keys only; no
   issue carries it until it is triaged.
6. **Corpora.** `rust/fuzz/corpus/` and `rust/fuzz/abi/corpus/` are
   gitignored; caching them between nightly runs is optional (a cache
   restore is safe here: nothing is published from this job).

## The 2026-09-29 run

Ten minutes per target on a shared four-core machine (other lanes'
builds running), nightly Rust, cargo-fuzz 0.13.2, OpenSSL 4.0.2 built by
`tools/openssl-asan.sh`, `abi-call` over the name-stripped module of
`rust/bindings/abi/build.sh`:

| Target | Runs | Coverage (cov / ft) | Corpus | Finding |
|---|---|---|---|---|
| `verify-receipt` | 284,043 | 6,440 / 22,201 | 820 units, 6.4 MB | none |
| `verify-receipt-base64` | 738,649 | 5,664 / 16,352 | 729 units, 15.6 MB | none |
| `verify-transaction` | 1,015,209 | 6,443 / 18,338 | 866 units, 1.7 MB | none |
| `endpoint-json` | 1,656,477 | 6,479 / 17,906 | 1,651 units, 5.3 MB | none |
| `ffi` | 9,512,387 | 4,988 / 10,856 | 1,971 units, 318 KB | none |
| `abi-call` | 506,142 | 45,999 / 47,023 (host side) | 39 units, 80 KB | none (one slow unit: the module's compile, item 4) |

Every run ended at its 600 s budget with exit 0: no crash, no ASan or
LeakSanitizer report, no timeout, no invariant failure. Coverage counts
are libFuzzer's and are not comparable between the five OpenSSL targets
and `abi-call`, whose count is Wasmtime's.
