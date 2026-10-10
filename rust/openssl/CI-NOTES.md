# CI notes for the OpenSSL core

What `.github/` needs for the OpenSSL-backed core. None of it is applied
here; the workflow files belong to the integration of this branch.

## Test and lint jobs (`rust`, `rust-lint`)

1. **Every cargo command that builds OpenSSL runs with `working-directory:
   rust`** (or `rust/ffi`, `rust/fuzz`), as the jobs do today.
   `rust/.cargo/config.toml` sets `OPENSSL_CONFIG_DIR`, and Cargo reads it
   by working directory only.
2. **The default build compiles OpenSSL 4.0.3 from source** (openssl-src,
   about 5 to 7 minutes on two cores, once per cache key). It needs `perl`,
   `make` and a C compiler, all on the GitHub Linux and macOS images. Test
   jobs keep caching `target/` (publish jobs still never cache).
3. **`cargo test --locked --no-default-features` now links a system
   OpenSSL**, and `aprv-openssl`'s build script refuses anything older than
   4.0, so on ubuntu-latest (OpenSSL 3) that leg fails as written. Either
   give it an OpenSSL 4 (`OPENSSL_NO_VENDOR=1 OPENSSL_DIR=<prefix>
   OPENSSL_STATIC=1`, built from the pinned tarball in
   `openssl/README.md`), which makes it the prebuilt-OpenSSL leg, or drop
   it. Before this branch the crate had no features, so the leg repeated
   the default one.
4. **The isolation test wants `strace`.** Install it on the Linux legs
   (`sudo apt-get install -y strace`) and set `APRV_REQUIRE_STRACE=1`, so a
   missing or blocked tracer fails the job instead of skipping the
   system-call half of `openssl/tests/isolation.rs`. macOS and Windows run
   the test without the trace.
5. **The 1.85.0 floor** was not run here (no 1.85 toolchain in this
   session). Every new dependency declares a `rust-version` at or below it
   (openssl 1.80, openssl-sys 1.80, cc 1.65, libc 1.65), and the adapter
   uses nothing newer than 1.82 (`&raw mut`, `Option::is_none_or`), but the
   floor leg is the proof.
6. `cargo clippy --locked --all-targets --all-features -- -D warnings` and
   `cargo fmt --check` from `rust/` cover both crates (one workspace).

## `rust-ffi` (Linux, macOS, Windows)

7. `rust/ffi` is its own workspace now (an empty `[workspace]` table), with
   the same `[patch.crates-io]`; its lock was regenerated. The Windows leg
   builds OpenSSL with MSVC through openssl-src, which needs Perl
   (Strawberry Perl is on the image) and, for the assembly, NASM; neither
   Windows nor macOS was run here.
8. `cargo deny --manifest-path ffi/Cargo.toml --config deny.toml check`:
   with cargo-deny 0.18.9, `--config` is an option of `check`
   (`cargo deny --manifest-path ffi/Cargo.toml check --config deny.toml`),
   and a relative path there did not find the file (every licence came
   back "not explicitly allowed"); an absolute path worked. Check the
   installed version's behaviour when the job next runs.

## `cargo-deny` (`rust` workspace)

9. `deny.toml` no longer bans `openssl` and `openssl-sys`, bans
   `openssl-probe`, drops the RUSTSEC-2023-0071 ignore with the `rsa`
   crate, and allows `Unicode-3.0` (unicode-ident under openssl-macros).
   `bans licenses sources` pass for both manifests; `advisories` was not
   run here (the advisory database could not be fetched from this session).

## `rust-fuzz`

10. Four targets remain (`verify-receipt`, `verify-receipt-base64`,
    `verify-transaction`, `endpoint-json`); `run.sh all` knows them. The
    job's comment still describes "the hand-written ASN.1, CMS, X.509 and
    JWS readers"; only the JSON reader is still hand-written. The fuzz
    crate builds the vendored OpenSSL without sanitizer instrumentation;
    for coverage inside OpenSSL, link the ASan and fuzzer-no-link build
    (`docs/evidence/2026-09-26-substrate-followup/scripts/build-libs.sh
    openssl-fuzz`) with `OPENSSL_NO_VENDOR=1 OPENSSL_DIR=...`.

## Release (`release.yml`, `release-please.yml`)

11. **Blocker for crates.io.** A crates.io user does not get the
    workspace's openssl-sys patch, so the published core's default
    `vendored` feature pulls openssl-src 300.x (OpenSSL 3), which
    `aprv-openssl`'s build script refuses. Until openssl-sys accepts
    openssl-src 400.x, a registry build works only with
    `OPENSSL_NO_VENDOR=1 OPENSSL_DIR=<OpenSSL 4>`, and
    `post-publish-smoke.yml`'s `crates` job fails as written. This needs a
    decision before a release carries the migration.
12. `publish-crates` must publish `aprv-openssl` (`rust/openssl`) before
    the core, which now requires it at the same version. crates.io trusted
    publishing is configured per crate, and a new crate cannot be created
    by the OIDC flow: the first `aprv-openssl` publish is an owner
    bootstrap step (`BOOTSTRAP.md`, crates.io section).
13. `release-please-config.json` now bumps `rust/openssl/Cargo.toml` and
    the core's requirement on it (the generic marker on that line). The
    lock step after release-please should run `cargo update --workspace`
    in `rust/` (it covers both crates) and, in `rust/ffi` and `rust/fuzz`,
    `cargo update -p apple-purchase-receipt-verifier -p aprv-openssl`.

## Dependabot

14. `rust/vendor/openssl-sys` is a patched copy of openssl-sys 0.9.117. A
    Dependabot bump of `openssl-sys` past 0.9.117 leaves the patch unused
    and brings back openssl-src 300.x, which the build refuses. Ignore
    `openssl-sys` (and keep `openssl-src` on 400.x) in the three cargo
    ecosystems; move it with `rust/vendor/refresh-openssl-sys.sh`, which
    downloads the release, checks its SHA-256 and changes the one line.
15. `aprv-openssl` imports `ForeignType` and `ForeignTypeRef` from
    foreign-types 0.3 to reach the raw pointers behind the openssl crate's
    `X509` and CMS types. Those types implement the traits of the
    foreign-types release the openssl crate depends on (0.3, through
    foreign-types-shared 0.1), so a newer foreign-types is a second pair
    of traits that nothing implements and the crate stops compiling (#197).
    Dependabot ignores `foreign-types >= 0.4.0` in `/rust` and
    `/rust/fuzz`; it moves only together with the openssl crate.

## `changes` filter

15. Nothing to do: `.github/scripts/changed-areas.sh` maps every `rust/*`
    path to the `rust` area, which covers `rust/openssl/`, `rust/vendor/`
    and `rust/.cargo/`.

## wasm32-wasip1 (lane A2)

16. The core builds for wasm32-wasip1 against the wasi-sdk 34 OpenSSL
    4.0.3 with `CC_wasm32_wasip1`, `CFLAGS_wasm32_wasip1="--target=wasm32-wasip1
    --sysroot=<wasi-sdk>/share/wasi-sysroot"`, `AR_wasm32_wasip1`,
    `OPENSSL_NO_VENDOR=1 OPENSSL_DIR=<prefix> OPENSSL_STATIC=1` (see
    `openssl/README.md`). Linking a wasip1 binary also needs the wasi-sdk
    sysroot's libc and crt: `-C link-self-contained=no -L
    native=<sysroot>/lib/wasm32-wasip1 -C
    link-arg=<sysroot>/lib/wasm32-wasip1/crt1-command.o` (or the reactor
    crt) and the four `wasi-emulated-*` libraries.
