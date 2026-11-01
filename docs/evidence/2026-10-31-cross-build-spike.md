# Cross-build spike: building aprv-server and the C ABI for macOS and Windows on Linux

Date: 2026-10-31. Sources and results are in `2026-10-31-cross-build-spike/`
(its `README.md` has the file table and the commands); the CI half is
`.github/workflows/spike-cross-build.yml` with the scripts in `tools/cross/`.
Nothing in `release.yml` or `ci.yml` changed.

**Question.** Can Linux runners build the `aprv-server` binary
(`rust/server`) and the C ABI library (`rust/ffi`) for the release targets,
so macOS and Windows runners only download the files and test them? And
which of three topologies should `release.yml`'s `build-server` take:

- **A**, today: each of six native legs runs `build-static.sh`, which
  builds the Cranelift precompiler, precompiles the component for its
  target, then builds the runtime-only binary around that `.ccwasm`;
- **B**, the precompiler built once on Linux with `wasmtime/all-arch`, one
  `.ccwasm` per target written there, and each target's final runtime-only
  build kept native;
- **C**, B's `.ccwasm` files, and every final binary built on Linux too
  (cargo-zigbuild for darwin and aarch64 Linux, cargo-xwin for Windows),
  with native runners verifying the downloaded files before anything
  publishes.

Labels: **MEASURED** (ran here, on Linux), **MEASURED (API)** (read from
past release.yml runs through the public API), **TO MEASURE** (the spike
workflow's first CI run measures it; nobody has seen that run yet),
**INFERRED** (reasoned, not run), **UNTESTED**.

**Environment** (MEASURED): Linux x86_64 container, 4 vCPU, 15 GB RAM, the
same vCPU count as a GitHub `ubuntu-latest` runner but not the same CPU.
Rust 1.99.1 (`rust/rust-toolchain.toml`), with the rust-std targets
aarch64-apple-darwin, x86_64-apple-darwin, x86_64-pc-windows-gnu and
x86_64-pc-windows-msvc. zig 0.17.0, cargo-zigbuild 0.24.0 and cargo-xwin
0.23.1 from PyPI (`tools/cross/requirements.txt`, hash-pinned); Ubuntu
clang and LLD 18.1.3. Crates: wasmtime 50.0.1. The component is a local
build of this tree, SHA-256 `ce2123fa…1d216a10`; the CI run builds its own.

## Answer

- **The `.ccwasm` does not depend on where or how the precompiler was
  built (MEASURED on one host, TO MEASURE across hosts).** One precompiler
  build on Linux x86_64 wrote all six release targets' `.ccwasm` in 2.7 to
  3.9 s each. Built three ways (release with `compile` only, release with
  `wasmtime/all-arch`, and all-arch with LTO off and 16 codegen units) it
  wrote byte-identical files for every target it could reach. Whether the
  native legs' files (today's A, built on macOS and Windows) equal the
  Linux ones is the spike workflow's first comparison, and the question B
  depends on.
- **The cheaper precompiler profile changes nothing in the output.** LTO off and 16 codegen
  units built the precompiler in 156 s against 291 s, with identical
  `.ccwasm` hashes for all six targets and the same 3 to 4 s per
  precompile.
- **Every server target tried cross-builds from Linux (MEASURED, build
  only; x86_64 musl was not tried here, and is a native Linux build
  today).** aarch64-apple-darwin and x86_64-apple-darwin with cargo-zigbuild,
  x86_64-pc-windows-msvc and aarch64-pc-windows-msvc with cargo-xwin,
  x86_64-pc-windows-gnu and aarch64-unknown-linux-musl with
  cargo-zigbuild; the runtime-only build around a ready `.ccwasm` took
  69 to 126 s per target here.
- **The C ABI cross-builds for darwin and windows-gnu, not for MSVC
  (MEASURED).** OpenSSL compiles through zig for both Macs and for MinGW.
  For both MSVC targets `openssl-src` runs OpenSSL's `Configure
  VC-WIN64A` (or `VC-WIN64-ARM`), which refuses a Unix perl ("This perl
  implementation doesn't produce Windows like paths") and would then need
  `nmake`. No release artifact is a C ABI library today, so this does not
  block a server-only change.
- **cargo-xwin's first fetch of the MSVC CRT and Windows SDK took 16 m 59 s
  here** (its own timer, behind this container's proxy), and release jobs
  may not restore a cache. The CI fetch time is TO MEASURE; until it is
  known, a cross-built Windows binary is not faster than today's native
  one.
- **Three defects a naive cross build ships, found and fixed in
  `tools/cross/build.sh`:** a macOS minimum of 15.0 instead of 11.0, a C
  ABI dylib whose install name is a Linux path, and server test
  executables that look for fixtures at the build machine's path
  (section 2).
- **Recommendation: B** (section 7): the precompiler built once on Linux,
  native final builds. On the numbers below it takes build-server's
  critical path from 13.6 minutes to about 10 (the Linux x86_64 leg's
  reproduction becomes the longest leg; about 7.5 if that reproduction
  reuses the shared `.ccwasm`) and about 14 macOS and 11 Windows runner
  minutes off every release, with no new toolchain on any shipped binary.
  C saves at most a minute more, and only if cargo-xwin's fetch turns out
  short in CI; it adds that fetch, zig's
  signature and MinGW-or-MSVC choices to every shipped binary, and moves
  50 to 340 MB of test executables per target between jobs.

## 1. What cross-builds from Linux (MEASURED, `results/local-builds.txt`)

Each row is one build on the 4-vCPU host with a cold target directory.
"Stage 1" is the precompiler build for the host; "stage 2" the
runtime-only server around the `.ccwasm`. The first four rows ran an
earlier `tools/cross/build.sh` that still built stage 1 itself, as
`build-static.sh` does; the script was then split into
`tools/cross/precompile.sh` (stage 1 and the precompiles, once) and
`tools/cross/build.sh` (everything after, per target), and the last two
rows ran that pair. The earlier script was never committed, so the first
four rows' Stage 1 column cannot be rerun as recorded; `precompile.sh` is
its successor, and its own stage-1 times are in
`results/precompile-timings.tsv`. Every other column is what `build.sh`
runs today.

| Target | Tool | Stage 1 | Stage 2 | Server tests (`--no-run`) | C ABI (release) | C ABI tests | Result |
|---|---|---:|---:|---:|---:|---:|---|
| aarch64-apple-darwin | cargo-zigbuild | 4 m 46 s (all-arch) | 1 m 23 s | 2 m 14 s | 1 m 13 s | 1 m 09 s | every artifact built |
| x86_64-apple-darwin | cargo-zigbuild | 3 m 54 s | 1 m 23 s | 2 m 20 s | 1 m 07 s | 1 m 08 s | every artifact built |
| x86_64-pc-windows-gnu | cargo-zigbuild | 4 m 01 s | 2 m 06 s | 3 m 21 s | 2 m 08 s | 2 m 09 s | every artifact built |
| x86_64-pc-windows-msvc | cargo-xwin | 3 m 54 s | 1 m 09 s, after a 16 m 59 s CRT and SDK fetch | 2 m 32 s | **failed**: OpenSSL `Configure VC-WIN64A` refuses a Unix perl | n/a | server and its tests built; C ABI not |
| aarch64-pc-windows-msvc | cargo-xwin | shared (B) | 1 m 15 s, CRT and SDK from cargo-xwin's cache | 2 m 01 s | **failed**: the same, `VC-WIN64-ARM` | n/a | server and its tests built; C ABI not |
| aarch64-unknown-linux-musl | cargo-zigbuild | shared (B) | 1 m 44 s | 3 m 10 s | none: Rust builds no cdylib for musl | n/a | server and its tests built |

The aarch64-apple-darwin figures are from its first run; its log in
`results/local-builds.txt` is a rerun with a warm target directory
(100 s in all). "shared (B)" rows took their `.ccwasm` from one
`tools/cross/precompile.sh` run (section 4). x86_64-unknown-linux-musl
did not run here (no musl-gcc in this container); release.yml builds it
natively on Linux today, and the spike workflow runs it.

- **The OpenSSL C build works through zig.** The C ABI links the core over
  OpenSSL 4.0.3, which `openssl-src` compiles from source with whatever
  `CC` cargo-zigbuild hands it. It built for both darwin targets and for
  windows-gnu with no change to `rust/openssl` or the vendored
  `openssl-sys`.
- **No macOS SDK is needed for these crates.** rustc warns that `xcrun`
  could not find MacOSX.sdk; zig links against its bundled libSystem stubs
  instead. The binaries link only `/usr/lib/libSystem.B.dylib`,
  `libiconv` and `libcharset` (section 2): no framework. A dependency that
  later links a framework (Security, CoreFoundation) would fail here, since
  zig ships no framework stubs (INFERRED from zig's documentation of
  `-framework`; UNTESTED here).
- **Stage 2 is short.** Around a ready `.ccwasm` the runtime-only build
  took 1 m 23 s for each darwin target and 2 m 06 s for windows-gnu,
  against 3 m 54 s to 4 m 46 s for the precompiler. That ratio is what
  makes B worth having (section 4).
- **Litter.** cc-rs's compiler probes under zig left `a.o` files in
  `rust/openssl/` and `rust/vendor/openssl-sys/` of the source tree
  (untracked; a CI build would discard them with the runner).

## 2. What the cross-built files are (MEASURED, `results/inspect-*.txt`)

`inspect.sh` reads each file's headers on the Linux host.

- **Mach-O, arm64.** `LC_BUILD_VERSION` minos 11.0 (after the fix below),
  sdk 27.0; `LC_CODE_SIGNATURE` present on the server, the dylib and every
  test executable: zig writes the ad-hoc signature arm64 macOS requires
  before it will exec a binary. Whether macOS accepts zig's signature is
  TO MEASURE (`codesign -dv` and every run in the verify job).
- **Mach-O, x86_64.** `LC_VERSION_MIN_MACOSX` 10.12, sdk 27.0, no code
  signature, as Apple's own linker leaves x86_64 by default.
- **PE, windows-gnu.** AMD64; imports kernel32, ntdll, ws2_32,
  bcryptprimitives and the UCRT's `api-ms-win-crt-*` sets (zig's MinGW
  links the UCRT, so Windows 10 or later); the DLL also imports user32,
  advapi32, crypt32 and userenv. `SizeOfStackReserve` is **16 MiB** on
  every executable zig linked, against MSVC's 1 MiB default.
- **Three problems found and fixed in `tools/cross/build.sh`:**
  1. *Deployment target.* Without `MACOSX_DEPLOYMENT_TARGET`, zig stamped
     minos **15.0**: the binary would refuse to start on macOS 11 to 14,
     where rustc's own link gives 11.0 (arm64) or 10.12 (x86_64). The
     script now exports rustc's default (`rustc --print
     deployment-target`).
  2. *Dylib install name.* The C ABI dylib's `LC_ID_DYLIB` was the absolute
     Linux path the linker wrote it to, so a consumer linked against it
     would look for the library at a path no Mac has. The darwin build now
     passes `-Wl,-install_name,@rpath/libapple_purchase_receipt_verifier_ffi.dylib`.
     A native build has the same habit with a Mac path; it goes unnoticed
     only because the consumer runs on the machine that built it.
  3. *Baked build path.* The server tests read fixtures through
     `env!("CARGO_MANIFEST_DIR")`, fixed at compile time: the server test
     executable holds the build path 12 times (darwin) and 61 times
     (windows-gnu, with DWARF). The spike builds from `/tmp/aprv-src` and
     recreates that path on each verify runner (a symlink on macOS, a
     junction at `<drive>:\tmp\aprv-src` on Windows). Reading the
     directory at run time, with the compile-time value as the fallback,
     would remove the trick; that is a change to `rust/server/src`, not
     made here.

## 3. Today's cost, A (MEASURED (API), `results/release-timings.txt`)

`release-timings.py` over the last seven successful release.yml runs
(2026-10-04 to 2026-10-15; three tagged releases, four dispatches from
main or a branch). The `build` step is `build-static.sh` (stage 1 and
stage 2 together; the API does not split them). The brief's figures for
run 37845798653 match the API to the second.

| Target | Runner | `build` median | range | job median |
|---|---|---:|---:|---:|
| x86_64-apple-darwin | macos-15-intel | 767 s | 515–1043 s | 818 s |
| x86_64-pc-windows-msvc | windows-latest | 564 s | 442–596 s | 592 s |
| aarch64-pc-windows-msvc | windows-11-arm | 439 s | 398–447 s | 484 s |
| aarch64-apple-darwin | macos-latest | 405 s | 375–484 s | 437 s |
| x86_64-unknown-linux-musl | ubuntu-latest | 307 s | 239–317 s | 774 s (with a 7-minute reproduction) |
| aarch64-unknown-linux-musl | ubuntu-24.04-arm | 242 s | 210–264 s | 507 s (with reproduction) |

The legs run in parallel, so the critical path is the slowest leg:
**x86_64-apple-darwin at 818 s (13.6 min)**, then the Linux x86_64 leg at
774 s because of its reproduction. Stage 1's share of each `build` step is
not in the API; on the Linux host it was 74% (3 m 54 s of 5 m 17 s for
x86_64-apple-darwin), so on the macOS Intel leg stage 1 is roughly
570 s and stage 2 roughly 200 s (INFERRED; `a-native` in the spike
workflow prints cargo's per-stage "Finished" lines, TO MEASURE).

## 4. B and C against A

### The shared precompile step (MEASURED, `results/precompile-timings.tsv`, `results/ccwasm-compare-*.tsv`)

| Precompiler build | Build | Per-target precompile |
|---|---:|---:|
| release, `compile` (A on an x86_64 leg) | 246 s | 3.2–3.6 s (x86_64 targets only) |
| release, `compile,wasmtime/all-arch` (B) | 291 s; 286, 299 and 321 s in three other runs | 2.7–3.9 s |
| LTO off, 16 codegen units, all-arch | 156 s | 3.2–3.9 s |

All three wrote the same `.ccwasm` for every target they could reach
(`results/ccwasm-compare-hashes.tsv`; release without all-arch reaches only
the three x86_64 targets):

| Target | `.ccwasm` SHA-256 (Linux x86_64 precompiler) | bytes |
|---|---|---:|
| x86_64-unknown-linux-musl | `4d3b61b0ef3ee734de85eaee793856f1ab1f68388181994edeb164de0c2b0912` | 9,517,744 |
| aarch64-unknown-linux-musl | `f17173c87c5a47360aea1969b391fd9e38ead21c663cadf49c8423116a9bf8f1` | 9,275,024 |
| x86_64-apple-darwin | `511683545817ecfbc4d1836751a165a96e0936a4f00dcd0e8996d1084a505d5d` | 9,517,744 |
| aarch64-apple-darwin | `4b88b8def15507beb4b961a4e284e78def6cf56cd9ff558e9af83261d371bc4d` | 9,176,720 |
| x86_64-pc-windows-msvc | `5b853266f3ef01a5786b09451b73a064917fdec977daf3722baba39cb698af67` | 11,082,480 |
| aarch64-pc-windows-msvc | `2ede6a86e8dfb86272210314341f80bd7be1d4b56a5f6cdededce99b8c810d79` | 8,607,440 |

These belong to the local component (`ce2123fa…`); the CI run has its own.
The two x86_64 Unix files are the same size and differ in their target
metadata, so one `.ccwasm` per target stays the rule (build.rs refuses a
file made for another target or Wasmtime version, MEASURED by reading
`rust/server/build.rs`). Whether a native leg's own precompile on macOS or
Windows writes these same bytes is TO MEASURE (`a-native` against
`precompile` in the spike's compare table). If it does, B ships the same
binaries A ships today.

### Wall clock and runner minutes

A's `build` step ran stage 1 and stage 2 on each leg; on the Linux host
stage 1 was 74% of the two (section 3). Applying the Linux host's stage-2
time, scaled by each runner's A-to-Linux ratio, gives the INFERRED stage 2
per runner: about 200 s on macOS Intel (767 s against 317 s locally, ×2.4),
105 s on macOS arm64, 130 s on Windows x64 and 110 s on Windows arm64.

| | A (today) | B | C |
|---|---|---|---|
| Precompiler builds per release | 6, one per leg (two on macOS) | 1, on ubuntu-latest | 1, on ubuntu-latest |
| Before the target legs start | nothing | the precompile job: about 3 min with the cheap profile, 5 with release (156 or 291 s + 7 × 3.5 s, MEASURED here; TO MEASURE on a runner) | the same |
| Slowest target leg | macOS Intel, 818 s median job (MEASURED (API)) | macOS Intel stage 2, about 200 s + 60 s setup (INFERRED) | the Windows cross builds: stage 2 + the CRT and SDK fetch (17 min here, TO MEASURE in CI); then a verify job of download + tests, 3 to 5 min (TO MEASURE) |
| Critical path, build-server only | about 13.6 min | about 3 + 7 = 10 min, set by the Linux x86_64 leg when its reproduction still rebuilds stage 1 (stage 2 about 1.5 min + the reproduction's 5.5 to 7 min, from A's 420 s); about 3 + 4.5 = 7.5 min if the reproduction reuses the shared `.ccwasm` (cheap profile; add 2 min for the release profile; INFERRED) | about 3 + 2 + 4 = 9 min without the fetch; 26 min with today's local fetch (INFERRED) |
| macOS runner time per release | 818 + 437 s, about 21 min | about 4.5 + 2.5 = 7 min (INFERRED) | the verify jobs, about 6 to 8 min (TO MEASURE) |
| Windows runner time per release | 592 + 484 s, about 18 min | about 3.5 + 3 = 6.5 min (INFERRED) | the verify jobs (TO MEASURE) |
| New toolchain in a shipped binary | none | none | zig's Mach-O linker and signature; cargo-xwin's CRT, SDK and lld-link |

The Linux x86_64 leg's job is 774 s today because its reproduction
rebuilds stage 1 and stage 2 in a fresh clone. Under B the reproduction
could take the shared `.ccwasm` and rebuild stage 2 only, or keep
rebuilding stage 1 and additionally compare its `.ccwasm` with the shared
one; either keeps the claim the release makes today (section 7).

### Transfer (MEASURED sizes; transfer time TO MEASURE)

B moves one `.ccwasm` per leg (8.6 to 11.1 MB). C moves the shipped
binary (11.5 to 13.9 MB) and, for the verify jobs, the test executables:
the server's is 51 MB (darwin, DWARF in the Mach-O), 29 MB (MSVC, debug
info left in the PDB, which build.sh does not copy), 287 MB (aarch64 musl)
and 338 MB (windows-gnu). Building them with `debug = 0` would shrink the
last two; it is not tried here.

## 5. Risks the verify jobs must settle

The four the owner named, then what the spike found. Every item is TO
MEASURE on the real OS unless it says otherwise.

1. **Windows main-thread stack size.** MEASURED from the PE headers:
   cargo-xwin's lld-link writes `SizeOfStackReserve` 1 MiB, MSVC's
   default and what a native MSVC build gets; zig's MinGW link writes
   16 MiB. The server sets no stack size of its own (no linker argument in
   `rust/server`; `rust/.cargo/config.toml` sets only an environment
   variable for OpenSSL; the one thread it names,
   `aprv-stdin`, takes Rust's default). Wasmtime runs guest code on the
   calling thread with a 512 KiB `max_wasm_stack` by default, which fits
   in 1 MiB with the host frames above it, as the native MSVC build
   already proves on every release. The difference matters for GNU only in
   the other direction (more headroom), and makes GNU and MSVC builds
   behave differently near the limit. The verify job's server tests and
   the cases run on each.
2. **Wasmtime trap handling.** Wasmtime catches guest traps with signal
   handlers on Unix, a Mach exception port on macOS and a vectored
   exception handler on Windows; the code is the same whoever links it,
   but the unwind tables are the linker's. The server tests include the
   hostile component (`rust/server/tests/hostile.wat`), whose endless loop
   the epoch must interrupt and whose `unreachable` must come back as an
   error, not a crash; they run in every verify job, on every target.
   UNTESTED until that run.
3. **The ad-hoc signature on arm64 macOS.** MEASURED: zig wrote
   `LC_CODE_SIGNATURE` into the server, the dylib and every test
   executable for aarch64-apple-darwin; x86_64 gets none, as with Apple's
   own linker. Whether the kernel accepts zig's signature is answered by
   the first exec on macos-latest; the verify job also prints
   `codesign -dv`. A Developer ID signature or notarisation is a separate
   step either way (none today).
4. **The MSVC CRT and SDK licence.** cargo-xwin downloads Microsoft's CRT
   and Windows SDK packages from Microsoft's servers and accepts their
   licence on the user's behalf (it has no licence flag of its own;
   `xwin`, which it drives, requires `--accept-license`). The binaries
   link against those import libraries and, like a native MSVC build,
   import `VCRUNTIME140.dll` at run time (MEASURED in the PE imports), so
   what is redistributed is unchanged; whether the Visual Studio licence
   terms permit building on a non-Windows host with packages fetched this
   way is a question for the owner, not answered here. cargo-xwin also
   takes the newest CRT and SDK in Microsoft's manifest unless
   `XWIN_CRT_VERSION` and `XWIN_SDK_VERSION` pin them, so two release runs
   can link against different SDKs.
5. **Found here: the deployment target, the dylib install name and the
   baked build path** (section 2), all fixed in the spike's script; a
   production version must keep all three.
6. **Found here: no macOS SDK.** zig links against its own libSystem stubs
   and stamps sdk 27.0. Today's crates need nothing else; a dependency
   that adds a framework would fail to link (INFERRED).
7. **Supply chain.** C puts zig (a PyPI wheel), cargo-zigbuild and
   cargo-xwin into the build of every shipped binary, and the MSVC CRT and
   SDK as unpinned downloads. B adds nothing: the precompiler is the same
   crate at the same lockfile, built on a Linux runner instead of on each
   leg.
8. **Reproducibility.** The Linux builds reproduce today
   (`tools/reproduce-server.sh`); the macOS and Windows ones are "attested
   but not claimed to reproduce". C could in principle make all six
   reproducible on Linux; whether zig's and lld-link's output is
   byte-for-byte stable across runs is UNTESTED.

## 6. What the spike workflow measures

`.github/workflows/spike-cross-build.yml` runs on a pull request that
touches it or `tools/cross/`, and by hand. None of it has run yet.

| Job | Runs on | Measures |
|---|---|---|
| `component` | ubuntu-latest | the component, from this commit |
| `precompile` | ubuntu-latest | `precompile.sh`: the precompiler build and seven precompiles, timed; each `.ccwasm` hash as a job output |
| `a-native` | the six release runners | today's `build-static.sh`, per-stage "Finished" lines, total; the native `.ccwasm` hash |
| `b-native` | the six release runners | the Linux `.ccwasm` checked against `precompile`'s hash; the native runtime-only build, its tests and the C ABI (`build.sh`); then `verify.sh` |
| `c-build` | ubuntu-latest, seven targets | the cross builds (`build.sh`), timed; each target's `SHA256SUMS` hash as a job output |
| `c-verify` | the six release runners, plus windows-latest for windows-gnu | the download, timed; every file against `c-build`'s hash; `verify.sh` |
| `gate` | ubuntu-latest | every `c-verify` leg green and every file still `c-build`'s: where publishing would wait |
| `compare` | ubuntu-latest | the tables: precompile timings, Linux against native `.ccwasm` per target, A's stages, B and C step times, every check, sizes |

`verify.sh` runs, on the target's own OS: `aprv info`, which deserializes
the embedded `.ccwasm` and runs the component's init with the built-in
roots (`rust/server/src/main.rs`, `info`), so it is the proof that each
target's `.ccwasm` loads in that target's runtime-only binary; `codesign
-dv` on macOS; every case of `fixtures/cases.json` over HTTP and through the
CLI (`cases.py --mode both`); the managed mode (`managed-smoke.py`); the
static check on musl; the server crate's own tests with `--include-ignored`
and this tree's component; and for the C ABI its Rust tests, the C++
conformance (`aprv_conformance`, MSVC or clang consumer, skipped for a
MinGW library) and the ctypes conformance over the same cases.

Known gaps in the first run: the C ABI on both MSVC targets fails in
`c-build` (recorded, not fatal), and on `b-native`'s windows-11-arm leg a
native OpenSSL build may need a perl and nmake the image may not carry
(UNTESTED). A matrix job's per-leg outputs (`sums-<target>`) rely on each
leg setting only its own key; `c-verify` and `gate` fail loudly if a key is
empty.

## 7. Recommendation

**B.** Build the precompiler once on Linux, write one `.ccwasm` per
target there, and keep every final build native. On these numbers it
takes the build-server critical path from about 13.6 to about 10 minutes
with step 3 below as written (the Linux reproduction becomes the longest
leg), or about 7.5 if the reproduction reuses the shared `.ccwasm`, and
saves about 14 macOS and 11 Windows runner minutes per release, while every shipped binary keeps exactly today's
toolchain, linker, SDK and signature. C saves no more wall clock while
cargo-xwin's fetch is uncached, cannot build the C ABI for MSVC, and adds
four toolchains and a licence question to every shipped binary; keep it as
an option to revisit if the spike run shows the fetch is short and
reproducible-on-Linux becomes a goal for macOS and Windows.

Condition before switching: the spike run's `compare` table must show the
native `.ccwasm` equal to the Linux one for all six targets. If one
differs, B still works (build.rs checks target and Wasmtime version, and
`aprv info` on the native leg proves the load), but the release would no
longer ship byte-for-byte what A ships, and the note must say so.

What `release.yml` would change (not changed here):

1. A new job, `precompile-server` (ubuntu-latest, `needs: build-wasm`, no
   cache): check the component against `build-wasm`'s hash, build the
   precompiler once (`--features compile,wasmtime/all-arch`; the cheap
   profile is safe by the hashes above), run `aprv precompile --target T`
   for the six targets, upload the six `.ccwasm` files and manifests, and
   publish each SHA-256 as a job output.
2. `build-server` (the six native legs, unchanged runners): `needs:
   precompile-server`; download its target's `.ccwasm`, check it against
   that output, then run stage 2 only. `build-static.sh` would take the
   `.ccwasm` instead of the component (a new argument), so the readelf
   checks, the native `aprv info` and the size line stay in the one script.
   Toolchain install, attestation and upload stay as they are.
3. The Linux reproduction (`tools/reproduce-server.sh`) keeps rebuilding
   stage 1 in its fresh clone on x86_64 and adds one comparison: its
   `.ccwasm` must equal the shared one. That keeps today's claim and makes
   the shared precompiler checked on every release.
4. No verify jobs are needed for B: the final build and `aprv info` already
   run on the target's own OS, as today. The verify-job shape in the spike
   workflow (`c-verify`, `gate`) is what C would add.

## Where this stops holding

- The local numbers are one 4-vCPU container, one run each; GitHub's
  runners differ in CPU and disk. The CI run gives per-runner numbers.
- Every run on macOS and Windows is TO MEASURE: nothing in this note ran a
  cross-built binary on either OS.
- Versions: zig 0.17.0, cargo-zigbuild 0.24.0, cargo-xwin 0.23.1 (whose
  MSVC CRT and SDK versions float unless pinned), wasmtime 50.0.1, Rust
  1.99.1.
