# How CI is wired after the rust-core migration

What each workflow builds, what every job consumes, which jobs are gated
and on what, and which are held and why. The lanes' own `CI-NOTES.md`
files say what their jobs run; this file says how the jobs connect. The
decisions cited (OD-01 to OD-14) are in `docs/rust-core/STATUS.md`.

## The module and the server binary

No host package commits `aprv.wasm` (Go and Swift will, once, at
integration: DECISIONS.md R14), so every job that runs it gets it from
the same run.

- `rust-wasm` builds `aprv.wasm`, `aprv.component.wasm`, `aprv.wit` and
  `SHA256SUMS` with `rust/bindings/abi/build.sh`, the toolchain
  `tools/wasm-toolchain.sh` pins, and the rustc of
  `rust/rust-toolchain.toml` (named in `RUSTUP_TOOLCHAIN`, because
  `build.sh` runs from the repository root, where rustup does not read
  that file). It uploads them as the `aprv-wasm` artifact and does
  nothing else, so host jobs start as soon as it finishes.
- It runs whenever any area is selected (`changes` output `module`).
  Every host job receives the module this run built, never one from an
  earlier run (OD-01).
- `.github/scripts/place-module.sh <artifact-dir> <host>...` checks the
  artifact against its `SHA256SUMS`, copies the module where the host
  reads it (Node takes the component), and rewrites that host's tracked
  pin in the checkout. A pin that differs from the build is a
  `::warning::`, not an error: pins lag the core between releases, and
  `release-please.yml` rewrites them on the release branch.
- `aprv-server-linux` builds the static x86_64 musl `aprv` around the
  run's component (`rust/server/scripts/build-static.sh`, which needs
  `musl-tools` for the C that Wasmtime compiles) and uploads it as
  `aprv-server-x86_64-unknown-linux-musl`. It runs when the server, PHP
  or Java is selected (`changes` output `server-bin`). PHP jobs get it as
  `APRV_BIN`; the java-wasm jobs as `-Daprv.server.linux-x86_64` with a
  `SHA256SUMS` generated beside it.

## ci.yml, by area

`changes` (`.github/scripts/changed-areas.sh`) selects the areas `java`
(including `java-wasm/`, `java-bench/`, `jvm-interop/`), `node`, `python`,
`ruby`, `php`, `go`, `rust`, `swift`, `dotnet` and `server`
(`rust/server/`). A change to the core, the bindings or the toolchain
selects every area. Each job below runs when its area is selected; the
second column is what it takes from other jobs.

| Area | Jobs | Consumes |
|---|---|---|
| module | `rust-wasm`; `rust-wasm-checks` (tools' tests, `check-wasm.sh`, the ABI tests, the cases, the wire schemas, wasm32 clippy, a reproduction in a fresh clone); `rust-wasm-abi` (`rust/bindings/abi/tests` with `APRV_WASM` and `APRV_COMPONENT`); `wasm-copies` (every committed copy and every pin; strict on `release-please--*` branches, warnings elsewhere) | `aprv-wasm` |
| rust | `rust` (`--workspace`, target/ cached, 40 minutes, strace required, the 1.85.0 floor without `aprv-abi`, and a leg on an OpenSSL 4 built by `tools/openssl-native.sh`: OD-09), `rust-lint` (with `tools/check-layering.mjs`), `rust-ffi`, `elixir-ffi`, `rust-fuzz`, `rust-supply-chain` | nothing |
| server | `aprv-server` (x86_64 gnu, aarch64 musl with its own static build, macOS, Windows: fmt, both clippy feature sets, tests with `--include-ignored`), `aprv-server-contract` (Spectral, two Schemathesis runs), `aprv-server-image` (buildx from source per architecture, and the `prebuilt` stage on amd64, each through `docker-smoke.sh`) | `aprv-wasm`; `aprv-server-linux` for the contract and the prebuilt image |
| node | `node`, `node-runtimes` (node, bun, deno, workerd, edge), `node-browsers` (Playwright 1.56.1), `node-lint`, `smoke-npm` | `aprv-wasm` (the component) |
| python | `python` (Python 3.10 to 3.14 on the six runner images wasmtime-py ships wheels for, a second warm-cache run), `python-musl` (digest-pinned `ghcr.io/astral-sh/uv` Alpine images, with `libgcc`), `python-fuzz`, `python-tools`, `smoke-pypi` | `aprv-wasm` |
| go | `go`, `go-platforms`, `go-cross`, `go-scratch` (a static corpus runner in an empty chroot), `go-race`, `go-fuzz`, `go-lint`, `smoke-go` | `aprv-wasm` |
| swift | `swift` (6.3 and 6.4 containers, debug build then release tests), `swift-macos` and `swift-ios` (`macos-26`: the package needs Swift tools 6.3), `swift-fuzz`, `swift-format`, `smoke-swiftpm` | `aprv-wasm` |
| ruby | `ruby`, `ruby-gem`, `ruby-macos`, `ruby-tools`, `ruby-fuzz`, `smoke-rubygems` | `aprv-wasm` |
| dotnet | `dotnet`, `dotnet-mono`, `dotnet-trim`, `dotnet-fuzz`, `dotnet-format`, `smoke-nuget` | `aprv-wasm` |
| php | `php` (the suites, then the conformance cases, then HTTP on 8.4), `php-lowest`, `php-static`, `php-fuzz`, `php-format` | `aprv-server-x86_64-unknown-linux-musl` |
| java | `java`, `java-runtime-8`, `java-hardened-policy`, `java-distroless`, `jvm-interop`, `java-spring-boot`, `java-fuzz`, `java-format`, `smoke-maven` (the pure-Java 0.7 artifact, which needs no module) | nothing |
| java | `java-wasm-endive` (JDK 11 to 27), `java-wasm-runtime-8` (the server engine on a real Java 8, with a noexec check), `java-wasm-consumers` (jvm-interop and Spring Boot on the -wasm artifact), `java-classpath-guard` (`java-wasm/scripts/classpath-guard.sh`) | `aprv-wasm`; the server binary for the first two |
| always | `one-implementation` (`--enforce all`, with the per-file allowlist OD-04 describes in `tools/check-one-implementation.mjs`), `conformance` (`tools/check-cert-copies.mjs`, which finds `rust/certs` alone since Phase 7, and `tools/check-licence-copies.mjs`), `zizmor` | nothing |

The eight fuzz jobs (`go-fuzz`, `rust-fuzz`, `dotnet-fuzz`, `php-fuzz`,
`ruby-fuzz`, `python-fuzz`, `swift-fuzz`, `java-fuzz`) build in a step of
their own, so a compile error stays readable, then fuzz with each
target's output in a file on the runner (`.github/scripts/fuzz-quiet.sh`
over the targets the harness's `run.sh list` names; `go-fuzz` writes the
same list inline). On a failure, `.github/scripts/fuzz-report.sh`, the
only step that holds the Telegram secrets, hands each failed target to
`fuzz-finding.sh`, which prints the target and the input's SHA-256 and
seals the input and the log; the job uploads only
`fuzz-findings-sealed-<job>` and fails (R37). `swift-fuzz` installs curl
first, since the swift image ships without it.

## Gated and held

| Job | Gate | Why |
|---|---|---|
| ci.yml `smoke-crates`, release.yml `publish-crates`, post-publish-smoke.yml `crates` | `vars.APRV_PUBLISH_CRATES == 'true'` | OD-03: crates.io stays at 0.7 until openssl-sys accepts openssl-src 400.x. A registry build of this tree would get OpenSSL 3, which `aprv-openssl` refuses, and `aprv-openssl` is not on crates.io yet. The owner sets the variable when both are resolved |
| nightly.yml `corpus` | `fixtures/corpus.json` names the archive; the archive must match its `sha256` | OD-05: the corpora (200 MB of generated rows) stay out of the repository. A missing or malformed pin file fails the job. The archive is a `.tar.gz` with the G1 layout at its top level (`aprv.wasm`, `aprv.component.wasm`, `same.py`, `calls/<corpus>.pinned.jsonl`, `rows/module-<corpus>.jsonl`). Each host leg runs its lane's one-command gate over it. The rows belong to the archive's module, so the archive is refreshed, in a PR that changes the pin, after a release changes the module (the job warns when it no longer matches the pins) |

No other job is gated on a file existing: every lane has landed, and a
gate that can only be true would turn a deleted directory into a green
run.

## Retired

| Job | Why |
|---|---|
| `node-runtimes-web` | `node/CI-NOTES.md`, its row: the `/web` entry point runs the same module as `.`, every `node-runtimes` leg smokes both entry points, and the `test:runtimes:web` script is gone |
| `node-runtimes-fastly` | `node/CI-NOTES.md`, its row (R5): Fastly Compute runs no WebAssembly; the `test:runtimes:fastly` script and `@fastly/js-compute` are gone |
| `node-fuzz` | `node/CI-NOTES.md`, its row, and the deleted `node/fuzz/`: it fuzzed the JavaScript DER, CMS and JWS readers, which are gone. The core's fuzz jobs cover the parser |
| `php-mutation` | `php/CI-NOTES.md`, "Jobs to delete or change": `MutationTest` mutated receipts through the PHP verifier, which is gone, so the `mutation` group no longer exists. The module's mutation corpus is lane A's |
| `node-roots-generated`, `go-generate-check`, `dotnet-roots`, and the root drift steps in `ruby` and `php-static` | Phase 7 (the "Phase 7" sections of `node/`, `go/`, `dotnet/`, `ruby/`, `php/` and `rust/bindings/` CI-NOTES): the wrappers' copies of the roots and their generators are deleted, since the three Apple roots live only in the module |

## release.yml

- `build-wasm` builds the module with the pinned toolchain and checks
  every committed copy and every pin strictly.
- `build-server` builds `aprv-<target>[.exe]` for the release targets
  with `build-static.sh` (musl legs install `musl-tools`), refuses any
  component but build-wasm's (`COMPONENT_SHA256`), and reproduces the
  Linux builds in a fresh clone (`tools/reproduce-server.sh`).
- The publish jobs never cache. `publish-pypi` builds with
  `tools/build_dist.py`. `publish-npm` requires the transpiled module and
  every licence file in the tarball. `publish-maven` hands both Linux
  binaries and their `SHA256SUMS` to the -wasm build. `publish-rubygems`
  copies the module into `lib/` and checks its pin.
- `tag-go-module` refuses to tag a tree without
  `go/internal/wasm/aprv.wasm` and its pin (the Go module is published by
  the tag alone, so the module must be committed first), and checks the
  proxy's zip carries the library and both files.
- `php-binaries` compares `php/binaries.json` with the binaries this
  release built (OD-06). The `smoke` job then runs post-publish-smoke.yml
  for every published registry, `php` included.

## release-please.yml

On every release-please PR: `release-branch-wasm` builds the module and
component from the branch, `release-branch-server` builds the two Linux
musl binaries (read-only), and `refresh-wasm-copies` runs
`tools/refresh-wasm-pins.sh` (every tracked copy of `aprv.wasm` and every
`aprv.wasm.sha256` and `aprv.component.wasm.sha256`, each copy checked
against its pin) and writes `php/binaries.json` with `jq` (the release tag
and the two Linux hashes; the macOS and Windows entries stay `null`:
OD-06). It commits all of that once. The lock step updates the workspace
and `rust/fuzz`; `rust/ffi` has no lockfile of its own now.

## Other workflows

- `post-publish-smoke.yml`: a `packagist` leg installs the published PHP
  package, runs `vendor/bin/aprv-install`, and runs
  `.github/smoke/packagist-smoke.php`.
- `benchmark.yml` (manual): a `module` job builds the module and a
  `server` job the static binary. Every host benchmark places the module
  as ci.yml does, and PHP benchmarks both transports over the binary.
- `codeql.yml`: Go, Swift and .NET compile against an empty stand-in
  `aprv.wasm`. CodeQL never runs what it builds, and without a file there
  the library is left out of those three databases. The java-kotlin build
  also compiles `java-wasm/src/main/java` through that pom's
  `default-compile` execution alone, which needs no module;
  `src/main/java11` compiles only against Endive's class generated from
  the real module and is not scanned.
- `nightly.yml`: `rust-fuzz-openssl` fuzzes every target over an ASan
  OpenSSL, with each target's output kept on the runner; a finding prints
  the target and the input's SHA-256, and `.github/scripts/fuzz-finding.sh`
  seals the input and report with age (R37); `java-differential` runs `tools/differential.sh` (lane A3)
  over a module built from the commit; `java-wasm-s390x` runs the -wasm
  artifact's Endive cases and ABI tests on a big-endian JVM (an s390x
  Temurin under QEMU user emulation, forked by surefire through a
  wrapper); `corpus` is described above.
- `support-matrix.yml`: weekly (Monday) and on demand, runs
  `tools/support-matrix.mjs --check`, writes the vendor statuses to the
  job summary, and fails when a line SUPPORT-MATRIX.md lists as tested,
  and not as a floor or kept, is past its end of life.
- `scorecard.yml`: OpenSSF Scorecard, weekly and on pushes to `main`,
  with `publish_results` (so the workflow keeps to Scorecard's
  restrictions) and its SARIF uploaded to code scanning.
- `dependabot.yml` watches `java-wasm/`, `rust/server/`'s image bases,
  and `rust/server` with `rust/bindings/abi/tests` as one cargo entry
  (their exact wasmtime pins move together). It ignores `openssl-sys`
  (vendored and patched), `openssl-src` majors, `wit-bindgen` (moves with
  the toolchain's CLI) and `golang.org/x/sys` `>= 0.48.0` (each raises
  Go's 1.25 floor).

## Why the smoke jobs fetch the tag themselves

`post-publish-smoke.yml` runs on `workflow_run` after `release.yml`, and
every leg tests the published version with the smoke program and
fixtures of the release tag. The tag name comes from the triggering
run (`github.event.workflow_run.head_branch`), which CodeQL's
`actions/untrusted-checkout` query treats as a pull request's head: any
`actions/checkout` whose `ref:` is derived from it is reported as a
checkout of untrusted code, however the value was checked on the way.

The `resolve` job is the actual control. It accepts only a release run
that a tag push or a dispatch started (`release.yml` has no
`pull_request` trigger), only a version made of digits, letters, dots
and hyphens, and only a `v<version>` that exists as a tag of this
repository (`gh api repos/<repo>/git/ref/tags/v<version>`). The ref is
therefore repository-controlled.

Because CodeQL's taint tracking cannot see that check, each leg checks
out the default ref with `actions/checkout` and then switches to the
tag in a run step, `git fetch --depth 1 origin refs/tags/$REF` and
`git checkout --detach`, with the name in an environment variable. The
tree each leg tests is the same as before, the credentials are still
not persisted, and no permission changed. The repository is public, so
the fetch needs no token. The same shape is used in all ten legs, not
only the two CodeQL reported, so the workflow has one way to reach the
tag.

## release-please.yml's literal branch

The release branch jobs check out
`release-please--branches--main--components--apple-purchase-receipt-verifier`
by its literal name rather than by the branch the release-please action
reports. The name is the manifest-mode form: the base branch plus the
`package-name` from `release-please-config.json`, which the action adds
even though `include-component-in-tag` is false. The release-please
job fails if the action opened any other branch, and
`release-branch-server` and `refresh-wasm-copies` fail unless the branch
still points at the commit `release-branch-wasm` built.

## Owner-side and open

- Repository variable: `APRV_PUBLISH_CRATES` (OD-03). The corpus
  archive (OD-05) is pinned in `fixtures/corpus.json`, not in a
  variable. BOOTSTRAP.md has the rest: the `docker-hub` environment, and
  making the GHCR package public after its first push.
- Go's and Swift's committed copies of the module (R14) are Phase 7
  work. Until they exist, `tag-go-module` refuses to tag.
- The -wasm jar does not yet carry the licence texts of the code
  compiled into the module: a Java package change (`pom.xml` resource from
  `../licenses/wasm` and a test), written up in `java-wasm/CI-NOTES.md`,
  "Release". `tools/check-licence-copies.mjs` needs no Java entry, since
  the pom reads the source in place.
- The macOS x86_64 runner label is `macos-15-intel`; check that GitHub
  still offers it before the first 0.8.0 tag.
