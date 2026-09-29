# CI for the rust-core migration: what is wired, and what waits

The integrator's checklist for the jobs the supply-chain lane added
(MIGRATION.md steps 1.5, 1.13 to 1.15, 2.8 to 2.10, "CI matrix", "Release
artifact matrix", "Release workflow changes"). Every job that needs another
lane's files checks that they exist first, prints a `::notice::` naming
what it waits for, and succeeds, so `rust-core` stays green while the lanes
land. Each row says what flips the gate and what the job then asks of the
file's owner.

## The contracts these jobs call

| Caller | Expects | Owner |
|---|---|---|
| `rust-wasm`, `build-wasm`, `release-branch-wasm`, `tools/reproduce-*.sh` | `rust/bindings/abi/build.sh <out-dir>` writes `aprv.wasm`, `aprv.component.wasm`, `aprv.wit` and `SHA256SUMS` (the three files, `sha256sum` format), reading `WASI_SDK_DIR`, `OPENSSL_WASM_DIR` and `PATH` (wasm-tools, wit-bindgen) as `tools/wasm-toolchain.sh` sets them, and the rustc of `rust/rust-toolchain.toml`. It runs from the repository root in a fresh clone, so it must not depend on the clone's path: remap `CARGO_HOME` and the source tree with `--remap-path-prefix` (the round-13 stand-in module carries both paths) | lane A2 |
| `tools/check-wasm.sh` | the committed WIT at `rust/bindings/abi/wit/aprv.wit`; module exports exactly the four operations, their `cabi_post_` functions, `cabi_realloc`, `memory`, `_initialize` and wit-bindgen's own `cabi_realloc_wit_bindgen_<version>`. The stand-in still exports `aprv_clock_now_ms` and `aprv_random_get` (finding 7 of the final round); the check fails on them | lane A2 |
| `rust-wasm` schema step, `tools/validate-wire.mjs` | `rust/bindings/wire/schema/{init-config,init-result,verify-receipt-result,verify-signed-data-result}.schema.json`, JSON Schema 2020-12, `$ref`s by relative file name or `$id`. The trap host writes the matching answers as `init-config.jsonl`, `init.jsonl`, `verify-receipt.jsonl`, `verify-signed-data.jsonl` | lane A2 |
| `aprv-server`, `aprv-server-contract`, `build-server`, `tools/reproduce-server.sh` | `rust/server/scripts/build-static.sh <component.wasm> <target-triple> <out-dir>` does the two-stage build (precompile for an explicit baseline with the serving features, then the embedding build) for every release target, not only musl, and leaves `<out-dir>/aprv` (`aprv.exe` on Windows); `aprv info` runs with no arguments; `aprv serve` binds `APRV_LISTEN`; `GET /healthz` and `GET /openapi.json` answer. `cargo test --manifest-path rust/server/Cargo.toml --target <t>` finds the component in `APRV_COMPONENT` | lane B |
| `aprv-server-contract` | `rust/server/openapi.yaml`, `rust/server/.spectral.yaml` (Spectral 6.16.3, `--fail-severity=hint`: 0 findings), Schemathesis 4.28.0 `run --checks all` against the served document; `rust/server/scripts/image-smoke.sh <image>` for the image smoke (g5 with `APRV_LISTEN`, nothing answers without it). The job builds the image with `docker build -f rust/server/Dockerfile .` from the repository root | lane B |
| `publish-image` | `rust/server/Dockerfile` has a stage named `prebuilt` that copies `aprv-${TARGETARCH}` (`aprv-amd64`, `aprv-arm64`) from the build context into the digest-pinned distroless base; the release builds the image from its own attested static binaries with `--target prebuilt`, and nothing compiles inside Docker there. The multi-stage build stays for local use | lane B |
| `java-wasm-endive` | `java-wasm/pom.xml`; `mvn -B verify` runs the 311 cases with Endive; `-Daprv.wasm=<path>` points the Endive compile at the module rust-wasm built (without it, the pom's own default) | Java lane |
| `java-classpath-guard` | `java-wasm/scripts/classpath-guard.sh`, exit 0 when both jars on one classpath fail fast and a Gradle build asking for both fails at resolution | Java lane |
| `publish-maven` | `mvn -B -P central deploy` in `java-wasm/` with `-Daprv.wasm=`, `-Daprv.server.linux-x86_64=` and `-Daprv.server.linux-aarch64=` (paths to build-wasm's module and build-server's two static binaries), attaching the classifier jars `linux-x86_64` and `linux-aarch64`; jars land as `java-wasm/target/apple-purchase-receipt-verifier-wasm-*.jar` | Java lane |
| `publish-npm`, `publish-pypi`, `publish-rubygems`, `publish-nuget` | each host's package build reads the module from `APRV_WASM` (core module) or `APRV_COMPONENT` (component, for jco), which the job sets after checking the file against build-wasm's SHA-256, and packs that file; no publish job compiles the module | host lanes |
| `release-please.yml`, `wasm-copies`, `build-wasm` | committed copies are found with `git ls-files '*aprv.wasm'`: `go/internal/wasm/aprv.wasm` and `swift/Sources/ApplePurchaseReceiptVerifier/Resources/aprv.wasm` | Go and Swift lanes |
| `java-differential` (nightly) | `tools/differential.sh <aprv.wasm> <out-dir>`: runs the Java implementation and the core over every input it collects, writes its report to `<out-dir>`, exits non-zero on a difference R20 does not record | lane A (step 1.8) |
| `rust-fuzz-openssl` (nightly) | `rust/openssl/` (the adapter) and `rust/fuzz/run.sh all <seconds>` building against `OPENSSL_DIR` | lane A |

## Gates to flip

| Job | Gate today | Flip when |
|---|---|---|
| `rust-wasm` (build, checks, cases, reproduce, artifact) | `rust/bindings/abi/build.sh` exists | A2 lands step 1.4 |
| `rust-wasm` schema step | `rust/bindings/wire/schema/` exists | A2 lands step 1.14 |
| `wasm-copies` | `rust-wasm` built; any committed `aprv.wasm` | Go or Swift lane commits its copy. Strict on `release-please--*` branches, a warning elsewhere (copies lag the core until the release branch refreshes them) |
| `one-implementation` | `--enforce java-wasm` only; every other language reports | add each language to `--enforce` as its wrapper replaces the 0.7 verifier (node, python, go, swift, ruby, dotnet, php); `--enforce all` is Phase 7 step 5 |
| `aprv-server`, `aprv-server-contract` | `rust/server/Cargo.toml` (and each file above per step) | lane B lands |
| `java-wasm-endive` | `java-wasm/pom.xml` | Java lane lands |
| `java-classpath-guard` | `java-wasm/scripts/classpath-guard.sh` | Java lane lands step 3.5 |
| `rust-fuzz-openssl` | `rust/openssl/` | lane A1 lands step 1.1 |
| `java-differential` | `tools/differential.sh` and `build.sh` | step 1.8 |
| release.yml `build-wasm`, `build-server`, `sbom`, `release-assets`, `publish-image` | none: a release after the merge needs them all | they only run on a tag; main's release.yml is unchanged until `rust-core` merges |
| release.yml `publish-maven` -wasm steps | `java-wasm/pom.xml` | Java lane lands |

## Not wired here

- `java-wasm-s390x` (the Endive corpus under QEMU before each release): no
  job yet; it needs the corpus runner from the Java lane.
- The corpus (1,179 rows, 5,000 mutants) is scratch data from the evidence
  rounds and is not in the repository, so CI's reference rows are the 311
  cases. `node tools/wasm-trap-host.mjs calls <module> <calls.jsonl>` runs a
  corpus wherever it lives; on the round-13 stand-in it gave the round's
  result (6,176 identical, 2 `clock-moves-chain`, 1 `init-refusal`).
- Dependabot entries for `rust/server/Dockerfile` (docker) and `java-wasm/`
  (maven), once those files exist; a watched directory that does not exist
  is an error in Dependabot.
- The macOS x86_64 runner label is `macos-15-intel`; check it is still
  offered before the first 0.8.0 tag.
- BOOTSTRAP.md has the owner's side: the `docker-hub` environment
  (`DOCKERHUB_TOKEN`, `DOCKERHUB_USERNAME`, `DOCKERHUB_NAMESPACE`) and
  making the GHCR package public after its first push.
