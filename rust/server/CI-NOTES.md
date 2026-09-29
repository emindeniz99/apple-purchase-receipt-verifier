# CI notes for aprv-server (for the integrator of `.github/`)

What the `aprv-server` job of MIGRATION.md's CI matrix needs. Nothing here
is wired yet; lane B does not edit `.github/`.

## Inputs every leg needs

- The component: `aprv.component.wasm` from the `rust-wasm` job (its
  SHA-256 is that job's output). Lane B checked G1's component (the 0.7
  core, sha256 8f758c0b…) with the commands below.
- Rust 1.98.1 (the toolchain the evidence used), with the
  `x86_64-unknown-linux-musl` target; `binutils` for `readelf`.
- Python 3.10+ (standard library only for the scripts); Node 22 for
  Spectral; a venv with `schemathesis` (4.28.0 was used).
- No secrets. The image legs need `packages: write` only in the publish
  job, which is not this one.

## Job `aprv-server` (test job; may cache `~/.cargo` and the target dir)

Matrix: `ubuntu-24.04` (x86_64, glibc and static musl) and
`ubuntu-24.04-arm` (aarch64 static musl, built natively there, no cross
linker). macOS (x86_64, arm64) and Windows (x86_64, arm64) legs build and
run the tests only (`cargo test --features compile`); their release
binaries are not built in this lane (MIGRATION.md step 2.4 leaves them
open).

Steps, working directory `rust/server`, `COMPONENT` = the component path.
`scripts/check-component.sh` runs all of the non-lint steps below in one
command (APRV_COMPONENT, OUT, and optionally CALLS, ROWS, SCHEMATHESIS,
SPECTRAL; see its header) and is how lane B takes a new component.

```sh
cargo fmt --check
cargo clippy --locked --all-targets --features compile -- -D warnings
cargo clippy --locked --all-targets -- -D warnings            # the runtime-only feature set
APRV_TEST_COMPONENT=$COMPONENT cargo test --locked --features compile
# once lane A's rust/bindings/abi/wit/aprv.wit and rust/bindings/wire/schema/ exist, also:
APRV_TEST_COMPONENT=$COMPONENT cargo test --locked --features compile -- --ignored

# the two-stage static build, readelf checked inside the script
COMPONENT_SHA256=<rust-wasm output> sh scripts/build-static.sh $COMPONENT            # x86_64 leg
COMPONENT_SHA256=<rust-wasm output> sh scripts/build-static.sh $COMPONENT aarch64-unknown-linux-musl  # arm leg
BIN=dist/aprv-<target>

# a static binary runs with nothing around it
mkdir -p /tmp/empty && cp $BIN /tmp/empty/aprv && sudo chroot /tmp/empty /aprv info

python3 scripts/cases.py --aprv $BIN --mode both --list     # the 311 cases
python3 scripts/managed-smoke.py --aprv $BIN
sh scripts/hostile-smoke.sh target/<host triple>/release/aprv   # the full build step 1 left; needs wasm-tools
R="--calls $CALLS --suffix .pinned --reference $ROWS"
python3 scripts/corpus.py --aprv $BIN $R --mode http --lifecycle fresh
python3 scripts/corpus.py --aprv $BIN $R --mode http --lifecycle pool
python3 scripts/corpus.py --aprv $BIN $R --mode cli

npx --yes @stoplight/spectral-cli@6.16.3 lint --fail-severity=hint --ruleset .spectral.yaml openapi.yaml

# Schemathesis writes .schemathesis/ and .hypothesis/ into its working
# directory (both in the root .gitignore); run it from a scratch directory.
$BIN serve --listen 127.0.0.1:18080 & sleep 1
schemathesis run http://127.0.0.1:18080/openapi.json --checks all --max-examples 50 --workers 1
T=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
APRV_TOKEN=$T $BIN serve --listen 127.0.0.1:18081 & sleep 1   # the token path too
schemathesis run http://127.0.0.1:18081/openapi.json --checks all --max-examples 30 --workers 1 -H "X-Aprv-Token: $T"
kill %1 %2
```

Notes on the steps:

- `cases.py` must exit 0: with the G1 component, 278 of 278 expressible
  cases pass on each transport. The 33 `decodeBase64` cases are not
  expressible through the server (it exposes no decoder) and are
  reported as such.
- The corpus inputs are the call files with every clock pinned
  (`$CALLS/<corpus>.pinned.jsonl`) and the module's own answers to them
  (`$ROWS/module-<corpus>.jsonl`, identical to the native core); lane D's
  corpus job produces both. Expected per transport: every row identical
  except the 27 whose body is over 3,145,728 bytes, which the module
  refuses for size and the server answers 413 (the CLI exits 3) before
  the module sees them. With G1: 6,152 identical, 27 over-cap, 0
  different, on HTTP fresh, HTTP pool and the CLI.
- Spectral resolves the two `$ref`s to `../bindings/wire/schema/`; on a
  branch without lane A2's files it reports 2 `invalid-ref` errors and
  nothing else. With A2's files beside it: 0 findings. Schemathesis can
  also load `openapi.yaml` from that tree (`schemathesis run openapi.yaml
  --url http://127.0.0.1:18080`), which validates every response body
  against A2's schemas: 653 of 653 passed with G1.
- `python3 scripts/startup.py --aprv $BIN` prints start-up and per-call
  times for the record; it is not a gate (README.md, "Measured").
- `sudo chroot` needs root; on GitHub's hosted runners `sudo` works.

## Job `aprv-server-image` (after the static builds)

```sh
docker buildx build --platform linux/amd64,linux/arm64 -f rust/server/Dockerfile \
  --build-context component=<dir holding aprv.component.wasm> \
  --build-arg COMPONENT_SHA256=<sha256> --build-arg VERSION=<version> \
  --build-arg REVISION=$GITHUB_SHA --load -t aprv-server:ci .
sh rust/server/scripts/docker-smoke.sh aprv-server:ci
```

(`--load` takes one platform at a time; run the smoke per platform.) The
publish job pushes the same build to GHCR with no cache, attests it and
attaches its SBOM (MIGRATION.md step 2.10, lane D).

## Release (`release.yml`, lane D)

`build-server` runs `scripts/build-static.sh` per Linux target with no
cache and with `COMPONENT_SHA256` set to the `build-wasm` output, and
uploads `dist/aprv-<target>` (and its `.ccwasm.json` manifest for the
record). The classifier jars (R26) take those binaries.
