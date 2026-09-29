# CI needs of the Python package (lane C, MIGRATION steps 5.1 to 5.3)

For the integrator, who owns `.github/`. Nothing here has run in GitHub
Actions: the only interpreter in the lane's environment was CPython 3.11 on
glibc x86_64, and the results in the hand-back say which leg ran where.

Every command runs in `python/`. `aprv.wasm` is git-ignored: every job copies
the module into `apple_purchase_receipt_verifier/aprv.wasm` before the tests run, or
sets `APRV_WASM` for them (only `tests/_support.py`, `tests/corpus_rows.py` and
`tools/build_dist.py` read it; the package never does, and a test greps for that).
A missing or mismatched file is an error at the first `Verifier`.
The file to copy is the release build's `aprv.wasm` (SHA-256 in `aprv.wasm.sha256`). The package has one runtime dependency,
`wasmtime>=49`; the `dev` extra adds ruff, mypy and setuptools (the
install-failure test builds this source tree with it).

## 1. Test matrix (job `python`, replaces the current one)

CPython 3.10, 3.11, 3.12, 3.13 and 3.14 on each of these, so the 3.10 floor and
the platform claims are legs and not sentences:

| Leg | Runner | Why |
|---|---|---|
| glibc x86_64 | `ubuntu-latest` | wasmtime-py's `manylinux1_x86_64` wheel (library needs glibc 2.28) |
| glibc aarch64 | `ubuntu-24.04-arm` | `manylinux2014_aarch64` |
| musl x86_64 | a container: `ghcr.io/astral-sh/uv:python3.<n>-alpine` on `ubuntu-latest` | `musllinux_1_2_x86_64`; root inside the container, so the read-only cache case is the simulated one |
| musl aarch64 | the same image on `ubuntu-24.04-arm` | `musllinux_1_2_aarch64` |
| macOS arm64 | `macos-15` | `macosx_11_0_arm64` |
| macOS x86_64 | `macos-15-intel` | `macosx_10_13_x86_64` |
| Windows amd64 | `windows-latest` | `win_amd64` |
| Windows arm64 | `windows-11-arm` | `win_arm64` |

Commands (every leg):

```sh
uv sync --locked --extra dev
uv run --locked --extra dev python -m unittest discover -s tests
```

- `discover` picks up `test_conformance.py`, whose `tearDownModule` fails the
  run unless every case id ran; `test_abi.py`, `test_facade.py`,
  `test_concurrency.py`, `test_fuzz_targets.py`, `test_trust_isolation.py`,
  `test_api_shape.py`, `test_cache.py` and `test_install_failure.py`.
- `HOME` (and `LOCALAPPDATA` on Windows) must be writable: `test_cache.py`
  points the cache at temporary directories but starts fresh interpreters.
- Leave `APRV_WASM_CACHE_DIR` unset; the tests set it where they need it.
- The suite takes about 1 to 2 minutes on 4 CPUs (103 s on a busy shared
  runner); the cold compile is 1 to 3 s idle and about 5 s of CPU busy, and
  `test_cache.py` compiles five times. Budget 10 minutes per leg.
- `test_cache.py` covers the cache rules with a real read-only directory when
  the user is not root (every hosted runner) and a simulated one when it is
  (the Alpine containers). The foreign-owned and group-writable cases skip on
  Windows only, where the rule does not apply (`unittest` prints the reason).
- Every case must pass against the release module (checked: 338 of 338 on
  the G1b module, sha256 `9c0a581c...a263`); there is no list of expected
  differences. `tools/g1.sh G1_DIR` runs the whole re-run for a new module in
  one command (see "Re-running against a new module" below).
- Each leg should also run once with the cache warm (the second run of the
  step above) and record the wall time of `tests/test_cache.py`'s printed
  cold and warm starts, which feed the README's numbers.

## 2. Corpus parity (after the release module lands)

The 1,179 corpus rows plus the 5,000 mutants (6,179 rows in five files) through
the package's host layer, compared byte for byte with the module's own rows
(`rows/module-<corpus>.jsonl`, from the core lane's trap host). The call files
(`calls/<corpus>.pinned.jsonl`, every clock pinned) and the rows are large and
live in the parity job's workspace, not in the repository:

```sh
for c in cases hostile algorithms substrate fuzz; do
  uv run --locked python tests/corpus_rows.py $G1/calls/$c.pinned.jsonl > $WORK/pkg-$c.jsonl
  python3 $G1/same.py $WORK/pkg-$c.jsonl $G1/rows/module-$c.jsonl
done
```

Every row must be identical and no call may trap: 6,179 of 6,179 on the G1
module. The five files take about 30 s on a busy 4-CPU runner (the 5,000
mutants 21 s); a run near 226 s means something went back to the per-byte
component API.

## Re-running against a new module

```sh
PYTHON=/path/to/venv/bin/python tools/g1.sh $G1
```

copies `$G1/aprv.wasm` into the package (git-ignored), rewrites the tracked
`aprv.wasm.sha256` from it (commit that file), runs the whole suite and then
the section 2 comparison for every corpus, and exits non-zero on any failure.

## 3. Install failure (new job `python-install`, R28)

On `ubuntu-latest`, Python 3.13:

```sh
python -m pip install build
python tools/build_dist.py --out dist         # the sdist and the 8 platform wheels
python tools/build_dist.py --check dist       # exactly those; no py3-none-any wheel
sh tools/check-install.sh dist                # pip, platform faked as linux-i686
sh tools/check-install.sh dist linux-s390x    # and as another unsupported one
```

`check-install.sh` needs network for wasmtime's and setuptools's wheels only;
the package under test comes from `dist/`. It proves, at the level of pip:

- on a faked unsupported platform pip picks the sdist, the build stops, and the
  output names `aprv-server` and the C ABI; and
- on the real platform the tagged wheel installs and verifies the genuine
  sandbox receipt.

One real leg on a machine that has no wasmtime-py wheel: 32-bit Linux under
QEMU on `ubuntu-latest` (`docker run --platform linux/386` with
`i386/python:3.12-slim`, `apt-get install -y build-essential` not needed):

```sh
docker run --rm --platform linux/386 -v "$PWD/dist:/dist:ro" i386/python:3.12-slim \
  pip install --find-links /dist "apple-purchase-receipt-verifier==$VERSION"
```

It must exit non-zero with the message. Pin the version: before the release is
published the index has no such version, and after it has no `py3-none-any`
wheel, so the sdist is the only candidate either way. Not run in the lane
(no container daemon).

`uv pip install` was checked with the faked platform too and stops with the
same message; a `uv` leg is optional.

## 4. Release (`release.yml`, PyPI job)

The job currently runs `python3 -m build`, which publishes one `py3-none-any`
wheel: on the platforms wasmtime-py has no wheel for, pip would install it and
`import` would fail later, which is what R28 removes. Replace that step with:

```sh
python3 -m pip install --upgrade build
python3 tools/build_dist.py --out dist
python3 tools/build_dist.py --check dist
```

and upload `python/dist/` as today (trusted publishing, no cache; the workflow
file keeps its name). Before the build, put the release build's module in
place and check it:

```sh
export APRV_WASM="$ARTIFACTS/aprv.wasm"     # tools/build_dist.py copies it in
echo "$RELEASE_SHA256  aprv.wasm" | (cd "$ARTIFACTS" && sha256sum -c -)
```

`build_dist.py` writes `aprv.wasm.sha256` from the module it copies, and the
package refuses to start when the two disagree. The
module is not committed on this branch; only `go/` and the Swift package commit
the real one, once, at integration (DECISIONS.md R14).

The wheels carry OpenSSL's licence and NOTICE, wasi-libc's and Rust std's texts
(ARCHITECTURE.md §9, "Licences ship with the code"): add them to
`package-data` and the sdist's `MANIFEST.in` when Phase 1 produces them.

Post-publish smoke (gate G5): in a clean venv on Python 3.10,
`pip install apple-purchase-receipt-verifier==$VERSION` from PyPI, then verify
the genuine sandbox receipt as `check-install.sh` does.

## 5. Other jobs that touch this package

- `python-tools`: `uv sync --locked --extra dev`, then `ruff check .`,
  `ruff format --check .`, `mypy` (both clean), and the `runpy` import check of
  `bench/bench.py`, which still resolves. The advisory `ty` step resolves
  `wasmtime`'s types instead of `cryptography`'s.
- `python-fuzz`: unchanged (`./run.sh all 60` in `python/fuzz`), but there are
  three targets now (`receipt-base64`, `jws`, `endpoint-json`); the comment
  above the job still says five and names the receipt attribute reader.
  `atheris` publishes no wheel for CPython 3.11, the only interpreter in the
  lane's environment, so the fuzzer itself has not run; the targets run
  without it in `tests/test_fuzz_targets.py`.
- `benchmark.yml`: `bench/bench.py` reports three operations now
  (`verifierBase64`, `endpointJson`, `rejectTamperedSignature`); 0.7's
  `decodeBase64` and `core` have no Python counterpart because the package has
  no decoder and no DER entry point. BENCHMARKS.md's Python rows for those two
  go blank in Phase 7.
- Dependabot: the `uv` entry for `python/` now tracks `wasmtime`, with no upper
  pin by design (R27), and its comment about the `cryptography` early warning is
  stale. The early warning for a new wasmtime-py major is `tests/test_cache.py`:
  the cache is switched off silently when Wasmtime rejects its configuration
  file (49.0.0 reads `[cache]` with a `directory` and no `enabled` key), so the
  test that asserts the cache filled is what notices a change of format.
- The one-implementation job (ARCHITECTURE.md §9) may grep `python/` for
  `cryptography`, `asn1crypto`, `hmac`, `OpenSSL` and `x509`: the package
  imports none of them, and `tests/test_trust_isolation.py` asserts it.
