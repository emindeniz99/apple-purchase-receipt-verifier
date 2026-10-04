#!/usr/bin/env bash
# Runs one fuzz target for a fixed budget, seeded from the shared fixtures.
#
#   ./run.sh <target> [seconds]      default 60
#   ./run.sh all [seconds]
#   ./run.sh list                    the targets `all` runs
#   ./run.sh build                   the fuzzer's environment and the
#                                    generated seed; no run
#
# libFuzzer takes several corpus directories and writes new units only to the
# first, so the shared fixtures seed every run without being copied into this
# directory. A crasher lands under artifacts/<target>/; reduce it and pin it
# as a test under ../tests/ rather than committing it here.
#
# Requires uv. The fuzzer is installed into an ephemeral environment next to
# wasmtime and platformdirs, the package's dependencies, so nothing here is a
# dependency of the package: `uv pip install -e .` in python/ never sees
# atheris. FUZZ_PYTHON overrides the interpreter, which is pinned to a line
# atheris publishes a wheel for (see README.md).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="$here/../../fixtures"
target="${1:?usage: run.sh <target>|all|list|build [seconds]}"
seconds="${2:-60}"
targets=(receipt-base64 jws endpoint-json)

if [ "$target" = list ]; then
  printf '%s\n' "${targets[@]}"
  exit 0
fi

# --no-project so the SOURCE TREE is what gets fuzzed, resolved off PYTHONPATH
# exactly as the `python` CI job resolves it -- not an installed wheel.
# `harness` is on the path too, which is how the targets reach the library
# without importing it ahead of the instrumentation block.
export PYTHONPATH="$here/..:$here"
python=(uv run --no-project --python "${FUZZ_PYTHON:-3.13}"
  --with atheris --with wasmtime --with platformdirs python)

# One seed is built here from a shared fixture rather than checked in, so the
# genuine receipt keeps exactly one copy in the repository: the endpoint's
# request body carrying it.
generated="$here/.seeds-generated"
mkdir -p "$generated/endpoint-json"
"${python[@]}" - "$fixtures" "$generated" <<'PY'
import json
import sys
from pathlib import Path

fixtures, generated = Path(sys.argv[1]), Path(sys.argv[2])
b64 = fixtures.joinpath("public-receipts", "receipt-sandbox-g5.b64").read_text().split()
(generated / "endpoint-json" / "sandbox-g5.json").write_text(
    json.dumps({"receipt-data": "".join(b64)})
)
PY

if [ "$target" = build ]; then
  exit 0
fi

run_one() {
  local name="$1"
  local seeds
  case "$name" in
    receipt-base64)
      seeds=("$fixtures/generated/receipt-b64" "$fixtures/public-receipts" "$fixtures/apple-official/xcode") ;;
    jws)
      seeds=("$fixtures/generated" "$fixtures/apple-official/mock_signed_data" "$fixtures/apple-official/xcode") ;;
    endpoint-json)
      seeds=("$here/seeds/endpoint-json" "$generated/endpoint-json") ;;
    *) echo "unknown target: $name" >&2; exit 2 ;;
  esac
  mkdir -p "$here/corpus/$name" "$here/artifacts/$name"
  echo "=== $name (${seconds}s) ==="
  "${python[@]}" "$here/targets/${name//-/_}.py" "$here/corpus/$name" "${seeds[@]}" \
    -max_total_time="$seconds" -artifact_prefix="$here/artifacts/$name/" -print_final_stats=1
}

if [ "$target" = all ]; then
  for name in "${targets[@]}"; do
    run_one "$name"
  done
else
  run_one "$target"
fi
