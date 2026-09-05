#!/usr/bin/env bash
# Runs one fuzz target for a fixed budget, seeded from the shared fixtures.
#
#   ./run.sh <target> [seconds]      default 60
#   ./run.sh all [seconds]
#
# libFuzzer takes several corpus directories and writes new units only to the
# first, so the shared fixtures seed every run without being copied into this
# directory. A crasher lands under artifacts/<target>/; reduce it and pin it
# as a test under ../tests/ rather than committing it here.
#
# Requires uv. The fuzzer is installed into an ephemeral environment, so
# nothing here is a dependency of the package: `uv pip install -e .` in
# python/ never sees atheris. FUZZ_PYTHON overrides the interpreter, which is
# pinned to a line atheris publishes a wheel for (see README.md).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="$here/../../fixtures"
target="${1:?usage: run.sh <target>|all [seconds]}"
seconds="${2:-60}"

# --no-project so the SOURCE TREE is what gets fuzzed, resolved off PYTHONPATH
# exactly as the `python` CI job resolves it -- not an installed wheel.
# `harness` is on the path too, which is how the targets reach the library
# without importing it ahead of the instrumentation block.
export PYTHONPATH="$here/..:$here"
python=(uv run --no-project --python "${FUZZ_PYTHON:-3.13}"
  --with atheris --with cryptography --with asn1crypto python)

# Two seeds are built here from shared fixtures rather than checked in, so
# each of those receipts keeps exactly one copy in the repository: the
# endpoint's request body carrying a genuine receipt, and the raw attribute
# SET out of the generated receipt -- the payload bytes the hand-written
# reader takes, which no fixture holds on its own.
generated="$here/.seeds-generated"
mkdir -p "$generated/endpoint-json" "$generated/receipt-attributes"
"${python[@]}" - "$fixtures" "$generated" <<'PY'
import json
import sys
from pathlib import Path

from asn1crypto import cms

fixtures, generated = Path(sys.argv[1]), Path(sys.argv[2])
b64 = fixtures.joinpath("public-receipts", "receipt-sandbox-g5.b64").read_text().split()
(generated / "endpoint-json" / "sandbox-g5.json").write_text(
    json.dumps({"receipt-data": "".join(b64)})
)
for name in ("receipt", "receipt-type-vpp", "receipt-no-type"):
    der = fixtures.joinpath("generated", f"{name}.der").read_bytes()
    payload = cms.ContentInfo.load(der)["content"]["encap_content_info"]["content"].native
    (generated / "receipt-attributes" / name).write_bytes(payload)
PY

run_one() {
  local name="$1"
  local seeds
  case "$name" in
    receipt-der)
      seeds=("$fixtures/generated" "$fixtures/apple-official/certs") ;;
    receipt-attributes)
      seeds=("$generated/receipt-attributes" "$fixtures/generated") ;;
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
  for name in receipt-der receipt-attributes receipt-base64 jws endpoint-json; do
    run_one "$name"
  done
else
  run_one "$target"
fi
