#!/bin/sh
# The install-failure check (docs/rust-core R28, MIGRATION step 5.2), at the
# level of pip: with the release files as the only candidates and the platform
# faked as one wasmtime-py has no wheel for, `pip install` must stop with the
# pointer to aprv-server and the C ABI; on the real platform the same files
# must install and verify a genuine receipt.
#
#   sh tools/check-install.sh DIST [FAKE_PLATFORM]
#
# DIST is the output of `python tools/build_dist.py`. FAKE_PLATFORM defaults to
# linux-i686 and is what sysconfig.get_platform() answers to pip
# (_PYTHON_HOST_PLATFORM). Needs python3 with venv and network access to PyPI
# for wasmtime's wheels; every install itself is from DIST and a wheel
# directory made here, never from the index, so the published 0.7.0 cannot
# stand in for the files under test.
set -eu

dist="$(cd "${1:?usage: check-install.sh DIST [FAKE_PLATFORM]}" && pwd)"
fake="${2:-linux-i686}"
here="$(cd "$(dirname "$0")" && pwd)"
receipt="$here/../../fixtures/public-receipts/receipt-sandbox-g5.b64"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

python3 -m venv "$work/venv"
pip="$work/venv/bin/pip"
mkdir "$work/wheels"

# What pip would find on the index: the build dependency, wasmtime's own wheel
# for this platform, and the py3-none-any wheel it falls back to elsewhere
# (which holds only the Windows library).
"$pip" download 'setuptools>=70.1' --no-deps --only-binary=:all: -d "$work/wheels" -q
"$pip" download 'wasmtime>=49' --no-deps --only-binary=:all: -d "$work/wheels" -q
"$pip" download 'wasmtime>=49' --no-deps --only-binary=:all: -d "$work/wheels" -q \
  --platform linux_i686 --python-version 3.11 --implementation cp

echo "== $fake: pip must refuse"
if output="$(_PYTHON_HOST_PLATFORM="$fake" "$pip" install --no-index \
    --find-links "$dist" --find-links "$work/wheels" apple-purchase-receipt-verifier 2>&1)"; then
  echo "FAIL: the install succeeded on $fake"
  exit 1
fi
for needle in "aprv-server" "C ABI" "$fake"; do
  case "$output" in
    *"$needle"*) ;;
    *) echo "FAIL: the failure does not mention '$needle'"; echo "$output"; exit 1 ;;
  esac
done
echo "ok: refused, with the pointer"

echo "== this platform: pip must install and verify"
"$pip" install --no-index --find-links "$dist" --find-links "$work/wheels" \
  apple-purchase-receipt-verifier
cd "$work"
"$work/venv/bin/python" - "$receipt" <<'PY'
import pathlib
import sys

from apple_purchase_receipt_verifier import Config, Verifier

receipt = "".join(pathlib.Path(sys.argv[1]).read_text().split())
result = Verifier(Config.defaults()).verify_receipt(receipt)
assert result.verified, result.failure
print("ok: the genuine sandbox receipt verifies")
PY
