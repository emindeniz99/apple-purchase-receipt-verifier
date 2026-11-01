#!/usr/bin/env bash
# The python job's suite on one interpreter line:
#
#   .github/scripts/python-suite.sh <python-version>
#
# Run from the repository root, after astral-sh/setup-uv. ci.yml calls it
# from python (one leg per line and runner) and, on a pull request, from
# macos-wrappers and windows-wrappers, which run two lines in sequence on
# one runner; one script keeps them from drifting. --python names the line
# on every uv call, so a combined job switches lines without UV_PYTHON.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <python-version>" >&2
  exit 2
fi
python="$1"
cd python

# python/uv.lock is committed and every leg installs from it, so no push
# resolves a version range. uv forks the resolution on the interpreter and
# records a version per marker, so one file covers 3.11 through 3.14
# without pinning the whole matrix to what the floor can take. `uv sync`
# installs the project editable, which keeps this a test of the SOURCE TREE
# rather than of a built wheel. A sync for another line replaces .venv.
echo "::group::uv sync (Python $python)"
uv sync --locked --extra dev --python "$python"
echo "::endgroup::"

# APRV_WASM_CACHE_DIR stays unset: test_cache.py sets it where it needs it,
# and the default cache directory under HOME is part of what it tests.
echo "::group::the suite (Python $python)"
uv run --locked --extra dev --python "$python" python -m unittest discover -s tests
echo "::endgroup::"

# Again with the compile cache warm: the second run is the one a deployment
# sees after its first start, and test_cache.py prints the cold and warm
# start times for the README's numbers. In a combined job the second line's
# first run may already find the cache warm; the tests do not depend on it.
echo "::group::the suite again, with the compile cache warm (Python $python)"
uv run --locked --extra dev --python "$python" python -m unittest discover -s tests
echo "::endgroup::"
