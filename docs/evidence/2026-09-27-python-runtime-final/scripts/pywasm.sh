#!/bin/sh
# Spike only (2026-09-27, round 11). pywasm 2.2.3: install, sizes, Python
# floor evidence, the early-stop probe, and the assert/`python -O` check.
#   pywasm.sh > results/pywasm.txt
# Stop rule (decided before the run): time g5 #1..#2 and JWS #1 first. If a
# steady JWS call takes longer than 1 s (JWS/s < 1, a tenth of the owner's
# ~10/s floor), record the numbers and stop: no full corpus, no ABI suite.
set -eu
. "$(dirname "$0")/env.sh"
[ -x "$PYWASM_VENV/bin/python" ] || { "$PY312" -m venv "$PYWASM_VENV"; "$PYWASM_VENV/bin/pip" install -q --no-compile pywasm==2.2.3; }
P="$PYWASM_VENV/lib/python3.12/site-packages/pywasm"
echo "# pywasm $("$PYWASM_VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("pywasm"))') on $("$PYWASM_VENV/bin/python" --version), $(date -u +%F), load $(cut -d' ' -f1-3 /proc/loadavg)"
curl -sS https://pypi.org/pypi/pywasm/json | python3 -c "
import json, sys
d = json.load(sys.stdin); i = d['info']
print(f\"PyPI: latest {i['version']}, requires_python {i['requires_python']!r}; files: \" + ', '.join(f\"{f['filename']} {f['size']} bytes\" for f in d['urls']))"
echo "README (github.com/libraries/pywasm, master): $(curl -sS https://raw.githubusercontent.com/libraries/pywasm/master/README.md | grep -o 'requires Python version >= [0-9.]*')"
echo "source uses typing.Self (Python >= 3.11): $(grep -c 'typing.Self' "$P/core.py") sites in core.py; pywasm/__init__.py still says version = $(grep -o "version = '[^']*'" "$P/__init__.py")"
echo "installed: $(find "$P" -name '*.py' | xargs cat | wc -c) bytes of .py in $(find "$P" -name '*.py' | wc -l) files ($(find "$P" -name '*.py' | xargs cat | wc -l) lines), no native code; wheel 44,605 bytes"
echo "## probe: g5 #1..#2, JWS #1 (budget 600 s per op), one fresh process"
APRV_MODULE="$MOD" PYTHONPATH="$FE/py" setsid timeout -s KILL 1800 "$PYWASM_VENV/bin/python" -B "$FE/py/pywasm_probe.py" "$S/in/g5.bin" "$S/in/jws.bin" 2 1 600 \
  || echo "probe ended with status $? (137 = killed at the 1800 s limit)"
echo "## traps are asserts: the same three cases with python and python -O"
for o in "" -O; do
  APRV_MODULE="$MOD" PYTHONPATH="$FE/py" setsid timeout -s KILL 900 "$PYWASM_VENV/bin/python" -B $o "$FE/py/pywasm_asserts.py" 2>&1 | grep -v '^  ' | tail -3 \
    | sed "s/^Traceback.*/python $o: traceback while loading the module:/"
done
