#!/bin/sh
# Spike only (2026-09-29, round 12). The five corpora (6,179 rows) through
# one host, each row compared byte for byte with ABI v1's Node rows by ABI
# v1's abi_compare.py (which masks request_date* on endpoint rows whose
# clock was not pinned).
#   corpus.sh LABEL -- HOST ARGV... (the host reads $S/calls/<corpus>.jsonl as its last argument)
#   corpus.sh wazero -- $S/aprv-wazero calls $MODC      > results/corpus-wazero.txt
# The host's rows go to $S/run/<label>-<corpus>.jsonl, its stderr summary
# to .err. $S/calls is made by py/calls_cabi.py (see ../README.md).
set -u
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
label=$1; shift 2
echo "# $label: $(date -u +%F); load before: $(cut -d' ' -f1-3 /proc/loadavg)"
for c in cases hostile algorithms substrate fuzz; do
  [ -f "$S/calls/$c.jsonl" ] || python3 "$FE/py/calls_cabi.py" "$CALLS/$c.jsonl" > "$S/calls/$c.jsonl" 2>/dev/null
  start=$(date +%s)
  if ! timeout -s KILL 3600 "$@" "$S/calls/$c.jsonl" > "$S/run/$label-$c.jsonl" 2> "$S/run/$label-$c.err"; then
    echo "$c: host failed: $(tail -3 "$S/run/$label-$c.err" | tr '\n' ' ' | cut -c1-300)"; continue
  fi
  python3 "$AB/py/abi_compare.py" "$CORPORA/$c.jsonl" "$NATIVENEW-$c.jsonl" "$CALLS/$c.jsonl" "$NODEROWS/node-$c.jsonl" "$S/run/$label-$c.jsonl" \
    | sed -n "2,\$s#^other host 1#    $label#p"
  echo "    $(tail -1 "$S/run/$label-$c.err") $(( $(date +%s) - start )) s wall"
done
