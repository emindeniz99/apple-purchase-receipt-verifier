#!/bin/sh
# The PHP corpus parity run against one aprv binary (DECISIONS.md R35): the
# corpus through the façade over both transports, compared with the module's
# own rows. Rows only: the phpunit suites (the shared cases through the CLI
# and over HTTP, the façade, transport and installer tests) run in ci.yml
# against the freshly built binary, and the archive's module predates
# whatever the core and the shared cases changed since its release.
#
#   tools/rerun.sh /path/to/aprv /path/to/g1
#
# The g1 directory holds calls/<corpus>.pinned.jsonl and rows/module-<corpus>.jsonl
# (and same.py, used for the byte-for-byte comparison when it is there). The
# binary is passed to tools/corpus.php as --aprv; the library reads no
# environment variable.
set -eu
[ $# -eq 2 ] || { echo "usage: tools/rerun.sh APRV_BINARY G1_DIR" >&2; exit 2; }
here=$(cd "$(dirname "$0")/.." && pwd)
APRV_BIN=$1
g1=$2
cd "$here"
rows=$(mktemp -d)
trap 'rm -rf "$rows"' EXIT
failed=0

for mode in cli http; do
    echo "== corpus through the façade, $mode"
    php -d memory_limit=1G tools/corpus.php --aprv "$APRV_BIN" --calls "$g1/calls" --reference "$g1/rows" \
        --suffix .pinned --mode "$mode" --out "$rows" || failed=1
    if [ -f "$g1/same.py" ]; then
        for corpus in cases hostile algorithms substrate fuzz; do
            printf '   same.py %-10s ' "$corpus"
            python3 "$g1/same.py" "$rows/$mode-$corpus.jsonl" "$g1/rows/module-$corpus.jsonl" | tail -1 || true
        done
    fi
done
[ "$failed" -eq 0 ] && echo "== all green" || echo "== FAILED"
exit "$failed"
