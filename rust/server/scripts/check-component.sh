#!/bin/sh
# The server's corpus parity run (DECISIONS.md R35): rebuilds aprv-server
# around one component, checks that the binary names that component, and
# runs the corpus through each transport against the module's own rows, in
# one command:
#
#   APRV_COMPONENT=aprv.component.wasm OUT=DIR CALLS=DIR ROWS=DIR sh check-component.sh
#
# CALLS holds <corpus>.pinned.jsonl and ROWS the module's own answers,
# module-<corpus>.jsonl. Rows only: the cargo tests, the shared cases, the
# managed and hostile smokes and the OpenAPI checks run in ci.yml against
# the freshly built component, and the archive's component predates
# whatever the core and the shared cases changed since its release
# (README.md, "Tests and checks", lists each command). Optional:
#   COMPONENT_SHA256  refuse any other component
#   SKIP_BUILD=1      reuse OUT's binary
#   CARGO_TARGET_DIR  as usual; the release trees are deleted after the
#                     build to keep the disk footprint small
#
# Writes into OUT: aprv-x86_64-unknown-linux-musl (the shipped binary), the
# .ccwasm and its manifest, the corpus rows and check-*.txt logs. Every step
# runs; the exit status is 1 if any failed.
set -u
: "${APRV_COMPONENT:?set APRV_COMPONENT to the component .wasm}" "${OUT:?set OUT to the output directory}"
: "${CALLS:?set CALLS to the directory of <corpus>.pinned.jsonl}" "${ROWS:?set ROWS to the directory of module-<corpus>.jsonl}"
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
host=$(rustc -vV | sed -n 's/^host: //p')
target=x86_64-unknown-linux-musl
targetdir=${CARGO_TARGET_DIR:-$here/target}
bin="$OUT/aprv-$target"
mkdir -p "$OUT"
status=0
step() { # name command...
  name=$1; shift
  if "$@" > "$OUT/check-$name.txt" 2>&1; then r=PASS; else r=FAIL; status=1; fi
  echo "$r $name ($OUT/check-$name.txt)"
}

# 1. The two-stage build.
if [ "${SKIP_BUILD:-0}" != 1 ]; then
  step build sh "$here/scripts/build-static.sh" "$APRV_COMPONENT" "$target" "$OUT"
  rm -rf "$targetdir/$host" "$targetdir/$target" "$targetdir/release"
fi
step info "$bin" info
want=$(sha256sum "$APRV_COMPONENT" | cut -c1-64)
if grep -q "\"component_sha256\": \"$want\"" "$OUT/check-info.txt"; then echo "PASS info names component $want"
else echo "FAIL info does not name component $want"; status=1; fi

# 2. The corpus through each transport, against the module's own rows.
for m in "http --lifecycle fresh" "http --lifecycle pool" "cli"; do
  label=$(echo "$m" | sed 's/ --lifecycle /-/')
  step "corpus-$label" python3 "$here/scripts/corpus.py" --aprv "$bin" --calls "$CALLS" --suffix .pinned \
    --reference "$ROWS" --mode $m --out "$OUT"
done
echo "binary $bin: $(wc -c < "$bin") bytes, sha256 $(sha256sum "$bin" | cut -c1-64)"
exit $status
