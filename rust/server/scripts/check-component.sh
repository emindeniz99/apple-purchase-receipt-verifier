#!/bin/sh
# Rebuilds aprv-server around one component and runs the whole lane's
# checks against it, in one command, so a new aprv.wasm is cheap to take:
#
#   APRV_COMPONENT=aprv.component.wasm OUT=DIR sh check-component.sh
#
# Optional:
#   COMPONENT_SHA256  refuse any other component
#   CALLS, ROWS       the corpus: CALLS/<corpus>.pinned.jsonl and the module's
#                     own answers ROWS/module-<corpus>.jsonl (skipped if unset)
#   SCHEMATHESIS      a schemathesis executable (skipped if unset)
#   SPECTRAL          a spectral executable (skipped if unset)
#   SKIP_BUILD=1      reuse OUT's binaries
#   CARGO_TARGET_DIR  as usual; the debug and release trees are deleted
#                     between steps to keep the disk footprint small
#
# Writes into OUT: aprv-x86_64-unknown-linux-musl (the shipped binary),
# aprv-full-gnu (the Cranelift build for the build host), the .ccwasm and its manifest, and
# check-*.txt logs. Every step runs; the exit status is 1 if any failed.
set -u
: "${APRV_COMPONENT:?set APRV_COMPONENT to the component .wasm}" "${OUT:?set OUT to the output directory}"
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
host=$(rustc -vV | sed -n 's/^host: //p')
target=x86_64-unknown-linux-musl
targetdir=${CARGO_TARGET_DIR:-$here/target}
bin="$OUT/aprv-$target"
full="$OUT/aprv-full-gnu"   # the Cranelift build, for the build host (glibc here)
mkdir -p "$OUT"
status=0
step() { # name command...
  name=$1; shift
  if "$@" > "$OUT/check-$name.txt" 2>&1; then r=PASS; else r=FAIL; status=1; fi
  echo "$r $name ($OUT/check-$name.txt)"
}

# 1. Tests in process, against this component (the debug tree, then drop it).
step cargo-test env APRV_TEST_COMPONENT="$APRV_COMPONENT" \
  cargo test --locked --manifest-path "$here/Cargo.toml" --features compile
rm -rf "$targetdir/debug"

# 2. The two-stage build.
if [ "${SKIP_BUILD:-0}" != 1 ]; then
  step build sh "$here/scripts/build-static.sh" "$APRV_COMPONENT" "$target" "$OUT"
  cp "$targetdir/$host/release/aprv" "$full"
  rm -rf "$targetdir/$host" "$targetdir/$target" "$targetdir/release"
fi
step info "$bin" info
want=$(sha256sum "$APRV_COMPONENT" | cut -c1-64)
if grep -q "\"component_sha256\": \"$want\"" "$OUT/check-info.txt"; then echo "PASS info names component $want"
else echo "FAIL info does not name component $want"; status=1; fi

# 3. Conformance, managed mode, limits.
step cases python3 "$here/scripts/cases.py" --aprv "$bin" --mode both --list
step managed python3 "$here/scripts/managed-smoke.py" --aprv "$bin"
step hostile sh "$here/scripts/hostile-smoke.sh" "$full"

# 4. The OpenAPI document.
if [ -n "${SPECTRAL:-}" ]; then
  step spectral "$SPECTRAL" lint --fail-severity=hint --ruleset "$here/.spectral.yaml" "$here/openapi.yaml"
fi
if [ -n "${SCHEMATHESIS:-}" ]; then
  work=$(mktemp -d)
  "$bin" serve --listen 127.0.0.1:18080 >/dev/null 2>&1 & sp=$!
  sleep 1
  step schemathesis sh -c "cd '$work' && '$SCHEMATHESIS' run http://127.0.0.1:18080/openapi.json --checks all --max-examples 50 --workers 1"
  kill $sp
  rm -rf "$work"
fi

# 5. The corpus through each transport, against the module's own rows.
if [ -n "${CALLS:-}" ] && [ -n "${ROWS:-}" ]; then
  for m in "http --lifecycle fresh" "http --lifecycle pool" "cli"; do
    label=$(echo "$m" | sed 's/ --lifecycle /-/')
    step "corpus-$label" python3 "$here/scripts/corpus.py" --aprv "$bin" --calls "$CALLS" --suffix .pinned \
      --reference "$ROWS" --mode $m --out "$OUT"
  done
fi

# 6. For the record.
step timing python3 "$here/scripts/startup.py" --aprv "$bin"
echo "binary $bin: $(wc -c < "$bin") bytes, gzip -9 $(gzip -9c "$bin" | wc -c), sha256 $(sha256sum "$bin" | cut -c1-64)"
echo "binary $full: $(wc -c < "$full") bytes, gzip -9 $(gzip -9c "$full" | wc -c), sha256 $(sha256sum "$full" | cut -c1-64)"
exit $status
