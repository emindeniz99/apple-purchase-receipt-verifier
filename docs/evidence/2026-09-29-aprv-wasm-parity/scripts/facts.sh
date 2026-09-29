#!/bin/sh
# Evidence only (2026-09-29). The facts of one aprv.wasm build: sizes,
# hashes, imports, exports, custom sections, the interface read back from
# the component, and where a panic and the start function lead.
#
#   facts.sh <dir build.sh wrote>
#
# Needs wasm-tools on PATH.
set -eu
D="$1"; M="$D/aprv.wasm"; C="$D/aprv.component.wasm"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
wasm-tools print "$M" > "$T/aprv.wat"
wasm-tools strip --all "$M" -o "$T/stripped.wasm"
echo "aprv.wasm: $(wc -c < "$M") bytes, sha256 $(sha256sum "$M" | cut -c1-64)"
echo "  stripped of every custom section (wasm-tools strip --all): $(wc -c < "$T/stripped.wasm") bytes;" \
  "gzip -9 of that: $(gzip -9 -c "$T/stripped.wasm" | wc -c) bytes; gzip -9 of the module as built: $(gzip -9 -c "$M" | wc -c) bytes"
echo "aprv.component.wasm: $(wc -c < "$C") bytes, sha256 $(sha256sum "$C" | cut -c1-64)"
echo "imports:"; grep -oE '^ *\(import "[^"]*" "[^"]*"' "$T/aprv.wat" | sed -E 's/^ *\(import /  /'
echo "exports:"; grep -oE '^ *\(export "[^"]*"' "$T/aprv.wat" | sed -E 's/^ *\(export /  /'
echo "custom sections:"; wasm-tools objdump "$M" | grep custom | sed -E 's/ +/ /g; s/^/ /'
echo "the component's interface (wasm-tools component wit):"; wasm-tools component wit "$C" | sed 's/^/  /'
echo "panic machinery linked (functions whose name holds panic or unwind): $(grep -oE '\(func \$[^ ]*(panic|unwind)[^ ]*' "$T/aprv.wat" | sort -u | wc -l)"
echo "where a panic ends (std's hook writes to stderr first; panic = \"abort\" aborts):"
for f in '_rust_start_panic' '\$abort ' '__imported_wasi_snapshot_preview1_fd_write'; do
  awk -v f="$f" '$0 ~ "\\(func .*" f { p = 1 } p { print "  " $0 } p && /^  \)/ { p = 0 }' "$T/aprv.wat"
done
echo "the one constructor, which every export runs on its first call (so _initialize is optional):"
awk '/\(func \$__wasm_call_ctors /{p=1} p{print "  " $0} p && /^  \)/{p=0}' "$T/aprv.wat"
echo "the first instructions of an export: the constructor guard"
awk '/\(func \$aprv:verifier\/verify@1.0.0#init /{p=1} p{print "  " $0; n++} n==12{exit}' "$T/aprv.wat"
