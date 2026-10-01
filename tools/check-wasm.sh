#!/usr/bin/env bash
# Checks a built aprv.wasm against the contract ARCHITECTURE.md §3, §4 and
# §9 state, with wasm-tools (tools/wasm-toolchain.sh installs it):
#
#   tools/check-wasm.sh <dir> <aprv.wit>
#
# <dir> holds what rust/bindings/abi/build.sh writes: aprv.wasm,
# aprv.component.wasm, aprv.wit and SHA256SUMS. Checked, and each failure
# named:
#
#   1. SHA256SUMS lists the module, the component and the WIT, and matches.
#   2. The core module imports exactly one function, random-get from
#      aprv:verifier/host@0.1.0.
#   3. It exports the four operations, their four cabi_post_ functions,
#      cabi_realloc, memory and _initialize, and nothing else but
#      wit-bindgen's own versioned cabi_realloc alias; the internal symbols
#      the link-time C file uses must not be exports.
#   4. The component's interface reads back as the committed WIT: both are
#      rendered by `wasm-tools component wit` from a component (the
#      committed file through a dummy one), so comments and layout do not
#      count and every name, type and doc comment does.
#   5. The WIT in <dir> is the committed file, byte for byte.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <dir> <aprv.wit>" >&2
  exit 2
fi
DIR=$1
WIT=$2
IFACE='aprv:verifier/verify@0.1.0#'
failed=0
fail() { echo "check-wasm: FAIL $*" >&2; failed=1; }
pass() { echo "check-wasm: ok   $*"; }

for f in aprv.wasm aprv.component.wasm aprv.wit SHA256SUMS; do
  [[ -f "$DIR/$f" ]] || { echo "check-wasm: $DIR/$f is missing" >&2; exit 1; }
done

# 1. The hashes.
if (cd "$DIR" && sha256sum --check --strict --quiet SHA256SUMS) \
   && for f in aprv.wasm aprv.component.wasm aprv.wit; do grep -qE "^[0-9a-f]{64}  \*?$f\$" "$DIR/SHA256SUMS" || exit 1; done; then
  pass "SHA256SUMS lists and matches aprv.wasm, aprv.component.wasm and aprv.wit"
else
  fail "SHA256SUMS does not list or match all three files"
fi

# 2 and 3. The core module's imports and exports.
printed="$(wasm-tools print "$DIR/aprv.wasm")"
imports="$(grep -oE '^ *\(import "[^"]*" "[^"]*"' <<<"$printed" | sed -E 's/^ *\(import "([^"]*)" "([^"]*)"/\1 \2/')" || true
if [[ "$imports" == "aprv:verifier/host@0.1.0 random-get" ]] \
   && grep -qE '^ *\(import "aprv:verifier/host@0.1.0" "random-get" \(func' <<<"$printed"; then
  pass "imports exactly aprv:verifier/host@0.1.0 random-get"
else
  fail "imports are not exactly random-get: $(tr '\n' ';' <<<"$imports")"
fi

exports="$(grep -oE '^ *\(export "[^"]*"' <<<"$printed" | sed -E 's/^ *\(export "([^"]*)"/\1/' | sort)"
expected="$(for op in init verify-receipt verify-signed-data verify-receipt-endpoint; do
  echo "$IFACE$op"; echo "cabi_post_$IFACE$op"; done; printf '%s\n' cabi_realloc memory _initialize)"
expected="$(sort <<<"$expected")"
missing="$(comm -23 <(echo "$expected") <(echo "$exports"))"
extra="$(comm -13 <(echo "$expected") <(echo "$exports") | grep -vE '^cabi_realloc_wit_bindgen_[0-9]+_[0-9]+_[0-9]+$' || true)"
if [[ -z "$missing" && -z "$extra" ]]; then
  pass "exports the four operations, their post-return functions, cabi_realloc, memory and _initialize, nothing else"
else
  [[ -n "$missing" ]] && fail "missing exports: $(tr '\n' ' ' <<<"$missing")"
  [[ -n "$extra" ]] && fail "unexpected exports: $(tr '\n' ' ' <<<"$extra")"
fi

# 4. The interface read back from the component, against the committed WIT.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
world="$(sed -nE 's/^ *world +([a-z][a-z0-9-]*) *\{.*/\1/p' "$WIT" | head -1)"
if wasm-tools component embed --dummy "$WIT" --world "$world" -o "$tmp/dummy.wasm" \
   && wasm-tools component new "$tmp/dummy.wasm" -o "$tmp/dummy.component.wasm" \
   && wasm-tools component wit "$tmp/dummy.component.wasm" > "$tmp/want.wit" \
   && wasm-tools component wit "$DIR/aprv.component.wasm" > "$tmp/got.wit"; then
  if diff -u "$tmp/want.wit" "$tmp/got.wit" > "$tmp/wit.diff"; then
    pass "the component's interface reads back as $WIT (world $world)"
  else
    fail "the component's interface differs from $WIT:"
    cat "$tmp/wit.diff" >&2
  fi
else
  fail "wasm-tools could not render the interfaces"
fi

# 5. The WIT shipped beside the module is the committed one.
if cmp -s "$WIT" "$DIR/aprv.wit"; then
  pass "$DIR/aprv.wit is $WIT"
else
  fail "$DIR/aprv.wit is not $WIT"
fi

exit "$failed"
