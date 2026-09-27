#!/bin/sh
# Spike only (2026-09-27, round 10). The exact link line of the two musl
# builds (features server,embed), from rustc's --print link-args, with
# scratch paths replaced by placeholders and the long object lists
# summarised: which linker driver, which crt objects, which libc.a.
#   linkargs.sh > results/linkargs.txt   (after build.sh)
set -eu
. "$(dirname "$0")/env.sh"
M="$S/src/server/Cargo.toml"
one() { # triple how cwasm-triple
  export APRV_CWASM="$S/art/aprv-abi1.$3.cwasm"
  if [ "$2" = zigbuild ]; then set -- "$1" "$2" "$3" env PATH="$ZIGVENV/bin:$PATH" cargo zigbuild; else set -- "$1" "$2" "$3" cargo build; fi
  t=$1; shift 3
  touch "$S/src/server/src/main.rs"
  "$@" --release --locked --manifest-path "$M" --target "$t" --no-default-features --features server,embed \
    --config "target.$t.rustflags=['--print','link-args']" 2>&1 | grep -E '^LC_ALL=' | head -1 > "$S/run/link-$t.txt" || true
  python3 - "$S/run/link-$t.txt" "$t" "$SCRATCH" "$RUSTUP_HOME" "$ZIGVENV" <<'PYEOF'
import shlex, sys
raw = open(sys.argv[1]).read().strip()
t, scratch, rh, zv = sys.argv[2:6]
if not raw:
    print(f"{t}: no link line captured"); sys.exit()
args = shlex.split(raw)
while args and "=" in args[0] and not args[0].startswith("-"):
    args.pop(0)  # the LC_ALL= and PATH= prefix rustc prints
def clean(a):
    return a.replace(rh, "$RUSTUP_HOME").replace(zv, "$ZIGVENV").replace(scratch, "$SCRATCH")
import os
driver = clean(args[0])
if "zigcc" in driver:
    driver = "cargo-zigbuild's zig cc wrapper for " + t
crt = [os.path.basename(a) for a in args if a.endswith(".o") and "self-contained" in a]
libs = [clean(a) for a in args if a.endswith("libc.a") or a in ("-lc", "-lunwind", "-lgcc_s", "-static", "-static-pie", "-no-pie", "-pie", "-nostartfiles", "-nodefaultlibs")]
fuse = [a for a in args if a.startswith("-fuse-ld") or a.startswith("-Wl,--as-needed")]
selfc = sorted({clean(os.path.dirname(a)) for a in args if "self-contained" in a})
print(f"{t}: driver {driver}; {len(args)} args")
print(f"    self-contained crt objects: {' '.join(crt) or 'none'}")
print(f"    self-contained dirs: {' '.join(selfc) or 'none'}")
print(f"    libc/link-mode flags: {' '.join(libs)}")
PYEOF
}
echo "# linkargs.sh, $(date -u +%F)"
one x86_64-unknown-linux-musl build x86_64-unknown-linux-musl
one aarch64-unknown-linux-musl zigbuild aarch64-unknown-linux-musl
