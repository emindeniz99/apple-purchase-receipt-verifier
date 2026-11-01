#!/usr/bin/env bash
# Static checks on what tools/cross/build.sh wrote for one target, run on
# the Linux build host (nothing here executes the binaries):
#
#   inspect.sh <build-dir> [<source-path-the-build-saw>]
#
# Per Mach-O file: LC_BUILD_VERSION (minos, sdk), whether it carries
# LC_CODE_SIGNATURE, and the dylibs it links. Per PE file: the machine,
# SizeOfStackReserve/Commit, and the DLLs it imports. With a source path,
# whether that path is baked into each test executable (the server tests'
# env!("CARGO_MANIFEST_DIR")). Needs llvm-otool, llvm-readobj and
# llvm-objdump (LLVM 18 here; set LLVM_BIN to their directory).
set -uo pipefail
dir="${1:?usage: inspect.sh <build-dir> [<source-path>]}"
src="${2:-}"
bin="${LLVM_BIN:-/usr/lib/llvm-18/bin}"

find "$dir" -type f ! -name '*.json' ! -name '*.txt' ! -name '*.tsv' ! -name SHA256SUMS | LC_ALL=C sort | while read -r f; do
  rel="${f#"$dir"/}"
  kind="$(file -b "$f")"
  printf '== %s (%s bytes)\n   %s\n' "$rel" "$(wc -c < "$f")" "${kind%%,*}"
  case "$kind" in
    Mach-O*)
      # LC_BUILD_VERSION (minos, sdk), or LC_VERSION_MIN_MACOSX (version,
      # sdk), which a 10.12 x86_64 deployment target gets instead.
      "$bin/llvm-otool" -l "$f" | awk '
        /cmd LC_BUILD_VERSION|cmd LC_VERSION_MIN_MACOSX/ { b = 1; print "   " $2; next }
        /cmd / { b = 0 }
        b && /^ *(minos|sdk|version) / { printf "     %s %s\n", $1, $2 }
        /LC_CODE_SIGNATURE/ { s = 1 }
        END { print "   code signature: " (s ? "yes" : "no") }'
      "$bin/llvm-otool" -L "$f" | tail -n +2 | sed 's/^[[:space:]]*/   links /'
      ;;
    PE32*)
      "$bin/llvm-readobj" --file-headers "$f" | grep -E 'Machine:|SizeOfStackReserve|SizeOfStackCommit' | sed 's/^[[:space:]]*/   /'
      "$bin/llvm-objdump" -p "$f" | sed -n 's/^[[:space:]]*DLL Name: /   imports /p'
      ;;
  esac
  if [[ -n "$src" && "$rel" == tests/* ]]; then
    n="$(grep -c -a -F "$src/rust/" "$f" || true)"
    echo "   lines holding $src/rust/: $n"
  fi
done
