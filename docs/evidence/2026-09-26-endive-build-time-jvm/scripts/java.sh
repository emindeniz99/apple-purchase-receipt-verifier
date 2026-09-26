#!/bin/sh
# Spike only (2026-09-26). Three-way tallies (Java oracle / current Rust /
# candidate, the substrate bake-off's py/tri.py) for the Endive runs, checked
# against round 4's native baseline. Same columns as round 4's java.sh.
#   scripts/java.sh > results/java-tallies.txt
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
tally() { python3 "$SPIKE/py/tri.py" "$CORPORA/$1.jsonl" "$CORPORA/jvm25-$1.jsonl" "$SCRATCH/run/rust-$1.jsonl" "$2" 2>/dev/null | awk '$1 == "total" { print $2, $3, $4, $5, $6 }'; }
echo "# \$SPIKE/py/tri.py, 2026-09-26. Columns per corpus: agree cand=java cand=rust cand-own abi. Java rows: JDK 25.0.4.1 + BC 1.86 (reused)."
echo "# java-equal = agree + cand=java over the 1,048 rows the C ABI can express. 'same' = identical to round 4's base tallies."
printf '%-24s %-18s %-18s %-20s %-16s %-11s %s\n' run cases substrate hostile algorithms java-equal vs-base
row() { # label, prefix
  line=""; je=0; all=same
  for c in cases substrate hostile algorithms; do
    x=$(tally $c "$2-$c.jsonl"); n=$(tally $c "$BASE-$c.jsonl")
    [ "$x" = "$n" ] || all=DIFFERS
    line="$line$(printf '%-18s ' "$x")"; je=$((je + $(echo $x | awk '{print $1+$2}')))
  done
  printf '%-24s %s %-11s %s\n' "$1" "$line" "$je" "$all"
}
row "round-4 base (native)" "$BASE"
for t in jdk11 jdk17 jdk21 jdk25 jdk25-bytearray; do row "endive $t" "$E/run/$t"; done
