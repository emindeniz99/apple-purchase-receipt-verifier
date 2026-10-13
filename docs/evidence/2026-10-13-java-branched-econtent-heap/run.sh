#!/bin/sh
# Usage: run.sh OUT CLASSPATH
#   OUT        where the inputs are written; PresignatureCost's
#              baseline.b64 and tiny-attributes.b64 must already be there
#   CLASSPATH  BranchedEContent's and PresignatureCost's classes, the
#              library, its test classes and dependencies
# Prints the sizes of the shapes tried, then for the baseline, the
# tiny-attributes receipt and every shape that fits the cap: the smallest
# -Xmx (MiB) at which one call under Apple's roots completes in a fresh
# JVM, bisected three times.
set -u
OUT=$1
CP=$2

smallest_heap() { # main-class file [args]
  main=$1
  shift
  lo=4
  hi=1024
  while [ $((hi - lo)) -gt 1 ]; do
    mid=$(((lo + hi) / 2))
    if java -Xmx${mid}m -cp "$CP" "$main" once "$@" >/dev/null 2>&1; then
      hi=$mid
    else
      lo=$mid
    fi
  done
  echo "$hi"
}

three() {
  echo "$(smallest_heap "$@") $(smallest_heap "$@") $(smallest_heap "$@")"
}

echo "== sizes"
# The research shapes (2, 19, 2) and (2, 18, 6), then the ones tried here.
for shape in "2 19 2" "2 18 6" "2 18 4" "2 19 0" "2 17 8" "5 17 3" "5 16 10" "3 18 1"; do
  java -cp "$CP" BranchedEContent size $shape 2>&1 | grep -v JAVA_TOOL_OPTIONS
done

echo "== smallest -Xmx (default G1), MiB, under Apple's roots"
echo "baseline: $(three PresignatureCost "$OUT/baseline.b64" default)"
echo "tiny-attributes: $(three PresignatureCost "$OUT/tiny-attributes.b64" default)"
for shape in "2 18 4" "2 19 0" "2 17 8" "5 17 3" "5 16 10" "3 18 1"; do
  name=tree-$(echo "$shape" | tr ' ' '-')
  java -cp "$CP" BranchedEContent make "$OUT/$name.b64" $shape 2>&1 | grep -v JAVA_TOOL_OPTIONS
  java -cp "$CP" BranchedEContent once "$OUT/$name.b64" 2>&1 | grep -v JAVA_TOOL_OPTIONS
  echo "$name: $(three BranchedEContent "$OUT/$name.b64")"
done
