#!/bin/sh
# Usage: run.sh OUT CLASSPATH [GC]
#   OUT        where `PresignatureCost make` wrote the inputs
#   CLASSPATH  the probe's classes, the library, its test classes and dependencies
#   GC         optional collector flag for the bisection, e.g. -XX:+UseSerialGC
# Prints, for each input and each set of roots: three `measure` runs, then
# the smallest -Xmx (MiB) at which one call completes, bisected three times.
set -u
OUT=$1
CP=$2
GC=${3:-}

smallest_heap() { # input roots
  lo=4
  hi=1024
  while [ $((hi - lo)) -gt 1 ]; do
    mid=$(((lo + hi) / 2))
    if java $GC -Xmx${mid}m -cp "$CP" PresignatureCost once "$1" "$2" >/dev/null 2>&1; then
      hi=$mid
    else
      lo=$mid
    fi
  done
  echo "$hi"
}

for input in baseline tiny-attributes unsigned-attribute; do
  for roots in "$OUT/root.der" default; do
    echo "== $input, roots: $(basename "$roots")"
    if [ -z "$GC" ]; then
      for run in 1 2 3; do
        java -cp "$CP" PresignatureCost measure "$OUT/$input.b64" "$roots" 2>&1 | grep -v JAVA_TOOL_OPTIONS
      done
    fi
    echo "smallest -Xmx ${GC:-(default G1)}, MiB: $(smallest_heap "$OUT/$input.b64" "$roots") $(smallest_heap "$OUT/$input.b64" "$roots") $(smallest_heap "$OUT/$input.b64" "$roots")"
  done
done
