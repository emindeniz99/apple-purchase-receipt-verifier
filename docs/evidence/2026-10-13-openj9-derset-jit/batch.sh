#!/bin/bash
# usage: batch.sh <prefix> <count> <java> "<jvm opts>" [classes...]
S=${SCRATCH:?}
prefix=$1; n=$2; java=$3; opts=$4; shift 4
for i in $(seq 1 $n); do
  $S/scripts/runj.sh "$prefix-$i" "$java" "-Dverbose=true -Dtraces=40 $opts" "$@" >> $S/results.txt
done
echo "BATCH-DONE $prefix" >> $S/results.txt
