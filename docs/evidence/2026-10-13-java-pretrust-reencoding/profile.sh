#!/bin/sh
# Usage: profile.sh <out-dir> <classpath> <probe-class> <probe-args...>
# Runs one probe under JFR (method sampling every 10 ms) and prints the
# 25 most frequent stack prefixes, top 12 frames each, from the samples.
set -e
out=$1; cp=$2; cls=$3; shift 3
jfr_file=$out/profile.jfr
java -XX:FlightRecorderOptions:stackdepth=2048 -XX:StartFlightRecording=filename=$jfr_file,settings=profile -cp "$cp" "$cls" "$@"
jfr print --events jdk.ExecutionSample --stack-depth 2048 "$jfr_file" > "$out/samples.txt"
awk '/stackTrace = \[/{s="";n=0;inst=1;next} inst&&/^[[:space:]]*\]/{c[s]++;inst=0;next} inst{gsub(/^[[:space:]]+/,"");sub(/line:.*/,"");if(n<12)s=s" < "$0;n++}
END{for(k in c)print c[k]"\t"k}' "$out/samples.txt" | sort -rn | head -25
