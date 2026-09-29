#!/bin/sh
# Spike only. The Java 8 client on Temurin 8: mode 2 (managed child: ops,
# token, crash, SIGKILL, bench, close), mode 1 (configured URL), child
# clean-up when the JVM exits without close() and when it is SIGKILLed,
# mode 3 (download from a loopback stand-in for GitHub Releases: concurrent
# JVMs, tampered cache entry, tampered download).
#   JDK8=... java.sh > results/java8.txt
set -eu
. "$(dirname "$0")/env.sh"; . "$(dirname "$0")/lib.sh"
: "${JDK8:?}"
# gone PID: the process no longer runs. A zombie counts as gone (it has exited;
# only its new parent has not reaped it yet), and the line says so.
gone() { st=$(ps -o stat= -p "$1" 2>/dev/null | cut -c1); [ -z "$st" ] && return 0; [ "$st" = Z ] && { echo "   (pid $1 exited; zombie left for its new parent, pid $(ps -o ppid= -p "$1" | tr -d ' '), to reap)"; return 0; }; return 1; }
unset JAVA_TOOL_OPTIONS || true
J="$JDK8/bin/java"; CP="$SV/java"
mkdir -p "$CP"
"$JDK8/bin/javac" -source 8 -target 8 -d "$CP" "$EV/java/AprvClient.java" "$EV/java/Tests.java" 2>&1 | grep -v 'bootstrap classpath' || true
echo "# $("$J" -version 2>&1 | head -2 | tr '\n' ' ')"
echo "## mode 2: managed child (aprv-min-spike: variant B + the spike-only crash route)"
"$J" -cp "$CP" Tests managed "$SV/bin/aprv-min-spike" "$SV/in/g5.b64" "$SV/in/jws.txt" "$SV/in/endpoint-sandbox.json" 2>/dev/null
echo "## mode 1: configured URL (a standalone aprv-min with a token)"
TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
APRV_TOKEN=$TOKEN start_server "$SV/bin/aprv-min" --lifecycle fresh
"$J" -cp "$CP" Tests url "http://$SRV_ADDR" "$TOKEN" "$SV/in/g5.b64" "$SV/in/jws.txt" "$SV/in/endpoint-sandbox.json"
stop_server
echo "## JVM exits without close(): the shutdown hook stops the child"
pid=$("$J" -cp "$CP" Tests hold "$SV/bin/aprv-min" exit 2>/dev/null | sed -n 's/^CHILD //p')
sleep 0.3
[ -n "$pid" ] && gone "$pid" && echo "PASS child $pid gone after System.exit" || echo "FAIL child $pid still running"
echo "## JVM killed with SIGKILL (no hook runs): the child sees stdin EOF and exits"
"$J" -cp "$CP" Tests hold "$SV/bin/aprv-min" sleep > "$SV/run/hold.out" 2>/dev/null &
jpid=$!
while ! grep -q '^CHILD ' "$SV/run/hold.out"; do sleep 0.05; done
pid=$(sed -n 's/^CHILD //p' "$SV/run/hold.out")
kill -9 $jpid; wait $jpid 2>/dev/null || true
sleep 0.3
gone "$pid" && echo "PASS child $pid gone after kill -9 of the JVM" || { echo "FAIL child $pid still running"; kill "$pid"; }
echo "## mode 3: managed download from a loopback stand-in for the release location"
DL="$SV/dl"; rm -rf "$DL" "$SV/dl-cache"; mkdir -p "$DL/official" "$DL/tampered"
cp "$SV/bin/aprv-min" "$DL/official/aprv-linux-x86_64"
cp "$SV/bin/aprv-min" "$DL/tampered/aprv-linux-x86_64"
printf '\001' | dd of="$DL/tampered/aprv-linux-x86_64" bs=1 seek=1000000 conv=notrunc 2>/dev/null
PIN=$(sha256sum "$DL/official/aprv-linux-x86_64" | cut -c1-64)
echo "pinned sha256 $PIN; tampered copy $(sha256sum "$DL/tampered/aprv-linux-x86_64" | cut -c1-64)"
python3 -u -m http.server 0 --bind 127.0.0.1 --directory "$DL" > "$SV/run/fs.out" 2> "$SV/run/fs.log" &
FS=$!
while ! grep -q 'port' "$SV/run/fs.out"; do sleep 0.05; done
PORT=$(sed -n 's/.* port \([0-9]*\).*/\1/p' "$SV/run/fs.out")
echo "### two JVMs at once, four threads each, empty cache"
"$J" -cp "$CP" Tests download "http://127.0.0.1:$PORT/official/" "$SV/dl-cache" aprv-linux-x86_64 "$PIN" 4 "$SV/in/g5.b64" > "$SV/run/dl1.out" 2>/dev/null &
p1=$!
"$J" -cp "$CP" Tests download "http://127.0.0.1:$PORT/official/" "$SV/dl-cache" aprv-linux-x86_64 "$PIN" 4 "$SV/in/g5.b64" > "$SV/run/dl2.out" 2>/dev/null &
p2=$!
wait $p1; wait $p2
cat "$SV/run/dl1.out" "$SV/run/dl2.out" | grep -v '^#'
echo "GET requests the file server saw: $(grep -c 'GET /official/' "$SV/run/fs.log")"
echo "### a tampered cache entry is re-verified at start, replaced, not executed"
f="$SV/dl-cache/aprv-$PIN"; chmod u+w "$f"; printf 'X' >> "$f"; chmod u-w "$f"
"$J" -cp "$CP" Tests download "http://127.0.0.1:$PORT/official/" "$SV/dl-cache" aprv-linux-x86_64 "$PIN" 1 "$SV/in/g5.b64" 2>/dev/null | grep -v '^#'
echo "GET requests the file server saw: $(grep -c 'GET /official/' "$SV/run/fs.log")"
echo "### a download whose hash is not the pin"
rm -rf "$SV/dl-cache2"
"$J" -cp "$CP" Tests tampered "http://127.0.0.1:$PORT/tampered/" "$SV/dl-cache2" aprv-linux-x86_64 "$PIN" 2>/dev/null | grep -v '^#'
kill $FS; wait $FS 2>/dev/null || true
rm -rf "$DL" "$SV/dl-cache" "$SV/dl-cache2"
