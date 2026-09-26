#!/bin/sh
# Spike only (2026-09-26). The whole route, on the build machine:
#
#   scripts/build.sh lib       aprv.wasm -> Endive build-time compiler -> library jar,
#                              deployed to a file repository ($E/remote-repo)
#   scripts/build.sh trap      trap.wat -> trap.wasm -> the same plugin -> trap-probe jar
#   scripts/build.sh consumer  the clean consumer, built with an EMPTY local
#                              repository ($E/m2-consumer) from the file repository
#                              and Maven Central only
#
# The build side uses $E/m2-build; the consumer never sees it. The library
# and the probe are built with JDK 17 (any JDK >= 11 works for the plugin).
set -eu
. "$(dirname "$0")/env.sh"
MVN_BUILD="mvn -B -Dmaven.repo.local=$E/m2-build"
case "$1" in
lib)
  [ -f "$WASM" ] || { echo "missing $WASM: run round 4's build.sh routec-new"; exit 1; }
  rm -rf "$E/work/lib"; cp -r "$EV/lib" "$E/work/lib"
  sha256sum "$WASM" > "$E/work/lib.wasm.sha256"
  start=$(date +%s%N)
  (cd "$E/work/lib" && JAVA_HOME="$JDK17" $MVN_BUILD -Daprv.wasm="$WASM" \
     -DaltDeploymentRepository=spike::file://"$E/remote-repo" deploy) > "$E/work/lib-build.log" 2>&1
  echo "lib: $(( ($(date +%s%N) - start) / 1000000 )) ms wall for mvn deploy" | tee "$E/work/lib-time.txt"
  grep -E 'endive:.*:compile|Compiling classes|BUILD|Total time' "$E/work/lib-build.log"
  ;;
trap)
  rm -rf "$E/work/trap"; cp -r "$EV/trap" "$E/work/trap"
  wasm-tools parse "$EV/trap/src/main/wat/trap.wat" -o "$E/work/trap.wasm"
  (cd "$E/work/trap" && JAVA_HOME="$JDK17" $MVN_BUILD -Dtrap.wasm="$E/work/trap.wasm" \
     -DaltDeploymentRepository=spike::file://"$E/remote-repo" deploy) > "$E/work/trap-build.log" 2>&1
  grep -E 'BUILD|Total time' "$E/work/trap-build.log"
  ;;
consumer)
  rm -rf "$E/work/consumer" "$E/m2-consumer"; cp -r "$EV/consumer" "$E/work/consumer"
  (cd "$E/work/consumer" && JAVA_HOME="$JDK17" mvn -B -Dmaven.repo.local="$E/m2-consumer" \
     -Dspike.repo.url=file://"$E/remote-repo" package dependency:tree dependency:build-classpath \
     -Dmdep.outputFile=cp.txt) > "$E/work/consumer-build.log" 2>&1
  grep -E 'BUILD|Total time' "$E/work/consumer-build.log"
  ;;
*) echo "usage: build.sh lib|trap|consumer"; exit 2 ;;
esac
