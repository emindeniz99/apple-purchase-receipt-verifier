#!/usr/bin/env bash
# Runs one Jazzer target for a fixed budget, seeded from the shared fixtures.
#
#   ./run.sh <target> [seconds]      default 60
#   ./run.sh all [seconds]
#   ./run.sh list
#
# Jazzer is libFuzzer with a JVM on top, so it takes several corpus directories
# and writes new units only to the first: the shared fixtures seed every run
# without being copied into java/. A crasher lands under artifacts/<target>/;
# reduce it and turn it into a test under ../src/test, where it runs on every
# JDK in the matrix rather than only where a fuzzer is installed.
#
# Environment:
#   MVN         maven binary                          (default mvn)
#   MVN_ARGS    extra maven flags, e.g. -o            (default empty)
#   JOBS        parallel targets for `all`            (default 1)
#   MAX_LEN     libFuzzer -max_len                    (default 65536)
#   HEAP        JVM max heap for the fuzzed process   (default 2g)
#   COVERAGE    non-empty: write artifacts/<t>.coverage.txt at the end
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
fixtures="$root/fixtures"

# Jazzer's standalone driver, from Maven Central rather than the GitHub
# release: it is the same all-in-one jar (the libFuzzer driver and the
# fuzzed-data-provider natives for linux/macOS/Windows on x86-64 and aarch64
# are inside it), Central is the mirror already reachable wherever this
# project's Maven build runs, and the coordinate makes the pin checkable
# against the publisher's own checksum file.
#
# Two coordinates, not one: `jazzer` carries the driver, the agent and the
# natives, but the half-dozen `com.code_intelligence.jazzer.api` classes the
# driver reflects over live only in `jazzer-api`. Without it the run dies at
# startup with NoClassDefFoundError on AutofuzzConstructionException, before
# the first execution and with nothing to say it was a packaging problem.
jazzer_version="0.30.0"
jazzer_central="https://repo.maven.apache.org/maven2/com/code-intelligence"
jazzer_jar="$here/.jazzer/jazzer-${jazzer_version}.jar"
jazzer_api_jar="$here/.jazzer/jazzer-api-${jazzer_version}.jar"
jazzer_sha256="8bdeac017bcd3d9473c9772fac62111c4df830188571def1d001a1b743a62b2f"
jazzer_api_sha256="d36a725cfedcb7f3590206866cc2836f84d12afccf7c98912f5c720e4d2208d7"

all_targets=(receipt receipt-base64 jws endpoint-json readers)

target_class() {
  case "$1" in
    receipt)        echo io.github.emindeniz99.applepurchasereceiptverifier.fuzz.FuzzReceiptDer ;;
    receipt-base64) echo io.github.emindeniz99.applepurchasereceiptverifier.fuzz.FuzzReceiptBase64 ;;
    jws)            echo io.github.emindeniz99.applepurchasereceiptverifier.fuzz.FuzzJws ;;
    endpoint-json)  echo io.github.emindeniz99.applepurchasereceiptverifier.fuzz.FuzzEndpointJson ;;
    readers)        echo io.github.emindeniz99.applepurchasereceiptverifier.fuzz.FuzzReaders ;;
    *) echo "unknown target: $1" >&2; exit 2 ;;
  esac
}

seeds_for() {
  case "$1" in
    receipt)        echo "$fixtures/generated" "$fixtures/apple-official/certs" ;;
    receipt-base64) echo "$fixtures/generated/receipt-b64" "$fixtures/public-receipts" "$fixtures/apple-official/xcode" ;;
    jws)            echo "$fixtures/generated" "$fixtures/apple-official/mock_signed_data" "$fixtures/apple-official/xcode" ;;
    endpoint-json)  echo "$here/.seeds/endpoint-json" ;;
    readers)        echo "$fixtures/generated" "$fixtures/apple-official/mock_signed_data" ;;
  esac
}

fetch_one() {
  local url="$1" path="$2" expected="$3" actual
  if [ -f "$path" ]; then
    return
  fi
  mkdir -p "$(dirname "$path")"
  echo "fetching $(basename "$path")"
  curl -fsSL --retry 3 -o "$path.tmp" "$url"
  actual="$(sha256sum "$path.tmp" | cut -d' ' -f1)"
  if [ "$actual" != "$expected" ]; then
    rm -f "$path.tmp"
    echo "$(basename "$path"): sha256 mismatch, expected $expected, got $actual" >&2
    exit 1
  fi
  mv "$path.tmp" "$path"
}

fetch_jazzer() {
  fetch_one "$jazzer_central/jazzer/${jazzer_version}/jazzer-${jazzer_version}.jar" \
    "$jazzer_jar" "$jazzer_sha256"
  fetch_one "$jazzer_central/jazzer-api/${jazzer_version}/jazzer-api-${jazzer_version}.jar" \
    "$jazzer_api_jar" "$jazzer_api_sha256"
}

# The library jar plus its runtime dependencies, then the harness compiled
# against them by a modern javac. The targets are NOT built by the project's
# own Maven build: they are not in src/, the pom gains no fuzzing dependency,
# and nothing here can reach the published artifact or the `java` matrix.
# They are also not held to the pom's --release 8 floor, because they are
# never shipped -- see README.md.
build() {
  local mvn="${MVN:-mvn}"
  # shellcheck disable=SC2086
  "$mvn" ${MVN_ARGS:-} -B -q -f "$root/java/pom.xml" -DskipTests package
  # shellcheck disable=SC2086
  "$mvn" ${MVN_ARGS:-} -B -q -f "$root/java/pom.xml" dependency:build-classpath \
    -DincludeScope=runtime -Dmdep.outputFile="$here/.build/deps.txt"

  local jar
  jar="$(ls "$root"/java/target/apple-purchase-receipt-verifier-*.jar | grep -v -e -sources -e -javadoc | head -n 1)"
  classpath="$jar:$(cat "$here/.build/deps.txt")"

  rm -rf "$here/.build/classes"
  mkdir -p "$here/.build/classes"
  find "$here/src" -name '*.java' -print0 | xargs -0 \
    javac -encoding UTF-8 -nowarn -d "$here/.build/classes" -cp "$classpath"
  classpath="$here/.build/classes:$classpath"
}

# No fixture is a verifyReceipt request body, so the endpoint target's seeds
# are built at run time from the shared base64 receipts into a gitignored
# directory -- rather than committing a second copy of a 7 KB receipt here,
# where it could drift from the shared one.
generate_seeds() {
  local out="$here/.seeds/endpoint-json"
  rm -rf "$here/.seeds"
  mkdir -p "$out"
  local n=0 file
  for file in "$fixtures"/public-receipts/*.b64 "$fixtures"/generated/receipt-b64/*.txt; do
    [ -f "$file" ] || continue
    n=$((n + 1))
    printf '{"receipt-data":"%s","password":"secret"}' \
      "$(tr -d '\n\r' < "$file")" > "$out/receipt-$n.json"
  done
  printf '{"receipt-data":"","exclude-old-transactions":true}' > "$out/empty.json"
  printf '[]' > "$out/array.json"
  cp "$fixtures/generated/manifest.json" "$out/manifest.json"
}

run_one() {
  local name="$1" seeds
  read -r -a seeds <<< "$(seeds_for "$name")"
  mkdir -p "$here/corpus/$name" "$here/artifacts/$name"

  local coverage=()
  if [ -n "${COVERAGE:-}" ]; then
    coverage=(--coverage_report="$here/artifacts/$name.coverage.txt")
  fi

  # -cp rather than the driver's own --cp: that flag is documented "native
  # launcher only" and is silently ignored when Jazzer is started from the
  # standalone jar, which leaves the target class not-found on a class path
  # holding nothing but jazzer itself.
  echo "=== $name for ${seconds}s ==="
  java "-Xmx${HEAP:-2g}" -cp "$jazzer_jar:$jazzer_api_jar:$classpath" com.code_intelligence.jazzer.Jazzer \
    --target_class="$(target_class "$name")" \
    --instrumentation_includes='io.github.emindeniz99.**:org.bouncycastle.**:com.fasterxml.jackson.**' \
    --instrumentation_excludes='io.github.emindeniz99.applepurchasereceiptverifier.fuzz.**' \
    --reproducer_path="$here/artifacts/$name" \
    "${coverage[@]}" \
    "$here/corpus/$name" "${seeds[@]}" \
    -max_total_time="$seconds" \
    -max_len="${MAX_LEN:-65536}" \
    -rss_limit_mb=0 \
    -timeout=25 \
    -print_final_stats=1 \
    -artifact_prefix="$here/artifacts/$name/"
}

target="${1:?usage: run.sh <target>|all|list [seconds]}"
seconds="${2:-60}"

if [ "$target" = list ]; then
  printf '%s\n' "${all_targets[@]}"
  exit 0
fi

fetch_jazzer
build
generate_seeds

if [ "$target" != all ]; then
  run_one "$target"
  exit 0
fi

jobs="${JOBS:-1}"
if [ "$jobs" -le 1 ]; then
  for name in "${all_targets[@]}"; do run_one "$name"; done
  exit 0
fi

# One log per target: interleaved libFuzzer output is unreadable.
pids=()
for name in "${all_targets[@]}"; do
  run_one "$name" > "$here/artifacts/$name.log" 2>&1 &
  pids+=("$!")
  while [ "$(jobs -rp | wc -l)" -ge "$jobs" ]; do wait -n; done
done
status=0
for pid in "${pids[@]}"; do wait "$pid" || status=1; done
for name in "${all_targets[@]}"; do
  echo "=== $name ==="; tail -n 20 "$here/artifacts/$name.log"
done
exit "$status"
