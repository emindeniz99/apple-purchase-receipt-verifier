#!/usr/bin/env bash
# The classpath guard (MIGRATION.md step 3.5): the main artifact and the
# -wasm artifact must never run side by side.
#
#   java-wasm/scripts/classpath-guard.sh      from any directory
#
# 1. Maven: both real jars in one class loader, in both orders, make
#    Verifier.create throw the guard's IllegalStateException; each alone
#    gets past it; every public member of the main jar exists in the -wasm
#    jar (the classpath-guard profile's ClasspathGuardJarsIT).
# 2. Gradle: both artifacts deployed to a file repository, and a build that
#    asks for both must fail at resolution on their shared capability
#    (java-wasm/src/it/gradle-capability).
#
# Needs a JDK 11 or later for Maven, `gradle` on PATH, and the module at
# java-wasm/src/main/wasm/aprv.wasm matching its pin (the build checks it;
# CI puts it there with .github/scripts/place-module.sh). Only the guard's
# own test runs here: the unit tests run in java-wasm-endive.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mvn -B -f "$repo_root/java/pom.xml" package -DskipTests
mvn -B -f "$repo_root/java-wasm/pom.xml" verify -Pclasspath-guard \
  -Dtest=NONE -Dsurefire.failIfNoSpecifiedTests=false

deploy="$work/repo"
mvn -B -f "$repo_root/java/pom.xml" deploy -DskipTests -DaltDeploymentRepository="guard::file://$deploy"
mvn -B -f "$repo_root/java-wasm/pom.xml" deploy -DskipTests -DaltDeploymentRepository="guard::file://$deploy"
version="$(cat "$repo_root/version.txt")"
if gradle -q -p "$repo_root/java-wasm/src/it/gradle-capability" \
    -PaprvRepo="file://$deploy" -PaprvVersion="$version" resolveBoth > "$work/gradle.txt" 2>&1; then
  cat "$work/gradle.txt"
  echo "classpath-guard: Gradle resolved both artifacts; the capability conflict did not fire" >&2
  exit 1
fi
cat "$work/gradle.txt"
if ! grep -q "apple-purchase-receipt-verifier" "$work/gradle.txt" || ! grep -qi "capability" "$work/gradle.txt"; then
  echo "classpath-guard: Gradle failed, but not on the capability conflict" >&2
  exit 1
fi
echo "classpath-guard: both jars on one classpath fail, and Gradle refuses both"
