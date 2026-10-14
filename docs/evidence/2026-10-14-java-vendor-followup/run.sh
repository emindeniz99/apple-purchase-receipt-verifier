#!/usr/bin/env bash
set -euo pipefail
: "${REPO:?Set REPO to the repository root}"
: "${SCRATCH:?Set SCRATCH to a directory outside the repository}"
: "${JAVA_HOME:?Set JAVA_HOME to Temurin 17}"
export PATH="$JAVA_HOME/bin:$PATH"
EVIDENCE="$REPO/docs/evidence/2026-10-14-java-vendor-followup"
mkdir -p "$SCRATCH/tree" "$SCRATCH/classes"
if [[ "${1:-}" != --probe-only ]]; then
python3 - "$SCRATCH/settings.xml" <<'PY'
import os, sys, urllib.parse, xml.etree.ElementTree as ET
settings = ET.Element('settings')
ET.SubElement(settings, 'localRepository').text = os.path.join(os.environ['SCRATCH'], 'm2')
proxy = os.environ.get('HTTPS_PROXY')
if proxy:
    parsed = urllib.parse.urlparse(proxy)
    entry = ET.SubElement(ET.SubElement(settings, 'proxies'), 'proxy')
    for key, value in [('id', 'session'), ('active', 'true'), ('protocol', 'http'),
                       ('host', parsed.hostname), ('port', str(parsed.port or 80))]:
        ET.SubElement(entry, key).text = value
ET.ElementTree(settings).write(sys.argv[1], encoding='unicode')
PY
export MAVEN_ARGS="--settings $SCRATCH/settings.xml"
# Use the executor's CA store when its outbound proxy terminates TLS.
if [[ -f /etc/ssl/certs/java/cacerts ]]; then
  export MAVEN_OPTS="${MAVEN_OPTS:-} -Djavax.net.ssl.trustStore=/etc/ssl/certs/java/cacerts"
fi
# Build an unmodified copy so Maven outputs never enter the working tree.
git -C "$REPO" ls-files -z java fixtures certs | tar -C "$REPO" --null -T - -cf - | tar -x -C "$SCRATCH/tree"
java -version > "$SCRATCH/runtime.log" 2>&1
mvn -version >> "$SCRATCH/runtime.log" 2>&1
cd "$SCRATCH/tree"
mvn -B -f java/pom.xml verify > "$SCRATCH/verify.log" 2>&1
mvn -B -f java/pom.xml dependency:build-classpath -Dmdep.outputFile="$SCRATCH/classpath.txt" > "$SCRATCH/classpath.log" 2>&1
fi
CP="$SCRATCH/tree/java/target/classes:$SCRATCH/tree/java/target/test-classes:$(cat "$SCRATCH/classpath.txt")"
if [[ -f "$EVIDENCE/VendorProbe.java" ]]; then
  javac --release 8 -cp "$CP" -d "$SCRATCH/classes" "$EVIDENCE/VendorProbe.java"
  java -Xmx512m -cp "$SCRATCH/classes:$CP" io.github.emindeniz99.applepurchasereceiptverifier.VendorProbe "$REPO" > "$SCRATCH/probe.log"
fi
