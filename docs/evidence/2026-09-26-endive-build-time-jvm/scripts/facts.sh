#!/bin/sh
# Spike only (2026-09-26). What Endive is, from primary sources: Maven
# Central's metadata and POMs, and the project's own documentation
# (endive.run/llms-full.txt, the docs site as one file).
#   scripts/facts.sh > results/endive-facts.txt
set -eu
. "$(dirname "$0")/env.sh"
MC=https://repo1.maven.org/maven2
echo "# $(date -u +%F). Maven Central, group run.endive (the fork of com.dylibso.chicory)"
echo "## artifacts in the group"
curl -sS -m 60 "$MC/run/endive/" | sed -e 's/<[^>]*>//g' | grep -E '^[a-z].*/ ' | awk '{print $1}' | tr '\n' ' '; echo
for a in runtime wasm endive-compiler-maven-plugin build-time-compiler compiler wasi redline-runner-experimental; do
  sleep 2   # repo1 rate-limits bursts (HTTP 429)
  echo "$a: $(curl -sS -m 60 "$MC/run/endive/$a/maven-metadata.xml" | tr -d ' \n' | grep -oE '<release>[^<]*</release>|<lastUpdated>[^<]*</lastUpdated>' | sed 's/<[^>]*>//g' | tr '\n' ' ')(release, lastUpdated)"
done
sleep 2
echo "## last com.dylibso.chicory release: $(curl -sS -m 60 "$MC/com/dylibso/chicory/runtime/maven-metadata.xml" | tr -d ' \n' | grep -oE '<release>[^<]*</release>|<lastUpdated>[^<]*</lastUpdated>' | sed 's/<[^>]*>//g' | tr '\n' ' ')"
for p in "endive/$ENDIVE_VERSION/endive-$ENDIVE_VERSION.pom" "runtime/$ENDIVE_VERSION/runtime-$ENDIVE_VERSION.pom" "wasm/$ENDIVE_VERSION/wasm-$ENDIVE_VERSION.pom" "endive-compiler-maven-plugin/$ENDIVE_VERSION/endive-compiler-maven-plugin-$ENDIVE_VERSION.pom"; do
  sleep 2
  curl -sS -m 60 "$MC/run/endive/$p" > "$E/work/pom.xml.tmp"
  echo "## $p: non-test dependencies, licence, compiler release"
  python3 - "$E/work/pom.xml.tmp" <<'PY'
import re, sys
s = open(sys.argv[1], encoding="utf-8").read()
s = re.sub(r"<dependencyManagement>.*?</dependencyManagement>", "", s, flags=re.S)
s = re.sub(r"<build>.*?</build>", "", s, flags=re.S)
deps = re.findall(r"<dependency>(.*?)</dependency>", s, re.S)
out = []
for d in deps:
    g = re.search(r"<groupId>(.*?)</groupId>", d); a = re.search(r"<artifactId>(.*?)</artifactId>", d)
    sc = re.search(r"<scope>(.*?)</scope>", d)
    if sc and sc.group(1) == "test":
        continue
    out.append(f"{g.group(1) if g else '?'}:{a.group(1)}{':' + sc.group(1) if sc else ''}")
print("dependencies:", ", ".join(out) or "none")
lic = re.findall(r"<license>\s*<name>(.*?)</name>", s)
if lic: print("licence:", ", ".join(lic))
rel = re.search(r"<maven.compiler.release>(.*?)</maven.compiler.release>", s)
if rel: print("maven.compiler.release:", rel.group(1))
PY
done
rm -f "$E/work/pom.xml.tmp"
sleep 2
curl -sS -m 60 https://endive.run/llms-full.txt > "$E/work/llms-full.txt"
echo "## endive.run/llms-full.txt ($(wc -c < "$E/work/llms-full.txt") bytes, sha256 $(sha256sum "$E/work/llms-full.txt" | cut -c1-16)): quoted lines"
grep -nE 'requires \*\*Java 11\*\*|without post-compilation verification|interpreterFallback \(Default|build time compiler will FAIL|not thread-safe|ByteArrayMemory`: An optimized|NameSectionMethodPrefixer|fewer runtime dependencies|Bytecode is always generated alongside|workaround only activates on Java 17|integrated\]\(https://github.com/openjdk' "$E/work/llms-full.txt" | cut -c1-260
