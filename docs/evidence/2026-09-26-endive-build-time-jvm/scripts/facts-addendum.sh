#!/bin/sh
# Facts checked after the spike, for R12 and R18 (2026-09-26):
#  1. Endive's own description and Java floor, from its docs site.
#  2. Byte order in Endive's two memory classes (big-endian JVMs).
#  3. Which platforms ship a Java 8, and a Java 11+, today.
# Usage: RUNTIME_JAR=<run.endive:runtime:1.1.0 jar> JAVAP=<javap> scripts/facts-addendum.sh
set -eu
: "${RUNTIME_JAR:?path to runtime-1.1.0.jar}"; : "${JAVAP:=javap}"
echo "# endive.run/llms-full.txt"
curl -sSL https://endive.run/llms-full.txt | grep -m1 -E '^> Endive is'
curl -sSL https://endive.run/llms-full.txt | grep -m1 -E 'requires \*\*Java 11\*\*'
echo "# ByteOrder in the memory classes of $(basename "$RUNTIME_JAR")"
for c in ByteBufferMemory ByteArrayMemory; do
  printf '%s: ' "$c"
  "$JAVAP" -c -p -cp "$RUNTIME_JAR" "run.endive.runtime.$c" | grep -oE 'ByteOrder\.[A-Z_]+' | sort | uniq -c | tr '\n' ' '
  echo
done
echo "# Temurin (api.adoptium.net), os/arch per feature release"
for v in 8 11 17 21 25; do
  printf 'Temurin %s: ' "$v"
  curl -sS "https://api.adoptium.net/v3/assets/latest/$v/hotspot?image_type=jdk&vendor=eclipse" |
    python3 -c 'import json,sys; print(sorted({(a["binary"]["os"],a["binary"]["architecture"]) for a in json.load(sys.stdin)}))'
done
echo "# Azul Zulu 8 (api.azul.com), os/arch from package names"
curl -sS "https://api.azul.com/metadata/v1/zulu/packages/?java_version=8&release_status=ga&availability_types=CA&latest=true&page_size=1000" |
  python3 -c 'import json,re,sys
s=set()
for p in json.load(sys.stdin):
    m=re.search(r"-(linux_musl|linux|macosx|win|solaris)_([a-z0-9_]+)\.(tar\.gz|zip|msi|dmg|deb|rpm|apk)",p["name"])
    if m: s.add((m.group(1),m.group(2)))
print(sorted(s))'
echo "# Alpine openjdk8 package, edge"
curl -sS "https://pkgs.alpinelinux.org/packages?name=openjdk8&branch=edge&repo=&arch=&maintainer=" |
  python3 -c 'import html,re,sys
s=sys.stdin.read(); a=[]
for r in re.findall(r"<tr>(.*?)</tr>",s,flags=re.S):
    t=[html.unescape(re.sub(r"<[^>]+>","",c)).strip() for c in re.findall(r"<td[^>]*>(.*?)</td>",r,flags=re.S)]
    if len(t)>6: a.append(t[6])
print(sorted(a))'
