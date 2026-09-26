#!/bin/sh
# Spike only (2026-09-26). Primary-source facts for wasmtime-py: PyPI's JSON
# API (versions, dates, requires_python, every file of 49.0.0), the git log
# of bytecodealliance/wasmtime-py, what the py3-none-any wheel and the sdist
# contain, the glibc symbol versions the Linux libraries need, and which
# wheel pip picks on platforms without one.
#   facts.sh > results/facts.txt
set -eu
. "$(dirname "$0")/env.sh"
F="$S/facts"; rm -rf "$F"; mkdir -p "$F"
echo "# fetched $(date -u +%FT%TZ)"
curl -sS https://pypi.org/pypi/wasmtime/json -o "$F/pypi.json"
python3 - "$F/pypi.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
i = d["info"]
print(f"PyPI wasmtime: latest {i['version']}, requires_python {i['requires_python']}, license {i.get('license_expression') or i.get('license')}, source {i['project_urls'].get('Source Code')}")
rel = d["releases"]
dated = sorted((min(f["upload_time_iso_8601"] for f in fs)[:10], v) for v, fs in rel.items() if fs)
print("last 12 releases:", ", ".join(f"{v} ({t})" for t, v in dated[-12:]))
print(f"files of {i['version']}:")
for f in d["urls"]:
    print(f"  {f['filename']}  {f['size']} bytes  {f['upload_time_iso_8601'][:10]}")
PY
git -c gc.auto=0 clone -q --filter=blob:none --no-checkout https://github.com/bytecodealliance/wasmtime-py "$F/git"
echo "git: $(git -C "$F/git" log --since=2025-09-26 --oneline | wc -l) commits by $(git -C "$F/git" log --since=2025-09-26 --format=%an | sort -u | wc -l) authors in the 12 months to 2026-09-26; latest:"
git -C "$F/git" log -3 --format='  %cs %s' | cut -c1-110
URL=$(python3 -c "import json;d=json.load(open('$F/pypi.json'));print([f['url'] for f in d['urls'] if f['filename'].endswith('none-any.whl')][0])")
curl -sS -o "$F/any.whl" "$URL"
echo "py3-none-any wheel, native files: $(python3 -m zipfile -l "$F/any.whl" | awk '{print $1}' | grep -E '\.(dll|so|dylib)$' | tr '\n' ' ')"
URL=$(python3 -c "import json;d=json.load(open('$F/pypi.json'));print([f['url'] for f in d['urls'] if f['filename'].endswith('.tar.gz')][0])")
curl -sS -o "$F/sdist.tgz" "$URL"
echo "sdist: native files: $(tar tzf "$F/sdist.tgz" | grep -cE '\.(dll|so|dylib)$'); build backend downloads the C API: $(tar xzf "$F/sdist.tgz" -O --wildcards '*/ci/download-wasmtime.py' | grep -o 'https://github.com/bytecodealliance/wasmtime/releases/download/' | head -1)"
echo "loader (wasmtime/_ffi.py of 49.0.0): $(tar xzf "$F/sdist.tgz" -O --wildcards '*/wasmtime/_ffi.py' | grep -E "raise RuntimeError" | sed 's/^ *//' | tr '\n' ' ')"
for tag in manylinux1_x86_64 manylinux2014_aarch64; do
  URL=$(python3 -c "import json;d=json.load(open('$F/pypi.json'));print([f['url'] for f in d['urls'] if '$tag' in f['filename']][0])")
  curl -sS -o "$F/w.whl" "$URL"; rm -rf "$F/w"; python3 -m zipfile -e "$F/w.whl" "$F/w"
  so=$(ls "$F"/w/wasmtime/linux-*/_libwasmtime.so)
  echo "$tag wheel: highest glibc symbol version its library needs: $(objdump -T "$so" | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -1)"
done
echo "pip's choice on platforms with no wasmtime wheel (pip download --platform ... --only-binary=:all:):"
for p in manylinux2014_ppc64le manylinux2014_s390x manylinux2014_i686 manylinux2014_armv7l linux_armv6l win32 musllinux_1_2_riscv64; do
  python3 -m pip download --quiet --disable-pip-version-check --no-deps --only-binary=:all: --platform "$p" --python-version 3.12 --implementation cp --dest "$F/dl-$p" wasmtime==49.0.0 > /dev/null 2>&1 || true
  echo "  $p -> $(ls "$F/dl-$p" 2>/dev/null || echo none)"
done
echo "Wasmtime's own C API release assets for v49.0.0, .tar.xz (HTTP status of the download URL; Windows ships .zip):"
for a in x86_64-linux aarch64-linux x86_64-musl aarch64-musl s390x-linux riscv64gc-linux i686-linux armv7-linux powerpc64le-linux x86_64-macos aarch64-macos; do
  echo "  $a: $(curl -sSIL -o /dev/null -w '%{http_code}' "https://github.com/bytecodealliance/wasmtime/releases/download/v49.0.0/wasmtime-v49.0.0-$a-c-api.tar.xz")"
done
