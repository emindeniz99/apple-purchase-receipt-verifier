#!/bin/sh
# Spike only (2026-09-26). Primary sources behind the candidates: OpenSSL
# 4.0.2's own INSTALL.md and ec_curve.c (from the checked tarball), whether
# wasi-sdk's clang meets the nistp option's requirements, and how Debian
# and Fedora configure OpenSSL.
#   facts.sh > results/facts.txt
set -eu
. "$(dirname "$0")/env.sh"
T="$SCRATCH/dl/openssl-4.0.2.tar.gz"
echo "736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8  $T" | sha256sum -c - >/dev/null
X="$S/facts-src"; rm -rf "$X"; mkdir -p "$X"; tar -C "$X" -xzf "$T" openssl-4.0.2/INSTALL.md openssl-4.0.2/crypto/ec/ec_curve.c openssl-4.0.2/Configurations/10-main.conf
O="$X/openssl-4.0.2"
echo "## OpenSSL 4.0.2 INSTALL.md: enable-ec_nistp_64_gcc_128 and no-pic"
sed -n '/^### enable-ec_nistp_64_gcc_128/,/^### enable-egd/p' "$O/INSTALL.md" | grep -v '^### enable-egd'
sed -n '/^### no-pic/,/^### enable-pie/p' "$O/INSTALL.md" | grep -v '^### enable-pie'
echo "## crypto/ec/ec_curve.c: the curves whose EC_METHOD the option switches (lines naming the nistp methods)"
grep -n 'nistp224_method\|nistp256_method\|nistp384_method\|nistp521_method' "$O/crypto/ec/ec_curve.c" | grep -v s390x
echo "## Configurations/10-main.conf, linux-generic32: the release CFLAGS the baseline uses"
awk '/"linux-generic32" =>/,/^    },/' "$O/Configurations/10-main.conf" | grep -n 'CFLAGS\|release\|inherit'
echo "## wasi-sdk 34 clang, wasm32-wasip1: __SIZEOF_INT128__ = $(echo '__SIZEOF_INT128__' | "$WASI_SDK/bin/clang" --target=wasm32-wasip1 -E -x c - | tail -1); little-endian, unaligned loads allowed by the wasm spec"
printf 'unsigned __int128 m(unsigned long long a, unsigned long long b){return (unsigned __int128)a*b;}\n' > "$X/i128.c"
"$WASI_SDK/bin/clang" --target=wasm32-wasip1 -O2 -c "$X/i128.c" -o "$X/i128.o"
echo "a 64x64->128 multiply compiles to: $(wasm-tools print "$X/i128.o" | grep -oE 'call \$?[a-z_0-9]+|i64\.mul' | sort | uniq -c | tr '\n' ' ')(a compiler-rt helper call, not one instruction)"
rm -rf "$X"
echo "## Debian openssl 4.0.2-1, debian/rules (sources.debian.org)"
curl -sS -m 60 "https://sources.debian.org/data/main/o/openssl/4.0.2-1/debian/rules" | grep -n -B1 -A1 'ec_nistp_64_gcc_128'
echo "## Fedora rawhide openssl.spec (src.fedoraproject.org), architectures that set it"
curl -sS -m 60 https://src.fedoraproject.org/rpms/openssl/raw/rawhide/f/openssl.spec | grep -n -B3 'sslflags=enable-ec_nistp_64_gcc_128'
