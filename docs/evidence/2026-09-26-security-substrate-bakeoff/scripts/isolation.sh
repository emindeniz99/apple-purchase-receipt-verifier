#!/bin/sh
# Trust-store isolation, per built variant. Plants the chains' real root in
# SSL_CERT_FILE and SSL_CERT_DIR, points OPENSSL_CONF (and the OpenSSL 3+
# module and engine variables) at hostile files, pins an unrelated root,
# and runs c/run1.c under strace. Expected: code 4 for both inputs, 0 for
# the controls, and no open/stat of any planted or default path, no socket.
#
#   REPO=... SCRATCH=... scripts/isolation.sh <variant>...
set -eu
: "${REPO:?}" "${SCRATCH:?}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
PY="${PY:-python3}"
ISO="$SCRATCH/iso"
rm -rf "$ISO"; mkdir -p "$ISO"
"$PY" "$SPIKE/py/gen_isolation.py" "$ISO"
for v in "$@"; do
  LIB="$SCRATCH/target-$v/release"
  cc -O1 -g -I"$REPO/rust/ffi/include" "$SPIKE/c/run1.c" -L"$LIB" \
    -lapple_purchase_receipt_verifier_ffi -Wl,-rpath,"$LIB" -o "$ISO/run1-$v"
  for case in "receipt $ISO/receipt.der com.example.substrate $ISO/pinned-other.der" \
              "jws $ISO/transaction.jws com.example.app $ISO/pinned-other.der" \
              "receipt $ISO/receipt.der com.example.substrate $ISO/receipt-root.der" \
              "jws $ISO/transaction.jws com.example.app $ISO/jws-root.der"; do
    set -- $case
    kind=$1 root=$(basename "$4")
    trace="$ISO/strace-$v-$kind-$root.txt"
    out=$(env -i SSL_CERT_FILE="$ISO/ambient.pem" SSL_CERT_DIR="$ISO/certdir" \
      OPENSSL_CONF="$ISO/openssl.cnf" OPENSSL_MODULES="$ISO/certdir" OPENSSL_ENGINES="$ISO/certdir" \
      strace -f -qq -e trace=%file,%network -o "$trace" "$ISO/run1-$v" "$@")
    # Every syscall line that names something other than the loader, libc,
    # the binary, the variant's own .so and the two input files.
    other=$(grep -v -e "$ISO/run1-$v" -e "$LIB/" -e '/etc/ld.so' -e '/lib/x86_64-linux-gnu/' \
      -e '^[0-9]* *execve(' -e "\"$2\"" -e "\"$4\"" -e '+++ exited' "$trace" || true)
    n_other=$(printf '%s' "$other" | grep -c . || true)
    net=$(grep -c -E 'socket\(|connect\(' "$trace" || true)
    echo "$v $kind pinned=$root -> code ${out%% *}, other file syscalls $n_other, network syscalls $net"
    [ -z "$other" ] || printf '%s\n' "$other" | sed "s#$ISO#\$ISO#g; s/^/    /" | head -8
  done
done
