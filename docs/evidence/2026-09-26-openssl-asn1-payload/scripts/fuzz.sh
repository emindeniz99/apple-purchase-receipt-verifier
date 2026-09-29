#!/bin/sh
# Task 4, and the differential check behind task 3's "identical or explain".
#
#   verify-receipt  the repository's own target (rust/fuzz, unchanged) over
#                   the no-asn1 tree: CMS path, payload through OpenSSL's
#                   ASN.1 templates, no prescan. OpenSSL 4.0.2 is the
#                   follow-up's AddressSanitizer + libFuzzer-coverage build
#                   ($SCRATCH/inst/openssl-4.0.2-fuzz). Seeded with round 3's
#                   receipt corpus, the follow-up's, and the seed set.
#   payload-diff    fuzz/payload-diff.rs: the old reader (asn1.rs, compiled
#                   in from $REPO/rust/src unchanged) against the new one on
#                   raw payloads; differences are filed by signature in
#                   $C/fuzz/diff/, never a crash. Seeded with the payloads of
#                   every receipt fixture, their BER re-spellings, and the
#                   payloads of the round-3 receipt corpus.
#
# The one exception to "rustc 1.98.1 for everything": cargo-fuzz passes
# -Zsanitizer=address and the sancov passes, which stable rustc refuses, so
# this uses the nightly in $SCRATCH/rustup (1.100.0-nightly 2026-09-25), as
# rounds 2 and 3 did. payload.c is built by cc without sanitizer flags; it
# holds only template tables and two functions returning a static.
#
#   scripts/fuzz.sh build [target]
#   scripts/fuzz.sh seeds                      payload seeds for payload-diff
#   scripts/fuzz.sh run <target> <seconds>
#   scripts/fuzz.sh replay                     the differential inputs through the final harness
#   ANY=1 scripts/fuzz.sh build payload-diff && ANY=1 scripts/fuzz.sh replay
#                                              the same against the payload-any walk
set -eu
. "$(dirname "$0")/env.sh"
FZ="$C/fuzz"; mkdir -p "$FZ"
case "$1" in
build)
  sed -n '/^adapter()/,/^}/p;/^tree()/,/^}/p' "$EV/scripts/build.sh" > "$FZ/fns.sh"
  . "$FZ/fns.sh"
  adapter fuzz 1; tree fuzz fuzz 1
  T="$SCRATCH/tree-fuzz"
  mkdir -p "$T/fixtures"; cp -r "$REPO/fixtures/generated" "$T/fixtures/"
  sed -i 's#^\[dependencies.apple-purchase-receipt-verifier\]#&\nfeatures = ["substrate-cms"]#' "$T/rust/fuzz/Cargo.toml"
  mkdir -p "$T/rust/fuzz/old"
  for f in asn1 clock datetime error receipt_payload; do cp "$REPO/rust/src/$f.rs" "$T/rust/fuzz/old/"; done
  cp "$EV/fuzz/payload-diff.rs" "$T/rust/fuzz/fuzz_targets/"
  # payload-diff reads the adapter's refusal reasons (feature payload-diagnostics,
  # through this crate's own `diagnostics` feature); verify-receipt is built without.
  printf '\n[[bin]]\nname = "payload-diff"\npath = "fuzz_targets/payload-diff.rs"\ntest = false\ndoc = false\nbench = false\nrequired-features = ["diagnostics"]\n' >> "$T/rust/fuzz/Cargo.toml"
  sed -i "s#^\[dependencies\]#&\naprv-security-openssl = { path = \"$C/adapter-fuzz/security-openssl\" }#" "$T/rust/fuzz/Cargo.toml"
  printf '\n[features]\ndiagnostics = ["aprv-security-openssl/payload-diagnostics"]\n' >> "$T/rust/fuzz/Cargo.toml"
  cd "$T/rust"
  export RUSTUP_TOOLCHAIN=nightly PATH="$CARGO_HOME/bin:$PATH"
  for t in ${2:-verify-receipt payload-diff}; do
    f=""; [ "$t" = payload-diff ] && f="--features diagnostics${ANY:+,apple-purchase-receipt-verifier/substrate-payload-any}"
    OPENSSL_DIR="$SCRATCH/inst/openssl-4.0.2-fuzz" OPENSSL_STATIC=1 \
      cargo fuzz build --sanitizer address --target-dir "$SCRATCH/target-fuzz" $f "$t"
  done
  cp "$T/rust/fuzz/Cargo.lock" "$FZ/Cargo.lock"
  ;;
seeds)
  S="$FZ/seeds-payload"; rm -rf "$S"; mkdir -p "$S"
  cp "$C"/ber/der/* "$C"/ber/var/* "$S/"
  F="$REPO/fixtures"
  "$C/art/spike_payload-new" --dump="$S" "$F"/public-receipts/*.b64 "$F"/apple-official/xcode/xcode-app-receipt-* \
    "$F"/generated/receipt*.der > /dev/null
  # Payloads of the round-3 and follow-up receipt corpora (their inputs are
  # whole CMS blobs; the ones that are not a signedData are skipped).
  find "$SCRATCH/cms/fuzz/corpus-verify-receipt" "$SCRATCH/fu/fuzz/corpus-ossl-verify-receipt" -type f -print0 |
    xargs -0 -n 400 "$C/art/spike_payload-new" --der --dump="$S" > /dev/null
  ls "$S" | wc -l
  ;;
replay)
  # Every input the differential campaign kept (its corpus, its seeds and
  # every filed difference) run once through the payload-diff binary as
  # built now, into a fresh filing directory: the classification in
  # results/diff-classes.txt comes from this pass.
  L="$FZ/replay-list"; find "$FZ/corpus-payload-diff" "$FZ/seeds-payload" "$FZ/diff" -type f ! -name '*.txt' > "$L"
  mkdir -p "$FZ/replay-in"; rm -rf "$FZ/replay-in"/*; i=0
  while read -r f; do i=$((i + 1)); cp "$f" "$FZ/replay-in/$i"; done < "$L"
  OUT="$FZ/diff-final${ANY:+-any}"; rm -rf "$OUT"; mkdir -p "$OUT"
  APRV_DIFF_DIR="$OUT" ASAN_OPTIONS=detect_leaks=1 \
    "$SCRATCH/target-fuzz/x86_64-unknown-linux-gnu/release/payload-diff" -runs=0 "$FZ/replay-in" \
    > "$FZ/log-replay.txt" 2>&1 || echo "exit $?" >> "$FZ/log-replay.txt"
  echo "replayed $(ls "$FZ/replay-in" | wc -l) inputs; $(ls "$OUT" | wc -l) signatures"
  ;;
run)
  T="$2"; SECS="$3"
  PF="$SCRATCH/fu/fuzz"; R3="$SCRATCH/cms/fuzz"
  case "$T" in
    verify-receipt) S="$R3/corpus-verify-receipt $PF/corpus-ossl-verify-receipt $PF/seeds-receipt" ;;
    payload-diff) S="$FZ/seeds-payload"; export APRV_DIFF_DIR="$FZ/diff"; mkdir -p "$APRV_DIFF_DIR" ;;
  esac
  BIN="$SCRATCH/target-fuzz/x86_64-unknown-linux-gnu/release/$T"
  CO="$FZ/corpus-$T"; A="$FZ/artifacts-$T"; mkdir -p "$CO" "$A"
  # New units go to $CO only; the seed directories are read.
  ASAN_OPTIONS=detect_leaks=1:allocator_may_return_null=0 \
    "$BIN" "$CO" $S -max_total_time="$SECS" -timeout=10 -rss_limit_mb=2048 \
    -max_len=65536 -print_final_stats=1 -artifact_prefix="$A/" \
    > "$FZ/log-$T.txt" 2>&1 || echo "exit $?" >> "$FZ/log-$T.txt"
  ;;
esac
