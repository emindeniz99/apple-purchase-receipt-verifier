#!/bin/sh
# Start-up and speed of the host layer: compile, first and later instances, and
# calls per second at 1 and 4 threads for a genuine g5 receipt and a JWS. Run on
# an otherwise idle machine, one mode at a time. Needs corpus.sh's build.
#   REPO=... SCRATCH=... G1=<folder with calls/> sh speed.sh
set -eu
. "$(dirname "$0")/env.sh"
: "${G1:?the folder with calls/}"
R="dotnet $S/corpusrun/ApplePurchaseReceiptVerifier.CorpusRun.dll"
echo "load: $(cut -d' ' -f1-3 /proc/loadavg); cpus: $(nproc)"
$R startup
$R speed verify-receipt "$G1/calls/cases.pinned.jsonl" receipt/verify-genuine-sandbox-g5-against-apple-roots 8 1 4
$R speed verify-signed-data "$G1/calls/cases.pinned.jsonl" transaction/verify-shared-sandbox 8 1 4
echo "load: $(cut -d' ' -f1-3 /proc/loadavg)"
