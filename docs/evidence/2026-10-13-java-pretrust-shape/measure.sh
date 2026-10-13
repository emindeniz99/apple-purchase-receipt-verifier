#!/bin/sh
# Usage: measure.sh JAVA MAIN_CLASSES TEST_CLASSES PROBE_CLASSES DEPENDENCIES
# Runs each probe shape in a fresh JVM (each probe repeats its own calls)
# and prints the probes' output.
set -u
j=$1
cp="$4:$2:$3:$5"
p=io.github.emindeniz99.applepurchasereceiptverifier
run() { "$j" -cp "$cp" "$p.$@" 2>&1 | grep -v JAVA_TOOL_OPTIONS; }
for args in "subject 30" "issuer 30" "spki 30" "sigalg 30" "subject 50" "san 30" "widerdn 100"; do
  run ShapeProbe $args 2290000
done
run ShapeProbe jws 30 143000
run ShapeProbe signedattrs 30 2290000
run ShapeProbe signerparams 30 2290000
# The signer's serial and issuer RDN count, one and four SignerInfos.
run SidIssuerProbe 30 2290000 1 1
run SidIssuerProbe 30 2290000 4 1
for salt in 32 1000000000 2147483647; do
  run BagPssProbe $salt
  run JwsPssRsaProbe $salt
done
