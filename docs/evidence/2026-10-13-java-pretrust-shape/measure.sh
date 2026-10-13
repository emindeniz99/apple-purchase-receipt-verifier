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
# Review 5's probes, added after results/before-* and after-* were made;
# their output is results/review-*.txt. The EXTERNAL data value descriptor:
run ExternalDescriptorProbe 30
run ExternalSignerParamsProbe
run SkiSignerInfoProbe external 3
# The residual costs: nested SEQUENCEs of about 2.1 MB, the
# subjectKeyIdentifier amplifier over them, and flat shapes.
for args in "1 700000 key" "30 23300 key" "50 14000 key" "55 13000 key" "55 6500 label"; do
  run NestedSequenceProbe $args
done
for copies in 0 3; do
  run SkiSignerInfoProbe seq55 $copies
done
for mode in keyusage subject-rdns issuer-rdns bigstring manyext; do
  run FlatCostProbe $mode
done
