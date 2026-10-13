#!/bin/sh
# Usage: measure.sh JAVA MAIN_CLASSES TEST_CLASSES PROBE_CLASSES DEPENDENCIES [all]
# Runs each probe shape in a fresh JVM (each probe repeats its own calls)
# and prints the probes' output. Without "all", only the shapes of the
# review's results.txt, the signature label and the PSS salt.
set -u
j=$1
cp="$4:$2:$3:$5"
p=io.github.emindeniz99.applepurchasereceiptverifier
run() { "$j" -cp "$cp" "$p.$@" 2>&1 | grep -v JAVA_TOOL_OPTIONS; }
run NestedValueProbe plain 0 2300000
run NestedValueProbe cert 30 2300000
run NestedValueProbe sid 30 2300000
# padBytes labels signerInfos: rsaEncryption then md2WithRSAEncryption
run SigAlgDigestProbe 2200000 1.2.840.113549.1.1.1,1.2.840.113549.1.1.2 1
run SigAlgDigestProbe 2200000 1.2.840.113549.1.1.1,1.2.840.113549.1.1.2 4
run PssSaltProbe 32
run PssSaltProbe 1000000000
run PssSaltProbe 1000000000 4
run PssSaltProbe 2147483647
if [ "${6:-}" = all ]; then
  run NestedValueProbe cert 50 2300000
  run NestedValueProbe sid 50 2300000
  run NestedValueProbe string 0 2300000
  for args in "bag 30" "issuer 30" "subject 30" "spki 30" "sigalg 30" "issuer 0" "issuer 50"; do
    run CertShapeProbe $args 2290000
  done
fi
