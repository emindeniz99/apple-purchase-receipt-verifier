#!/bin/sh
# Usage: measure.sh JAVA MAIN_CLASSES TEST_CLASSES PROBE_CLASSES DEPENDENCIES [all|routes|composite]
# Runs each probe shape in a fresh JVM (each probe repeats its own calls)
# and prints the probes' output. Without "all", only the shapes of the
# review's results.txt, the signature label and the PSS salt. "routes"
# runs only the PSS parameters under each label that reaches the PSS
# verifier (Q142 a). "composite" runs only the generic composite label,
# on a SignerInfo and on a bag certificate (Q144 a).
set -u
j=$1
cp="$4:$2:$3:$5"
p=io.github.emindeniz99.applepurchasereceiptverifier
run() { "$j" -cp "$cp" "$p.$@" 2>&1 | grep -v JAVA_TOOL_OPTIONS; }
if [ "${6:-}" = routes ]; then
  for label in pss eac-sha256 eac-sha1 composite; do
    run PssSaltProbe 32 1 $label
    run PssSaltProbe 1000000000 1 $label
  done
  exit 0
fi
if [ "${6:-}" = composite ]; then
  # signer PARTS PAYLOAD_BYTES: sha256WithRSAEncryption parts, no signed attributes
  for args in "1 1000000" "1000 1000000" "3000 1000000" "50000 1000"; do
    run CompositeLabelProbe signer $args
  done
  # cert PARTS KIND: a bag entry naming the RSA root as its issuer
  for args in "1000 ecdsa" "10000 ecdsa" "20000 ecdsa" "8500 ed25519" "10000 unknown" "20000 rsa"; do
    run CompositeLabelProbe cert $args
  done
  exit 0
fi
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
