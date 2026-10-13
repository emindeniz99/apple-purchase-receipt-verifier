#!/bin/sh
# Usage: run.sh JAVA21 JAVA8 CLASSPATH OID[,OID...]
#   JAVA21, JAVA8  the two `java` launchers
#   CLASSPATH      DigestLeverProbe's class, the library, its test classes
#                  and dependencies
#   OIDs           the digestAlgorithm OIDs to declare, comma-separated
# For each OID: a cap-sized receipt whose four SignerInfos name the test
# PKI's genuine leaf, declare that digest and are signed by an unrelated
# key, verified once in a fresh JVM (cold) three times per JDK, then six
# times in one JVM (warm: the first call and the best of the other five).
set -u
J21=$1
J8=$2
CP=$3
OIDS=$4

probe() { # label java mode oid
  echo "$1 $3 $("$2" -cp "$CP" io.github.emindeniz99.applepurchasereceiptverifier.DigestLeverProbe "$3" "$4" 4 2>&1 | grep -v JAVA_TOOL_OPTIONS)"
}

for oid in $(echo "$OIDS" | tr ',' ' '); do
  for i in 1 2 3; do
    probe jdk21 "$J21" cold "$oid"
    probe jdk8 "$J8" cold "$oid"
  done
  probe jdk21 "$J21" warm "$oid"
  probe jdk8 "$J8" warm "$oid"
done
