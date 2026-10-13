#!/bin/bash
# usage: runj.sh <label> <java> "<jvm opts>" [classes...]   (default: CI order through the cost class + 3 after)
# Kills the JVM after 240 s without log output (OpenJ9 JIT hang) and reports HANG.
S=${SCRATCH:?set SCRATCH to a directory outside the repository}
W=${REPO:?set REPO to the repository root}/java
label=$1; java=$2; opts=$3; shift 3
classes="$*"
[ -z "$classes" ] && classes="VerifierApiTest InputSizeBoundsTest ReceiptCertificatesTest DigestDenylistCostTest HostPolicyTest ReceiptContentInfoTest ReceiptDecoderTest TrustStoreIsolationTest EndpointStatusTest EndpointJsonReadTest CertificateDecodeTest VerifyReceiptEndpointTest FixtureGeneratorTest AppleRootCertsTest ReceiptSignerInfoTest FailureMessageTest ReadmeSyntheticReceiptExampleTest DIAG UnauthenticatedKeyCostTest DIAG ConformanceCasesTest SignedDataTest"
CP=$W/target/test-classes:$W/target/classes:$(cat $S/cp.txt):$HOME/.m2/repository/org/junit/platform/junit-platform-launcher/1.14.4/junit-platform-launcher-1.14.4.jar:$S/launcher
mkdir -p $S/runs
log=$S/runs/$label.log
start=$(date +%s)
env -C $W -u JAVA_TOOL_OPTIONS $java $opts -Daprv.fixtures.dir=$W/../fixtures -Ddiag.dump=$S/dumps/$label -cp $CP OrderedRun $classes > $log 2>&1 &
pid=$!
hang=""
last=$(date +%s); size=0
while kill -0 $pid 2>/dev/null; do
  sleep 5
  ns=$(stat -c %s $log)
  if [ "$ns" != "$size" ]; then size=$ns; last=$(date +%s); fi
  if [ $(( $(date +%s) - last )) -gt ${WATCHDOG:-240} ]; then
    hang="HANG"
    top -b -n1 -H -p $pid | head -14 > $log.top; timeout 150 gdb -p $pid -batch -ex 'set pagination off' -ex 'thread apply all bt 4' > $log.gdb 2>&1
    kill -9 $pid
  fi
done
wait $pid 2>/dev/null
end=$(date +%s)
first=$(grep -m1 -E '^  FAIL' $log | grep -v -E 'generate\(\)' )
echo "$label $((end-start))s $hang | $(grep -E '^CLASS UnauthenticatedKeyCostTest' $log) | $(grep TOTAL_FAILED $log) | diagBad: $(grep -c 'DIAG BAD' $log) probeFail: $(grep -c '^Caused by: java.lang.IllegalStateException: this runtime cannot verify\|^java.lang.IllegalStateException: this runtime cannot verify' $log) ff: $(grep -c 'definite-length 0xFF' $log) timing: $(grep -c 'AssertionFailedError: took' $log) firstCorrupt: $(grep -B3 -m1 -E 'cannot verify Apple|0xFF' $log | grep -o -E 'FAIL t=[0-9]+ [A-Za-z]+' | tail -1)"
