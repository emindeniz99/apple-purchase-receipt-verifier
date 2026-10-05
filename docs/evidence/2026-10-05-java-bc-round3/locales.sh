#!/bin/bash
: "${REPO:?}" "${SCRATCH:?}"
S=$SCRATCH
cd "$REPO"
run() { name=$1; shift; mvn -o -B -q -f java/pom.xml surefire:test -Dtest='ConformanceCasesTest,EndpointStatusTest,VerifyReceiptEndpointTest,ReceiptDecoderTest,PublicReceiptsTest' "-DargLine=$*" > "$S/loc-$name.log" 2>&1; echo "$name exit=$?" >> "$S/loc-summary.log"; }
: > "$S/loc-summary.log"
run tr "-Duser.language=tr -Duser.country=TR"
run th "-Duser.language=th -Duser.country=TH -Duser.variant=TH -Duser.timezone=Asia/Bangkok"
run jp "-Duser.language=ja -Duser.country=JP -Duser.variant=JP -Dfile.encoding=ISO-8859-1 -Duser.timezone=Asia/Tokyo"
run ar "-Duser.language=ar -Duser.country=SA -Duser.timezone=Pacific/Kiritimati"
