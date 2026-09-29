#!/usr/bin/env bash
# buildwar.sh <out.war> [nolib]  -- uniffi/jakarta only, JNA 5.19.1
set -euo pipefail
E=$SCRATCH/enterprise1
J=$SCRATCH/jna-latest
OUT=$1; NOLIB=${2:-}
API=$E/apache-tomcat-10.1.60/lib/servlet-api.jar; NS=https://jakarta.ee/xml/ns/jakartaee; VER=6.0; REL=11
D=$(mktemp -d $J/wbuild.XXXX); mkdir -p $D/src/spikeweb $D/w/WEB-INF/classes $D/w/WEB-INF/lib
sed "s/__PKG__/jakarta/" $J/war-src/VerifyServlet.java.tmpl > $D/src/spikeweb/VerifyServlet.java
cp $J/war-src/Impl-uniffi.java $D/src/spikeweb/Impl.java
sed "s#__NS__#$NS#; s#__VER__#$VER#" $J/war-src/web.xml.tmpl > $D/w/WEB-INF/web.xml
tr -d ' \n\r\t' < $REPO/fixtures/public-receipts/receipt-sandbox-g5.b64 > $D/w/WEB-INF/classes/receipt.b64
LIBS="$J/lib/aprv-uniffi.jar $J/lib/jna-5.19.1.jar $J/lib/kotlin-stdlib-2.2.20.jar $J/lib/annotations-13.0.jar"
env -u JAVA_TOOL_OPTIONS javac --release $REL -nowarn -cp "$API:$(echo $LIBS | tr ' ' ':')" -d $D/w/WEB-INF/classes $D/src/spikeweb/*.java
[ -z "$NOLIB" ] && cp $LIBS $D/w/WEB-INF/lib/
env -u JAVA_TOOL_OPTIONS jar --create --file $OUT -C $D/w .
rm -rf $D
echo built $OUT
