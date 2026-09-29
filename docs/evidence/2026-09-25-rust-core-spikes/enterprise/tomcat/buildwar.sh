#!/usr/bin/env bash
# buildwar.sh <uniffi|jni> <jakarta|javax> <out.war> [nolib]
set -euo pipefail
E=$SCRATCH/enterprise1
S=$SCRATCH
F=$1; P=$2; OUT=$3; NOLIB=${4:-}
if [ "$P" = jakarta ]; then API=$E/apache-tomcat-10.1.60/lib/servlet-api.jar; NS=https://jakarta.ee/xml/ns/jakartaee; VER=6.0; REL=11
else API=$E/apache-tomcat-9.0.122/lib/servlet-api.jar; NS=http://xmlns.jcp.org/xml/ns/javaee; VER=4.0; REL=8; fi
D=$(mktemp -d $E/wbuild.XXXX); mkdir -p $D/src/spikeweb $D/w/WEB-INF/classes $D/w/WEB-INF/lib
sed "s/__PKG__/$P/" $E/war-src/VerifyServlet.java.tmpl > $D/src/spikeweb/VerifyServlet.java
cp $E/war-src/Impl-$F.java $D/src/spikeweb/Impl.java
sed "s#__NS__#$NS#; s#__VER__#$VER#" $E/war-src/web.xml.tmpl > $D/w/WEB-INF/web.xml
tr -d ' \n\r\t' < $REPO/fixtures/public-receipts/receipt-sandbox-g5.b64 > $D/w/WEB-INF/classes/receipt.b64
if [ $F = uniffi ]; then LIBS="$E/lib/aprv-uniffi.jar $S/jvm-spike/target/dependency/jna-5.17.0.jar $S/jvm-spike/target/dependency/kotlin-stdlib-2.2.20.jar $S/jvm-spike/target/dependency/annotations-13.0.jar"
else LIBS=$E/lib/aprv-jni.jar; fi
env -u JAVA_TOOL_OPTIONS javac --release $REL -nowarn -cp "$API:$(echo $LIBS | tr ' ' ':')" -d $D/w/WEB-INF/classes $D/src/spikeweb/*.java
[ -z "$NOLIB" ] && cp $LIBS $D/w/WEB-INF/lib/
env -u JAVA_TOOL_OPTIONS jar --create --file $OUT -C $D/w .
rm -rf $D
echo built $OUT
