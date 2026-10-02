#!/bin/sh
# Compiles ClientMatrix with main's HttpConn, Apache HttpClient 5.6.4 and
# java.net.http, and runs both modes on every JVM given.
#
#   REPO=... SCRATCH=... JARS=dir-with-the-jars run-matrix.sh JAVA_HOME...
#
# JARS holds httpclient5-5.6.4, httpcore5-5.4.3, httpcore5-h2-5.4.3,
# slf4j-api-1.7.36, slf4j-simple-1.7.36 (log mode only) and jspecify-1.0.0
# from Maven Central. Compiled with
# the first JAVA_HOME's javac (a JDK 11 or later): --release 8 for all but
# JnhClients (--release 11). JAVA_TOOL_OPTIONS is cleared for the runs so
# no proxy or trust store setting of the shell reaches them.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${REPO:?}" "${SCRATCH:?}" "${JARS:?}"
out=$SCRATCH/matrix
rm -rf "$out"
mkdir -p "$out/classes" "$out/keys"
cp=$(ls "$JARS"/httpclient5-5.6.4.jar "$JARS"/httpcore5-5.4.3.jar "$JARS"/httpcore5-h2-5.4.3.jar \
  "$JARS"/slf4j-api-1.7.36.jar "$JARS"/jspecify-1.0.0.jar | tr '\n' ':')
pkg=$REPO/java-wasm/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier
javac=$1/bin/javac
"$javac" -nowarn --release 8 -cp "$cp" -d "$out/classes" \
  "$pkg/HttpConn.java" "$here/ClientMatrix.java" "$here/Hc5Clients.java"
"$javac" -nowarn --release 11 -cp "$cp$out/classes" -d "$out/classes" "$here/JnhClients.java"

# Three server keys; the JVM trust store gets "right" (127.0.0.1) and "other" (other.example).
keytool=$1/bin/keytool
for k in forged:ip:127.0.0.1 right:ip:127.0.0.1 other:dns:other.example; do
  name=${k%%:*}
  san=SAN=${k#*:}
  "$keytool" -genkeypair -keystore "$out/keys/$name.p12" -storetype PKCS12 -storepass changeit \
    -keypass changeit -alias server -keyalg EC -keysize 256 -validity 2 -dname "CN=$name" -ext "$san" 2>/dev/null
done
for name in right other; do
  "$keytool" -exportcert -keystore "$out/keys/$name.p12" -storepass changeit -alias server -file "$out/keys/$name.cer"
  "$keytool" -importcert -noprompt -keystore "$out/keys/trust.jks" -storetype JKS -storepass changeit \
    -alias "$name" -file "$out/keys/$name.cer"
done 2>/dev/null

for home in "$@"; do
  v=$(env -u JAVA_TOOL_OPTIONS "$home/bin/java" -version 2>&1 | sed -n '1s/.*"\(.*\)".*/\1/p')
  echo "== $v plain"
  env -u JAVA_TOOL_OPTIONS "$home/bin/java" -cp "$cp$out/classes" \
    io.github.emindeniz99.applepurchasereceiptverifier.ClientMatrix plain
  echo "== $v tls"
  env -u JAVA_TOOL_OPTIONS "$home/bin/java" -Djavax.net.ssl.trustStore="$out/keys/trust.jks" \
    -Djavax.net.ssl.trustStorePassword=changeit -cp "$cp$out/classes" \
    io.github.emindeniz99.applepurchasereceiptverifier.ClientMatrix tls "$out/keys"
  # java.net.http reads a JDK-internal property that turns host name checks off for every client.
  case "$v" in 1.8*) ;; *)
    echo "== $v tls, -Djdk.internal.httpclient.disableHostnameVerification"
    env -u JAVA_TOOL_OPTIONS "$home/bin/java" -Djdk.internal.httpclient.disableHostnameVerification \
      -Djavax.net.ssl.trustStore="$out/keys/trust.jks" -Djavax.net.ssl.trustStorePassword=changeit \
      -cp "$cp$out/classes" io.github.emindeniz99.applepurchasereceiptverifier.ClientMatrix tls "$out/keys" \
      | grep "another name"
  esac
  # Logging configured from outside the code: does the token or the request body reach stderr?
  for c in httpconn hc5-hardened jnh-hardened; do
    case "$v" in 1.8*) [ "$c" = jnh-hardened ] && continue ;; esac
    env -u JAVA_TOOL_OPTIONS "$home/bin/java" -Dorg.slf4j.simpleLogger.defaultLogLevel=debug \
      -Djdk.httpclient.HttpClient.log=headers,content -cp "$cp$JARS/slf4j-simple-1.7.36.jar:$out/classes" \
      io.github.emindeniz99.applepurchasereceiptverifier.ClientMatrix log "$c" >"$out/log.out" 2>"$out/log.err"
    echo "log with -D flags only	$c	stderr $(wc -l <"$out/log.err") lines; token in it: $(grep -c a-token-only "$out/log.err"); request body in it: $(grep -c receipt "$out/log.err")"
  done
done
