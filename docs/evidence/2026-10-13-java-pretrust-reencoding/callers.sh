#!/bin/sh
# Usage: callers.sh <profile.jfr>
# For each sample, the first 6 frames outside org.bouncycastle.asn1 and
# java.* below the hot frame (the caller that started the work), counted.
jfr print --events jdk.ExecutionSample --stack-depth 2048 "$1" | awk '
/stackTrace = \[/{s="";n=0;inst=1;next}
inst&&/^[[:space:]]*\]/{c[s]++;inst=0;next}
inst{gsub(/^[[:space:]]+/,"");sub(/[[:space:]]*line:.*/,"");
  if($0 ~ /^org\.bouncycastle\.asn1\.(ASN1|DER|DL|BER|Definite|Limited|Indefinite)/ || $0 ~ /^java\./ || $0 ~ /^\.\.\./) next;
  if(n<6){s=s" < "$0;n++}}
END{for(k in c)print c[k]"\t"k}' | sort -rn | head -15
