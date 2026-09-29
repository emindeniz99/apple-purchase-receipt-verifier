#!/usr/bin/env bash
# tcrun.sh <name> <tomcat-home> <java-home> <war1> [war2] -- runs deploy + 3 redeploys; optional SHARED_LIBS, OPTS env
set -uo pipefail
J=$SCRATCH/jna-latest
NAME=$1; H=$2; JH=$3; W1=$4; W2=${5:-}
B=$J/runs/$NAME; rm -rf $B; mkdir -p $B/{webapps,logs,temp,work,lib}
cp -r $H/conf $B/conf; cp -r $H/webapps/manager $B/webapps/
cat > $B/conf/tomcat-users.xml <<'X'
<tomcat-users><role rolename="manager-script"/><user username="s" password="s" roles="manager-script"/></tomcat-users>
X
for l in ${SHARED_LIBS:-}; do cp $l $B/lib/; done
export CATALINA_HOME=$H CATALINA_BASE=$B JAVA_HOME=$JH CATALINA_PID=$B/pid
export CATALINA_OPTS="${OPTS:-}"
unset JAVA_TOOL_OPTIONS
cp $W1 $B/webapps/app1.war; [ -n "$W2" ] && cp $W2 $B/webapps/app2.war
$H/bin/catalina.sh start >/dev/null
hit() { for i in $(seq 1 60); do r=$(curl -s -m 20 http://127.0.0.1:8080/$1/verify) && [ -n "$r" ] && { echo "$r"; return; }; sleep 1; done; echo "NO RESPONSE"; }
deployed() { grep -c "Deployment of web application archive \[$B/webapps/$1.war\] has finished" $B/logs/catalina.out; }
waitdeploy() { for i in $(seq 1 90); do [ "$(deployed $1)" -ge "$2" ] && return; sleep 1; done; echo "(timeout waiting deploy $1 #$2)"; }
waitdeploy app1 1; [ -n "$W2" ] && waitdeploy app2 1
echo "== initial"; echo "app1: $(hit app1)"; [ -n "$W2" ] && echo "app2: $(hit app2)"
for n in 1 2 3; do
  sleep 1; touch $B/webapps/app1.war; [ -n "$W2" ] && touch $B/webapps/app2.war
  waitdeploy app1 $((n+1)); [ -n "$W2" ] && waitdeploy app2 $((n+1))
  echo "== redeploy $n"; echo "app1: $(hit app1)"; [ -n "$W2" ] && echo "app2: $(hit app2)"
done
sleep 2
echo "== findleaks: $(curl -s -u s:s 'http://127.0.0.1:8080/manager/text/findleaks?statusLine=true')"
sleep 3; echo "== after findleaks(GC) app1: $(hit app1)"
echo "== log warnings/errors:"; grep -E 'SEVERE|WARNING|Exception|Error' $B/logs/catalina.out | grep -v 'Picked up' | cut -c1-400 | sort | uniq -c | sort -rn | head -20
$H/bin/catalina.sh stop 10 -force >/dev/null 2>&1
