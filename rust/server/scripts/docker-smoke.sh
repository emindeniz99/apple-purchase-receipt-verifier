#!/bin/sh
# Smoke test of a built aprv-server image. CI runs it after the image build;
# this repository's development container has no Docker daemon, so it has
# not been run here.
#
#   docker-smoke.sh IMAGE [RECEIPT.b64]
#
# Checks:
#   1. the org.opencontainers.image.* labels are set (source, revision,
#      version, licenses, description) and the image runs as uid 65532;
#   2. without APRV_LISTEN nothing answers on the published port (the
#      server listens on 127.0.0.1 inside the container);
#   3. with APRV_LISTEN=0.0.0.0:8080 and a token, /healthz answers, a /v1/
#      route without the token is a 401 problem, and the g5 sandbox receipt
#      verifies with it;
#   4. `aprv info` runs in the image and names the embedded component.
set -eu
image=${1:?usage: docker-smoke.sh IMAGE [RECEIPT.b64]}
here=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
receipt=${2:-$here/fixtures/public-receipts/receipt-sandbox-g5.b64}
fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }

for k in source revision version licenses description; do
  v=$(docker inspect -f "{{ index .Config.Labels \"org.opencontainers.image.$k\" }}" "$image")
  [ -n "$v" ] || fail "label org.opencontainers.image.$k is missing"
  pass "label $k = $v"
done
[ "$(docker inspect -f '{{ .Config.User }}' "$image")" = "65532:65532" ] || fail "the image does not run as 65532"
pass "user 65532:65532"

docker run --rm --entrypoint /usr/local/bin/aprv "$image" info | grep -q '"component_sha256"' || fail "aprv info"
pass "aprv info names the embedded component"

port=18080
c=$(docker run -d --rm -p 127.0.0.1:$port:8080 "$image")
trap 'docker rm -f "$c" >/dev/null 2>&1 || true' EXIT
sleep 2
if curl -s -m 3 "http://127.0.0.1:$port/healthz" >/dev/null; then fail "something answered without APRV_LISTEN"; fi
pass "nothing answers without APRV_LISTEN"
docker rm -f "$c" >/dev/null

token=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
c=$(docker run -d --rm -e APRV_LISTEN=0.0.0.0:8080 -e APRV_TOKEN="$token" -p 127.0.0.1:$port:8080 "$image")
i=0
until curl -fs -m 2 "http://127.0.0.1:$port/healthz" >/dev/null; do
  i=$((i + 1)); [ $i -lt 50 ] || fail "the server did not come up"; sleep 0.2
done
pass "healthz with APRV_LISTEN set"
code=$(curl -s -o /dev/null -w '%{http_code}' --data-binary @"$receipt" "http://127.0.0.1:$port/v1/receipt/verify")
[ "$code" = 401 ] || fail "no token: HTTP $code, not 401"
pass "no token: 401"
body=$(tr -d ' \n\r\t' < "$receipt" | curl -s -H "X-Aprv-Token: $token" --data-binary @- "http://127.0.0.1:$port/v1/receipt/verify")
echo "$body" | grep -q '"verified":true' || fail "g5 did not verify: $(echo "$body" | cut -c1-200)"
pass "g5 verifies"
