#!/bin/sh
# Spike only. Builds the image and runs the smoke test when a Docker daemon
# is reachable; otherwise records why nothing ran.
#   docker.sh > results/docker.txt
set -u
. "$(dirname "$0")/env.sh"
if ! docker info > "$SV/run/docker-info.txt" 2>&1; then
  echo "# $(date -u +%F): docker info failed, so the image was not built or run:"
  grep -iE 'failed|cannot|error' "$SV/run/docker-info.txt" | sed 's/^ *//'
  docker --version
  exit 0
fi
set -e
docker buildx build --platform linux/amd64 -f "$EV/docker/Dockerfile" --build-context module="$SCRATCH/abi/art" -t aprv-server:spike "$EV/server"
docker image ls aprv-server:spike --format '{{.Repository}}:{{.Tag}} {{.Size}}'
cid=$(docker run -d --rm -e APRV_LISTEN=0.0.0.0:8080 -p 127.0.0.1:18080:8080 aprv-server:spike)
sleep 1
curl -fsS http://127.0.0.1:18080/healthz; echo
curl -fsS --data-binary @"$SV/in/g5.b64" http://127.0.0.1:18080/v1/receipt/verify | cut -c1-80
curl -fsS --data-binary @"$SV/in/jws.txt" http://127.0.0.1:18080/v1/signed-data/verify | cut -c1-80
docker exec "$cid" /usr/local/bin/aprv info 2>/dev/null || echo "(no exec in distroless; id from inspect:) $(docker inspect -f '{{.Config.User}}' "$cid")"
docker stop "$cid"; docker image rm aprv-server:spike
