#!/usr/bin/env bash
# Installs age from its GitHub release, pinned by version and SHA-256, for
# the nightly job that seals fuzz findings (fuzz-finding.sh) and for that
# script's test. No package manager: Ubuntu's archive carries an older age
# at whatever version the runner image last pulled.
#
#   install-age.sh <dir>     puts age and age-keygen in <dir>
#
# The hash is the one GitHub lists for the asset, checked against a
# download of it when the pin was set. A new pin changes all three lines.
set -euo pipefail

AGE_VERSION=v1.3.2
AGE_URL=https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz
AGE_SHA256=cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10

if [[ $# -ne 1 || -z "$1" ]]; then
  echo "usage: $0 <dir>" >&2
  exit 2
fi
if [[ "$(uname -s)-$(uname -m)" != Linux-x86_64 ]]; then
  echo "install-age: the pin is for linux-amd64 only" >&2
  exit 1
fi
mkdir -p "$1"
dir="$(cd "$1" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL --retry 4 --retry-delay 2 -o "$work/age.tar.gz" "$AGE_URL"
echo "$AGE_SHA256  $work/age.tar.gz" | sha256sum -c - > /dev/null
tar -xzf "$work/age.tar.gz" -C "$work" age/age age/age-keygen
install -m 0755 "$work/age/age" "$work/age/age-keygen" "$dir/"
echo "install-age: age $AGE_VERSION in $dir" >&2
