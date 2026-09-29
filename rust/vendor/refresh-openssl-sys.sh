#!/bin/sh
# Rebuilds rust/vendor/openssl-sys from the crates.io release, checked
# against its registry SHA-256, with exactly one manifest line changed: the
# openssl-src build dependency moves from "300.2.0" (^300.2.0, OpenSSL 3.x)
# to "400.0.1" (^400.0.1, OpenSSL 4.x). Nothing else in the crate changes;
# openssl-sys's build script calls only openssl_src::Build::{new,
# openssl_dir, build} and Artifacts::{lib_dir, include_dir}, which 400.x
# keeps. The workspace's [patch.crates-io] points openssl-sys here.
#
# Run from anywhere; CI runs it and fails on `git diff --exit-code
# rust/vendor`. Drop the copy and the patch once a released openssl-sys
# accepts openssl-src 400.x (rust/openssl/README.md).
#
#   rust/vendor/refresh-openssl-sys.sh
set -eu
VERSION=0.9.117
SHA256=b47e7e6bb2c38cd930d25a23b40fa52e068c10e85f3e03a7f5ba5aaca5713695
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -sSfL -o "$work/openssl-sys.crate" \
  "https://static.crates.io/crates/openssl-sys/openssl-sys-$VERSION.crate"
echo "$SHA256  $work/openssl-sys.crate" | sha256sum -c - >/dev/null
tar -xzf "$work/openssl-sys.crate" -C "$work"
src="$work/openssl-sys-$VERSION"
# The one change. The awk script fails unless it changed exactly one line.
awk '
  /^\[build-dependencies\.openssl-src\]$/ { in_section = 1; print; next }
  /^\[/ { in_section = 0 }
  in_section && $0 == "version = \"300.2.0\"" { print "version = \"400.0.1\""; changed++; next }
  { print }
  END { if (changed != 1) { print "expected one openssl-src requirement, changed " changed > "/dev/stderr"; exit 1 } }
' "$src/Cargo.toml" > "$work/Cargo.toml"
mv "$work/Cargo.toml" "$src/Cargo.toml"
# Registry bookkeeping, not source.
rm -f "$src/.cargo_vcs_info.json" "$src/.cargo-ok"
rm -rf "$here/openssl-sys"
cp -R "$src" "$here/openssl-sys"
