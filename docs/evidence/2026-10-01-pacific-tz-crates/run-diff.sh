#!/usr/bin/env bash
# The native differential (diff/), built into $SCRATCH/diff.
S="$(dirname "$(readlink -f "$0")")"
: "${SCRATCH:?set SCRATCH to a directory outside the repository}"
CHRONO_TZ_TIMEZONE_FILTER="^America/Los_Angeles$" cargo run -q --release --manifest-path "$S/diff/Cargo.toml" --target-dir "$SCRATCH/diff/target"
