#!/usr/bin/env bash
# Runs a fuzz harness one target at a time with each target's output in a
# file on the runner, for the per-push fuzz jobs in ci.yml that drive a
# run.sh (docs/rust-core/DECISIONS.md R37); go-fuzz has no run.sh and writes
# the same list inline. The repository is public, and a fuzzer's report of
# a finding holds the crashing input, the stack and the panic message, so
# none of it may reach the job log.
#
#   fuzz-quiet.sh <artifacts-parent> <seconds>
#
# runs `./run.sh <target> <seconds>` in the current directory for each
# target `./run.sh list` names (the set `./run.sh all` runs, so a target
# added to the harness is fuzzed here without a workflow change), with its
# stdout and stderr in $RUNNER_TEMP/fuzz-logs/<target>.log. The job log
# gets one line per target: that it ran its budget without a finding, or
# that it failed. A failed target is appended to
# $RUNNER_TEMP/fuzz-failed.tsv as
#
#   <target> TAB <cwd>/<artifacts-parent>/<target> TAB <log>
#
# which is what fuzz-report.sh hands to fuzz-finding.sh: the directory the
# harness writes crashing inputs to (libFuzzer's artifact_prefix,
# php-fuzzer's crashes/) and the target's whole output. The list is
# truncated first, so it holds this run's failures only. Every target runs
# even after a failure; the exit status is 1 if any failed, and 2 if
# `./run.sh list` fails or names nothing.
#
# No secret may be in this script's environment: every fuzzed process
# inherits it.
set -uo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <artifacts-parent> <seconds>" >&2
  exit 2
fi
parent="$1"
seconds="$2"
: "${RUNNER_TEMP:?RUNNER_TEMP is not set}"
logs="$RUNNER_TEMP/fuzz-logs"
list="$RUNNER_TEMP/fuzz-failed.tsv"
mkdir -p "$logs"
: > "$list"

if ! names="$(./run.sh list)" || [[ -z "$names" ]]; then
  echo "fuzz: ./run.sh list named no target" >&2
  exit 2
fi
mapfile -t targets <<< "$names"

failed=0
for t in "${targets[@]}"; do
  if ./run.sh "$t" "$seconds" > "$logs/$t.log" 2>&1; then
    echo "fuzz: $t ran $seconds s without a finding"
  else
    failed=1
    echo "fuzz: $t failed; its output stays on the runner"
    printf '%s\t%s\t%s\n' "$t" "$PWD/$parent/$t" "$logs/$t.log" >> "$list"
  fi
done
exit "$failed"
