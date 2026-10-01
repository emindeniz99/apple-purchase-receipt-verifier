#!/usr/bin/env bash
# The failure step of every per-push fuzz job in ci.yml: the one step that
# holds TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, and it runs no fuzzer.
# nightly.yml's rust-fuzz-openssl does the same inline. It installs age,
# hands each target the fuzz step listed (fuzz-quiet.sh) to fuzz-finding.sh
# (which prints the target and the input's SHA-256, seals the input and
# the log to the recipient key and sends the notice) and exits 1, so the
# job stays red (docs/rust-core/DECISIONS.md R37).
#
#   fuzz-report.sh
#
# reads $RUNNER_TEMP/fuzz-failed.tsv and leaves the sealed files in
# $RUNNER_TEMP/fuzz-sealed/ for the workflow's upload step. An empty list
# means an earlier step failed, not a target; it says so and exits 1.
#
# Environment:
#   AGE   the age binary; when unset, install-age.sh puts the pinned
#         release in $RUNNER_TEMP/age (the test sets it to skip the download)
#   the variables fuzz-finding.sh reads pass through unchanged
set -uo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP is not set}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
list="$RUNNER_TEMP/fuzz-failed.tsv"
sealed="$RUNNER_TEMP/fuzz-sealed"

if [[ ! -s "$list" ]]; then
  echo "fuzz: no target finding to report; an earlier step failed"
  exit 1
fi

if [[ -z "${AGE:-}" ]]; then
  if "$here/install-age.sh" "$RUNNER_TEMP/age"; then
    export AGE="$RUNNER_TEMP/age/age"
  else
    echo "fuzz: age could not be installed; nothing is sealed"
  fi
fi

while IFS=$'\t' read -r t artifacts log; do
  "$here/fuzz-finding.sh" "$t" "$artifacts" "$log" "$sealed"
done < "$list"
exit 1
