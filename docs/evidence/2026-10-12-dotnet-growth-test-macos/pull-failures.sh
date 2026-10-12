#!/usr/bin/env bash
# Lists every `dotnet (<os>)` job of the ci workflow since a date, and
# pulls the growth test's lines out of each failing macOS job's log.
#
#   pull-failures.sh <since, ISO-8601> <out dir>
#
# Writes <out>/runs.txt (one ci run per line), <out>/jobs.txt (one
# dotnet OS-matrix job per line, every attempt) and
# <out>/messages/job-<id>.txt. Needs an authenticated `gh api` for the
# listings; the log redirect is followed with plain curl. GitHub keeps
# job logs for 90 days.
#
# A ci run has more than 100 jobs (163 to 330 seen), so the job listing
# is paged: the first page alone often misses the dotnet matrix.
set -euo pipefail
since=$1
out=$2
repo=emindeniz99/apple-purchase-receipt-verifier
mkdir -p "$out/logs" "$out/messages"

retry() { for _ in 1 2 3 4 5 6 7 8; do "$@" && return 0; sleep 10; done; return 1; }

: > "$out/runs.txt"
page=1
while :; do
  rows=$(retry gh api "repos/$repo/actions/workflows/ci.yml/runs?per_page=100&page=$page&created=%3E%3D$since" \
    --jq '.workflow_runs[] | "\(.id) \(.created_at) \(.head_sha[0:8]) \(.event) \(.head_branch)"')
  [ -z "$rows" ] && break
  echo "$rows" >> "$out/runs.txt"
  page=$((page + 1))
done

: > "$out/jobs.txt"
while read -r id created sha event branch; do
  page=1
  while :; do
    rows=$(retry gh api "repos/$repo/actions/runs/$id/jobs?per_page=100&page=$page&filter=all" \
      --jq ".jobs[] | \"\(.id) \(.run_attempt) \(.name) \(.conclusion) $id $created $sha $event\"")
    [ -z "$rows" ] && break
    echo "$rows" | grep -E '^[0-9]+ [0-9]+ dotnet \(' >> "$out/jobs.txt" || true
    page=$((page + 1))
  done
done < "$out/runs.txt"

grep ' dotnet (macos-latest) failure ' "$out/jobs.txt" | while read -r job rest; do
  url=$(curl -s -o /dev/null -w '%{redirect_url}' "https://api.github.com/repos/$repo/actions/jobs/$job/logs")
  curl -sL "$url" -o "$out/logs/$job.log"
  sed -E 's/\x1b\[[0-9;]*m//g' "$out/logs/$job.log" \
    | grep -E 'failed ApplePurchaseReceiptVerifier.Tests.PlatformTests.RepeatedVerification|each verification left|Tests\.dll \(net[0-9.]+\|arm64\) (passed|failed) ' \
    | grep -v '^\S*\s\s\s*/' \
    | sed -E 's#[^ ]*/apple-purchase-receipt-verifier/apple-purchase-receipt-verifier/#$REPO/#' \
    > "$out/messages/job-$job.txt" || true
done
