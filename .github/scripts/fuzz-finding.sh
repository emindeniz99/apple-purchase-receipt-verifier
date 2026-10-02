#!/usr/bin/env bash
# Handles one fuzz target that failed in a fuzz job (nightly.yml, and
# ci.yml's per-push jobs through fuzz-report.sh) without letting the
# finding into the public log (docs/rust-core/DECISIONS.md R37). The
# repository is public, and a memory-safety crash is reported privately
# before anything about it is published (SECURITY.md).
#
#   fuzz-finding.sh <target> <artifacts-dir> <log> <sealed-dir>
#
# <artifacts-dir> is where the harness wrote the reproducer (libFuzzer's
# artifact_prefix, such as rust/fuzz/artifacts/<target>/); slow-unit-*
# files there are not findings and are left out. It may be empty or
# missing, when the harness only printed the finding. <log> is the
# target's whole output, which holds the input, the stack and the panic
# message, so it stays on the runner.
#
# Standard output gets the target name and the SHA-256 of each crashing
# input, nothing else: no input, no stack, no panic message, nothing for
# GITHUB_STEP_SUMMARY and no workflow command (no annotation).
#
# With a recipient file, the inputs and the log go into one tar sealed with
# age to it, at <sealed-dir>/<target>.tar.age, for the workflow to upload.
# Without one, nothing is sealed and nothing leaves the runner. Either way
# a Telegram notice goes out when both secrets are set: the repository,
# the target, the input hashes and the run URL.
#
# Environment:
#   FINDINGS_RECIPIENT  the age recipients file
#                       (default .github/fuzz/findings-recipient.txt)
#   AGE                 the age binary (default: age on PATH)
#   TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID   the notice's bot and chat
#   TELEGRAM_API        the Bot API base (default https://api.telegram.org;
#                       the test points it at a local server)
#   GITHUB_REPOSITORY, RUN_URL   named in the notice
#
# It exits 0 once the finding is handled; the caller fails the job. It
# exits 2 on a usage error.
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <target> <artifacts-dir> <log> <sealed-dir>" >&2
  exit 2
fi
target="$1"
artifacts="$2"
log="$3"
sealed="$4"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
recipient="${FINDINGS_RECIPIENT:-$repo/.github/fuzz/findings-recipient.txt}"
age_bin="${AGE:-age}"

inputs=()
hashes=()
if [[ -d "$artifacts" ]]; then
  while IFS= read -r -d '' f; do
    inputs+=("$f")
    hashes+=("$(sha256sum < "$f" | cut -c1-64)")
  done < <(find "$artifacts" -maxdepth 1 -type f ! -name 'slow-unit-*' -print0 | sort -z)
fi

if [[ ${#inputs[@]} -eq 0 ]]; then
  hashes=(none)
  echo "fuzz: $target failed without a crashing input; its log stays sealed"
else
  for h in "${hashes[@]}"; do
    echo "fuzz: $target found a crash; input sha256 $h"
  done
fi
hash_list="${hashes[*]}"

# A recipients file has at least one line that is neither blank nor a
# comment; age itself refuses a line that is not a key.
if [[ -f "$recipient" ]] && grep -qv -e '^[[:space:]]*$' -e '^[[:space:]]*#' "$recipient"; then
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  mkdir -p "$work/$target" "$sealed"
  for f in "${inputs[@]}"; do cp "$f" "$work/$target/"; done
  [[ -f "$log" ]] && cp "$log" "$work/$target/fuzzer.log"
  if tar -C "$work" -cf - "$target" | "$age_bin" -R "$recipient" -o "$sealed/$target.tar.age" 2> /dev/null; then
    echo "fuzz: $target sealed to the recipient key"
  else
    rm -f "$sealed/$target.tar.age"
    echo "finding withheld: the recipient key was refused; target $target, input sha256 $hash_list"
  fi
else
  echo "finding withheld: no recipient key; target $target, input sha256 $hash_list"
fi

token="${TELEGRAM_BOT_TOKEN:-}"
chat="${TELEGRAM_CHAT_ID:-}"
if [[ -z "$token" || -z "$chat" ]]; then
  echo "telegram notice skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not set"
elif [[ ! "$token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
  echo "telegram notice skipped: TELEGRAM_BOT_TOKEN is not a bot token"
else
  text="repository: ${GITHUB_REPOSITORY:-unknown}
target: $target
input sha256: $hash_list
run: ${RUN_URL:-unknown}"
  # The URL carries the token, so it goes to curl on standard input rather
  # than on the command line.
  if printf 'url = "%s/bot%s/sendMessage"\n' "${TELEGRAM_API:-https://api.telegram.org}" "$token" |
    curl -fsS --max-time 30 --retry 2 -o /dev/null -K - \
      --data-urlencode "chat_id=$chat" --data-urlencode "text=$text" 2> /dev/null; then
    echo "telegram notice sent"
  else
    echo "telegram notice failed"
  fi
fi
