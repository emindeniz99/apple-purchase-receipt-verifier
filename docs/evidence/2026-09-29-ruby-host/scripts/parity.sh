#!/bin/sh
# The 6,179 corpus rows through the Ruby gem's host code, compared with the
# ABI v1 Node reference rows by round 13's classify.py. Expected result:
#   6,176 identical, 2 clock-moves-chain, 1 init-refusal.
#
#   REPO=... SCRATCH=... GEM_HOME=... sh parity.sh
#
# $SCRATCH holds the wasm bake-off's scratch tree: abi/calls (ABI v1's calls
# per corpus) and abi/run (its Node rows). Everything this writes goes to
# $SCRATCH/ruby-host. The gem's bundle (ruby/Gemfile) must be installed.
set -eu
: "${REPO:?}" "${SCRATCH:?}"
FE="$REPO/docs/evidence/2026-09-29-canonical-abi-final"
W="$SCRATCH/ruby-host"
mkdir -p "$W/calls" "$W/run"
for c in cases hostile algorithms substrate fuzz; do
  python3 "$FE/py/calls_bytes.py" "$SCRATCH/abi/calls/$c.jsonl" > "$W/calls/$c.jsonl" 2> /dev/null
  (cd "$REPO/ruby" && bundle exec ruby -Ilib bench/corpus.rb "$W/calls/$c.jsonl") > "$W/run/ruby-$c.jsonl" 2> "$W/run/ruby-$c.err"
  echo "$c: $(tail -1 "$W/run/ruby-$c.err")"
done
python3 "$FE/py/classify.py" ruby "$W/calls" "$SCRATCH/abi/run" "$W/run/ruby"
