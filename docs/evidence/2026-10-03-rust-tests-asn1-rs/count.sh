#!/bin/sh
# Lines of hand-written BER/DER code under rust/tests at one revision.
# Usage: sh count.sh <rev>   (run anywhere inside the repository)
# Prints, per file: all lines, then code lines (not blank, not a comment).
set -eu
rev=$1
count() { # name, text on stdin
  awk -v name="$1" '
    { all++ }
    !/^[[:space:]]*$/ && !/^[[:space:]]*\/\// { code++ }
    END { printf "%-44s %5d %5d\n", name, all, code }'
}
for reader in rust/tests/common/der.rs rust/tests/common/ber.rs; do
  if git cat-file -e "$rev:$reader" 2>/dev/null; then
    git show "$rev:$reader" | count "$reader (reader)"
  fi
done
git show "$rev:rust/tests/common/mod.rs" |
  awk '/^\/\/ --- a minimal DER writer/ { on = 1 } /^\/\/\/ A P-256 test PKI/ { on = 0 } on' |
  count "rust/tests/common/mod.rs (DER writer)"
git show "$rev:rust/tests/common/cms.rs" | count "rust/tests/common/cms.rs (CMS walk)"
echo "reader call sites (parse_exact, parse_cms, certificate_identity):"
git grep -c -E 'parse_exact\(|parse_cms\(|certificate_identity\(' "$rev" -- rust/tests |
  grep -v -E 'common/(der|ber|cms)\.rs' | sed "s/^$rev://"
