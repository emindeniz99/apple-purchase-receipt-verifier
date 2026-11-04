#!/bin/sh
# usage: tagdate.sh owner/repo tag [tag...] ; prints tag, tagger date (annotated) or commit date, commit sha
repo=$1; shift
d=$(mktemp -d "${SCRATCH:?}/tg.XXXXXX")
git init -q --bare "$d"
for t in "$@"; do
  git -C "$d" fetch -q --depth=1 --filter=blob:none "https://github.com/$repo.git" "refs/tags/$t:refs/tags/$t" 2>/dev/null || { echo "$repo $t FETCH-FAILED"; continue; }
  git -C "$d" for-each-ref --format="$repo %(refname:short) tagger=%(taggerdate:iso-strict) commit=%(*committerdate:iso-strict)%(committerdate:iso-strict) sha=%(*objectname)%(objectname)" "refs/tags/$t"
done
rm -rf "$d"
