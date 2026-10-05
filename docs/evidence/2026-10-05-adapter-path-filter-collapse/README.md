# The adapter's path filter: probes

| File | Question |
|---|---|
| `collapse.patch` | The change tried: the core records what vouched for each certificate and hands OpenSSL one path and one anchor; the adapter's per-anchor runs and `linked_above` go. |
| `corpus_replay.rs` | What does the native twin of `aprv.wasm` answer for every call of a corpus call file, at the checked-out tree? (A test of `rust/ffi`, so it builds in the workspace's target directory.) |
| `replay.sh` | Runs `corpus_replay.rs` over the five pinned call files of the corpus archive. |
| `classify.py` | Which rows of two answer sets for the same calls differ, and how: verdict, reason, payload or message? |
| `message-changes.py` | Over the five corpora, which `'old' -> 'new'` messages do the differing rows show, and how many rows differ in all? |
| `path_cost.rs` | How many signatures does the core check itself, and how long does a verification take, for the shared receipt and transaction? |
| `renewed_intermediate.rs` | Does a genuine receipt still verify when its bag holds an expired certificate for the intermediate's key ahead of the renewal? |
| `results/` | The outputs the note quotes. |

All commands run on the commit that added this folder, with `$E` set to
`$REPO/docs/evidence/2026-10-05-adapter-path-filter-collapse`, and leave
the tree as they found it.

Fetch the archive `fixtures/corpus.json` pins and check it (the release
asset sits on a private repository, so it is fetched through the API):

```sh
mkdir -p "$SCRATCH/corpus"
curl -sSfL -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/octet-stream" \
  -o "$SCRATCH/corpus/corpus.tar.gz" \
  https://api.github.com/repos/emindeniz99/apple-purchase-receipt-verifier/releases/assets/599217907
echo "89b599c52f0448dae22298972db5841a795991edf52df520bea7c545774b956d  $SCRATCH/corpus/corpus.tar.gz" | sha256sum -c -
tar -xzf "$SCRATCH/corpus/corpus.tar.gz" -C "$SCRATCH/corpus" calls
```

Replay without and with the patch, and compare:

```sh
REPO="$REPO" sh "$E/replay.sh" "$SCRATCH/corpus" "$SCRATCH/rows-without"
git -C "$REPO" apply "$E/collapse.patch"
REPO="$REPO" sh "$E/replay.sh" "$SCRATCH/corpus" "$SCRATCH/rows-with"
git -C "$REPO" apply -R "$E/collapse.patch"
for c in cases hostile algorithms substrate fuzz; do
  printf '%s: ' "$c"
  python3 "$E/classify.py" "$SCRATCH/rows-without/$c.jsonl" "$SCRATCH/rows-with/$c.jsonl"
done
```

Expected: `results/collapse.txt`, every row the same.

The whole branch against its base, 352f0d1 (on a clean tree: the second
checkout puts `rust/` back as committed):

```sh
git -C "$REPO" checkout 352f0d1 -- rust
REPO="$REPO" sh "$E/replay.sh" "$SCRATCH/corpus" "$SCRATCH/rows-base"
git -C "$REPO" checkout HEAD -- rust
for c in cases hostile algorithms substrate fuzz; do
  printf '%s: ' "$c"
  python3 "$E/classify.py" "$SCRATCH/rows-base/$c.jsonl" "$SCRATCH/rows-without/$c.jsonl" --list \
    | grep -v '^    '
done
python3 "$E/message-changes.py" "$SCRATCH/rows-base" "$SCRATCH/rows-without"
```

Expected: `results/branch-before-collapse.txt` from the loop (no verdict,
five reason rows listed by id) and `results/branch-message-changes.txt`
from the script, whose last line counts the 573 rows that differ: 568 in
their message only, 5 in their reason.

The two probes, without and with the patch (each prints `COST` or
`RENEWAL` lines; remove the copies afterwards):

```sh
for probe in path_cost renewed_intermediate; do cp "$E/$probe.rs" "$REPO/rust/tests/"; done
run() {
  for probe in path_cost renewed_intermediate; do
    cargo test --quiet --locked --all-features --manifest-path "$REPO/rust/Cargo.toml" \
      -p apple-purchase-receipt-verifier --test "$probe" -- --nocapture
  done
}
run
git -C "$REPO" apply "$E/collapse.patch"; run; git -C "$REPO" apply -R "$E/collapse.patch"
rm "$REPO/rust/tests/path_cost.rs" "$REPO/rust/tests/renewed_intermediate.rs"
```

Expected: `results/path-cost.txt` (5 and 4 signature checks without the
patch, 3 and 3 with it; times vary) and `results/renewed-intermediate.txt`
(the expired-first receipt verifies without the patch and is
`INVALID_CERTIFICATE` with it).
