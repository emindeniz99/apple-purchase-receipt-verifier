# Ruby host on the wasmtime gem: sources

Sources for `../2026-09-29-ruby-host.md`. The gem itself is `ruby/`; this
folder holds only what measured it.

| File | What it answered |
|---|---|
| `scripts/parity.sh` | The 6,179 corpus rows through the gem's host code against the ABI v1 Node rows, with round 13's `classify.py` |
| `scripts/standin-differences.rb` | Which of the 311 conformance cases fail against the stand-in module, and why |
| `results/classify.txt`, `results/corpus-runs.txt` | The parity result and the per-corpus row, trap and instance counts |
| `results/standin-differences.txt` | The 221 failing case ids with their category |
| `results/startup.txt` | `ruby/bench/startup.rb`, three fresh processes, with the load average |
| `results/threads.txt` | `ruby/bench/threads.rb`, three runs, with the load average |
| `results/test-inventory.tsv` | Every test of 0.7's `ruby/test/` (184, not counting the conformance runner) with its fate |

`ruby/bench/corpus.rb`, `bench/startup.rb`, `bench/threads.rb` and
`test/thread_test.rb` are the code that ran; they live with the gem.

`$REPO` is the repository root, `$SCRATCH` the wasm bake-off's scratch tree
(it holds `abi/calls` and `abi/run`).

```sh
export REPO=... SCRATCH=...
cd $REPO/ruby && bundle install
sh $REPO/docs/evidence/2026-09-29-ruby-host/scripts/parity.sh
bundle exec ruby -Ilib bench/startup.rb
bundle exec ruby -Ilib bench/threads.rb
OUT=standin-differences.txt bundle exec ruby ../docs/evidence/2026-09-29-ruby-host/scripts/standin-differences.rb
```

`results/test-inventory.tsv` has four columns: the 0.7 test file, the test,
its fate and its target. The fates:

| Fate | Meaning |
|---|---|
| `C` | covered by an existing case of `fixtures/cases.json` (the target names it) |
| `P` | port-only behaviour: the target is the proposed new case |
| `K` | kept in this lane's suite (the target names the file) |
| `F` | belongs to the corpus and the differential job: a sweep, not one input |
| `H` | stays with the host or the repository tooling, or moves to the core's own tests |
| `D` | died with the hand-written Ruby code: it tested a private class that no longer exists |
