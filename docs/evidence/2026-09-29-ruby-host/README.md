# Ruby host on the wasmtime gem: sources

Sources for `../2026-09-29-ruby-host.md`. The gem itself is `ruby/`; this
folder holds only what measured it.

| File | What it answered |
|---|---|
| `scripts/g1.sh` | One command for a module drop: install the module, pin its hash, run the whole suite (311 cases, packaging round trip), run the five pinned corpora through the gem's host code and compare every row with the module's own rows |
| `results/g1-suite-and-corpora.txt` | The suite result, the 311 case count and the per-corpus row comparison |
| `results/g1-startup.txt` | `ruby/bench/startup.rb`, three fresh processes, with the load average |
| `results/g1-threads.txt` | `ruby/bench/threads.rb`, one run, with the load average |
| `results/g1-fuzz.txt` | The four ruzzy targets on the real module |
| `results/test-inventory.tsv` | Every test of 0.7's `ruby/test/` (184, not counting the conformance runner) with its fate |

`ruby/bench/corpus.rb`, `bench/startup.rb`, `bench/threads.rb` and
`test/thread_test.rb` are the code that ran; they live with the gem.

`<g1-dir>` is the directory the core lane hands over: `aprv.wasm`,
`calls/<corpus>.pinned.jsonl`, `rows/module-<corpus>.jsonl` and `same.py`.

```sh
cd ruby && bundle install
sh ../docs/evidence/2026-09-29-ruby-host/scripts/g1.sh <g1-dir> [<work-dir>]
bundle exec ruby -Ilib bench/startup.rb
bundle exec ruby -Ilib bench/threads.rb
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
