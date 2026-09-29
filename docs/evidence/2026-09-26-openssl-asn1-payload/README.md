# OpenSSL ASN.1 for the receipt payload (2026-09-26)

Sources for `../2026-09-26-openssl-asn1-payload.md`. The question: can
`rust/src/asn1.rs` be deleted, with the one job it still has on the CMS
path (reading Apple's receipt payload) done by OpenSSL's own ASN.1 decoder,
and what is the safest OpenSSL API for it? The round also covers a fuzz
campaign on the receipt path without `asn1.rs` and a survey of Rust ASN.1
crates.

This round writes nothing to production code. It reuses four earlier
folders unchanged (`$SPIKE`, `$PREV`, `$FUP`, `$R3`, defined below).
Everything is built with rustc 1.98.1 from `$SCRATCH`, except the fuzz
binaries, which need nightly (see `scripts/fuzz.sh`). The only OpenSSL is
4.0.2.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the scratch directory of the wasm bake-off; this round writes under `$SCRATCH/asn1` |
| `$CORPORA` | the substrate bake-off's corpora |
| `$SPIKE` | `../2026-09-26-security-substrate-bakeoff` |
| `$PREV` | `../2026-09-26-wasm-architecture-bakeoff` |
| `$FUP` | `../2026-09-26-substrate-followup` |
| `$R3` | `../2026-09-26-openssl-cms-everywhere` |

## Files

| File | Question it answered |
|---|---|
| `adapter/payload.c` | Task 3 (a): the payload grammar as OpenSSL ASN.1 templates, 14 lines of declarations |
| `adapter/payload.rs` | Task 3: the adapter's payload API (`receipt_attributes`, `attribute_integer`, `attribute_string`) and the shared decode/free helpers |
| `adapter/payload_templates.rs` | Task 3 (a): the walk over the template result (default) |
| `adapter/payload_any.rs` | Task 3 (b): the walk over OpenSSL's generic `SET OF ANY` / `SEQUENCE OF ANY` items, no C (feature `payload-any`) |
| `adapter/adapter-asn1.patch` | Task 3: the adapter's `Cargo.toml`, `build.rs` (compiles `payload.c` with `cc`) and `lib.rs` changes |
| `patch/no-asn1.patch` | Task 3: the core without `asn1.rs` (and `x509.rs`, `cms.rs`, `crypto.rs`, `chain.rs`, which are built on it); `scripts/build.sh` deletes the files and applies this |
| `patch/spike_probe.rs`, `examples/spike_payload.rs` | Task 3: a hidden probe and an example, copied into both trees, that print what each payload reader returns for the same bytes |
| `scripts/env.sh` | Shared settings: rustc 1.98.1 from `$SCRATCH/rustup`, and the earlier folders |
| `scripts/build.sh` | Task 3: the baseline (round-3 CMS path, no prescan), the no-asn1 builds (templates, payload-any), native and Route C, the examples, and `check-new` (unit tests and clippy without `asn1.rs`) |
| `scripts/parity.sh` | Task 3: round 3's runner, 1,179 rows (or the 5,000 mutants) of one artifact on one host against the baseline |
| `scripts/java.sh` | Task 3: three-way Java tallies for every run |
| `scripts/replay.sh` | Task 3: every receipt fixture's payload read by the three readers, compared |
| `scripts/ber.sh`, `py/ber_variants.py` | Task 3: the genuine and generated payloads re-spelled in BER, read by the three readers |
| `fuzz/payload-diff.rs`, `py/diff_classes.py`, `results/diff-classes.tsv` | Task 3: a differential fuzz target, the old reader against the new one on raw payloads, every difference filed and classified |
| `scripts/fuzz.sh` | Task 4 (and the differential run): build, seeds, runs |
| `py/memory.py`, `py/memory_cms.py` | Task 2 criterion: peak memory of each reader on the largest payloads a receipt can carry |
| `scripts/loc.sh`, `py/loc.py` | Task 6: lines, `unsafe` and C before and after |
| `scripts/crates.sh`, `probe/` | Task 5: crates.io and repository facts per crate, and a probe of der, rasn and bcder on the payload spellings |
| `results/parity.txt` | Every comparison run |
| `results/conformance.txt` | `rust/ffi/tests/conformance.py` (all of `cases.json` through the C ABI) for the three native builds |
| `results/check-new.txt` | Unit tests and clippy of the no-asn1 tree |
| `results/java-tallies.txt` | Tallies per run |
| `results/payload-replay.txt`, `results/ber-variants.txt` | Task 3: per fixture and per BER spelling |
| `results/diff-classes.txt` | Task 3: every differential signature with its class and shortest culprit, for both walks, and the per-class totals |
| `results/fuzz-campaign.txt` | Task 4 and the differential campaign. The table rows come from round 3's `py/fuzz_campaign.py`; the `#` lines around them (setup, libFuzzer final stats, replay counts) were written by hand from the logs |
| `results/memory.txt`, `results/memory-cms.txt` | Task 2 criterion |
| `results/loc.txt` | Task 6 |
| `results/crates.txt`, `results/crate-probe.txt` | Task 5 |
| `scripts/inspect.sh`, `results/imports-sizes.txt` | Route C imports, `payload.c`'s presence in the modules, and sizes |
| `results/versions.txt` | Exact versions |

## Reproduce

These commands assume Linux x86_64, the wasm bake-off's toolchains
(`$SCRATCH/env.sh`), the follow-up's `$SCRATCH/rustup` with rustc 1.98.1
(target wasm32-wasip1, component clippy) and nightly, and round 3's fuzz
corpus in `$SCRATCH/cms/fuzz`.

```sh
export REPO=... SCRATCH=... CORPORA=... PLAYWRIGHT_MODULE=... FIREFOX=... WORKERD=...
. $SCRATCH/env.sh
AP=$REPO/docs/evidence/2026-09-26-openssl-asn1-payload; C=$SCRATCH/asn1
# builds
for b in native-base native-new native-any routec-new routec-any examples check-new; do $AP/scripts/build.sh $b; done > $AP/results/check-new.txt
# parity: baseline against the follow-up's CMS rows, then everything against the baseline
REF=$SCRATCH/fu/run/ossl402cms $AP/scripts/parity.sh native base $C/art/base
for t in new any; do $AP/scripts/parity.sh native $t $C/art/$t; CORPORA_LIST=fuzz $AP/scripts/parity.sh native $t $C/art/$t; done
for rt in node bun deno; do $AP/scripts/parity.sh js new-c $rt trap $C/art/new-c.wasm; done
$AP/scripts/parity.sh wazero new-c $C/art/new-c.wasm; $AP/scripts/parity.sh wasmtime new-c $C/art/new-c.wasm
$AP/scripts/parity.sh workerd new-c core $C/art/new-c.wasm trap
for br in chromium firefox webkit; do $AP/scripts/parity.sh browser new-c $br $C/art 'kind=core&mod=new-c.wasm&policy=trap'; done
$AP/scripts/parity.sh js any-c node trap $C/art/any-c.wasm; $AP/scripts/parity.sh workerd any-c core $C/art/any-c.wasm trap
$AP/scripts/parity.sh browser any-c chromium $C/art 'kind=core&mod=any-c.wasm&policy=trap'
for t in base new any; do python3 $REPO/rust/ffi/tests/conformance.py $C/art/$t; done > $AP/results/conformance.txt
$AP/scripts/java.sh > $AP/results/java-tallies.txt
# payload comparisons
$AP/scripts/replay.sh > $AP/results/payload-replay.txt
$AP/scripts/ber.sh > $AP/results/ber-variants.txt
python3 $AP/py/memory.py $C/mem $C/art/spike_payload-base $C/art/spike_payload-new $C/art/spike_payload-any > $AP/results/memory.txt
python3 $AP/py/memory_cms.py $C/memcms $C/mem $REPO/docs/evidence/2026-09-25-java-native-image-spike/py/run_rust.py $REPO \
  $REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff/js/run.mjs so:base=$C/art/base so:new=$C/art/new so:any=$C/art/any \
  wasm:new-c=$C/art/new-c.wasm wasm:any-c=$C/art/any-c.wasm > $AP/results/memory-cms.txt
# fuzzing (task 4) and the differential run
$AP/scripts/fuzz.sh build && $AP/scripts/fuzz.sh seeds
$AP/scripts/fuzz.sh run verify-receipt 2700 & $AP/scripts/fuzz.sh run payload-diff 2700 & wait
python3 $R3/py/fuzz_campaign.py $C/fuzz   # the rows of results/fuzz-campaign.txt
# the differential inputs through the final harness, templates first (the ANY=1 build replaces the binary)
$AP/scripts/fuzz.sh replay
ANY=1 $AP/scripts/fuzz.sh build payload-diff && ANY=1 $AP/scripts/fuzz.sh replay
{ echo '## templates (a): scripts/fuzz.sh replay'; python3 $AP/py/diff_classes.py $C/fuzz/diff-final $AP/results/diff-classes.tsv
  echo; echo '## payload-any (b): ANY=1 scripts/fuzz.sh replay'; python3 $AP/py/diff_classes.py $C/fuzz/diff-final-any $AP/results/diff-classes.tsv
} > $AP/results/diff-classes.txt
# task 5 and 6
$AP/scripts/crates.sh meta > $AP/results/crates.txt; $AP/scripts/crates.sh probe > $AP/results/crate-probe.txt
$AP/scripts/loc.sh > $AP/results/loc.txt
$AP/scripts/inspect.sh > $AP/results/imports-sizes.txt
```

## What is not here

Binaries, archives, library and crate sources, `node_modules`, fuzz corpora,
the differential run's filed inputs and target directories all stay in
`$SCRATCH/asn1`. The receipt-path campaign found nothing, so there are no
reproducers. The differential run files differences, not crashes; its inputs
are random payloads with no key material, and `results/diff-classes.txt`
keeps one short culprit per signature in hex.
