# OpenSSL core parity (2026-09-29)

The code behind [`../2026-09-29-openssl-core-parity.md`](../2026-09-29-openssl-core-parity.md).

| Path | Question it answers |
|---|---|
| `runner/` | What does one core tree's 0.7 public API answer for each ABI v1 call? (`Cargo.toml.in` is filled in by `parity.sh`.) |
| `scripts/parity.sh` | Builds the runner against a core tree and runs the five call files through it. |
| `scripts/compare.py` | Are two row sets identical (`same`)? Where a reference row set from another tree disagrees on the verdict, did the migration cause it (`ref`)? |
| `scripts/reasons.py` | Which rows flip verdict between two row sets, and which refusal reasons change? |
| `results/` | The outputs quoted in the note. |

Inputs, all outside the repository: the ABI v1 call files `$CALLS/{cases,hostile,algorithms,substrate,fuzz}.jsonl`
(made from the request corpora by
[`../2026-09-26-wasm-abi-v1/py/abi_calls.py`](../2026-09-26-wasm-abi-v1/py/abi_calls.py)),
the template-build rows `$SCRATCH/asn1/run/new-<corpus>.jsonl` and the ABI v1
Node rows `$SCRATCH/abi/run/node-<corpus>.jsonl`.

```sh
export CALLS=... OUT=$SCRATCH/rows WORK=$SCRATCH/parity
# the pre-migration core: rust/ at the parent of the migration commit
mkdir -p $SCRATCH/old/rust && git archive <commit>:rust | tar -x -C $SCRATCH/old/rust
sh scripts/parity.sh old $SCRATCH/old/rust
# the OpenSSL core, linked two ways
OPENSSL_NO_VENDOR=1 OPENSSL_DIR=<OpenSSL 4.0.2 install> OPENSSL_STATIC=1 \
  sh scripts/parity.sh openssl-dir $REPO/rust
OPENSSL_CONFIG_DIR=/nonexistent/aprv-openssl sh scripts/parity.sh vendored $REPO/rust
for c in cases hostile algorithms substrate fuzz; do
  python3 scripts/compare.py same $CALLS/$c.jsonl $OUT/old-$c.jsonl $OUT/openssl-dir-$c.jsonl
  python3 scripts/compare.py same $CALLS/$c.jsonl $OUT/openssl-dir-$c.jsonl $OUT/vendored-$c.jsonl
  python3 scripts/compare.py ref $CALLS/$c.jsonl $SCRATCH/asn1/run/new-$c.jsonl $OUT/old-$c.jsonl $OUT/openssl-dir-$c.jsonl
  python3 scripts/compare.py ref $CALLS/$c.jsonl $SCRATCH/abi/run/node-$c.jsonl $OUT/old-$c.jsonl $OUT/openssl-dir-$c.jsonl
done
python3 scripts/reasons.py $CALLS $OUT/old $OUT/openssl-dir
```
