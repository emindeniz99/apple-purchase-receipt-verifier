# Java against the round-3 case and the Phase 7 proposals

The note is [`../2026-09-29-java-align-round3.md`](../2026-09-29-java-align-round3.md).

| File | What it answered |
|---|---|
| `calls_from_probe.py` | Turns lane P7-code's `probe.py` into a `tools/differential.sh` call file: it swaps the Python package for the stub, so the probe mints each input and nothing runs a module. It also adds two rows the proposal note probed by hand: a fractional creation date, and the invalid-UTF-8 signed attribute in DER order. |
| `stub/apple_purchase_receipt_verifier/__init__.py` | The stub: it records each call as a call row. |
| `bitstring_variants.py` | The round-3 case's certificate with its signature BIT STRING in three spellings: the case's, X.690's, and one segment. Written as call rows. |
| `results/proposals.report.txt` | `compare.mjs` over the 82 proposal rows, core against Java. |
| `results/bitstring.report.txt` | The same comparison over the three spellings. |

Reproduce from the repository root. You need a checkout of
`lane/phase7-code` (for `probe.py`), a Python 3.10+ with `cryptography`,
and a built `aprv.wasm`:

```sh
git show 4b73900:docs/evidence/2026-09-29-phase7-proposed-cases/probe.py \
  > docs/evidence/2026-09-29-phase7-proposed-cases/probe.py   # if it is not checked out
E=docs/evidence/2026-09-29-java-align-round3
P7_CALLS="$SCRATCH/proposals.calls.jsonl" python3 "$E/calls_from_probe.py" \
  docs/evidence/2026-09-29-phase7-proposed-cases/probe.py
python3 "$E/bitstring_variants.py" . > "$SCRATCH/bitstring.calls.jsonl"
tools/differential.sh "$SCRATCH/aprv.wasm" "$SCRATCH/report" \
  "$SCRATCH/proposals.calls.jsonl" "$SCRATCH/bitstring.calls.jsonl"
```

`differential.sh` also runs `fixtures/cases.json`, and it exits 1 on the
rows that R20 does not record. The two reports here are the
`<name>.report.txt` files it writes.
