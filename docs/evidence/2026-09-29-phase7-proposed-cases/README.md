# Proposed shared cases for the Phase 7 "to add" rows

The note is [`../2026-09-29-phase7-proposed-cases.md`](../2026-09-29-phase7-proposed-cases.md).

| File | What it answered |
|---|---|
| `probe.py` | Mints one input per proposed case from generated material (the shared generated receipt and transaction respliced, or a P-256 PKI minted here), runs it through the Python package over the `aprv.wasm` under test, and prints the module's answer, one JSON line per proposal. Four controls come first: the minted PKI verifies, with and without signed attributes, and so does the shared receipt respliced unchanged. |
| `results.jsonl` | The run behind the note: G1c module (`a35b9fce...40a1`), 80 lines, 4 controls and 76 proposals. |

Reproduce from the repository root, with `aprv.wasm` copied into
`python/apple_purchase_receipt_verifier/` and a Python 3.10+ that has
`wasmtime` and `cryptography`:

```sh
python3 docs/evidence/2026-09-29-phase7-proposed-cases/probe.py "$SCRATCH/proposed" > "$SCRATCH/results.jsonl"
```

`$SCRATCH/proposed` then holds every input, named after its case id
(`/` written `--`), ready to register in `fixtures/cases.json`. The ECDSA
signatures are randomised, so the bytes differ between runs; the answers
do not. Nothing here writes to `fixtures/`.
