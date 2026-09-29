"""Runs a calls file of the corpus parity check through the package's host
layer (``_host.Pool`` over the bundled module) and writes one answer row per
call, in the format the other hosts write, so that
docs/evidence/2026-09-29-canonical-abi-final/py/classify.py can compare it
row by row with the ABI v1 Node reference rows. It is a script, not a test:
the corpora are large and live outside the repository.

    python tests/corpus_rows.py CALLS.jsonl > ROWS.jsonl

CALLS.jsonl is a corpus file after docs/evidence/2026-09-29-canonical-abi-final/py/calls_bytes.py:
one JSON object per line, either ``{"id", "map"}`` (nothing to call) or
``{"id", "fn", "config", "now", "b64"}`` with ``env`` on endpoint rows.
``config`` is what ``init`` takes and keys the pool (one pool per distinct
config, as the other hosts keep one instance per config); ``now`` is the
instant to pass, or null for the wall clock.

The public ``Verifier`` reads a clock and maps the answer, neither of which
a raw comparison wants: the pinned instants, the ``init`` refusals and the
byte-for-byte answers are the module's. So this drives the layer under it,
which is also where every byte crosses: the pool, the canonical-ABI call, the
store limits and the trap handling.
"""

import base64
import json
import sys
import time

from apple_purchase_receipt_verifier import _host

_POOL_SIZE = 2


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def main(path: str) -> int:
    runtime = _host.default_runtime()
    pools: dict[str, _host.Pool | str] = {}  # a str is init's refusal
    rows = traps = 0
    out = sys.stdout
    with open(path, encoding="utf-8") as calls:
        for line in calls:
            if not line.strip():
                continue
            row = json.loads(line)
            rows += 1
            if "map" in row:
                answer: dict[str, object] = {"id": row["id"], "map": row["map"]}
            else:
                config = row["config"]
                if config not in pools:
                    pool = _host.Pool(runtime, config.encode("utf-8"), _POOL_SIZE)
                    pools[config] = pool if pool.init_answer == '{"ok":true}' else pool.init_answer
                pool_or_refusal = pools[config]
                if isinstance(pool_or_refusal, str):
                    answer = {"id": row["id"], "out": pool_or_refusal}
                else:
                    now = row["now"] if row.get("now") is not None else now_ms()
                    scalars = (
                        (row["env"], now) if row["fn"] == "verify-receipt-endpoint" else (now,)
                    )
                    try:
                        text = pool_or_refusal.run(
                            row["fn"], scalars, base64.b64decode(row["b64"]), str
                        )
                        answer = {"id": row["id"], "out": text}
                    except _host.Fault as fault:
                        traps += 1
                        cause = fault.__cause__ if fault.__cause__ is not None else fault
                        answer = {"id": row["id"], "trap": str(cause).split("\n")[0]}
            out.write(json.dumps(answer, separators=(",", ":"), ensure_ascii=False) + "\n")
    print(
        json.dumps({"host": "the package's host layer", "rows": rows, "traps": traps}),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
