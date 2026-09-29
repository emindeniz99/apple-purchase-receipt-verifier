"""CPU time per call of the Python package on the three inputs the README
quotes: a genuine sandbox receipt with two purchases, one with 187, and a
StoreKit 2 JWS. CPU time (this process, all threads) rather than the wall
clock, because the wall clock of a shared runner is not reproducible; the
module is single-threaded, so CPU time is what one call costs.

    python calls.py       # the module bundled in the package on sys.path
"""

import base64
import json
import statistics
import sys
import time
from pathlib import Path

from apple_purchase_receipt_verifier import Config, Verifier

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"
NOW_MS = 1767225600000


def cpu_us(op, seconds=1.5):
    for _ in range(20):
        op()
    samples = []
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        start = time.process_time()
        for _ in range(10):
            op()
        samples.append((time.process_time() - start) * 1e5)
    return statistics.median(samples)


def main():
    out = {}
    verifier = Verifier(Config.create(roots=list(Config.defaults().roots), clock=lambda: NOW_MS))
    for name in ("receipt-sandbox-g5", "receipt-sandbox-legacy"):
        der = base64.b64decode((FIXTURES / "public-receipts" / f"{name}.b64").read_text("ascii"))
        text = base64.b64encode(der).decode("ascii")
        out[f"verify_receipt {name}"] = cpu_us(lambda text=text: verifier.verify_receipt(text))
    root = (FIXTURES / "generated" / "jws-root.der").read_bytes()
    jws = (FIXTURES / "generated" / "transaction.jws").read_text("ascii").strip()
    jws_verifier = Verifier(Config.create(roots=[root], clock=lambda: NOW_MS))
    out["verify_signed_data transaction.jws"] = cpu_us(lambda: jws_verifier.verify_signed_data(jws))
    print(json.dumps({k: round(v, 1) for k, v in out.items()}), file=sys.stdout)


main()
