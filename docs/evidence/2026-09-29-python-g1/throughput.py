"""Receipts per second with 1, 2 and 4 threads in one process, and with 1, 2
and 4 worker processes, on the genuine sandbox receipt (the README's "use
worker processes" figures).

    python throughput.py [SECONDS]        # default 3 per configuration
"""

import base64
import multiprocessing
import sys
import threading
import time
from pathlib import Path

from apple_purchase_receipt_verifier import Config, Verifier

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"
NOW_MS = 1767225600000


def receipt() -> str:
    path = FIXTURES / "public-receipts" / "receipt-sandbox-g5.b64"
    der = base64.b64decode(path.read_text("ascii"))
    return base64.b64encode(der).decode("ascii")


def make() -> Verifier:
    return Verifier(Config.create(roots=list(Config.defaults().roots), clock=lambda: NOW_MS))


def loop(verifier: Verifier, text: str, seconds: float) -> int:
    assert verifier.verify_receipt(text).verified
    count, end = 0, time.perf_counter() + seconds
    while time.perf_counter() < end:
        verifier.verify_receipt(text)
        count += 1
    return count


def process_worker(seconds: float, queue: "multiprocessing.Queue[int]") -> None:
    queue.put(loop(make(), receipt(), seconds))


def main() -> None:
    seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 3.0
    text = receipt()
    verifier = make()
    for n in (1, 2, 4):
        counts: list[int] = []
        threads = [
            threading.Thread(target=lambda c=counts: c.append(loop(verifier, text, seconds)))
            for _ in range(n)
        ]
        [t.start() for t in threads]
        [t.join() for t in threads]
        print(f"threads   {n}: {sum(counts) / seconds:8.0f} receipts/s")
    context = multiprocessing.get_context("spawn")
    for n in (1, 2, 4):
        queue = context.Queue()
        procs = [context.Process(target=process_worker, args=(seconds, queue)) for _ in range(n)]
        [p.start() for p in procs]
        total = sum(queue.get() for _ in procs)
        [p.join() for p in procs]
        print(f"processes {n}: {total / seconds:8.0f} receipts/s")


if __name__ == "__main__":
    main()
