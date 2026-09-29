"""Start-up time and memory of the Python package on the release aprv.wasm.

    python measure.py CACHE_PARENT [RUNS]

Each measurement is a fresh child process (this script with ``--child``) so
that nothing is loaded twice. Three cache states, each with all CPUs and with
one (``taskset -c 0``): the cache off (``APRV_WASM_CACHE_DIR=""``), a cache
directory that is empty (this run fills it), and the same directory again
(a hit). CACHE_PARENT is a directory outside the repository that this script
creates cache directories in. Prints one JSON line per configuration with the
median and minimum over RUNS (default 5) of:

  import_ms    ``import apple_purchase_receipt_verifier`` (reads and hashes
               the module, imports wasmtime)
  verifier_ms  the first ``Verifier(Config.defaults())``: compile or cache
               load, the linker, the first instance and ``init``
  verifier_cpu_ms  the same, in CPU time (all threads), which a busy machine
               inflates far less than the wall clock
  second_ms    a second ``Verifier`` in the same process
  rss_mb       peak resident set after the first Verifier
  rss_calls_mb peak resident set after 300 receipt verifications
"""

import json
import os
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def child() -> None:
    t0 = time.perf_counter()
    from apple_purchase_receipt_verifier import Config, Verifier

    t1 = time.perf_counter()
    c0 = time.process_time()
    verifier = Verifier(Config.defaults())
    t2 = time.perf_counter()
    cpu = time.process_time() - c0
    Verifier(Config.defaults())
    t3 = time.perf_counter()
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    for _ in range(300):
        verifier.verify_receipt("AAAA")  # refused fast: the call path, not the CMS work
    rss_calls = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(
        json.dumps(
            {
                "import_ms": (t1 - t0) * 1e3,
                "verifier_ms": (t2 - t1) * 1e3,
                "verifier_cpu_ms": cpu * 1e3,
                "second_ms": (t3 - t2) * 1e3,
                "rss_mb": rss / 1024,
                "rss_calls_mb": rss_calls / 1024,
            }
        )
    )


def run(cache: "str | None", one_cpu: bool) -> dict:
    env = dict(os.environ)
    env.pop("APRV_WASM", None)
    if cache is not None:
        env["APRV_WASM_CACHE_DIR"] = cache
    command = [sys.executable, __file__, "--child"]
    if one_cpu:
        command = ["taskset", "-c", "0", *command]
    done = subprocess.run(command, env=env, capture_output=True, text=True, check=True)
    return json.loads(done.stdout.splitlines()[-1])


def summarise(rows: "list[dict]") -> dict:
    out = {}
    for key in rows[0]:
        values = [r[key] for r in rows]
        out[key] = {"median": round(statistics.median(values), 1), "min": round(min(values), 1)}
    return out


def main() -> None:
    parent = Path(sys.argv[1])
    runs = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    parent.mkdir(parents=True, exist_ok=True)
    for one_cpu in (False, True):
        cpus = "1 CPU" if one_cpu else f"{len(os.sched_getaffinity(0))} CPUs"
        off = [run("", one_cpu) for _ in range(runs)]
        fill, hit = [], []
        for _ in range(runs):
            directory = tempfile.mkdtemp(dir=parent)
            fill.append(run(directory, one_cpu))
            hit.append(run(directory, one_cpu))
            shutil.rmtree(directory)
        for name, rows in (("cache off", off), ("cache fill", fill), ("cache hit", hit)):
            print(json.dumps({"cpus": cpus, "cache": name, "runs": runs, **summarise(rows)}))


if __name__ == "__main__":
    child() if "--child" in sys.argv else main()
