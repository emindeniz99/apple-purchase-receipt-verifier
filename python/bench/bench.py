"""The cross-port benchmark: the same operations on the same two genuine
sandbox receipts in every port, named after the Java JMH benchmarks in
java-bench/ (BENCHMARKS.md at the repository root has the table). The
package holds no decoder and no DER entry point of its own any more, so the
``decodeBase64`` and ``core`` benchmarks of 0.7 have no Python counterpart;
``verifierBase64``, ``endpointJson`` and ``rejectTamperedSignature`` do.

    uv sync --locked
    uv run --locked python bench/bench.py > python-bench.json

timeit rather than pyperf, which is not a dependency of this project. Each
benchmark warms up for one second, then takes ten samples of at least 100 ms
each, with the garbage collector left on as it is in every other port; the
JSON on stdout carries the median, minimum and maximum microseconds per
operation over those samples. The first call in the process compiles
``aprv.wasm`` (or loads it from Wasmtime's cache), which the warm-up absorbs.

    uv run --locked python bench/bench.py --worst-case

times, the same way, every shared case in fixtures/cases.json that carries a
maxMillis budget: the hostile inputs (oversized untrusted keys, certificate
meshes, encoding oddities inside certificates) the shared suite bounds in
time. Each call is run once first and must give the answer the case expects.
The README's worst-case CPU figure comes from this mode.
"""

from __future__ import annotations

import base64
import gc
import hashlib
import json
import platform
import statistics
import sys
import time
import timeit
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any

from apple_purchase_receipt_verifier import Config, Environment, Verifier

WARMUP_S = 1.0
SAMPLES = 10
MIN_SAMPLE_S = 0.1

# Any fixed instant (2026-01-01T00:00:00Z), in epoch milliseconds: it only
# feeds request_date.
NOW_MS = 1767225600000

# File under fixtures/public-receipts, and the bundle id, in-app count and
# digest fixtures/cases.json pins for it.
FIXTURES = [
    (
        "receipt-sandbox-g5",
        "dev.bonzer.weeka.app",
        2,
        "bebb16e2a17104d973eeef08177003f2c3303a19ddced83b42df349b4ac25ee0",
    ),
    (
        "receipt-sandbox-legacy",
        "com.nutcall.alert",
        187,
        "ec62c6bd4a34bd8e56b11e675bf5a28319ce69b71d050e73344bab22f46799a8",
    ),
]


def measure(benchmark: str, fixture: str, op: Callable[[], object]) -> dict[str, Any]:
    # timeit switches the collector off while it times; "gc.enable()" as the
    # setup is timeit's documented way to keep it on.
    timer = timeit.Timer(op, setup="gc.enable()", globals={"gc": gc})
    start = time.perf_counter()
    warmup_ops = 0
    while time.perf_counter() - start < WARMUP_S:
        op()
        warmup_ops += 1
    per_op = (time.perf_counter() - start) / warmup_ops
    ops = max(1, int(MIN_SAMPLE_S / per_op) + 1)
    samples = sorted(timer.timeit(ops) * 1e6 / ops for _ in range(SAMPLES))
    median = statistics.median(samples)
    print(f"{benchmark:>24} {fixture:<24} {median:>12.1f} us/op", file=sys.stderr)
    return {
        "benchmark": benchmark,
        "fixture": fixture,
        "us_per_op_median": median,
        "us_per_op_min": samples[0],
        "us_per_op_max": samples[-1],
        "ops_per_sample": ops,
    }


def tamper(der: bytes) -> bytes:
    """Flips one bit in the middle of the SignerInfo signature, the byte
    java-bench's flipSignatureByte flips. In both fixtures the signature is a
    256-byte OCTET STRING that ends the DER (openssl asn1parse shows it), so
    its middle byte is 128 from the end; setup proves the flip landed there
    by requiring a failed verification."""
    tampered = bytearray(der)
    tampered[-128] ^= 0x01
    return bytes(tampered)


def fixture_bytes(fixtures_dir: Path, entry: dict[str, str]) -> bytes:
    """A registered fixture's logical bytes, per its codec (the same rules
    the conformance adapter in tests/ applies)."""
    raw = (fixtures_dir / entry["path"]).read_bytes()
    codec = entry["codec"]
    if codec in ("raw", "text"):
        return raw
    if codec == "base64":
        return base64.b64decode(b"".join(raw.split()))
    if codec == "utf8":
        return raw.decode("utf-8").strip().encode("utf-8")
    raise ValueError(f"unknown fixture codec {codec!r}")


def worst_case() -> list[dict[str, Any]]:
    fixtures_dir = Path(__file__).resolve().parents[2] / "fixtures"
    file = json.loads((fixtures_dir / "cases.json").read_text(encoding="utf-8"))
    registry = file["fixtures"]
    results = []
    for case in file["cases"]:
        if "maxMillis" not in case:
            continue
        trusted = case["config"]["trustedRoots"]
        roots = None
        if trusted["source"] == "fixtures":
            roots = [fixture_bytes(fixtures_dir, registry[i]) for i in trusted["fixtures"]]
        verifier = Verifier(Config(roots=roots, clock=lambda: NOW_MS))
        entry = registry[case["input"]["fixture"]]
        data = fixture_bytes(fixtures_dir, entry)
        operation = case["operation"]
        if operation == "verifyReceipt":
            text = (
                base64.b64encode(data).decode("ascii")
                if entry["codec"] in ("raw", "base64")
                else data.decode("utf-8")
            )
            op = partial(verifier.verify_receipt, text)
        elif operation == "verifySignedData":
            op = partial(verifier.verify_signed_data, data.decode("utf-8"))
        else:
            raise ValueError(f"{case['id']}: no adapter for operation {operation}")

        # The answer the case expects, before anything is timed.
        result = op()
        outcome = "ok" if result.verified else result.failure.reason.name
        expected = case["expected"]
        if "oneOf" in expected:
            assert outcome in expected["oneOf"], f"{case['id']} answered {outcome}"
        else:
            want = "ok" if expected["status"] == "ok" else expected["reason"]
            assert outcome == want, f"{case['id']} answered {outcome}"
        results.append(measure(operation, case["id"], op))
    return results


def cross_port() -> list[dict[str, Any]]:
    fixtures_dir = Path(__file__).resolve().parents[2] / "fixtures" / "public-receipts"
    roots = None  # the built-in Apple roots
    results = []
    for name, bundle_id, in_app_count, sha256 in FIXTURES:
        der = base64.b64decode((fixtures_dir / f"{name}.b64").read_text(encoding="ascii"))
        assert hashlib.sha256(der).hexdigest() == sha256, f"{name} digest"
        text = base64.b64encode(der).decode("ascii")
        request_json = json.dumps({"receipt-data": text})
        tampered = base64.b64encode(tamper(der)).decode("ascii")
        clock = lambda: NOW_MS  # noqa: E731
        verifier = Verifier(Config(roots=roots, clock=clock))
        sandbox_endpoint = partial(verifier.verify_receipt_endpoint, Environment.SANDBOX)
        production_endpoint = partial(verifier.verify_receipt_endpoint, Environment.PRODUCTION)

        # Every call once, with the answer the conformance suite expects, so
        # no benchmark can time a fast failure by accident. The endpoint's
        # answer is the module's own JSON, read here for the receipt's
        # content.
        assert verifier.verify_receipt(text).verified
        ok = json.loads(sandbox_endpoint(request_json))
        assert ok["status"] == 0 and len(ok["receipt"]["in_app"]) == in_app_count
        assert ok["receipt"]["bundle_id"] == bundle_id
        rejected = json.loads(production_endpoint(json.dumps({"receipt-data": tampered})))
        assert rejected["status"] == 21003

        results += [
            measure("verifierBase64", name, partial(verifier.verify_receipt, text)),
            measure("endpointJson", name, partial(sandbox_endpoint, request_json)),
            measure(
                "rejectTamperedSignature",
                name,
                partial(production_endpoint, json.dumps({"receipt-data": tampered})),
            ),
        ]
    return results


def main() -> None:
    worst = "--worst-case" in sys.argv[1:]
    results = worst_case() if worst else cross_port()
    report = {
        "port": "python",
        "tool": f"bench/bench.py {'worst-case' if worst else 'cross-port'} (timeit)",
        "runtime": f"{platform.python_implementation()} {platform.python_version()}",
        "settings": {"warmup_s": WARMUP_S, "samples": SAMPLES, "min_sample_s": MIN_SAMPLE_S},
        "results": results,
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
