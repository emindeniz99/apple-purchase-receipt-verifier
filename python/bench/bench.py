"""The cross-port benchmark: the same six operations on the same two genuine
sandbox receipts in every port, named after the Java JMH benchmarks in
java-bench/ (BENCHMARKS.md at the repository root has the table).

    uv sync --locked
    uv run --locked python bench/bench.py > python-bench.json

timeit rather than pyperf, which is not a dependency of this project. Each
benchmark warms up for one second, then takes ten samples of at least 100 ms
each, with the garbage collector left on as it is in every other port; the
JSON on stdout carries the median, minimum and maximum microseconds per
operation over those samples.
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

from apple_purchase_receipt_verifier import (
    Reason,
    ReceiptVerifier,
    VerificationError,
    VerifyReceiptEndpoint,
    apple_receipt_roots,
    verify_receipt_core,
)

# The library's own receipt-data decoder, which the package does not export.
from apple_purchase_receipt_verifier._receipt_base64 import decode_receipt_base64

WARMUP_S = 1.0
SAMPLES = 10
MIN_SAMPLE_S = 0.1

# Any fixed instant (2026-01-01T00:00:00Z): it only feeds request_date.
NOW = 1767225600.0

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
    by requiring INVALID_SIGNATURE."""
    tampered = bytearray(der)
    tampered[-128] ^= 0x01
    return bytes(tampered)


def reject(der: bytes, roots: list[Any]) -> object:
    try:
        return verify_receipt_core(der, roots)
    except VerificationError as error:
        return error


def retry_in_sandbox(production: VerifyReceiptEndpoint, request: dict[str, str]) -> str:
    return production.verify_receipt_result(request).to_json("Sandbox")


def main() -> None:
    fixtures_dir = Path(__file__).resolve().parents[2] / "fixtures" / "public-receipts"
    roots = apple_receipt_roots()
    results = []
    for name, bundle_id, in_app_count, sha256 in FIXTURES:
        der = base64.b64decode((fixtures_dir / f"{name}.b64").read_text(encoding="ascii"))
        assert hashlib.sha256(der).hexdigest() == sha256, f"{name} digest"
        text = base64.b64encode(der).decode("ascii")
        request = {"receipt-data": text}
        request_json = json.dumps(request)
        tampered = tamper(der)
        verifier = ReceiptVerifier(roots, bundle_id)
        sandbox = VerifyReceiptEndpoint(roots, "Sandbox", clock=lambda: NOW)
        production = VerifyReceiptEndpoint(roots, "Production", clock=lambda: NOW)

        # Every call once, with the answer the conformance suite expects, so
        # no benchmark can time a fast failure by accident.
        assert decode_receipt_base64(text) == der
        for receipt in (verify_receipt_core(der, roots), verifier.verify(text)):
            assert receipt.bundle_id == bundle_id
            assert len(receipt.in_app_purchases) == in_app_count
        ok = json.loads(sandbox.verify_receipt_json(request_json))
        assert ok["status"] == 0 and len(ok["receipt"]["in_app"]) == in_app_count
        retry = json.loads(production.verify_receipt_result(request).to_json("Sandbox"))
        assert (retry["status"], retry["environment"]) == (0, "Sandbox")
        rejected = reject(tampered, roots)
        assert isinstance(rejected, VerificationError)
        assert rejected.reason == Reason.INVALID_SIGNATURE

        results += [
            measure("decodeBase64", name, partial(decode_receipt_base64, text)),
            measure("core", name, partial(verify_receipt_core, der, roots)),
            measure("verifierBase64", name, partial(verifier.verify, text)),
            measure("endpointJson", name, partial(sandbox.verify_receipt_json, request_json)),
            measure("retryViaResult", name, partial(retry_in_sandbox, production, request)),
            measure("rejectTamperedSignature", name, partial(reject, tampered, roots)),
        ]
    report = {
        "port": "python",
        "tool": "bench/bench.py (timeit)",
        "runtime": f"{platform.python_implementation()} {platform.python_version()}",
        "settings": {"warmup_s": WARMUP_S, "samples": SAMPLES, "min_sample_s": MIN_SAMPLE_S},
        "results": results,
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
