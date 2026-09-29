"""Writes standin_differences.txt: the ids of the fixtures/cases.json cases
that fail on the module the package carries, with a count of why. Run it when
the stand-in module is in place and the list needs regenerating; it is not a
test.

    python tests/record_standin_differences.py

With any module but the stand-in the list is not used, and this script
refuses to overwrite it.
"""

import collections
import sys
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support
import test_conformance

HERE = Path(__file__).resolve().parent


def category(case: "dict[str, Any]", result: Any, failure: AssertionError) -> str:
    """Why the case failed, as far as the wrapper's own view tells."""
    operation = case["operation"]
    if operation == "decodeBase64":
        return "text refused as base64 comes back as an unknown reason name (INTERNAL_ERROR)"
    if operation == "verifyReceiptEndpoint":
        return "the endpoint's answer differs from 0.7's"
    if result is None:
        return "no result"
    if result.verified:
        if operation == "verifyReceipt":
            return "verified, but the payload is 0.6's camelCase shape (every field reads None)"
        return "verified, but the signed payload is an object where 0.7 has a JSON string"
    reason = result.failure.reason.name
    cause = result.failure.cause
    if cause is not None and "outside the eight" in str(cause):
        return "rejected under a 0.6 reason name (INTERNAL_ERROR here)"
    if cause is not None and "not a JSON string" in str(cause):
        return "verified, but the signed payload is an object where 0.7 has a JSON string"
    if reason == "INTERNAL_ERROR":
        return "answered INTERNAL_ERROR (the 0.6 answer could not be read)"
    return f"answered {reason}, where 0.7 answers something else (the 0.6 core's own behaviour)"


def main() -> int:
    if not _support.IS_STANDIN:
        print("the bundled module is not the stand-in; nothing to record", file=sys.stderr)
        return 1
    last: dict[str, Any] = {}

    def remember(operation: "Callable[..., Any]") -> "Callable[..., Any]":
        def run(*args: Any) -> Any:
            last["result"] = operation(*args)
            return last["result"]

        return run

    test_conformance.OPERATIONS = {
        name: remember(operation) for name, operation in test_conformance.OPERATIONS.items()
    }
    failing: list[str] = []
    why: collections.Counter[str] = collections.Counter()
    case_test = test_conformance.ConformanceCasesTest("run_case")
    for case in test_conformance.CASES["cases"]:
        last.clear()
        try:
            case_test.run_case(case)
        except (AssertionError, KeyError, TypeError, unittest.SkipTest) as error:
            failing.append(case["id"])
            why[category(case, last.get("result"), AssertionError(str(error)))] += 1
    total = len(test_conformance.CASES["cases"])
    lines = [
        f"# Cases of fixtures/cases.json that fail on the stand-in module "
        f"(sha256 {_support.STANDIN_SHA256}): {len(failing)} of {total}.",
        "# The stand-in is the round-13 core module on the 0.6 core: it answers 0.6's",
        "# JSON shapes and reason names, which the wrapper does not read as 0.7.",
        "# Why, by count:",
        *(f"#   {count:>3}  {reason}" for reason, count in why.most_common()),
        "# Regenerate with `python tests/record_standin_differences.py`; the list is",
        "# ignored for any other module.",
        *failing,
    ]
    (HERE / "standin_differences.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{len(failing)} of {total} cases fail on the stand-in")
    for reason, count in why.most_common():
        print(f"{count:>5}  {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
