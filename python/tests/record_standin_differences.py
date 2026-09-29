"""Writes standin_differences.txt: the ids of the fixtures/cases.json cases
that fail on the module the package carries. Run it when the stand-in module
is in place and the list needs regenerating; it is not a test.

    python tests/record_standin_differences.py

With any module but the stand-in the list is not used, and this script
refuses to overwrite it.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support
import test_conformance


def main() -> int:
    if not _support.IS_STANDIN:
        print("the bundled module is not the stand-in; nothing to record", file=sys.stderr)
        return 1
    failing = []
    case_test = test_conformance.ConformanceCasesTest("run_case")
    for case in test_conformance.CASES["cases"]:
        try:
            case_test.run_case(case)
        except (AssertionError, KeyError, TypeError, unittest.SkipTest):
            failing.append(case["id"])
    total = len(test_conformance.CASES["cases"])
    header = (
        f"# Cases of fixtures/cases.json that fail on the stand-in module "
        f"(sha256 {_support.STANDIN_SHA256}): {len(failing)} of {total}.\n"
        "# The stand-in is the round-13 core module on the 0.6 core: it answers 0.6's\n"
        "# JSON shapes and reason names, which the wrapper does not read as 0.7.\n"
        "# Regenerate with `python tests/record_standin_differences.py`; the list is\n"
        "# ignored for any other module.\n"
    )
    (Path(__file__).resolve().parent / "standin_differences.txt").write_text(
        header + "\n".join(failing) + "\n", encoding="utf-8"
    )
    print(f"{len(failing)} of {total} cases fail on the stand-in")
    return 0


if __name__ == "__main__":
    sys.exit(main())
