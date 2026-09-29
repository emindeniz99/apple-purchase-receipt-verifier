#!/usr/bin/env python3
"""Spike only (2026-09-27, round 11). Round 9's driver
(../../2026-09-27-wasm-execution-modes/py/driver.py: the 37 ABI tests, the
isolation checks, the corpus runner), unchanged, with one addition: the
in-process host may be any facade module that has an InProcHost.

    driver.py calls|tests FILE.jsonl -- inproc:aprv_wasmi_rs
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "2026-09-27-wasm-execution-modes", "py"))
import driver  # noqa: E402  (round 9)


class InProcAny(driver.InProc):
    def __init__(self, name):
        self.m = importlib.import_module(name)
        self.h = self.m.InProcHost()


argv = sys.argv[sys.argv.index("--") + 1:]
if len(argv) == 1 and argv[0].startswith("inproc:"):
    name = argv[0][len("inproc:"):]
    driver.Host = lambda _argv: InProcAny(name)
    sys.argv[sys.argv.index("--") + 1:] = ["inproc-any"]
driver.main()
