#!/usr/bin/env python3
"""Which WebAssembly proposals does a module or component actually need?

    python3 features.py <file.wasm>...

Leave-one-out with wasm-tools 1.259.0: validate with every feature on,
then with each single feature off. A feature whose removal makes the file
invalid is required. Also reports whether the file validates as plain
WebAssembly 1.0 (wasm1), 2.0 (wasm2) and the "lime1" profile.
"""
import subprocess
import sys

FEATURES = ["mutable-global", "saturating-float-to-int", "sign-extension", "reference-types",
            "multi-value", "bulk-memory", "simd", "relaxed-simd", "threads", "shared-everything-threads",
            "tail-call", "floats", "multi-memory", "exceptions", "memory64", "extended-const",
            "component-model", "function-references", "memory-control", "gc", "custom-page-sizes",
            "legacy-exceptions", "wide-arithmetic", "call-indirect-overlong", "bulk-memory-opt",
            "cm-values", "cm-nested-names", "cm-async", "cm-error-context"]


def ok(path, feats):
    return subprocess.run(["wasm-tools", "validate", "--features", feats, path],
                          capture_output=True).returncode == 0


for path in sys.argv[1:]:
    if not ok(path, "all"):
        print(f"{path.split('/')[-1]}: INVALID even with all features")
        continue
    req = [f for f in FEATURES if not ok(path, f"all,-{f}")]
    profiles = [p for p in ("wasm1", "wasm2", "lime1") if ok(path, p + (",component-model" if "component-model" in req else ""))]
    print(f"{path.split('/')[-1]}: requires {req or ['nothing beyond all-on baseline']}; validates as {profiles or ['none of wasm1/wasm2/lime1']}")
