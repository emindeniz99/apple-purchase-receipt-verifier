#!/usr/bin/env python3
"""Evidence only (2026-09-29). Compares corpus rows row by row.

    compare.py same   calls.jsonl a.jsonl b.jsonl [--list]
        a and b are runner rows ({"id", "out"}): counts rows whose `out`
        is identical and prints every row that is not.
    compare.py ref    calls.jsonl ref.jsonl old.jsonl new.jsonl [--list]
        ref is a reference row set from another tree and ABI: the C ABI's
        {"id", "code", "json"} or ABI v1's {"id", "out": "<json text>"}.
        Their taxonomy and payload shapes differ from 0.7's, so rows are
        compared on the verdict alone: verified or refused, and an
        endpoint's status. A row where new's verdict differs from ref's is
        "pre-existing" when old (the pre-migration 0.7 core) gives new's
        verdict too, and "migration" otherwise.
"""
import collections
import json
import sys


def load(path):
    return [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]


def is_endpoint(call):
    return call.get("op") is not None and call["op"] % 256 in (3, 4)


def verdict(call, row):
    """('skip'|'error'|'endpoint'|'verified'|'refused', detail)."""
    if "code" in row:  # the C ABI's rows
        if row["code"] in ("CTOR_REFUSED", "NUL_IN_BODY", "NUL_IN_INPUT", -1, -2, -3, 101):
            return ("error", str(row["code"]))
        doc = json.loads(row["json"]) if row.get("json") else None
        if row["code"] is None:
            return ("endpoint", (doc or {}).get("status"))
        return ("verified", None) if row["code"] == 0 else ("refused", (doc or {}).get("reason"))
    if "out" not in row:  # an ABI v1 row with no call behind it
        return ("skip", None)
    out = row["out"]
    if isinstance(out, str):  # ABI v1's rows
        try:
            out = json.loads(out)
        except ValueError:
            return ("error", out[:40])
        if is_endpoint(call):
            return ("endpoint", out.get("status") if isinstance(out, dict) else None)
    if call.get("op") is None or "skip" in out:
        return ("skip", None)
    if "error" in out:
        return ("error", out["error"])
    if "endpoint" in out:
        e = out["endpoint"]
        return ("endpoint", e.get("status") if isinstance(e, dict) else None)
    return ("verified", None) if out.get("verified") else ("refused", out.get("reason"))


def brief(v):
    return v[0] if v[1] is None else f"{v[0]} {v[1]}"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    listing = "--list" in sys.argv
    mode, calls = args[0], load(args[1])
    if mode == "same":
        a, b = load(args[2]), load(args[3])
        assert len(calls) == len(a) == len(b), (len(calls), len(a), len(b))
        differ = []
        for c, x, y in zip(calls, a, b):
            assert c["id"] == x["id"] == y["id"]
            if x["out"] != y["out"]:
                differ.append((c["id"], x["out"], y["out"]))
        print(f"{len(calls)} rows: {len(calls) - len(differ)} identical, {len(differ)} differ")
        groups = collections.Counter((brief(verdict(c, {"out": x})), brief(verdict(c, {"out": y})))
                                     for (i, x, y), c in zip(differ, [c for c in calls if any(c["id"] == d[0] for d in differ)]))
        for (x, y), n in sorted(groups.items(), key=lambda kv: -kv[1]):
            print(f"  {n:5} {x}  ->  {y}")
        if listing:
            for i, x, y in differ:
                print(f"  {i}\n    a: {json.dumps(x)[:300]}\n    b: {json.dumps(y)[:300]}")
        return
    ref, old, new = load(args[2]), load(args[3]), load(args[4])
    assert len(calls) == len(ref) == len(old) == len(new), (len(calls), len(ref), len(old), len(new))
    counts = collections.Counter()
    groups = collections.Counter()
    migration = []
    for c, r, o, n in zip(calls, ref, old, new):
        assert c["id"] == r["id"] == o["id"] == n["id"]
        vr, vo, vn = verdict(c, r), verdict(c, o), verdict(c, n)
        if vn[0] == "skip" or vr[0] in ("error", "skip"):
            counts["not comparable (no 0.7 call, or the reference ABI refused the input)"] += 1
            continue
        same = vr[0] == vn[0] and (vr[0] != "endpoint" or vr[1] == vn[1])
        if same:
            counts["same verdict"] += 1
        elif vo[:2] == vn[:2] or (vo[0] == vn[0] and vo[0] != "endpoint"):
            counts["different verdict, pre-existing (old core agrees with new)"] += 1
            groups[(brief(vr), brief(vn))] += 1
        else:
            counts["different verdict, migration"] += 1
            migration.append((c["id"], brief(vr), brief(vo), brief(vn)))
    for k, v in sorted(counts.items()):
        print(f"  {v:5} {k}")
    for (x, y), n in sorted(groups.items(), key=lambda kv: -kv[1]):
        print(f"        {n:5} ref {x}  ->  0.7 {y}")
    for i, x, o, y in migration:
        print(f"  migration: {i}: ref {x}, old {o}, new {y}")


if __name__ == "__main__":
    main()
