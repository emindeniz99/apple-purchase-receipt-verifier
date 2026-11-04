# The highest rust_version among the registry crates of one Cargo.lock,
# from the crates_fetch.py cache: usage msrv.py <Cargo.lock> <cache/crates dir>.
import json, sys, tomllib, os
lock, cache = sys.argv[1], sys.argv[2]
def k(v): return tuple(int(x) for x in v.split("."))
rows, missing = [], []
for p in tomllib.load(open(lock, "rb"))["package"]:
    if "registry" not in p.get("source", ""): continue
    f = os.path.join(cache, p["name"] + ".json")
    if not os.path.exists(f): missing.append(p["name"]); continue
    vs = {v["num"]: v for v in json.load(open(f))["versions"]}
    v = vs.get(p["version"])
    if v is None: missing.append(p["name"] + "@" + p["version"]); continue
    rows.append((v["rust_version"] or "", p["name"], p["version"]))
rows.sort(key=lambda r: k(r[0]) if r[0] else (0,), reverse=True)
print("crates:", len(rows), "missing:", missing)
for r in rows[:25]: print(r)
