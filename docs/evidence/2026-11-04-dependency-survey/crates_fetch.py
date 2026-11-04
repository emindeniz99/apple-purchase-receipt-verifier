import json, os, sys, time, tomllib, urllib.request, glob
REPO, S = os.environ["REPO"], os.environ["SCRATCH"]
src = REPO
os.makedirs(os.path.join(S, "cache/crates"), exist_ok=True)
names = set()
for f in [f for f in glob.glob(src + "/rust/**/Cargo.lock", recursive=True) if "/target/" not in f]:
    for p in tomllib.load(open(f, "rb")).get("package", []):
        if "registry" in p.get("source", ""):
            names.add(p["name"])
# also direct deps from manifests that may not be in locks
for extra in sys.argv[1:]:
    names.add(extra)
print(len(names), "crates", file=sys.stderr)
for n in sorted(names):
    out = os.path.join(S, "cache/crates", n + ".json")
    if os.path.exists(out):
        continue
    req = urllib.request.Request(f"https://crates.io/api/v1/crates/{n}", headers={"User-Agent": "aprv-dep-audit (read-only audit)"})
    for attempt in range(3):
        try:
            d = json.load(urllib.request.urlopen(req, timeout=60))
            vs = [{"num": v["num"], "created_at": v["created_at"], "yanked": v["yanked"], "rust_version": v.get("rust_version")} for v in d["versions"]]
            json.dump({"name": n, "versions": vs}, open(out, "w"))
            break
        except Exception as e:
            print("err", n, e, file=sys.stderr); time.sleep(3)
    time.sleep(0.6)
