import json, sys, urllib.request, re
lock = json.load(open(sys.argv[1]))
cur = {p["name"]: p["version"].lstrip("v") for p in lock["packages"] + lock["packages-dev"]}
for n in sys.argv[2:]:
    d = json.load(urllib.request.urlopen(f"https://repo.packagist.org/p2/{n}.json", timeout=60))
    # p2 is minified: later entries inherit fields from earlier ones
    out, last = [], {}
    for p in d["packages"][n]:
        last = {**last, **{k: v for k, v in p.items() if v != "__unset"}}
        v = last["version"].lstrip("v")
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", v):
            out.append((v, last.get("time", "")[:16], (last.get("require") or {}).get("php")))
    c = cur.get(n)
    line = c.split(".")[0] if c else None
    same = [o for o in out if line and o[0].split(".")[0] == line]
    print(n, "locked", c, "| newest same major:", same[:3], "| newest overall:", out[:3])
