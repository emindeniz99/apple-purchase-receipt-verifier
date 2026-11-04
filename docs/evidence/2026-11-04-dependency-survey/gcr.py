import json, sys, urllib.request, datetime
for arg in sys.argv[1:]:
    repo, tag, pinned = arg.split(",")
    d = json.load(urllib.request.urlopen(f"https://gcr.io/v2/{repo}/tags/list", timeout=60))
    m = d["manifest"]
    def t(dg): return datetime.datetime.utcfromtimestamp(int(m[dg]["timeUploadedMs"]) / 1000).isoformat() if dg in m else "?"
    cur = [dg for dg, v in m.items() if tag in v.get("tag", [])]
    hist = sorted(((t(dg), dg) for dg, v in m.items() if v.get("mediaType", "").endswith(("index.v1+json", "list.v2+json"))), reverse=True)
    newer = [h for h in hist if h[0] > t(pinned)]
    cooled = [h for h in newer if h[0] <= "2026-10-28T23:59:59"]
    print(f"{repo}:{tag} pinned {pinned[7:19]} uploaded {t(pinned)} | current {cur[0][7:19] if cur else '?'} uploaded {t(cur[0]) if cur else '?'} | newer index digests: {len(newer)}, newest past cutoff: {cooled[0] if cooled else '-'}")
