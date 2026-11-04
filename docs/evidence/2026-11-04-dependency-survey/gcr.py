import json, sys, urllib.request, datetime
for arg in sys.argv[1:]:
    repo, tag, pinned = arg.split(",")
    d = json.load(urllib.request.urlopen(f"https://gcr.io/v2/{repo}/tags/list", timeout=60))
    m = d["manifest"]
    def t(dg): return datetime.datetime.utcfromtimestamp(int(m[dg]["timeUploadedMs"]) / 1000).isoformat() if dg in m else "?"
    cur = [dg for dg, v in m.items() if tag in v.get("tag", [])]
    # gcr.io keeps only the current tag on a digest, so the tag's earlier
    # digests cannot be told apart from other variants'. The count below is
    # repository-wide; the tag's own answer is "current" against "pinned".
    hist = sorted(((t(dg), dg) for dg, v in m.items() if v.get("mediaType", "").endswith(("index.v1+json", "list.v2+json"))), reverse=True)
    newer = [h for h in hist if h[0] > t(pinned)]
    cur_cooled = cur[0] if cur and t(cur[0]) <= "2026-10-28T23:59:59" else None
    print(f"{repo}:{tag} pinned {pinned[7:19]} uploaded {t(pinned)} | current {cur[0][7:19] if cur else '?'} uploaded {t(cur[0]) if cur else '?'} past cutoff: {'yes' if cur_cooled else 'no'} | newer index digests, repository-wide: {len(newer)}")
