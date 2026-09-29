import json, urllib.request, time
H={"User-Agent":"aprv-plan (emindeniz99)"}
get=lambda u: json.load(urllib.request.urlopen(urllib.request.Request(u,headers=H)))
seen={}
for kw in ["java","jvm","kotlin","jni"]:
    for page in (1,2):
        d=get(f"https://crates.io/api/v1/crates?keyword={kw}&sort=recent-downloads&per_page=50&page={page}")
        for c in d["crates"]:
            seen.setdefault(c["name"],(c,set()))[1].add(kw)
        time.sleep(0.3)
rows=sorted(seen.values(), key=lambda x:-x[0]["recent_downloads"])[:50]
for i,(c,k) in enumerate(rows,1):
    desc=(c.get("description") or "").replace("\n"," ").strip()[:70]
    print(f"{i:2}. {c['name']:30} 90d={c['recent_downloads']:>11,}  upd={c['updated_at'][:10]}  [{','.join(sorted(k))}]  {desc}")
