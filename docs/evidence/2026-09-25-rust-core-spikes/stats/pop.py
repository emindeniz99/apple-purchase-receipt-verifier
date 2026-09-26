import json, urllib.request
H={"User-Agent":"aprv-plan (emindeniz99)"}
get=lambda u: json.load(urllib.request.urlopen(urllib.request.Request(u,headers=H)))
print("Top crates in category development-tools::ffi, by downloads in the last 90 days:")
d=get("https://crates.io/api/v1/crates?category=development-tools::ffi&sort=recent-downloads&per_page=25")
for i,c in enumerate(d["crates"],1):
    print(f"{i:2}. {c['name']:28} 90d={c['recent_downloads']:>12,}  total={c['downloads']:>13,}  latest={c['max_version']}")
print("\nReverse dependencies (crates on crates.io that depend on it):")
for c in ["jni","uniffi","wasm-bindgen","pyo3","napi","cbindgen","diplomat","flapigen","boltffi"]:
    r=get(f"https://crates.io/api/v1/crates/{c}/reverse_dependencies?per_page=1")
    print(f"  {c:14} {r['meta']['total']:>6,}")
