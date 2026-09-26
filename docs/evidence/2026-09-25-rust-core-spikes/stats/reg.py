import json, urllib.request
def get(u):
    return json.load(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "aprv-plan (emindeniz99)"})))
print("crates.io (recent = last 90 days)")
for c in ["uniffi", "uniffi-bindgen-java", "uniffi-dart", "gobley-uniffi-bindgen", "uniffi-bindgen-cs", "uniffi-bindgen-go", "uniffi-bindgen-cpp", "wasm-bindgen", "jni", "cbindgen", "pyo3", "napi"]:
    try:
        d = get("https://crates.io/api/v1/crates/" + c)["crate"]
        print(f"  {c:24} recent={d['recent_downloads']:>11,} total={d['downloads']:>13,} latest={d['max_version']:<14} updated={d['updated_at'][:10]} repo={d.get('repository')}")
    except Exception as e:
        print(f"  {c:24} not on crates.io ({e.__class__.__name__})")
print("npm (last month)")
for p in ["uniffi-bindgen-react-native"]:
    try:
        dl = get("https://api.npmjs.org/downloads/point/last-month/" + p)["downloads"]
        meta = get("https://registry.npmjs.org/" + p)
        print(f"  {p:28} downloads={dl:,} latest={meta['dist-tags']['latest']} repo={meta.get('repository',{}).get('url')} modified={meta['time']['modified'][:10]}")
    except Exception as e:
        print(f"  {p} ERROR {e}")
