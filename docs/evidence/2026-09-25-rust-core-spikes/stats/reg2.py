import json, urllib.request
for c in ["jni","robusta_jni","flapigen","diplomat","diplomat-tool","boltffi","uniffi","uniffi-bindgen-java","jnix","java-locator"]:
    try:
        d=json.load(urllib.request.urlopen(urllib.request.Request("https://crates.io/api/v1/crates/"+c,headers={"User-Agent":"aprv-plan (emindeniz99)"})))["crate"]
        print(f"{c:22} recent90d={d['recent_downloads']:>11,} latest={d['max_version']:<12} updated={d['updated_at'][:10]}")
    except Exception as e: print(f"{c:22} not found")
