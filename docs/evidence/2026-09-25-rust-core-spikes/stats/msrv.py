import json, urllib.request
for c,v in [("uniffi","0.32.2"),("wasm-bindgen","0.2.129"),("jni","0.22.4"),("diplomat","0.16.1"),("diplomat_core","0.16.1"),("cbindgen","0.29.4")]:
    d=json.load(urllib.request.urlopen(urllib.request.Request(f"https://crates.io/api/v1/crates/{c}/{v}",headers={"User-Agent":"aprv-plan"})))["version"]
    print(f"{c:14} {v:9} declared rust-version={d.get('rust_version')}")
