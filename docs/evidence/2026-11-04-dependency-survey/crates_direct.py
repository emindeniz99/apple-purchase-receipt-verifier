import json, sys, tomllib, os
sys.path.insert(0, os.path.dirname(__file__))
from vlib import key, is_stable, CUT
REPO, S = os.environ["REPO"], os.environ["SCRATCH"]
direct = {
 "rust/Cargo.lock": "base64 jiff serde_json openssl openssl-sys foreign-types libc cc asn1-rs libtest-mimic hex serde jsonschema wit-bindgen",
 "rust/server/Cargo.lock": "wasmtime getrandom sha2 base64 pem serde_json axum tokio http-body-util clap subtle serde_yaml_ng wat tower",
 "rust/bindings/abi/tests/Cargo.lock": "base64 wasmtime getrandom serde_json",
 "rust/fuzz/Cargo.lock": "libfuzzer-sys serde_json openssl openssl-sys foreign-types base64 jiff libc cc serde",
 "rust/fuzz/abi/Cargo.lock": "base64 libfuzzer-sys wasmtime",
}
for lf, names in direct.items():
    lock = {}
    for p in tomllib.load(open(f"{REPO}/{lf}", "rb"))["package"]:
        if "registry" in p.get("source", ""):
            lock.setdefault(p["name"], []).append(p["version"])
    print("==", lf)
    for n in names.split():
        if n not in lock: print("  (not in lock)", n); continue
        cur = max(lock[n], key=key)
        d = json.load(open(f"{S}/cache/crates/{n}.json"))
        vs = [v for v in d["versions"] if not v["yanked"] and is_stable(v["num"].split("+")[0])]
        newer = sorted([v for v in vs if key(v["num"]) > key(cur)], key=lambda v: key(v["num"]))
        if not newer: print(f"  current {n} {cur}"); continue
        past = [v for v in newer if v["created_at"] <= CUT]
        held = [v for v in newer if v["created_at"] > CUT]
        def f(v): return f'{v["num"]}@{v["created_at"][:16]}(msrv {v["rust_version"]})'
        print(f'  {"A" if past else "B"} {n} {cur} -> past: {f(past[-1]) if past else "-"}; held: {", ".join(f(v) for v in held[-3:]) or "-"}; all newer: {[v["num"] for v in newer][-8:]}')
