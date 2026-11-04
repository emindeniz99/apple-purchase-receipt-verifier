import json, sys, tomllib, os, glob
sys.path.insert(0, os.path.dirname(__file__))
from vlib import key, is_stable, CUT
REPO, S = os.environ["REPO"], os.environ["SCRATCH"]
def compat(a, b):
    ka, kb = key(a), key(b)
    if ka[0] != 0: return ka[0] == kb[0]
    if ka[1] != 0: return kb[0] == 0 and ka[1] == kb[1]
    return ka[:3] == kb[:3]
for lf in ["rust/Cargo.lock", "rust/server/Cargo.lock", "rust/bindings/abi/tests/Cargo.lock", "rust/fuzz/Cargo.lock", "rust/fuzz/abi/Cargo.lock", "rust/vendor/openssl-sys/Cargo.lock"]:
    pk = [p for p in tomllib.load(open(f"{REPO}/{lf}", "rb"))["package"] if "registry" in p.get("source", "")]
    comp, held, major = [], [], []
    for p in pk:
        n, cur = p["name"], p["version"]
        d = json.load(open(f"{S}/cache/crates/{n}.json"))
        vs = [v for v in d["versions"] if not v["yanked"] and is_stable(v["num"].split("+")[0]) and key(v["num"]) > key(cur)]
        c = [v for v in vs if compat(cur, v["num"])]
        cp = [v for v in c if v["created_at"] <= CUT]
        if cp: comp.append(f'{n} {cur}->{max(cp, key=lambda v: key(v["num"]))["num"]}')
        elif c: held.append(f'{n} {cur}->{max(c, key=lambda v: key(v["num"]))["num"]}@{max(c, key=lambda v: key(v["num"]))["created_at"][:10]}')
        elif vs: major.append(n)
    print(f"== {lf}: {len(pk)} registry crates; semver-compatible past cooldown: {len(comp)}; compatible held: {len(held)}; only incompatible newer: {len(major)}")
    print("   compat-past:", "; ".join(comp))
    print("   compat-held:", "; ".join(held))
