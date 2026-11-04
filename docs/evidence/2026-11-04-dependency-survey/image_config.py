# For each <registry>/<repo>@<digest>: the amd64 image config's created time,
# User, Env (JAVA_*, *VERSION*, UV*) and version labels, and the platforms
# of the index. Registry hosts: gcr.io, ghcr.io, registry-1.docker.io.
import json, sys, urllib.request
ACC = "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"
def get(url, acc=ACC, tok=None):
    h = {"Accept": acc}
    if tok: h["Authorization"] = "Bearer " + tok
    return urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=60)
for arg in sys.argv[1:]:
    reg, rest = arg.split("/", 1); repo, dg = rest.split("@")
    tok = None
    if reg == "ghcr.io": tok = json.load(urllib.request.urlopen(f"https://ghcr.io/token?scope=repository:{repo}:pull"))["token"]
    if reg == "registry-1.docker.io": tok = json.load(urllib.request.urlopen(f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"))["token"]
    r = get(f"https://{reg}/v2/{repo}/manifests/{dg}", tok=tok)
    assert r.headers["Docker-Content-Digest"] == dg, (r.headers["Docker-Content-Digest"], dg)
    idx = json.load(r)
    plats = [f'{m["platform"]["os"]}/{m["platform"]["architecture"]}' for m in idx.get("manifests", []) if "platform" in m]
    if "manifests" in idx:
        sub = [m for m in idx["manifests"] if m.get("platform", {}).get("architecture") == "amd64" and m["platform"]["os"] == "linux"][0]
        man = json.load(get(f"https://{reg}/v2/{repo}/manifests/{sub['digest']}", tok=tok))
    else:
        man = idx
    cfg = json.load(get(f"https://{reg}/v2/{repo}/blobs/{man['config']['digest']}", acc="*/*", tok=tok))
    c = cfg.get("config", {})
    env = [e for e in c.get("Env", []) if any(k in e for k in ("JAVA", "VERSION", "UV"))]
    print(arg.split("/")[-1][:40], "| created", cfg.get("created"), "| user", c.get("User"), "| plats", sorted(set(plats)), "| env", env, "| labels", {k: v for k, v in (c.get("Labels") or {}).items() if "version" in k.lower()})
