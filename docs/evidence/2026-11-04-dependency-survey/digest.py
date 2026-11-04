import json, sys, urllib.request
ACC = "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"
def token(reg, repo):
    if reg == "registry-1.docker.io":
        u = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
    elif reg == "ghcr.io":
        u = f"https://ghcr.io/token?scope=repository:{repo}:pull"
    else:
        return None
    return json.load(urllib.request.urlopen(u, timeout=30))["token"]
def req(reg, repo, path, tok, acc=ACC, method="GET"):
    h = {"Accept": acc}
    if tok: h["Authorization"] = "Bearer " + tok
    return urllib.request.urlopen(urllib.request.Request(f"https://{reg}/v2/{repo}/{path}", headers=h, method=method), timeout=60)
def created(reg, repo, ref, tok):
    r = req(reg, repo, f"manifests/{ref}", tok); m = json.load(r)
    if "manifests" in m:
        sub = [x for x in m["manifests"] if x.get("platform", {}).get("architecture") == "amd64" and x.get("platform", {}).get("os") == "linux"]
        m = json.load(req(reg, repo, f"manifests/{sub[0]['digest']}", tok))
    cfg = json.load(req(reg, repo, f"blobs/{m['config']['digest']}", tok, acc="*/*"))
    return cfg.get("created")
for arg in sys.argv[1:]:
    ref, pinned = arg.split("@")
    name, tag = ref.rsplit(":", 1)
    if name.startswith(("gcr.io/", "ghcr.io/")):
        reg, repo = name.split("/", 1)
    else:
        reg, repo = "registry-1.docker.io", (name if "/" in name else "library/" + name)
    try:
        tok = token(reg, repo)
        cur = req(reg, repo, f"manifests/{tag}", tok, method="HEAD").headers["Docker-Content-Digest"]
        same = cur == pinned
        out = f"{ref}: pinned {pinned[:19]}.. current {cur[:19]}.. {'SAME' if same else 'DIFFERS'}"
        if not same:
            try: out += f" | pinned created={created(reg, repo, pinned, tok)} current created={created(reg, repo, cur, tok)}"
            except Exception as e: out += f" | created? {e}"
        print(out)
    except Exception as e:
        print(ref, "ERR", e)
