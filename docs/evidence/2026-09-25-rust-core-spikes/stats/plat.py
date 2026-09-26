import json, urllib.request, re
def get(u): return json.load(urllib.request.urlopen(u, timeout=30))
for pkg in ["pydantic-core","cryptography","orjson","polars","tiktoken"]:
    d=get(f"https://pypi.org/pypi/{pkg}/json")
    tags=set()
    for f in d["urls"]:
        if f["filename"].endswith(".whl"):
            plat=f["filename"][:-4].split("-")[-1]
            for p in plat.split("."):
                p=re.sub(r"manylinux_?\d*_?\d*|manylinux2014|manylinux1","manylinux",p)
                p=re.sub(r"musllinux_\d+_\d+","musllinux",p)
                p=re.sub(r"macosx_\d+_\d+","macosx",p)
                tags.add(p)
    print(f"PyPI {pkg} {d['info']['version']}: {' '.join(sorted(tags))}")
for pkg in ["esbuild","@biomejs/biome","@swc/core"]:
    d=get(f"https://registry.npmjs.org/{pkg}/latest")
    print(f"npm {pkg} {d['version']}: {' '.join(sorted(k.split('/')[-1].replace('cli-','').replace('core-','') for k in d.get('optionalDependencies',{})))}")
