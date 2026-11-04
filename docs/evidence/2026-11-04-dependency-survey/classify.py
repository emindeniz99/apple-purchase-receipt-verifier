# Post-processing for the 2026-10-31 survey's newer.py run with CUT=0000-00-00:
# splits each "newer" list at the cooldown cutoff.
import json, sys
CUT = sys.argv[3] if len(sys.argv) > 3 else "2026-10-28"
deps = json.load(open(sys.argv[1])); res = json.load(open(sys.argv[2]))
where = {}
for o in deps:
    where.setdefault((o["eco"], o["name"]), set()).add(f'{o["file"]}[{o["kind"]}]@{o["version"]}')
for k, r in sorted(res.items()):
    if r is None: continue
    if r[0] == "ERR": print("ERR", k, r[1]); continue
    ours, new = r[0], r[1]
    if not new: continue
    past = [v for v in new if v[1] <= CUT]; held = [v for v in new if v[1] > CUT]
    tag = "A" if past else "B"
    eco, name = k.split("|", 1)
    print(f"{tag}\t{k}\tours={ours}\tpast={past[-1] if past else '-'}\theld={[v for v in held][-3:]}\tnewest={r[2]}\t{sorted(where[(eco,name)])[:4]}")
