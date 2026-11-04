import re
import os
CUT = os.environ.get("CUT", "2026-10-28") + "T23:59:59"
def is_stable(v):
    return re.fullmatch(r"v?[0-9]+(\.[0-9]+)*", v) is not None
def key(v):
    v = v.lstrip("v")
    return tuple(int(x) for x in re.findall(r"[0-9]+", v.split("-")[0].split("+")[0]))
def summarize(name, cur, vt, stable_only=True):
    """vt: {version: iso_time}. returns dict"""
    vs = [v for v in vt if vt[v] and (is_stable(v) or not stable_only)]
    vs.sort(key=key)
    if not vs: return None
    latest = vs[-1]
    ok = [v for v in vs if vt[v] <= CUT]
    target = ok[-1] if ok else None
    newer = [v for v in vs if key(v) > key(cur)]
    return {"name": name, "cur": cur, "cur_time": (vt.get(cur) or "")[:10], "latest": latest, "latest_time": vt[latest][:10],
            "target": target, "target_time": vt[target][:10] if target else None,
            "newer": [f"{v}@{vt[v][:10]}" for v in newer]}
def fmt(r):
    if not r: return "?"
    status = "current" if not r["newer"] else ("A" if r["target"] and key(r["target"]) > key(r["cur"]) else "B")
    return f'{status:7} {r["name"]:40} {r["cur"]:>12} ({r["cur_time"]}) -> latest {r["latest"]} ({r["latest_time"]}); cooled target {r["target"]} ({r["target_time"]}); newer: {", ".join(r["newer"][-6:])}'
