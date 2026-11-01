"""The `build` step and job time of every build-server leg in recent
successful release.yml runs, with the median and range per target, from
the public GitHub API (no token needed).

    python3 release-timings.py [runs]

Prints one row per run and target, then a summary per target.
"""
import datetime
import json
import statistics
import sys
import urllib.request

REPO = "emindeniz99/apple-purchase-receipt-verifier"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 10


def get(url):
    with urllib.request.urlopen(url) as r:
        return json.load(r)


def t(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))


runs = get(f"https://api.github.com/repos/{REPO}/actions/workflows/release.yml/runs?status=success&per_page={N}")["workflow_runs"]
per = {}
for r in runs:
    jobs = get(f"https://api.github.com/repos/{REPO}/actions/runs/{r['id']}/jobs?per_page=100")["jobs"]
    for j in jobs:
        if not j["name"].startswith("build aprv-server") or not j["completed_at"]:
            continue
        target = j["name"].split("(")[1].rstrip(")")
        job = (t(j["completed_at"]) - t(j["started_at"])).total_seconds()
        step = {s["name"]: (t(s["completed_at"]) - t(s["started_at"])).total_seconds()
                for s in j["steps"] if s.get("started_at") and s.get("completed_at")}
        build = step.get("build")
        repro = step.get("the Linux build reproduces in a fresh clone")
        print(f"{r['id']} {r['head_branch']:>16} {target:28} job {job:5.0f}s build {build or 0:5.0f}s repro {repro or 0:5.0f}s")
        per.setdefault(target, []).append((job, build or 0, repro or 0))
print()
print(f"{'target':28} {'n':>2} {'build median':>12} {'build range':>13} {'job median':>10}")
for target, rows in sorted(per.items()):
    b = [x[1] for x in rows]
    jb = [x[0] for x in rows]
    print(f"{target:28} {len(rows):2} {statistics.median(b):11.0f}s {min(b):5.0f}-{max(b):5.0f}s {statistics.median(jb):9.0f}s")
