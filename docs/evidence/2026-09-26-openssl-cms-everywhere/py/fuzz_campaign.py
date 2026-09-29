#!/usr/bin/env python3
"""(Copied unchanged from the substrate follow-up.) Summarises libFuzzer logs from scripts/fuzz.sh run: seconds, executions,
exec/s, final coverage (cov = covered edges/counters, ft = features),
corpus size, peak RSS, and every finding libFuzzer reported (crash, leak,
timeout, OOM, deadly signal) with its artifact name.
    python3 fuzz_campaign.py <fuzz dir> > results/fuzz-campaign.txt
"""
import glob
import os
import re
import sys

d = sys.argv[1]
print("# target: seconds execs exec/s | final cov ft corpus | peak_rss_mb | seed files | findings")
for log in sorted(glob.glob(os.path.join(d, "log-*.txt"))):
    name = os.path.basename(log)[4:-4]
    text = open(log, encoding="utf-8", errors="replace").read()
    stat = dict(re.findall(r"^stat::(\S+):\s+(\d+)", text, re.M))
    last = [l for l in text.splitlines() if re.match(r"^#\d+\s", l)]
    m = re.search(r"cov: (\d+) ft: (\d+) corp: (\d+)/(\S+)", last[-1]) if last else None
    inited = re.search(r"^#\d+\s+INITED cov: (\d+) ft: (\d+) corp: (\d+)", text, re.M)
    seeds = re.findall(r"INFO:\s+(\d+) files found in \S*seeds", text)
    findings = re.findall(r"^(==\d+==ERROR: .*|SUMMARY: .*|.*deadly signal.*|.*ALARM: working on the last Unit.*|.*out-of-memory.*|.*Test unit written to .*)$", text, re.M)
    arts = sorted(os.listdir(os.path.join(d, "artifacts-" + name))) if os.path.isdir(os.path.join(d, "artifacts-" + name)) else []
    execs = int(stat.get("number_of_executed_units", 0))
    done = re.search(r"Done (\d+) runs in (\d+) second", text)
    secs = int(done.group(2)) if done else None
    print(f"{name}: {secs or '?'} s, {execs:,} execs, {stat.get('average_exec_per_sec','?')} exec/s"
          f" | start cov {inited.group(1) if inited else '?'} -> final cov {m.group(1) if m else '?'}, ft {m.group(2) if m else '?'}, corpus {m.group(3) if m else '?'} units ({m.group(4) if m else '?'})"
          f" | peak rss {stat.get('peak_rss_mb','?')} MB | seeds {seeds[0] if seeds else '?'} | findings {len(findings)} {findings[:6]} | artifacts {arts}")
