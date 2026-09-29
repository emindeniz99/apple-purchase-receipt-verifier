import json, sys, urllib.request
for r in sys.argv[1:]:
    try:
        d = json.load(urllib.request.urlopen(urllib.request.Request("https://api.github.com/repos/" + r, headers={"User-Agent": "x"})))
        print(f"{d['full_name']:42} stars={d['stargazers_count']:>6} last_push={d['pushed_at'][:10]} archived={d['archived']} owner={d['owner']['type']}")
    except Exception as e:
        print(f"{r:42} ERROR {e}")
