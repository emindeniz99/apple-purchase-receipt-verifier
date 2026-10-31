import json, sys, urllib.request, ssl
ctx = ssl.create_default_context()
deps = json.load(open(sys.argv[1]))
uniq = {}
for o in deps:
    eco = o['eco']; n = o['name']; v = o['version']
    if eco == 'Go-toolchain':
        if n == 'go': uniq[('Go', 'stdlib', v)] = 1
        continue
    if eco == 'Go': v = v.lstrip('v')
    if eco == 'Maven' and ('$' in v or 'set-me' in v): continue
    if eco == 'SwiftURL':
        base = n[:-4] if n.endswith('.git') else n
        for nn in {base, base + '.git', base.replace('https://', '')}:
            uniq[(eco, nn, v)] = 1
        continue
    uniq[(eco, n, v)] = 1
keys = list(uniq)
res = {}
def post(url, body):
    r = urllib.request.Request(url, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
    return json.load(urllib.request.urlopen(r, context=ctx, timeout=60))
for i in range(0, len(keys), 500):
    chunk = keys[i:i+500]
    q = {'queries': [{'package': {'ecosystem': e, 'name': n}, 'version': v} for e, n, v in chunk]}
    r = post('https://api.osv.dev/v1/querybatch', q)
    for k, rr in zip(chunk, r['results']):
        if rr.get('vulns'):
            res['|'.join(k)] = [x['id'] for x in rr['vulns']]
print(len(keys), 'queried;', len(res), 'hits')
ids = sorted({i for v in res.values() for i in v})
details = {}
for i in ids:
    details[i] = json.load(urllib.request.urlopen(f'https://api.osv.dev/v1/vulns/{i}', context=ctx, timeout=60))
json.dump({'hits': res, 'details': details}, open(sys.argv[2], 'w'))
for k, v in res.items():
    e, n, ver = k.split('|')
    for i in v:
        d = details[i]
        fixed = []
        for a in d.get('affected', []):
            if a['package']['name'].lower().rstrip('.git') != n.lower().rstrip('.git') and a['package']['name'] != n: continue
            for rg in a.get('ranges', []):
                for ev in rg.get('events', []):
                    if 'fixed' in ev: fixed.append(ev['fixed'])
        sev = d.get('database_specific', {}).get('severity') or [s.get('score') for s in d.get('severity', [])]
        print(f"{e}\t{n}\t{ver}\t{i}\t{d.get('aliases')}\t{sev}\tfixed={fixed}\t{d.get('summary','')[:90]}")
