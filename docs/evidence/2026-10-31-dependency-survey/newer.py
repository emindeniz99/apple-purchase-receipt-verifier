import json, os, sys, re, ssl, urllib.request, urllib.parse, time
from concurrent.futures import ThreadPoolExecutor
ctx = ssl.create_default_context()
CUT = os.environ.get('CUT', '2026-10-24')
UA = {'User-Agent': 'aprv-dep-survey (emindeniz99 repo audit)'}

def get(url, raw=False, head=False):
    for i in range(4):
        try:
            r = urllib.request.Request(url, headers=UA, method='HEAD' if head else 'GET')
            resp = urllib.request.urlopen(r, context=ctx, timeout=60)
            if head: return resp.headers
            b = resp.read()
            if b[:2]==b'\x1f\x8b':
                import gzip; b=gzip.decompress(b)
            return b.decode() if raw else json.loads(b)
        except urllib.error.HTTPError as e:
            if e.code == 404: return None
            if e.code == 429: time.sleep(3 + i * 3); continue
            if i == 3: raise
        except Exception:
            if i == 3: raise
            time.sleep(1)

def vkey(v):
    v = v.lstrip('v')
    main, _, pre = v.partition('-')
    nums = [int(x) if x.isdigit() else 0 for x in re.split(r'[.+]', main)[:4]]
    return (nums + [0] * (4 - len(nums)), 0 if pre else 1, pre)

def isPre(v):
    return bool(re.search(r'[-.]?(alpha|beta|rc|pre|preview|dev|a\d|b\d|M\d|SNAPSHOT|canary|next|nightly|insiders|experimental)', v, re.I)) or '-' in v.lstrip('v')

deps = json.load(open(sys.argv[1]))
want = {}
for o in deps:
    want.setdefault((o['eco'], o['name']), set()).add(o['version'])

def newer(versions_dates, ours):
    """versions_dates: list (ver, iso date). return newer-than-max(ours) after CUT, plus newest overall"""
    mo = max(ours, key=vkey)
    rel = [(v, d) for v, d in versions_dates if d and not isPre(v)]
    new = [(v, d[:10]) for v, d in rel if vkey(v) > vkey(mo) and d[:10] >= CUT]
    newest = max(rel, key=lambda x: vkey(x[0]), default=(None, None))
    return mo, sorted(new, key=lambda x: vkey(x[0])), (newest[0], (newest[1] or '')[:10])

def crates(name):
    d = get(f'https://crates.io/api/v1/crates/{name}/versions?per_page=100')
    time.sleep(0.4)
    return [(v['num'], v['created_at']) for v in (d or {}).get('versions', []) if not v.get('yanked')]

def crates_index_max(name):
    n = name.lower()
    p = '1/' + n if len(n) == 1 else '2/' + n if len(n) == 2 else f'3/{n[0]}/' + n if len(n) == 3 else f'{n[:2]}/{n[2:4]}/{n}'
    t = get(f'https://index.crates.io/{p}', raw=True)
    vs = [json.loads(l) for l in t.splitlines() if l.strip()]
    return [x['vers'] for x in vs if not x.get('yanked')]

def npm(name):
    d = get('https://registry.npmjs.org/' + name.replace('/', '%2F'))
    t = d.get('time', {})
    return [(v, t.get(v)) for v in d.get('versions', {})]

def pypi(name):
    d = get(f'https://pypi.org/pypi/{name}/json')
    out = []
    for v, files in d['releases'].items():
        if files and not all(f.get('yanked') for f in files):
            out.append((v, min(f['upload_time_iso_8601'] for f in files)))
    out.append(('_rp_' + str(d['info'].get('requires_python')), None))
    return out

def gems(name):
    d = get(f'https://rubygems.org/api/v1/versions/{name}.json')
    return [(v['number'], v['created_at']) for v in d if v.get('platform') in ('ruby', None)] + [(v['number'], v['created_at']) for v in d if v.get('platform') not in ('ruby', None)]

def gomod(name):
    esc = re.sub(r'[A-Z]', lambda m: '!' + m.group(0).lower(), name)
    t = get(f'https://proxy.golang.org/{esc}/@v/list', raw=True) or ''
    out = []
    for v in t.split():
        info = get(f'https://proxy.golang.org/{esc}/@v/{v}.info')
        out.append((v, info['Time'] if info else None))
    return out

def nuget(name):
    n = name.lower()
    d = get(f'https://api.nuget.org/v3/registration5-gz-semver2/{n}/index.json')
    out = []
    for page in d['items']:
        items = page.get('items') or get(page['@id'])['items']
        for it in items:
            ce = it['catalogEntry']
            if ce.get('listed', True):
                out.append((ce['version'], ce.get('published')))
    return out

def packagist(name):
    d = get(f'https://repo.packagist.org/p2/{name}.json')
    return [(p['version_normalized'] and p['version'].lstrip('v'), p.get('time')) for p in d['packages'][name]]

def maven(name):
    g, a = name.split(':')
    base = f'https://repo1.maven.org/maven2/{g.replace(".", "/")}/{a}'
    t = get(base + '/maven-metadata.xml', raw=True)
    if not t: return []
    vs = re.findall(r'<version>([^<]+)</version>', t)
    return vs

import email.utils
def maven_date(name, v):
    g, a = name.split(':')
    h = get(f'https://repo1.maven.org/maven2/{g.replace(".", "/")}/{a}/{v}/{a}-{v}.pom', head=True)
    if not h: return None
    return email.utils.parsedate_to_datetime(h['Last-Modified']).isoformat()

def work(k):
    eco, name = k
    ours = want[k]
    try:
        if eco == 'crates.io':
            idx = crates_index_max(name)
            mo = max(ours, key=vkey)
            if not any(vkey(v) > vkey(mo) and not isPre(v) for v in idx):
                return k, (mo, [], (mo, ''))
            vd = crates(name)
        elif eco == 'npm': vd = npm(name)
        elif eco == 'PyPI': vd = pypi(name)
        elif eco == 'RubyGems': vd = gems(name)
        elif eco == 'Go': vd = gomod(name)
        elif eco == 'NuGet': vd = nuget(name)
        elif eco == 'Packagist': vd = packagist(name)
        elif eco == 'Maven':
            ours = {v for v in ours if '$' not in v and 'set-me' not in v}
            if not ours: return k, None
            mo = max(ours, key=vkey)
            cands = [v for v in maven(name) if vkey(v) > vkey(mo) and not isPre(v)]
            vd = [(v, maven_date(name, v)) for v in cands] + [(mo, '0000')]
        else:
            return k, None
        extra = [v for v, d in vd if v.startswith('_rp_')]
        vd = [(v, d) for v, d in vd if not v.startswith('_rp_')]
        r = newer(vd, ours)
        return k, r + (extra,)
    except Exception as e:
        return k, ('ERR', repr(e))

import os
ONLY=os.environ.get('ONLY')
keys = [k for k in want if k[0] not in ('SwiftURL', 'Go-toolchain') and (not ONLY or k[0]==ONLY)]
res = {}
with ThreadPoolExecutor(6) as ex:
    for k, r in ex.map(work, keys):
        res['|'.join(k)] = r
json.dump(res, open(sys.argv[2], 'w'), indent=0)
for k, r in sorted(res.items()):
    if r is None: continue
    if r[0] == 'ERR': print('ERR', k, r[1]); continue
    if r[1]: print(k, 'ours', r[0], 'new>=cut', r[1], 'newest', r[2], r[3] if len(r) > 3 else '')
