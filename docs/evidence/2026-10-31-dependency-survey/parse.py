import json, re, sys, os, tomllib, glob
import xml.etree.ElementTree as ET
R = os.environ['REPO']
out = []  # (eco, name, version, file, kind)

def add(eco, name, ver, f, kind=''):
    out.append(dict(eco=eco, name=name, version=ver, file=f, kind=kind))

def rel(p): return os.path.relpath(p, R)

for f in ['rust/Cargo.lock','rust/bindings/abi/tests/Cargo.lock','rust/fuzz/Cargo.lock','rust/fuzz/abi/Cargo.lock','rust/server/Cargo.lock','rust/vendor/openssl-sys/Cargo.lock']:
    d = tomllib.load(open(f'{R}/{f}','rb'))
    for p in d.get('package', []):
        if p.get('source','').startswith('registry+'):
            add('crates.io', p['name'], p['version'], f)

for f in ['node/package-lock.json','tools/package-lock.json','node/examples/cloudflare-worker/package-lock.json']:
    d = json.load(open(f'{R}/{f}'))
    root = d['packages'].get('', {})
    direct = set(root.get('dependencies', {})) | set(root.get('devDependencies', {})) | set(root.get('optionalDependencies', {}))
    for k, v in d['packages'].items():
        if not k or 'version' not in v or v.get('link'): continue
        name = v.get('name') or k.split('node_modules/')[-1]
        kind = ('direct' if name in direct and k == 'node_modules/'+name else 'trans') + ('-dev' if v.get('dev') else '')
        add('npm', name, v['version'], f, kind)

d = tomllib.load(open(f'{R}/python/uv.lock','rb'))
for p in d.get('package', []):
    if 'registry' in p.get('source', {}):
        add('PyPI', p['name'], p['version'], 'python/uv.lock', 'rp=' + str(d.get('requires-python')))

for f in ['ruby/Gemfile.lock','ruby/gemfiles/fuzz.gemfile.lock','ruby/gemfiles/tools.gemfile.lock']:
    seen = set(); sec = None
    for line in open(f'{R}/{f}'):
        if re.match(r'^[A-Z]', line): sec = line.strip(); continue
        m = re.match(r'^    (\S+) \(([^)]+)\)$', line.rstrip('\n'))
        if m and sec == 'GEM':
            v = m.group(2).split('-')[0]
            if (m.group(1), v) not in seen:
                seen.add((m.group(1), v)); add('RubyGems', m.group(1), v, f)

for f in ['go/go.mod','go/tools/go.mod']:
    inreq = False
    for line in open(f'{R}/{f}'):
        s = line.strip()
        if s.startswith('require ('): inreq = True; continue
        if inreq and s == ')': inreq = False; continue
        m = re.match(r'^(?:require\s+)?(\S+)\s+(v\S+)(\s*//\s*indirect)?', s)
        if m and (inreq or s.startswith('require ')):
            add('Go', m.group(1), m.group(2), f, 'indirect' if m.group(3) else 'direct')
        m = re.match(r'^(go|toolchain)\s+(\S+)', s)
        if m: add('Go-toolchain', m.group(1), m.group(2), f)

for f in ['Package.resolved','swift/bench/Package.resolved','swift/fuzz/Package.resolved']:
    d = json.load(open(f'{R}/{f}'))
    for p in d.get('pins', []):
        add('SwiftURL', p['location'], p['state'].get('version') or p['state'].get('revision'), f)

for f in glob.glob(f'{R}/dotnet/**/packages.lock.json', recursive=True):
    d = json.load(open(f)); seen = set()
    for tfm, deps in d['dependencies'].items():
        for n, v in deps.items():
            if v.get('type') == 'Project' or 'resolved' not in v: continue
            if (n, v['resolved']) in seen: continue
            seen.add((n, v['resolved'])); add('NuGet', n, v['resolved'], rel(f), v['type'])

d = json.load(open(f'{R}/php/composer.lock'))
for sec in ['packages', 'packages-dev']:
    for p in d.get(sec, []):
        add('Packagist', p['name'], p['version'].lstrip('v'), 'php/composer.lock', sec)

NS = '{http://maven.apache.org/POM/4.0.0}'
for f in ['java/pom.xml','java-wasm/pom.xml','jvm-interop/pom.xml','java-bench/pom.xml','java/samples/spring-boot-smoke/pom.xml','.github/smoke/maven-smoke/pom.xml']:
    t = ET.parse(f'{R}/{f}').getroot()
    props = {}
    pe = t.find(NS+'properties')
    if pe is not None:
        for c in pe: props[c.tag.replace(NS,'')] = (c.text or '').strip()
    def sub(s):
        for _ in range(3):
            s = re.sub(r'\$\{([^}]+)\}', lambda m: props.get(m.group(1), m.group(0)), s)
        return s
    par = t.find(NS+'parent')
    if par is not None:
        add('Maven', par.find(NS+'groupId').text+':'+par.find(NS+'artifactId').text, par.find(NS+'version').text, f, 'parent')
    for tag in ['dependency', 'plugin', 'extension', 'path']:
        for e in t.iter(NS+tag):
            g = e.find(NS+'groupId'); a = e.find(NS+'artifactId'); v = e.find(NS+'version')
            if a is None or v is None: continue
            gid = g.text if g is not None else 'org.apache.maven.plugins'
            sc = e.find(NS+'scope')
            add('Maven', sub(gid)+':'+sub(a.text), sub(v.text), f, tag + (':'+sc.text if sc is not None else ''))

json.dump(out, open(sys.argv[1], 'w'), indent=0)
from collections import Counter
print(Counter(o['eco'] for o in out))
