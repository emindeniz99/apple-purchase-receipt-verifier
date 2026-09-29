// The package is a facade: no verification logic, no crypto, no trust
// store, no network, no runtime dependency (docs/rust-core/ARCHITECTURE.md
// §9, "One Rust implementation under eight languages"). These scans are the
// package's local copy of the one-implementation gate, so a change that
// brings any of it back fails here before it reaches CI.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const here = (rel) => fileURLToPath(new URL(`../${rel}`, import.meta.url));

function files(dir, suffix) {
  return readdirSync(here(dir), { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(suffix))
    .map((e) => `${e.parentPath.slice(here('').length)}/${e.name}`.replace(/^\/+/, ''));
}

const SOURCES = files('src', '.ts').filter(
  (f) => !f.startsWith('src/generated/') && f !== 'src/roots-data.ts',
);

test('the scan sees the facade sources', () => {
  for (const f of ['src/engine.ts', 'src/verifier.ts', 'src/payload.ts', 'src/load/node.ts']) {
    assert.ok(SOURCES.includes(f), `${f} not in ${SOURCES}`);
  }
});

test('the package declares no runtime dependencies at all', () => {
  const pkg = JSON.parse(readFileSync(here('package.json'), 'utf8'));
  for (const key of [
    'dependencies',
    'peerDependencies',
    'optionalDependencies',
    'bundleDependencies',
  ]) {
    assert.equal(pkg[key], undefined, key);
  }
});

test('the facade imports only itself, the bindings, and node:fs in the Node loader', () => {
  const importRe = /\bfrom\s+'([^']+)'|\bimport\s*\(\s*'([^']+)'/g;
  for (const file of SOURCES) {
    for (const m of readFileSync(here(file), 'utf8').matchAll(importRe)) {
      const spec = m[1] ?? m[2];
      const ok =
        spec.startsWith('./') ||
        spec.startsWith('../') ||
        spec === '#aprv-load' ||
        (spec === 'node:fs' && file === 'src/load/node.ts');
      assert.ok(ok, `${file} imports ${spec}`);
    }
  }
});

test('no facade source parses, hashes, verifies or trusts anything itself', () => {
  // The APIs a verifier would reach for, in any JS runtime.
  const forbidden = [
    /\bcrypto\.subtle\b/,
    /\bsubtle\./,
    /node:crypto/,
    /\bX509Certificate\b/,
    /\bcreate(Verify|PublicKey|Hash|Hmac)\b/,
    /\bverify(Es256|Signature)\b/,
    /\bnode:(tls|https?|net|dns|child_process)\b/,
    /\bfetch\(/,
    /\bprocess\.env\b/,
    /asn1|\bDER\b reader|\bparseCertificate\b|\bcms\b/i,
  ];
  for (const file of SOURCES) {
    const text = readFileSync(here(file), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/.*$/gm, '');
    for (const re of forbidden) {
      // The fetch loader is the one place fetch belongs: it loads the
      // package's own .wasm files.
      if (re.source === '\\bfetch\\(' && file === 'src/load/fetch.ts') {
        continue;
      }
      assert.ok(!re.test(text), `${file} matches ${re}`);
    }
  }
});

test('the only randomness is crypto.getRandomValues, never Math.random', () => {
  for (const file of SOURCES) {
    const text = readFileSync(here(file), 'utf8');
    assert.ok(!/Math\.random/.test(text), file);
  }
  assert.match(readFileSync(here('src/engine.ts'), 'utf8'), /crypto\.getRandomValues/);
});

test("jco's generated glue imports nothing: it runs wherever WebAssembly does", () => {
  const glue = readFileSync(here('dist/generated/aprv.js'), 'utf8');
  assert.ok(
    !/^\s*import\s/m.test(glue) && !/\bimport\s*\(/.test(glue) && !/\brequire\(/.test(glue),
  );
});

test('the browser, workerd and Vercel Edge graphs import no node: module', () => {
  const graph = [
    'dist/index.js',
    'dist/web/index.js',
    'dist/config.js',
    'dist/engine.js',
    'dist/environment.js',
    'dist/errors.js',
    'dist/payload.js',
    'dist/verifier.js',
    'dist/load/fetch.js',
    'dist/load/static.js',
    'dist/load/edge-light.js',
    'dist/load/names.js',
    'dist/generated/aprv.js',
  ];
  for (const file of graph) {
    assert.ok(!/['"]node:/.test(readFileSync(here(file), 'utf8')), file);
  }
});
