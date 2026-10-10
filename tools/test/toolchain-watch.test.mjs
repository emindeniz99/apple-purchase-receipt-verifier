import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { latest, main, newer, readPins } from '../toolchain-watch.mjs';

const pins = readPins(readFileSync(new URL('../wasm-toolchain.sh', import.meta.url), 'utf8'));
const DAY = 24 * 60 * 60 * 1000;
const ago = (days) => new Date(Date.now() - days * DAY).toISOString();

test('reads the four version pins tools/wasm-toolchain.sh builds with', () => {
  assert.deepEqual(Object.keys(pins), ['wasi-sdk', 'wasm-tools', 'wit-bindgen', 'OpenSSL']);
  for (const version of Object.values(pins)) assert.match(version, /^\d+(\.\d+)+$/);
  assert.throws(() => readPins('WASI_SDK_VERSION=34.0\n'), /pins no WASM_TOOLS_VERSION/);
});

test('compares versions as numbers, part by part', () => {
  assert.ok(newer('4.0.10', '4.0.9'), 'a string compare would call 4.0.10 older');
  assert.ok(newer('35', '34.0'), 'a wasi-sdk tag has no minor part');
  assert.ok(!newer('34', '34.0'));
  assert.ok(!newer('1.261.0', '1.261.0'));
});

test('a release younger than the seven-day cooldown is not reported yet', () => {
  const releases = [
    { version: '1.260.0', date: ago(20) },
    { version: '1.261.0', date: ago(3) },
    { version: 'not-a-version', date: ago(30) },
  ];
  assert.equal(latest(releases).version, '1.260.0');
  assert.equal(latest([{ version: '1.0.0', date: ago(1) }]), null);
});

// Stands in for the network: the shapes crates.io and the GitHub releases API
// answer with.
function upstream({ wasiSdk, wasmTools, witBindgen, openssl }) {
  const json = (body) => ({ ok: true, status: 200, json: async () => body });
  const crate = (versions) => json({ versions: versions.map(([num, days]) => ({ num, created_at: ago(days), yanked: false })) });
  const release = (tag, days, extra = {}) => ({ tag_name: tag, published_at: ago(days), draft: false, prerelease: false, ...extra });
  return async (url) => {
    if (url.includes('/WebAssembly/wasi-sdk/')) return json(wasiSdk.map(([v, d]) => release(`wasi-sdk-${v}`, d)));
    if (url.includes('/crates/wasm-tools/')) return crate(wasmTools);
    if (url.includes('/crates/wit-bindgen-cli/')) return crate(witBindgen);
    if (url.includes('/openssl/openssl/')) return json(openssl.map(([v, d, extra]) => release(`openssl-${v}`, d, extra)));
    throw new Error(`unexpected ${url}`);
  };
}

async function run(fake) {
  const saved = { fetch: globalThis.fetch, log: console.log };
  const lines = [];
  globalThis.fetch = fake;
  console.log = (line) => lines.push(line);
  try {
    return { code: await main(), out: lines.join('\n') };
  } finally {
    globalThis.fetch = saved.fetch;
    console.log = saved.log;
  }
}

test('exit 0 when upstream has nothing newer than the pins', async () => {
  const r = await run(upstream({
    wasiSdk: [[pins['wasi-sdk'].split('.')[0], 30]],
    wasmTools: [[pins['wasm-tools'], 30]],
    witBindgen: [[pins['wit-bindgen'], 30]],
    openssl: [[pins.OpenSSL, 30]],
  }));
  assert.equal(r.code, 0, r.out);
});

test('exit 1 names each pin behind, and ignores another OpenSSL major and prereleases', async () => {
  const major = Number(pins.OpenSSL.split('.')[0]);
  const r = await run(upstream({
    wasiSdk: [['999', 30]],
    wasmTools: [[pins['wasm-tools'], 30]],
    witBindgen: [[pins['wit-bindgen'], 30]],
    openssl: [
      [`${major + 1}.0.0`, 30],
      [`${major}.999.0`, 30, { prerelease: true }],
      [pins.OpenSSL, 30],
    ],
  }));
  assert.equal(r.code, 1);
  assert.match(r.out, new RegExp(`^wasi-sdk: pinned ${pins['wasi-sdk'].replace(/\./g, '\\.')}, 999 released `));
  assert.doesNotMatch(r.out, /OpenSSL|wasm-tools|wit-bindgen/);
});
