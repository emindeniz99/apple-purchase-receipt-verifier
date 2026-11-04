import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import {
  OTHER_PINS,
  gradleReleases,
  imageBehind,
  latest,
  main,
  newer,
  readImages,
  readPin,
  readPins,
  registryOf,
  rustupStable,
} from '../toolchain-watch.mjs';

const root = new URL('../../', import.meta.url);
const read = (file) => readFileSync(new URL(file, root), 'utf8');
const pins = readPins(read('tools/wasm-toolchain.sh'));
const others = Object.fromEntries(OTHER_PINS.map((p) => [p.name, readPin(read(p.file), p)]));
const images = readImages(
  readdirSync(new URL('.github/workflows/', root))
    .filter((name) => name.endsWith('.yml'))
    .map((name) => ({ file: `.github/workflows/${name}`, text: read(`.github/workflows/${name}`) })),
);
const DAY = 24 * 60 * 60 * 1000;
const ago = (days) => new Date(Date.now() - days * DAY).toISOString();
const D = (c) => `sha256:${c.repeat(64)}`;

test('reads the four version pins tools/wasm-toolchain.sh builds with', () => {
  assert.deepEqual(Object.keys(pins), ['wasi-sdk', 'wasm-tools', 'wit-bindgen', 'OpenSSL']);
  for (const version of Object.values(pins)) assert.match(version, /^\d+(\.\d+)+$/);
  assert.throws(() => readPins('WASI_SDK_VERSION=34.0\n'), /pins no WASM_TOOLS_VERSION/);
});

test('reads cbindgen, spectral-cli, Gradle and rustup from the files that pin them', () => {
  assert.deepEqual(Object.keys(others), ['cbindgen', 'spectral-cli', 'Gradle', 'rustup']);
  for (const version of Object.values(others)) assert.match(version, /^\d+(\.\d+)+$/);
  const cbindgen = OTHER_PINS[0];
  assert.equal(readPin('  cargo install cbindgen --locked --version 0.29.4\n', cbindgen), '0.29.4');
  // A pin moved by hand out of its pattern must fail the run, not vanish
  // from the report.
  assert.throws(() => readPin('cargo install cbindgen\n', cbindgen), /ci\.yml pins no cbindgen/);
  // Two versions in one file is a half-done bump: say so rather than pick one.
  assert.throws(
    () => readPin('cargo install cbindgen --locked --version 0.29.0\ncargo install cbindgen --locked --version 0.29.4\n', cbindgen),
    /pins cbindgen at 0\.29\.0 and 0\.29\.4/,
  );
  const rustup = OTHER_PINS.find((p) => p.name === 'rustup');
  assert.equal(readPin('ARG RUSTUP_VERSION=1.29.2\nARG RUSTUP_SHA256=00\n', rustup), '1.29.2');
});

test('finds every digest-pinned image, tagged in the reference or in a comment', () => {
  const found = readImages([
    { file: 'a.yml', text: [
      '    container: swift:6.3@' + D('a'),
      '            image: gcr.io/distroless/java21-debian13@' + D('b') + ' # java21-debian13:nonroot',
      '          - { image: "ghcr.io/astral-sh/uv:python3.12-alpine@' + D('c') + '" } # python3.12-alpine, uv 0.13.6',
      '      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1',
      'ziglang==0.17.0 --hash=sha256:' + 'd'.repeat(64),
    ].join('\n') },
    { file: 'b.yml', text: '            swift:6.3@' + D('a') + ' \\\n' },
  ]);
  assert.deepEqual(found, [
    { name: 'swift', tag: '6.3', digest: D('a'), files: ['a.yml', 'b.yml'] },
    { name: 'gcr.io/distroless/java21-debian13', tag: 'nonroot', digest: D('b'), files: ['a.yml'] },
    { name: 'ghcr.io/astral-sh/uv', tag: 'python3.12-alpine', digest: D('c'), files: ['a.yml'] },
  ]);
  // A digest with no tag anywhere cannot be compared, and must not be
  // skipped quietly.
  assert.throws(() => readImages([{ file: 'c.yml', text: 'image: gcr.io/distroless/static@' + D('e') }]), /c\.yml: .*names no tag/);
  assert.throws(() => readImages([{ file: 'c.yml', text: 'image: gcr.io/distroless/static@' + D('e') + ' # other:nonroot' }]), /names no tag/);
});

test('the workflows pin the swift, distroless, uv, mono and temurin images by digest', () => {
  const names = new Set(images.map((i) => i.name));
  for (const name of ['swift', 'gcr.io/distroless/java21-debian13', 'ghcr.io/astral-sh/uv', 'mono', 'eclipse-temurin']) {
    assert.ok(names.has(name), `no digest-pinned ${name} found`);
  }
});

test('places an image on its registry', () => {
  assert.deepEqual(registryOf('swift'), { registry: 'docker.io', repo: 'library/swift' });
  assert.deepEqual(registryOf('bitnami/redis'), { registry: 'docker.io', repo: 'bitnami/redis' });
  assert.deepEqual(registryOf('gcr.io/distroless/java21-debian13'), { registry: 'gcr.io', repo: 'distroless/java21-debian13' });
  assert.deepEqual(registryOf('ghcr.io/astral-sh/uv'), { registry: 'ghcr.io', repo: 'astral-sh/uv' });
});

test('takes only final Gradle releases, dated by their build time', () => {
  const all = [
    { version: '9.8.2', buildTime: '20261019162926+0000', final: true, broken: false, snapshot: false, nightly: false },
    { version: '9.9.0-rc-1', buildTime: '20261030141744+0000', final: false, broken: false, snapshot: false, nightly: false },
    { version: '9.9.0-20261103010224+0000', buildTime: '20261103010224+0000', final: false, broken: false, snapshot: true, nightly: false },
    { version: '9.7.0', buildTime: '20260801000000+0000', final: true, broken: true, snapshot: false, nightly: false },
  ];
  assert.deepEqual(gradleReleases(all), [{ version: '9.8.2', date: '2026-10-19T16:29:26.000Z' }]);
  // Gradle 1.0's buildTime is +0200: the offset counts, not just the digits.
  assert.deepEqual(gradleReleases([{ ...all[0], version: '1.0', buildTime: '20120612025621+0200' }]), [
    { version: '1.0', date: '2012-06-12T00:56:21.000Z' },
  ]);
  assert.throws(() => gradleReleases([{ ...all[0], buildTime: '2026-10-19' }]), /unexpected buildTime/);
});

test('reads the rustup version the stable channel names', () => {
  assert.equal(rustupStable("schema-version = '1'\nversion = '1.29.3'\n"), '1.29.3');
  assert.throws(() => rustupStable("schema-version = '1'\n"), /names no version/);
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

test('an image is behind once its tag names another digest pushed over seven days ago', () => {
  const pinned = { digest: D('a') };
  assert.equal(imageBehind(pinned, { digest: D('a'), date: ago(30) }), null, 'same digest');
  assert.equal(imageBehind(pinned, { digest: D('b'), date: ago(3) }), null, 'moved, still in the cooldown');
  const old = ago(8);
  assert.deepEqual(imageBehind(pinned, { digest: D('b'), date: old }), { digest: D('b'), date: old }, 'moved eight days ago');
  // No push time (ghcr.io): reported, never assumed young.
  assert.deepEqual(imageBehind(pinned, { digest: D('b'), date: null }), { digest: D('b'), date: null });
});

// Stands in for the network: the shapes each upstream answers with. `moved`
// maps "name:tag" to the digest and push age (days, or null) the tag names now.
function upstream({ wasiSdk, wasmTools, witBindgen, openssl, cbindgen, spectral, gradle, rustup, moved = {}, fail }) {
  const respond = (body, headers = {}) => ({
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => body,
    headers: { get: (h) => headers[h.toLowerCase()] ?? null },
  });
  const crate = (versions) => respond({ versions: versions.map(([num, days]) => ({ num, created_at: ago(days), yanked: false })) });
  const release = (tag, days, extra = {}) => ({ tag_name: tag, published_at: ago(days), draft: false, prerelease: false, ...extra });
  const now = (name, tag) => {
    const pin = images.find((i) => i.name === name && i.tag === tag);
    const [digest, days] = moved[`${name}:${tag}`] ?? [pin.digest, 400];
    return { digest, date: days === null ? null : ago(days) };
  };
  return async (url, init = {}) => {
    if (fail && url.includes(fail)) return { ok: false, status: 500 };
    if (url.includes('/WebAssembly/wasi-sdk/')) return respond(wasiSdk.map(([v, d]) => release(`wasi-sdk-${v}`, d)));
    if (url.includes('/crates/wasm-tools/')) return crate(wasmTools);
    if (url.includes('/crates/wit-bindgen-cli/')) return crate(witBindgen);
    if (url.includes('/crates/cbindgen/')) return crate(cbindgen);
    if (url.includes('/openssl/openssl/')) return respond(openssl.map(([v, d, extra]) => release(`openssl-${v}`, d, extra)));
    if (url.includes('registry.npmjs.org')) {
      return respond({ versions: Object.fromEntries(spectral.map(([v]) => [v, {}])), time: Object.fromEntries(spectral.map(([v, d]) => [v, ago(d)])) });
    }
    if (url.includes('services.gradle.org')) {
      return respond(gradle.map(([version, days, final = true]) => ({
        version, final, broken: false, snapshot: false, nightly: false,
        buildTime: ago(days).replace(/[-:]/g, '').replace('T', '').slice(0, 14) + '+0000',
      })));
    }
    if (url.endsWith('release-stable.toml')) return respond(`schema-version = '1'\nversion = '${rustup[0]}'\n`);
    if (url.includes('/rustup/archive/')) return respond('', { 'last-modified': new Date(ago(rustup[1])).toUTCString() });
    let m = /hub\.docker\.com\/v2\/repositories\/(.+)\/tags\/(.+)$/.exec(url);
    if (m) {
      const name = m[1].replace(/^library\//, '');
      const { digest, date } = now(name, m[2]);
      return respond({ digest, tag_last_pushed: date });
    }
    m = /gcr\.io\/v2\/(.+)\/tags\/list$/.exec(url);
    if (m) {
      const manifest = {};
      for (const i of images.filter((i) => i.name === `gcr.io/${m[1]}`)) {
        const { digest, date } = now(i.name, i.tag);
        manifest[digest] = { tag: [i.tag], timeUploadedMs: String(Date.parse(date)) };
      }
      return respond({ manifest });
    }
    if (url.startsWith('https://ghcr.io/token')) return respond({ token: 't' });
    m = /ghcr\.io\/v2\/(.+)\/manifests\/(.+)$/.exec(url);
    if (m && init.method === 'HEAD') return respond(null, { 'docker-content-digest': now(`ghcr.io/${m[1]}`, m[2]).digest });
    throw new Error(`unexpected ${init.method ?? 'GET'} ${url}`);
  };
}

const current = () => ({
  wasiSdk: [[pins['wasi-sdk'].split('.')[0], 30]],
  wasmTools: [[pins['wasm-tools'], 30]],
  witBindgen: [[pins['wit-bindgen'], 30]],
  openssl: [[pins.OpenSSL, 30]],
  cbindgen: [[others.cbindgen, 30]],
  spectral: [[others['spectral-cli'], 30]],
  gradle: [[others.Gradle, 30]],
  rustup: [others.rustup, 30],
});

async function run(fake) {
  const saved = { fetch: globalThis.fetch, log: console.log };
  const lines = [];
  globalThis.fetch = fake;
  console.log = (line) => lines.push(line);
  try {
    return { code: await main(root), out: lines.join('\n') };
  } finally {
    globalThis.fetch = saved.fetch;
    console.log = saved.log;
  }
}

test('exit 0 when upstream has nothing newer than the pins', async () => {
  const r = await run(upstream(current()));
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /all 8 version pins and \d+ image digests are current/);
});

test('exit 1 names each pin behind with its file, and ignores what is too young or not a release', async () => {
  const major = Number(pins.OpenSSL.split('.')[0]);
  const swift = images.find((i) => i.name === 'swift');
  const temurin = images.find((i) => i.name === 'eclipse-temurin');
  const uv = images.find((i) => i.name === 'ghcr.io/astral-sh/uv');
  const r = await run(upstream({
    ...current(),
    wasiSdk: [['999', 30]],
    openssl: [
      [`${major + 1}.0.0`, 30],
      [`${major}.999.0`, 30, { prerelease: true }],
      [pins.OpenSSL, 30],
    ],
    cbindgen: [['99.0.0', 10], [others.cbindgen, 30]],
    spectral: [['99.0.0', 2], ['98.0.0-beta.1', 30], [others['spectral-cli'], 30]],
    gradle: [['99.0', 3], ['98.0', 30, false], [others.Gradle, 30]],
    moved: {
      [`swift:${swift.tag}`]: [D('9'), 10],
      [`eclipse-temurin:${temurin.tag}`]: [D('8'), 2],
      [`ghcr.io/astral-sh/uv:${uv.tag}`]: [D('7'), null],
    },
  }));
  assert.equal(r.code, 1);
  const lines = r.out.split('\n');
  assert.ok(lines.includes(`tools/wasm-toolchain.sh: wasi-sdk ${pins['wasi-sdk']} -> 999 (released ${ago(30).slice(0, 10)})`), r.out);
  assert.ok(lines.includes(`.github/workflows/ci.yml: cbindgen ${others.cbindgen} -> 99.0.0 (released ${ago(10).slice(0, 10)})`), r.out);
  assert.ok(lines.some((l) => l.startsWith(`${swift.files.join(', ')}: swift:${swift.tag} ${swift.digest.slice(0, 19)} -> ${D('9')} (pushed `)), r.out);
  assert.ok(lines.some((l) => l.includes(`ghcr.io/astral-sh/uv:${uv.tag}`) && l.endsWith('(age unknown: the registry gives no push time)')), r.out);
  assert.equal(lines.length, 4, r.out);
  assert.doesNotMatch(r.out, /OpenSSL|spectral-cli|Gradle|eclipse-temurin|rustup/);
});

test('an upstream that fails rejects the whole run, so the CLI exits 2', async () => {
  await assert.rejects(run(upstream({ ...current(), fail: 'gcr.io/v2/' })), /HTTP 500/);
  await assert.rejects(run(upstream({ ...current(), fail: 'release-stable.toml' })), /HTTP 500/);
});
