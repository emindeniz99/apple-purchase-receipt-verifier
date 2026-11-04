import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import {
  OTHER_PINS,
  WORKFLOWS,
  gradleReleases,
  imageBehind,
  latest,
  main,
  newer,
  packagistReleases,
  pinnedIn,
  readImages,
  readPin,
  readPins,
  registryOf,
  releasesFeed,
  rustupStable,
} from '../toolchain-watch.mjs';

const root = new URL('../../', import.meta.url);
const read = (file) => readFileSync(new URL(file, root), 'utf8');
const pins = readPins(read('tools/wasm-toolchain.sh'));
const workflows = readdirSync(new URL('.github/workflows/', root))
  .filter((name) => name.endsWith('.yml'))
  .map((name) => ({ file: `.github/workflows/${name}`, text: read(`.github/workflows/${name}`) }));
const texts = (p) => (p.files === WORKFLOWS ? workflows : (p.files ?? [p.file]).map((file) => ({ file, text: read(file) })));
const others = Object.fromEntries(OTHER_PINS.map((p) => [p.name, pinnedIn(texts(p), p).pinned]));
const pin = (name) => OTHER_PINS.find((p) => p.name === name);
const images = readImages(workflows);
const DAY = 24 * 60 * 60 * 1000;
const ago = (days) => new Date(Date.now() - days * DAY).toISOString();
const D = (c) => `sha256:${c.repeat(64)}`;

test('reads the four version pins tools/wasm-toolchain.sh builds with', () => {
  assert.deepEqual(Object.keys(pins), ['wasi-sdk', 'wasm-tools', 'wit-bindgen', 'OpenSSL']);
  for (const version of Object.values(pins)) assert.match(version, /^\d+(\.\d+)+$/);
  assert.throws(() => readPins('WASI_SDK_VERSION=34.0\n'), /pins no WASM_TOOLS_VERSION/);
});

test('reads every other pin from the files that hold it', () => {
  assert.deepEqual(Object.keys(others), [
    'cbindgen', 'spectral-cli', 'Gradle', 'rustup', 'symfony/process', 'schemathesis', 'zizmor', 'ty',
    'cargo-deny', 'cargo-fuzz', 'cargo-cyclonedx', 'Maven', 'build', 'setuptools', 'Spring Boot', 'bun',
    'deno', 'workerd', 'minimatch', 'sharp', 'uv', 'age', 'palantir-java-format',
    'openssl-sys',
  ]);
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

test('reads the pins whose shape a regex could misread', () => {
  // symfony/process: the newest entry, not the 8.0.5 floor before it.
  assert.equal(readPin('        symfony-process: ["8.0.5", "8.1.7"]\n', pin('symfony/process')), '8.1.7');
  // Spring Boot: the first entry may be a Boot line or not.
  assert.equal(readPin('        boot: ["4.0.8", "4.1.1"]\n', pin('Spring Boot')), '4.1.1');
  assert.equal(readPin('        boot: ["pom", "4.1.1"]\n', pin('Spring Boot')), '4.1.1');
  // openssl-sys: the package's own version, not a dependency's.
  const manifest = '[package]\nname = "openssl-sys"\nversion = "0.9.117"\n\n[dependencies.libc]\nversion = "0.2"\n';
  assert.equal(readPin(manifest, pin('openssl-sys')), '0.9.117');
  // age: the version and both places the URL names it must agree.
  const age = 'AGE_VERSION=v1.3.2\nAGE_URL=https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz\n';
  assert.equal(readPin(age, pin('age')), '1.3.2');
  assert.throws(() => readPin(age.replace('download/v1.3.2', 'download/v1.3.3'), pin('age')), /pins age at 1\.3\.2 and 1\.3\.3/);
  // cargo-cyclonedx: the step's name repeats the version.
  const cyclonedx = '      - name: install cargo-cyclonedx 0.5.9\n          cargo install cargo-cyclonedx --version 0.5.10 --locked\n';
  assert.throws(() => readPin(cyclonedx, pin('cargo-cyclonedx')), /pins cargo-cyclonedx at 0\.5\.9 and 0\.5\.10/);
});

test('a use that names no version fails the run', () => {
  assert.throws(
    () => readPin('      - run: cargo install cargo-deny --locked\n      - run: cargo install cargo-deny --locked --version 0.20.2\n', pin('cargo-deny')),
    /runs cargo-deny 2 times and names its version 1 times/,
  );
  assert.throws(() => readPin('      - run: uvx zizmor .github/workflows/\n', pin('zizmor')), /pins no zizmor/);
});

test('every setup-uv step names the same uv version', () => {
  const uv = pin('uv');
  const step = (inputs) =>
    ['      - uses: astral-sh/setup-uv@' + 'a'.repeat(40) + ' # v10.3.0', ...inputs, '      - run: uv sync', ''].join('\n');
  const withVersion = step(['        with:', '          version: "0.13.6"', '          enable-cache: false']);
  const conditional = '      - if: matrix.host == \'python\'\n        uses: astral-sh/setup-uv@' + 'a'.repeat(40) + '\n        with:\n          python-version: "3.13"\n          version: "0.13.6"\n';
  assert.deepEqual(
    pinnedIn([{ file: 'a.yml', text: withVersion }, { file: 'b.yml', text: conditional }, { file: 'c.yml', text: 'jobs: {}\n' }], uv),
    { pinned: '0.13.6', file: 'a.yml, b.yml' },
  );
  // A step without one must not borrow the next step's.
  const bare = step([]) + withVersion;
  assert.throws(() => pinnedIn([{ file: 'a.yml', text: bare }], uv), /runs uv 2 times and names its version 1 times/);
  assert.throws(
    () => pinnedIn([{ file: 'a.yml', text: withVersion }, { file: 'b.yml', text: withVersion.replace('0.13.6', '0.13.7') }], uv),
    /uv is pinned at 0\.13\.6 in a\.yml, 0\.13\.7 in b\.yml/,
  );
  assert.throws(() => pinnedIn([{ file: 'c.yml', text: 'jobs: {}\n' }], uv), /no workflow pins uv/);
});

test('the three poms format with the same palantir-java-format', () => {
  const palantir = pin('palantir-java-format');
  const pom = (v) => `<palantirJavaFormat>\n  <version>${v}</version>\n</palantirJavaFormat>\n`;
  assert.throws(
    () => pinnedIn([{ file: 'java/pom.xml', text: pom('2.97.0') }, { file: 'java-bench/pom.xml', text: pom('2.98.0') }], palantir),
    /palantir-java-format is pinned at 2\.97\.0 in java\/pom\.xml, 2\.98\.0 in java-bench\/pom\.xml/,
  );
  // A listed file that lost the pin is an error, not a skip.
  assert.throws(() => pinnedIn([{ file: 'java/pom.xml', text: pom('2.97.0') }, { file: 'java-bench/pom.xml', text: '' }], palantir), /java-bench\/pom\.xml pins no/);
});

test('expands the minified version list Packagist answers with', () => {
  const list = [
    { name: 'symfony/process', version: 'v8.2.0-BETA1', time: '2026-11-03T14:34:49+00:00', require: { php: '>=8.4' } },
    { version: 'v8.1.10', time: '2026-10-25T14:40:25+00:00' },
    { version: 'v8.1.9' },
  ];
  assert.deepEqual(packagistReleases(list), [
    { version: '8.2.0-BETA1', date: '2026-11-03T14:34:49+00:00' },
    { version: '8.1.10', date: '2026-10-25T14:40:25+00:00' },
    // A field left out repeats the previous entry's.
    { version: '8.1.9', date: '2026-10-25T14:40:25+00:00' },
  ]);
});

test('reads releases from a releases.atom feed when the API refuses', () => {
  const entry = (tag, date) =>
    `<entry><id>tag:github.com,2008:Repository/1/${tag}</id><updated>${date}</updated>` +
    `<link rel="alternate" type="text/html" href="https://github.com/FiloSottile/age/releases/tag/${tag}"/><title>age ${tag}</title></entry>`;
  const feed = `<feed>${entry('v1.3.2', '2026-08-29T17:55:50Z')}${entry('v1.3.0-rc.1', '2026-01-01T00:00:00Z')}${entry('other-1.0', '2026-01-01T00:00:00Z')}</feed>`;
  assert.deepEqual(releasesFeed(feed, 'v'), [
    { version: '1.3.2', date: '2026-08-29T17:55:50Z' },
    { version: '1.3.0-rc.1', date: '2026-01-01T00:00:00Z' },
  ]);
  assert.throws(() => releasesFeed('<entry><updated>2026-01-01T00:00:00Z</updated></entry>', 'v'), /names no tag/);
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

// Stands in for the network: the shapes each upstream answers with.
// `releases` maps a pin's name to [version, age in days, extra] rows;
// `moved` maps "name:tag" to the digest and push age (days, or null) the
// tag names now; `fail` makes every URL containing it answer 500.
const SOURCES = [
  [/\/WebAssembly\/wasi-sdk\//, 'wasi-sdk'],
  [/\/openssl\/openssl\//, 'OpenSSL'],
  [/\/FiloSottile\/age\//, 'age'],
  [/\/crates\/wit-bindgen-cli\//, 'wit-bindgen'],
  [/\/crates\/([^/]+)\/versions$/, 1],
  [/registry\.npmjs\.org\/(.+)$/, 1],
  [/pypi\.org\/pypi\/([^/]+)\/json$/, 1],
  [/repo\.packagist\.org\/p2\/(.+)\.json$/, 1],
  [/apache\/maven\/apache-maven\//, 'Maven'],
  [/spring-boot-dependencies\//, 'Spring Boot'],
  [/palantir-java-format\//, 'palantir-java-format'],
  [/services\.gradle\.org/, 'Gradle'],
  [/static\.rust-lang\.org\/rustup\//, 'rustup'],
];
const GITHUB_TAG = { 'wasi-sdk': 'wasi-sdk-', OpenSSL: 'openssl-', age: 'v' };

function upstream({ releases, moved = {}, fail, githubDown = false }) {
  const respond = (body, headers = {}) => ({
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => body,
    headers: { get: (h) => headers[h.toLowerCase()] ?? null },
  });
  const rows = (name) => (releases[name] ?? []).map(([version, days, extra = {}]) => ({ version, date: ago(days), ...extra }));
  const now = (name, tag) => {
    const pinned = images.find((i) => i.name === name && i.tag === tag);
    const [digest, days] = moved[`${name}:${tag}`] ?? [pinned.digest, 400];
    return { digest, date: days === null ? null : ago(days) };
  };
  return async (url, init = {}) => {
    if (fail && url.includes(fail)) return { ok: false, status: 500 };
    let m = /hub\.docker\.com\/v2\/repositories\/(.+)\/tags\/(.+)$/.exec(url);
    if (m) {
      const { digest, date } = now(m[1].replace(/^library\//, ''), m[2]);
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

    const hit = SOURCES.map(([re, name]) => [re.exec(url), name]).find(([match]) => match);
    if (!hit) throw new Error(`unexpected ${init.method ?? 'GET'} ${url}`);
    const name = typeof hit[1] === 'number' ? decodeURIComponent(hit[0][1]) : hit[1];
    const list = rows(name);
    if (url.startsWith('https://api.github.com/')) {
      if (githubDown) return { ok: false, status: 403 };
      return respond(list.map((r) => ({ tag_name: GITHUB_TAG[name] + r.version, published_at: r.date, draft: false, prerelease: false, ...r })));
    }
    if (url.startsWith('https://github.com/')) {
      const entries = list.map(
        (r) => `<entry><updated>${r.date}</updated><link rel="alternate" type="text/html" href="https://github.com/x/y/releases/tag/${GITHUB_TAG[name]}${r.version}"/></entry>`,
      );
      return respond(`<feed>${entries.join('')}</feed>`);
    }
    if (url.includes('crates.io')) return respond({ versions: list.map((r) => ({ num: r.version, created_at: r.date, yanked: false })) });
    if (url.includes('registry.npmjs.org')) {
      return respond({ versions: Object.fromEntries(list.map((r) => [r.version, {}])), time: Object.fromEntries(list.map((r) => [r.version, r.date])) });
    }
    if (url.includes('pypi.org')) {
      return respond({ releases: Object.fromEntries(list.map((r) => [r.version, [{ upload_time_iso_8601: r.date, yanked: false }]])) });
    }
    if (url.includes('packagist.org')) return respond({ packages: { [name]: list.map((r) => ({ version: `v${r.version}`, time: r.date })) } });
    if (url.includes('repo1.maven.org')) {
      if (url.endsWith('maven-metadata.xml')) {
        return respond(`<metadata><versioning><versions>${list.map((r) => `<version>${r.version}</version>`).join('')}</versions></versioning></metadata>`);
      }
      const version = /\/([^/]+)\/[^/]+\.pom$/.exec(url)[1];
      return respond('', { 'last-modified': new Date(list.find((r) => r.version === version).date).toUTCString() });
    }
    if (url.includes('services.gradle.org')) {
      return respond(list.map((r) => ({
        version: r.version, final: r.final ?? true, broken: false, snapshot: false, nightly: false,
        buildTime: r.date.replace(/[-:]/g, '').replace('T', '').slice(0, 14) + '+0000',
      })));
    }
    if (url.endsWith('release-stable.toml')) return respond(`schema-version = '1'\nversion = '${list[0].version}'\n`);
    if (url.includes('/rustup/archive/')) return respond('', { 'last-modified': new Date(list[0].date).toUTCString() });
    throw new Error(`unexpected ${init.method ?? 'GET'} ${url}`);
  };
}

// Every pin's own version, released 30 days ago.
const current = () => ({
  ...Object.fromEntries(Object.entries(pins).map(([name, v]) => [name, [[name === 'wasi-sdk' ? v.split('.')[0] : v, 30]]])),
  ...Object.fromEntries(Object.entries(others).map(([name, v]) => [name, [[v, 30]]])),
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

const total = Object.keys(pins).length + Object.keys(others).length;

test('exit 0 when upstream has nothing newer than the pins', async () => {
  const r = await run(upstream({ releases: current() }));
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, new RegExp(`all ${total} version pins and \\d+ image digests are current`));
});

test('exit 1 names each pin behind with its file, and ignores what is too young or not a release', async () => {
  const major = Number(pins.OpenSSL.split('.')[0]);
  const [mavenMajor, mavenMinor] = others.Maven.split('.').map(Number);
  const [symfonyMajor] = others['symfony/process'].split('.').map(Number);
  const swift = images.find((i) => i.name === 'swift');
  const temurin = images.find((i) => i.name === 'eclipse-temurin');
  const uv = images.find((i) => i.name === 'ghcr.io/astral-sh/uv');
  const r = await run(upstream({
    releases: {
      ...current(),
      'wasi-sdk': [['999', 30]],
      OpenSSL: [[`${major + 1}.0.0`, 30], [`${major}.999.0`, 30, { prerelease: true }], [pins.OpenSSL, 30]],
      cbindgen: [['99.0.0', 10], [others.cbindgen, 30]],
      'spectral-cli': [['99.0.0', 2], ['98.0.0-beta.1', 30], [others['spectral-cli'], 30]],
      Gradle: [['99.0', 3], ['98.0', 30, { final: false }], [others.Gradle, 30]],
      // Another major (Packagist) or line (Maven) is not this pin's upgrade.
      'symfony/process': [[`${symfonyMajor + 1}.0.0`, 30], [`${symfonyMajor}.99.0-BETA1`, 30], [others['symfony/process'], 30]],
      Maven: [[`${mavenMajor}.${mavenMinor + 1}.0`, 30], [`${mavenMajor}.${mavenMinor}.99`, 9], [others.Maven, 30]],
      'palantir-java-format': [['2.999.0', 8], [others['palantir-java-format'], 30]],
      uv: [['9.9.9', 20], [others.uv, 30]],
      'openssl-sys': [['0.9.999', 8], [others['openssl-sys'], 30]],
      workerd: [['1.29991231.1', 1], [others.workerd, 30]],
    },
    moved: {
      [`swift:${swift.tag}`]: [D('9'), 10],
      [`eclipse-temurin:${temurin.tag}`]: [D('8'), 2],
      [`ghcr.io/astral-sh/uv:${uv.tag}`]: [D('7'), null],
    },
  }));
  assert.equal(r.code, 1);
  const lines = r.out.split('\n');
  const has = (line) => assert.ok(lines.includes(line), `missing: ${line}\n${r.out}`);
  has(`tools/wasm-toolchain.sh: wasi-sdk ${pins['wasi-sdk']} -> 999 (released ${ago(30).slice(0, 10)})`);
  has(`.github/workflows/ci.yml: cbindgen ${others.cbindgen} -> 99.0.0 (released ${ago(10).slice(0, 10)})`);
  has(`.github/workflows/release.yml: Maven ${others.Maven} -> ${mavenMajor}.${mavenMinor}.99 (released ${ago(9).slice(0, 10)})`);
  has(`java/pom.xml, java-wasm/pom.xml, java-bench/pom.xml: palantir-java-format ${others['palantir-java-format']} -> 2.999.0 (released ${ago(8).slice(0, 10)})`);
  // uv names every workflow that runs setup-uv.
  const uvLine = lines.find((l) => l.includes(`: uv ${others.uv} -> 9.9.9 `));
  assert.ok(uvLine?.startsWith('.github/workflows/') && uvLine.includes('.github/workflows/ci.yml, '), r.out);
  const sys = lines.find((l) => l.startsWith(`rust/vendor/openssl-sys/Cargo.toml: openssl-sys ${others['openssl-sys']} -> 0.9.999 `));
  assert.match(sys ?? '', /\): if this release accepts openssl-src 400\.x .* crates\.io publishing may unblock/, r.out);
  assert.ok(lines.some((l) => l.startsWith(`${swift.files.join(', ')}: swift:${swift.tag} ${swift.digest.slice(0, 19)} -> ${D('9')} (pushed `)), r.out);
  assert.ok(lines.some((l) => l.includes(`ghcr.io/astral-sh/uv:${uv.tag}`) && l.endsWith('(age unknown: the registry gives no push time)')), r.out);
  assert.equal(lines.length, 8, r.out);
  assert.doesNotMatch(r.out, /: (OpenSSL|spectral-cli|Gradle|symfony\/process|workerd) |eclipse-temurin|rustup/);
});

test('GitHub releases come from releases.atom when the API refuses', async () => {
  const r = await run(upstream({ releases: { ...current(), age: [['9.0.0', 30], ['9.1.0-rc.1', 30], [others.age, 30]] }, githubDown: true }));
  assert.equal(r.code, 1, r.out);
  assert.equal(r.out, `.github/scripts/install-age.sh: age ${others.age} -> 9.0.0 (released ${ago(30).slice(0, 10)})`);
  // Any other failure of the API still fails the run.
  await assert.rejects(run(upstream({ releases: current(), fail: 'api.github.com' })), /HTTP 500/);
});

test('an upstream that fails rejects the whole run, so the CLI exits 2', async () => {
  await assert.rejects(run(upstream({ releases: current(), fail: 'gcr.io/v2/' })), /HTTP 500/);
  await assert.rejects(run(upstream({ releases: current(), fail: 'release-stable.toml' })), /HTTP 500/);
  await assert.rejects(run(upstream({ releases: current(), fail: 'repo1.maven.org' })), /HTTP 500/);
});
