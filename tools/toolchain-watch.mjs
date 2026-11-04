// Reports the pins that have fallen behind upstream and that no Dependabot
// ecosystem updates. Dependabot moves rust/rust-toolchain.toml, the
// Dockerfiles' bases and every `uses:` action, but it reads neither shell
// scripts, nor a version inside a workflow's `run:` or `with:`, nor a
// workflow's container images, so these pins have no updater of their own:
//
//   tools/wasm-toolchain.sh
//     wasi-sdk       GitHub releases of WebAssembly/wasi-sdk
//     wasm-tools     crates.io
//     wit-bindgen    crates.io (wit-bindgen-cli)
//     OpenSSL        GitHub releases of openssl/openssl, same major only
//   .github/workflows/ci.yml
//     cbindgen       crates.io (`cargo install cbindgen --version`)
//     spectral-cli   npm (`npx @stoplight/spectral-cli@`)
//     Gradle         services.gradle.org (setup-gradle's `gradle-version`)
//   tools/reproduce/Dockerfile
//     rustup         static.rust-lang.org (`ARG RUSTUP_VERSION`); Dependabot
//                    moves that file's base image, not this ARG
//   .github/workflows/*.yml and .github/actions/*/action.yml
//     every image pinned as `name:tag@sha256:...` (or `name@sha256:...`
//     with `# name:tag` after it): behind when the tag now names another
//     digest. Docker Hub and gcr.io give the push time; ghcr.io gives
//     none, so a moved ghcr.io tag is reported with its age unknown.
//
// Like dependabot here (.github/dependabot.yml), a release or a push counts
// only once it is seven days old. Moving a pin stays a reviewed commit: a
// checksum or a digest changes with it, and for the toolchain the module's
// bytes too.
//
// Usage: node tools/toolchain-watch.mjs
//
// Prints one line per pin that is behind, naming the file that holds it,
// and exits 1, or exits 0 when none is. A pin it cannot find, an image it
// cannot read, any network or HTTP failure, and any error in this script
// exit 2 with the reason, never 0 or 1. GITHUB_TOKEN, when set,
// authenticates the GitHub API calls.
import { readFileSync, readdirSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const COOLDOWN_DAYS = 7;
const DAY = 24 * 60 * 60 * 1000;
const cutoff = (now) => now - COOLDOWN_DAYS * DAY;

// The VERSION pins of tools/wasm-toolchain.sh, by name.
export function readPins(text) {
  const pin = (name) => {
    const m = new RegExp(`^${name}_VERSION=(\\S+)$`, 'm').exec(text);
    if (!m) throw new Error(`tools/wasm-toolchain.sh pins no ${name}_VERSION`);
    return m[1];
  };
  return {
    'wasi-sdk': pin('WASI_SDK'),
    'wasm-tools': pin('WASM_TOOLS'),
    'wit-bindgen': pin('WIT_BINDGEN'),
    OpenSSL: pin('OPENSSL'),
  };
}

// The version pins outside tools/wasm-toolchain.sh: the file that holds
// each, and the pattern whose first group is the version.
export const OTHER_PINS = [
  { name: 'cbindgen', file: '.github/workflows/ci.yml', pattern: /cargo install cbindgen --locked --version (\S+)/g },
  { name: 'spectral-cli', file: '.github/workflows/ci.yml', pattern: /@stoplight\/spectral-cli@(\S+)/g },
  { name: 'Gradle', file: '.github/workflows/ci.yml', pattern: /gradle-version: "([^"]+)"/g },
  { name: 'rustup', file: 'tools/reproduce/Dockerfile', pattern: /^ARG RUSTUP_VERSION=(\S+)$/gm },
];

// One version from `text`; a pin that is missing, or held at two versions
// in the same file, is an error rather than a guess.
export function readPin(text, { name, file, pattern }) {
  const found = [...new Set([...text.matchAll(pattern)].map((m) => m[1]))];
  if (found.length === 0) throw new Error(`${file} pins no ${name}`);
  if (found.length > 1) throw new Error(`${file} pins ${name} at ${found.join(' and ')}`);
  return found[0];
}

// Every digest-pinned image in [{ file, text }], one entry per name, tag and
// digest, with the files that use it.
export function readImages(files) {
  const ref = /(?<![\w./:-])([a-z0-9][a-z0-9./_-]*?)(?::([A-Za-z0-9._-]+))?@(sha256:[0-9a-f]{64})([^\n]*)/g;
  const images = new Map();
  for (const { file, text } of files) {
    for (const [, name, written, digest, rest] of text.matchAll(ref)) {
      let tag = written;
      if (!tag) {
        // `name@sha256:...  # last-segment:tag`, as the distroless pins write it.
        const last = name.split('/').pop();
        const comment = /#\s*([a-z0-9._-]+):([A-Za-z0-9._-]+)/.exec(rest);
        if (!comment || comment[1] !== last) throw new Error(`${file}: ${name}@${digest} names no tag to compare against`);
        tag = comment[2];
      }
      const key = `${name}:${tag}@${digest}`;
      const entry = images.get(key) ?? { name, tag, digest, files: [] };
      if (!entry.files.includes(file)) entry.files.push(file);
      images.set(key, entry);
    }
  }
  return [...images.values()];
}

// Where an image name lives: Docker Hub unless the first segment is a host.
export function registryOf(name) {
  const [first, ...rest] = name.split('/');
  if (rest.length > 0 && /[.:]/.test(first)) return { registry: first, repo: rest.join('/') };
  return { registry: 'docker.io', repo: rest.length > 0 ? name : `library/${name}` };
}

// Final Gradle releases from services.gradle.org/versions/all.
export function gradleReleases(all) {
  return all
    .filter((v) => v.final && !v.broken && !v.snapshot && !v.nightly)
    .map((v) => {
      const m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)([+-]\d\d)(\d\d)$/.exec(v.buildTime);
      if (!m) throw new Error(`services.gradle.org: unexpected buildTime ${v.buildTime} for ${v.version}`);
      const local = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7]}:${m[8]}`;
      return { version: v.version, date: new Date(local).toISOString() };
    });
}

// The version static.rust-lang.org/rustup/release-stable.toml names.
export function rustupStable(toml) {
  const m = /^version = '([^']+)'$/m.exec(toml);
  if (!m) throw new Error('static.rust-lang.org: release-stable.toml names no version');
  return m[1];
}

// Numeric, part by part: 4.0.10 is newer than 4.0.9, and 35 than 34.0.
export function newer(candidate, pinned) {
  const a = candidate.split('.').map(Number);
  const b = pinned.split('.').map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d > 0;
  }
  return false;
}

// The newest of [{ version, date }] that is old enough, or null.
export function latest(releases, now = Date.now()) {
  return releases
    .filter((r) => /^\d+(\.\d+)*$/.test(r.version) && Date.parse(r.date) <= cutoff(now))
    .reduce((best, r) => (best === null || newer(r.version, best.version) ? r : best), null);
}

// Whether a pinned image is behind its tag's current { digest, date }:
// null when it is not (same digest, or the new one is still in the
// cooldown), else { digest, date }, date null when the registry gives none.
export function imageBehind(pinned, current, now = Date.now()) {
  if (current.digest === pinned.digest) return null;
  if (current.date === null) return current;
  return Date.parse(current.date) <= cutoff(now) ? current : null;
}

async function request(url, { method = 'GET', headers = {} } = {}) {
  const token = process.env.GITHUB_TOKEN;
  const github = url.startsWith('https://api.github.com/');
  let response;
  try {
    response = await fetch(url, {
      method,
      headers: {
        'User-Agent': 'apple-purchase-receipt-verifier toolchain-watch',
        ...(github ? { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' } : {}),
        ...(github && token ? { Authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    throw new Error(`${url}: ${error.cause?.message ?? error.message}`);
  }
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return response;
}

const get = async (url, headers) => (await request(url, { headers })).json();

async function crate(name) {
  const body = await get(`https://crates.io/api/v1/crates/${name}/versions`);
  return body.versions.filter((v) => !v.yanked).map((v) => ({ version: v.num, date: v.created_at }));
}

async function npm(name) {
  const body = await get(`https://registry.npmjs.org/${name.replace('/', '%2f')}`);
  return Object.keys(body.versions).map((version) => ({ version, date: body.time[version] }));
}

async function githubReleases(repo, tagPrefix) {
  const releases = await get(`https://api.github.com/repos/${repo}/releases?per_page=100`);
  return releases
    .filter((r) => !r.draft && !r.prerelease && r.tag_name.startsWith(tagPrefix))
    .map((r) => ({ version: r.tag_name.slice(tagPrefix.length), date: r.published_at }));
}

async function rustup() {
  const version = rustupStable(await (await request('https://static.rust-lang.org/rustup/release-stable.toml')).text());
  const head = await request(`https://static.rust-lang.org/rustup/archive/${version}/x86_64-unknown-linux-gnu/rustup-init`, { method: 'HEAD' });
  const modified = head.headers.get('last-modified');
  if (!modified) throw new Error(`static.rust-lang.org: no Last-Modified for rustup ${version}`);
  return [{ version, date: new Date(modified).toISOString() }];
}

const INDEX = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
].join(',');

// The digest a tag names now, and when it was pushed (null if unknown).
async function currentDigest({ name, tag }) {
  const { registry, repo } = registryOf(name);
  if (registry === 'docker.io') {
    const t = await get(`https://hub.docker.com/v2/repositories/${repo}/tags/${tag}`);
    if (!t.digest) throw new Error(`hub.docker.com: ${name}:${tag} has no digest`);
    return { digest: t.digest, date: t.tag_last_pushed ?? t.last_updated };
  }
  if (registry === 'gcr.io') {
    const { manifest } = await get(`https://gcr.io/v2/${repo}/tags/list`);
    const hit = Object.entries(manifest).find(([, m]) => (m.tag ?? []).includes(tag));
    if (!hit) throw new Error(`gcr.io: ${name} has no tag ${tag}`);
    return { digest: hit[0], date: new Date(Number(hit[1].timeUploadedMs)).toISOString() };
  }
  if (registry === 'ghcr.io') {
    const { token } = await get(`https://ghcr.io/token?scope=repository:${repo}:pull`);
    const head = await request(`https://ghcr.io/v2/${repo}/manifests/${tag}`, {
      method: 'HEAD',
      headers: { Accept: INDEX, Authorization: `Bearer ${token}` },
    });
    const digest = head.headers.get('docker-content-digest');
    if (!digest) throw new Error(`ghcr.io: ${name}:${tag} answered no digest`);
    return { digest, date: null };
  }
  throw new Error(`${name}: no support for registry ${registry}`);
}

// Every workflow and composite action, as [{ file, text }].
function workflowFiles(root) {
  const files = readdirSync(new URL('.github/workflows/', root))
    .filter((name) => /\.ya?ml$/.test(name))
    .sort()
    .map((name) => `.github/workflows/${name}`);
  for (const dir of readdirSync(new URL('.github/actions/', root), { withFileTypes: true })) {
    if (dir.isDirectory()) files.push(`.github/actions/${dir.name}/action.yml`);
  }
  return files.map((file) => ({ file, text: readFileSync(new URL(file, root), 'utf8') }));
}

export async function main(root = new URL('..', import.meta.url)) {
  const read = (file) => readFileSync(new URL(file, root), 'utf8');
  const toolchain = readPins(read('tools/wasm-toolchain.sh'));
  const others = OTHER_PINS.map((p) => ({ ...p, pinned: readPin(read(p.file), p) }));
  const images = readImages(workflowFiles(root));
  if (images.length === 0) throw new Error('found no digest-pinned image in .github/');

  const major = toolchain.OpenSSL.split('.')[0];
  const sources = {
    'wasi-sdk': () => githubReleases('WebAssembly/wasi-sdk', 'wasi-sdk-'),
    'wasm-tools': () => crate('wasm-tools'),
    'wit-bindgen': () => crate('wit-bindgen-cli'),
    OpenSSL: () =>
      githubReleases('openssl/openssl', `openssl-${major}.`).then((rs) =>
        rs.map((r) => ({ ...r, version: `${major}.${r.version}` })),
      ),
    cbindgen: () => crate('cbindgen'),
    'spectral-cli': () => npm('@stoplight/spectral-cli'),
    Gradle: () => get('https://services.gradle.org/versions/all').then(gradleReleases),
    rustup,
  };
  const versions = [
    ...Object.entries(toolchain).map(([name, pinned]) => ({ name, pinned, file: 'tools/wasm-toolchain.sh' })),
    ...others,
  ];
  const [upstream, current] = await Promise.all([
    Promise.all(versions.map((v) => sources[v.name]())),
    Promise.all(images.map(currentDigest)),
  ]);

  const behind = [];
  versions.forEach(({ name, pinned, file }, i) => {
    const best = latest(upstream[i]);
    if (best && newer(best.version, pinned)) {
      behind.push(`${file}: ${name} ${pinned} -> ${best.version} (released ${best.date.slice(0, 10)})`);
    }
  });
  images.forEach((image, i) => {
    const now = imageBehind(image, current[i]);
    if (!now) return;
    const age = now.date === null ? 'age unknown: the registry gives no push time' : `pushed ${now.date.slice(0, 10)}`;
    behind.push(`${image.files.join(', ')}: ${image.name}:${image.tag} ${image.digest.slice(0, 19)} -> ${now.digest} (${age})`);
  });
  if (behind.length === 0) {
    console.log(`toolchain-watch: all ${versions.length} version pins and ${images.length} image digests are current`);
    return 0;
  }
  console.log(behind.join('\n'));
  return 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exit(await main());
  } catch (error) {
    console.error(`toolchain-watch: ${error.stack ?? error}`);
    process.exit(2);
  }
}
