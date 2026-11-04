// Reports the pins that have fallen behind upstream and that no Dependabot
// ecosystem updates. Dependabot moves rust/rust-toolchain.toml, the
// Dockerfiles' bases, every `uses:` action and the manifests' dependencies,
// but it reads neither shell scripts, nor a version inside a workflow's
// `run:`, `with:` or matrix, nor a workflow's container images, nor a
// plugin's own configuration in a pom, so these pins have no updater of
// their own:
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
//     symfony/process  Packagist, same major only (the newest entry of
//                    php-symfony-process-8's matrix; the other is the floor)
//     schemathesis   PyPI (`uvx --from schemathesis==`)
//     zizmor, ty     PyPI (`uvx zizmor@`, `uvx ty@`)
//     cargo-deny     crates.io (`cargo install cargo-deny --version`)
//   .github/workflows/ci.yml and nightly.yml
//     cargo-fuzz     crates.io (`cargo install cargo-fuzz --version`)
//   .github/workflows/release.yml
//     cargo-cyclonedx  crates.io (`cargo install cargo-cyclonedx --version`)
//     Maven          Maven Central, the 3.9 line only: 3.10 breaks the
//                    Central deploy (the comment on the step says why)
//     build          PyPI (the PyPI job's `pip install build==`)
//   every workflow that runs astral-sh/setup-uv
//     uv             PyPI (setup-uv's `version:`, one per setup-uv step)
//   .github/scripts/install-age.sh
//     age            GitHub releases of FiloSottile/age
//   java/pom.xml, java-wasm/pom.xml, java-bench/pom.xml
//     palantir-java-format  Maven Central (Spotless's <palantirJavaFormat>)
//   rust/vendor/openssl-sys/Cargo.toml
//     openssl-sys    crates.io: not a pin to move but the vendored copy's
//                    upstream. A newer release may accept OpenSSL 4, which
//                    would retire the copy and unblock crates.io publishing
//                    (BOOTSTRAP.md), so its line says to check that.
//   tools/reproduce/Dockerfile
//     rustup         static.rust-lang.org (`ARG RUSTUP_VERSION`); Dependabot
//                    moves that file's base image, not this ARG
//   .github/workflows/*.yml and .github/actions/*/action.yml
//     every image pinned as `name:tag@sha256:...` (or `name@sha256:...`
//     with `# name:tag` after it): behind when the tag now names another
//     digest. Docker Hub and gcr.io give the push time; ghcr.io gives
//     none, so a moved ghcr.io tag is reported with its age unknown.
//
// A pin held in several places must agree in all of them, and a tool
// whose every use must name a version (uv, zizmor, ty, cargo-fuzz,
// cargo-deny) fails the run when one use names none.
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
// authenticates the GitHub API calls. Where the API refuses the request
// (401 or 403: no token, a bad one, or the rate limit), GitHub releases
// are read from the repository's releases.atom feed instead.
import { readFileSync, readdirSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const COOLDOWN_DAYS = 7;
export const DAY = 24 * 60 * 60 * 1000;
export const cutoff = (now) => now - COOLDOWN_DAYS * DAY;

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

const CI = '.github/workflows/ci.yml';
const RELEASE = '.github/workflows/release.yml';

// Every workflow and composite action that uses the tool at all, in place
// of a list of files.
export const WORKFLOWS = '.github/workflows/ and .github/actions/';

// The version pins outside tools/wasm-toolchain.sh: the file (or files)
// that hold each, and the pattern whose first group is the version. A
// listed file must pin it. `every`, when given, matches each use of the
// tool, and a use the pattern does not also match names no version.
// `note` follows the pin's line in the report.
export const OTHER_PINS = [
  { name: 'cbindgen', file: CI, pattern: /cargo install cbindgen --locked --version (\S+)/g },
  { name: 'spectral-cli', file: CI, pattern: /@stoplight\/spectral-cli@(\S+)/g },
  { name: 'Gradle', file: CI, pattern: /gradle-version: "([^"]+)"/g },
  { name: 'rustup', file: 'tools/reproduce/Dockerfile', pattern: /^ARG RUSTUP_VERSION=(\S+)$/gm },
  // The second entry; the first is the 8.x floor the constraint claims.
  { name: 'symfony/process', file: CI, pattern: /symfony-process: \["[^"]+", "([^"]+)"\]/g },
  { name: 'schemathesis', file: CI, pattern: /schemathesis==(\S+)/g },
  { name: 'zizmor', file: CI, pattern: /uvx zizmor@(\S+)/g, every: /uvx zizmor\b/g },
  { name: 'ty', file: CI, pattern: /uvx ty@(\S+)/g, every: /uvx ty\b/g },
  { name: 'cargo-deny', file: CI, pattern: /cargo install cargo-deny --locked --version (\S+)/g, every: /cargo install cargo-deny\b/g },
  {
    name: 'cargo-fuzz',
    files: [CI, '.github/workflows/nightly.yml'],
    pattern: /cargo install cargo-fuzz --locked --version (\S+)/g,
    every: /cargo install cargo-fuzz\b/g,
  },
  // The step's name repeats the version, so both are read.
  { name: 'cargo-cyclonedx', file: RELEASE, pattern: /cargo-cyclonedx (?:--(?!version\b)[^\s"]+ )*(?:--version )?(\d[^\s"]*)/g },
  { name: 'Maven', file: RELEASE, pattern: /apache-maven[/-](\d+\.\d+\.\d+)\b/g },
  { name: 'build', file: RELEASE, pattern: /pip install build==(\S+)/g, every: /pip install (?:--upgrade )?build\b/g },
  // The PIP_CONSTRAINT that build's isolated environment installs under.
  { name: 'setuptools', file: RELEASE, pattern: /setuptools==(\d+(?:\.\d+)*)/g },
  // The newest entry of java-spring-boot's matrix, whether the first names
  // a Boot version or not, and the boot-<version> leg of
  // java-wasm-consumers' `consumer:` matrix. Each matrix must name one.
  {
    name: 'Spring Boot',
    file: CI,
    pattern: /(?:\bboot: \["[^"]+", "|\bboot-)(\d+(?:\.\d+)+)(?="\]|[\s,\]])/g,
    every: /\bboot: \[|\bconsumer: \[[^\]\n]*\bboot-/g,
  },
  // Run through npx by the runtime:* scripts, not installed as
  // devDependencies: as those they would bring native binaries and a
  // postinstall to every npm ci.
  { name: 'bun', file: 'node/package.json', pattern: /npx --yes bun@(\S+)/g },
  { name: 'deno', file: 'node/package.json', pattern: /npx --yes deno@(\S+)/g },
  { name: 'workerd', file: 'node/package.json', pattern: /\bworkerd@(\d+(?:\.\d+)*)/g },
  // npm overrides of transitive packages, which Dependabot never moves.
  { name: 'minimatch', file: 'node/package.json', pattern: /"minimatch": "([^"]+)"/g },
  { name: 'sharp', file: 'node/examples/cloudflare-worker/package.json', pattern: /"sharp": "([^"]+)"/g },
  // setup-uv's `version:` input, in the `with:` block of its own step.
  {
    name: 'uv',
    files: WORKFLOWS,
    pattern: /astral-sh\/setup-uv@[0-9a-f]{40}[^\n]*\n(?: {8,}[^\n]*\n)*? {10,}version: "([^"]+)"/g,
    every: /astral-sh\/setup-uv@/g,
  },
  // AGE_VERSION and both places AGE_URL names it.
  { name: 'age', file: '.github/scripts/install-age.sh', pattern: /(?:AGE_VERSION=v|\/download\/v|\/age-v)(\d+(?:\.\d+)+)/g },
  {
    name: 'palantir-java-format',
    files: ['java/pom.xml', 'java-wasm/pom.xml', 'java-bench/pom.xml'],
    pattern: /<palantirJavaFormat>\s*<version>([^<]+)<\/version>/g,
  },
  {
    name: 'openssl-sys',
    file: 'rust/vendor/openssl-sys/Cargo.toml',
    pattern: /^\[package\]\n(?:(?!\[)[^\n]*\n)*?version = "([^"]+)"/gm,
    note:
      'if this release accepts openssl-src 400.x (OpenSSL 4), the vendored copy and its [patch] can go ' +
      'and crates.io publishing may unblock (BOOTSTRAP.md)',
  },
];

// One version from `text`; a pin that is missing, held at two versions in
// the same file, or used somewhere without one, is an error rather than a
// guess.
export function readPin(text, { name, file, pattern, every }, where = file) {
  const matches = [...text.matchAll(pattern)];
  const found = [...new Set(matches.map((m) => m[1]))];
  if (found.length === 0) throw new Error(`${where} pins no ${name}`);
  if (found.length > 1) throw new Error(`${where} pins ${name} at ${found.join(' and ')}`);
  const uses = every ? [...text.matchAll(every)].length : 0;
  if (uses > matches.length) throw new Error(`${where} runs ${name} ${uses} times and names its version ${matches.length} times`);
  return found[0];
}

// The one version a pin holds across [{ file, text }], and where. Under
// WORKFLOWS, a file that never uses the tool is skipped.
export function pinnedIn(texts, pin) {
  const held = texts
    .filter(({ text }) => pin.files !== WORKFLOWS || [...text.matchAll(pin.every)].length > 0)
    .map(({ file, text }) => ({ file, version: readPin(text, pin, file) }));
  if (held.length === 0) throw new Error(`no workflow pins ${pin.name}`);
  const versions = [...new Set(held.map((h) => h.version))];
  if (versions.length > 1) {
    throw new Error(`${pin.name} is pinned at ${held.map((h) => `${h.version} in ${h.file}`).join(', ')}`);
  }
  return { pinned: versions[0], file: held.map((h) => h.file).join(', ') };
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

export async function request(url, { method = 'GET', headers = {} } = {}) {
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

export const get = async (url, headers) => (await request(url, { headers })).json();

async function crate(name) {
  const body = await get(`https://crates.io/api/v1/crates/${name}/versions`);
  return body.versions.filter((v) => !v.yanked).map((v) => ({ version: v.num, date: v.created_at }));
}

async function npm(name) {
  const body = await get(`https://registry.npmjs.org/${name.replace('/', '%2f')}`);
  return Object.keys(body.versions).map((version) => ({ version, date: body.time[version] }));
}

// A version's date is its first upload that is not yanked: an old yanked
// file must not make a new upload look past the cooldown.
export function pypiReleases(body) {
  return Object.entries(body.releases)
    .map(([version, files]) => [version, files.filter((f) => !f.yanked)])
    .filter(([, files]) => files.length > 0)
    .map(([version, files]) => ({ version, date: files.map((f) => f.upload_time_iso_8601).sort()[0] }));
}

async function pypi(name) {
  return pypiReleases(await get(`https://pypi.org/pypi/${name}/json`));
}

// Packagist's p2 metadata is minified: each version lists only the fields
// that differ from the version before it.
export function packagistReleases(minified) {
  let full = {};
  return minified.map((entry) => {
    full = { ...full, ...entry };
    return { version: full.version.replace(/^v/, ''), date: full.time };
  });
}

async function packagist(name) {
  const body = await get(`https://repo.packagist.org/p2/${name}.json`);
  return packagistReleases(body.packages[name]);
}

// The versions of a Maven Central artifact newer than `pinned` that `keep`
// accepts, each dated by its pom's Last-Modified: maven-metadata.xml lists
// versions with no dates, and search.maven.org's index lags by months.
async function mavenCentral(path, pinned, keep = () => true) {
  const base = `https://repo1.maven.org/maven2/${path}`;
  const artifact = path.split('/').pop();
  const xml = await (await request(`${base}/maven-metadata.xml`)).text();
  const versions = [...xml.matchAll(/<version>([^<]+)<\/version>/g)]
    .map((m) => m[1])
    .filter((v) => /^\d+(\.\d+)*$/.test(v) && keep(v) && newer(v, pinned));
  return Promise.all(
    versions.map(async (version) => {
      const head = await request(`${base}/${version}/${artifact}-${version}.pom`, { method: 'HEAD' });
      const modified = head.headers.get('last-modified');
      if (!modified) throw new Error(`repo1.maven.org: no Last-Modified for ${artifact} ${version}`);
      return { version, date: new Date(modified).toISOString() };
    }),
  );
}

// Whether `version` shares the first `parts` parts of `pinned`.
const sameLine = (pinned, parts) => (version) =>
  version.split('.').slice(0, parts).join('.') === pinned.split('.').slice(0, parts).join('.');

// A repository's releases.atom: its ten newest releases, drafts left out.
// It marks no prerelease, but a prerelease's tag carries a suffix that
// latest() does not take for a version; and it dates an entry by its last
// edit, never earlier than the release, so the cooldown errs long.
export function releasesFeed(xml, tagPrefix) {
  return [...xml.matchAll(/<entry>([\s\S]*?)<\/entry>/g)]
    .map(([, entry]) => {
      const tag = /<link [^>]*href="[^"]*\/releases\/tag\/([^"]+)"/.exec(entry);
      const updated = /<updated>([^<]+)<\/updated>/.exec(entry);
      if (!tag || !updated) throw new Error('github.com: a releases.atom entry names no tag or no date');
      return { tag: decodeURIComponent(tag[1]), date: updated[1] };
    })
    .filter((r) => r.tag.startsWith(tagPrefix))
    .map((r) => ({ version: r.tag.slice(tagPrefix.length), date: r.date }));
}

async function githubReleases(repo, tagPrefix) {
  let releases;
  try {
    releases = await get(`https://api.github.com/repos/${repo}/releases?per_page=100`);
  } catch (error) {
    if (!/: HTTP 40[13]$/.test(error.message)) throw error;
    // The feed holds only the ten newest releases: when none of them is past
    // the cooldown, an older stable one may still be newer than the pin, so
    // the run fails rather than report nothing.
    const feed = releasesFeed(await (await request(`https://github.com/${repo}/releases.atom`)).text(), tagPrefix);
    if (!latest(feed)) throw new Error(`${repo}: releases.atom holds no release past the cooldown`);
    return feed;
  }
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

// A Docker Hub repository (`library/debian`) in the API path Dependabot's
// cooldown reads.
export function hubRepository(repo) {
  const [namespace, ...name] = repo.split('/');
  return `https://hub.docker.com/v2/namespaces/${namespace}/repositories/${name.join('/')}`;
}

// A Docker Hub tag: its `digest` (the index), `tag_last_pushed`, and
// `images[]`, each platform's `digest` and `last_pushed`.
export const hubTag = (repo, tag) => get(`${hubRepository(repo)}/tags/${tag}`);

// When Docker Hub says a tag was last pushed.
export const hubPushed = (t) => t.tag_last_pushed ?? t.last_updated;

// Every digest a gcr.io repository holds, tagged or not, each with its
// `tag` list and `timeUploadedMs`. The registry sets the upload time;
// `timeCreatedMs` comes from the image and is 0 for distroless.
export const gcrManifests = async (repo) => (await get(`https://gcr.io/v2/${repo}/tags/list`)).manifest;

export const gcrUploaded = (m) => new Date(Number(m.timeUploadedMs)).toISOString();

// The digest a tag names now, and when it was pushed (null if unknown).
async function currentDigest({ name, tag }) {
  const { registry, repo } = registryOf(name);
  if (registry === 'docker.io') {
    const t = await hubTag(repo, tag);
    if (!t.digest) throw new Error(`hub.docker.com: ${name}:${tag} has no digest`);
    return { digest: t.digest, date: hubPushed(t) };
  }
  if (registry === 'gcr.io') {
    const manifest = await gcrManifests(repo);
    const hit = Object.entries(manifest).find(([, m]) => (m.tag ?? []).includes(tag));
    if (!hit) throw new Error(`gcr.io: ${name} has no tag ${tag}`);
    return { digest: hit[0], date: gcrUploaded(hit[1]) };
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
  const workflows = workflowFiles(root);
  const others = OTHER_PINS.map((p) => {
    const texts = p.files === WORKFLOWS ? workflows : (p.files ?? [p.file]).map((file) => ({ file, text: read(file) }));
    return { ...p, ...pinnedIn(texts, p) };
  });
  const images = readImages(workflows);
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
    'symfony/process': (pinned) => packagist('symfony/process').then((rs) => rs.filter((r) => sameLine(pinned, 1)(r.version))),
    schemathesis: () => pypi('schemathesis'),
    zizmor: () => pypi('zizmor'),
    ty: () => pypi('ty'),
    'cargo-deny': () => crate('cargo-deny'),
    'cargo-fuzz': () => crate('cargo-fuzz'),
    'cargo-cyclonedx': () => crate('cargo-cyclonedx'),
    Maven: (pinned) => mavenCentral('org/apache/maven/apache-maven', pinned, sameLine(pinned, 2)),
    build: () => pypi('build'),
    setuptools: () => pypi('setuptools'),
    'Spring Boot': (pinned) => mavenCentral('org/springframework/boot/spring-boot-dependencies', pinned, sameLine(pinned, 2)),
    bun: () => npm('bun'),
    deno: () => npm('deno'),
    workerd: () => npm('workerd'),
    minimatch: () => npm('minimatch'),
    sharp: () => npm('sharp'),
    uv: () => pypi('uv'),
    age: () => githubReleases('FiloSottile/age', 'v'),
    'palantir-java-format': (pinned) => mavenCentral('com/palantir/javaformat/palantir-java-format', pinned),
    'openssl-sys': () => crate('openssl-sys'),
  };
  const versions = [
    ...Object.entries(toolchain).map(([name, pinned]) => ({ name, pinned, file: 'tools/wasm-toolchain.sh' })),
    ...others,
  ];
  const [upstream, current] = await Promise.all([
    Promise.all(versions.map((v) => sources[v.name](v.pinned))),
    Promise.all(images.map(currentDigest)),
  ]);

  const behind = [];
  versions.forEach(({ name, pinned, file, note }, i) => {
    const best = latest(upstream[i]);
    if (best && newer(best.version, pinned)) {
      const line = `${file}: ${name} ${pinned} -> ${best.version} (released ${best.date.slice(0, 10)})`;
      behind.push(note ? `${line}: ${note}` : line);
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
