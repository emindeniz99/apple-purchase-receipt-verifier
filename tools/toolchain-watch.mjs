// Reports the build toolchain pins in tools/wasm-toolchain.sh that have
// fallen behind upstream. Dependabot updates rust/rust-toolchain.toml and
// the Dockerfiles but cannot read a shell script, so these four pins have
// no updater of their own:
//
//   wasi-sdk     GitHub releases of WebAssembly/wasi-sdk
//   wasm-tools   crates.io
//   wit-bindgen  crates.io (wit-bindgen-cli)
//   OpenSSL      GitHub releases of openssl/openssl, same major only
//
// Like dependabot here (.github/dependabot.yml), a release counts only once
// it is seven days old. Moving a pin stays a reviewed commit: the archive's
// SHA-256 changes with it, and the module's bytes too.
//
// Usage: node tools/toolchain-watch.mjs
//
// Prints one line per pin that is behind and exits 1, or exits 0 when none
// is. Any network or HTTP failure, and any error in this script, exits 2
// with the reason, never 0 or 1. GITHUB_TOKEN, when set, authenticates the
// GitHub API calls.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const COOLDOWN_DAYS = 7;

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
  const cutoff = now - COOLDOWN_DAYS * 24 * 60 * 60 * 1000;
  return releases
    .filter((r) => /^\d+(\.\d+)*$/.test(r.version) && Date.parse(r.date) <= cutoff)
    .reduce((best, r) => (best === null || newer(r.version, best.version) ? r : best), null);
}

async function get(url) {
  const token = process.env.GITHUB_TOKEN;
  const github = url.startsWith('https://api.github.com/');
  let response;
  try {
    response = await fetch(url, {
      headers: {
        'User-Agent': 'apple-purchase-receipt-verifier toolchain-watch',
        ...(github ? { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' } : {}),
        ...(github && token ? { Authorization: `Bearer ${token}` } : {}),
      },
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    throw new Error(`${url}: ${error.cause?.message ?? error.message}`);
  }
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return response.json();
}

async function crate(name) {
  const body = await get(`https://crates.io/api/v1/crates/${name}/versions`);
  return body.versions.filter((v) => !v.yanked).map((v) => ({ version: v.num, date: v.created_at }));
}

async function githubReleases(repo, tagPrefix) {
  const releases = await get(`https://api.github.com/repos/${repo}/releases?per_page=100`);
  return releases
    .filter((r) => !r.draft && !r.prerelease && r.tag_name.startsWith(tagPrefix))
    .map((r) => ({ version: r.tag_name.slice(tagPrefix.length), date: r.published_at }));
}

export async function main() {
  const pins = readPins(readFileSync(new URL('wasm-toolchain.sh', import.meta.url), 'utf8'));
  const major = pins.OpenSSL.split('.')[0];
  const [wasiSdk, wasmTools, witBindgen, openssl] = await Promise.all([
    githubReleases('WebAssembly/wasi-sdk', 'wasi-sdk-'),
    crate('wasm-tools'),
    crate('wit-bindgen-cli'),
    githubReleases('openssl/openssl', `openssl-${major}.`).then((rs) =>
      rs.map((r) => ({ ...r, version: `${major}.${r.version}` })),
    ),
  ]);
  const upstream = { 'wasi-sdk': wasiSdk, 'wasm-tools': wasmTools, 'wit-bindgen': witBindgen, OpenSSL: openssl };
  const behind = [];
  for (const [name, pinned] of Object.entries(pins)) {
    const best = latest(upstream[name]);
    if (best && newer(best.version, pinned)) {
      behind.push(`${name}: pinned ${pinned}, ${best.version} released ${best.date.slice(0, 10)}`);
    }
  }
  if (behind.length === 0) {
    console.log('toolchain-watch: every pin in tools/wasm-toolchain.sh is current');
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
