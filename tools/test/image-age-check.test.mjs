import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { HUB_PAGES, PATHSPECS, imagesAt, introduced, main, parseArgs } from '../image-age-check.mjs';

const D = (c) => `sha256:${c.repeat(64)}`;
const NOW = Date.parse('2026-11-04T12:00:00.000Z');
const ago = (days) => new Date(NOW - days * 24 * 60 * 60 * 1000).toISOString();

// A scratch repository with one commit per tree ({ path: text, or null to
// delete }); returns its directory and the commits' SHAs.
function repo(trees) {
  const dir = mkdtempSync(join(tmpdir(), 'image-age-'));
  const git = (...args) =>
    execFileSync('git', ['-C', dir, '-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', ...args], { encoding: 'utf8' }).trim();
  git('init', '-q');
  const shas = trees.map((tree) => {
    for (const [path, text] of Object.entries(tree)) {
      if (text === null) {
        rmSync(join(dir, path));
      } else {
        mkdirSync(dirname(join(dir, path)), { recursive: true });
        writeFileSync(join(dir, path), text);
      }
    }
    git('add', '-A');
    git('commit', '-q', '--allow-empty', '-m', 'tree');
    return git('rev-parse', 'HEAD');
  });
  return { dir, shas, done: () => rmSync(dir, { recursive: true, force: true }) };
}

const distroless = (digest) => `FROM gcr.io/distroless/static-debian13:nonroot@${digest} AS runtime\n`;
const debian = (digest) => `FROM --platform=linux/amd64 debian:trixie-slim@${digest}\n`;

// Stands in for the registries. `gcr` maps a repository to { digest:
// upload time }; `tags` maps "namespace/repo:tag" to the tag Docker Hub
// answers with (404 when absent); `lists` maps "namespace/repo" to its
// tags, newest push first.
function registries({ gcr = {}, tags = {}, lists = {}, fail } = {}) {
  const urls = [];
  const respond = (body) => ({ ok: true, status: 200, json: async () => body });
  const fetch = async (url) => {
    urls.push(url);
    if (fail && url.includes(fail)) return { ok: false, status: 500 };
    let m = /^https:\/\/gcr\.io\/v2\/(.+)\/tags\/list$/.exec(url);
    if (m) {
      const held = Object.entries(gcr[m[1]] ?? {});
      return respond({ manifest: Object.fromEntries(held.map(([d, t]) => [d, { tag: [], timeCreatedMs: '0', timeUploadedMs: String(Date.parse(t)) }])) });
    }
    m = /^https:\/\/hub\.docker\.com\/v2\/namespaces\/([^/]+)\/repositories\/([^/]+)\/tags\/([^/?]+)$/.exec(url);
    if (m) {
      const tag = tags[`${m[1]}/${m[2]}:${m[3]}`];
      return tag ? respond(tag) : { ok: false, status: 404 };
    }
    m = /^https:\/\/hub\.docker\.com\/v2\/namespaces\/([^/]+)\/repositories\/([^/]+)\/tags\?(.*)$/.exec(url);
    if (m) {
      const query = new URLSearchParams(m[3]);
      assert.equal(query.get('ordering'), 'last_updated', 'the scan relies on newest first');
      const rows = lists[`${m[1]}/${m[2]}`] ?? [];
      const page = Number(query.get('page') ?? 1);
      const size = Number(query.get('page_size'));
      query.set('page', String(page + 1));
      const next = page * size < rows.length ? `${url.split('?')[0]}?${query}` : null;
      return respond({ results: rows.slice((page - 1) * size, page * size), next });
    }
    throw new Error(`unexpected ${url}`);
  };
  return { fetch, urls };
}

async function run(fake, { dir, base, head, now = NOW }) {
  const saved = { fetch: globalThis.fetch, log: console.log };
  const lines = [];
  globalThis.fetch = fake.fetch;
  console.log = (line) => lines.push(line);
  try {
    return { code: await main({ root: dir, base, head, now }), out: lines.join('\n'), lines };
  } finally {
    globalThis.fetch = saved.fetch;
    console.log = saved.log;
  }
}

test('reads pins from Dockerfiles, workflows and composite actions only', () => {
  const r = repo([{
    Dockerfile: `FROM swift:6.3@${D('1')}\n`,
    'rust/server/Dockerfile': distroless(D('2')),
    '.github/workflows/ci.yml': `    container: mono:6.12@${D('3')}\n`,
    '.github/actions/build-module/action.yml': `        image: eclipse-temurin:25-jre@${D('4')}\n`,
    // Outside the scope: prose, a nested workflow, a script.
    'docs/notes.md': `debian:trixie-slim@${D('5')}\n`,
    '.github/workflows/old/x.yml': `debian:trixie-slim@${D('6')}\n`,
    'tools/run.sh': `docker run debian:trixie-slim@${D('7')}\n`,
  }]);
  try {
    const found = imagesAt(r.dir, r.shas[0]);
    assert.deepEqual(found.map((i) => `${i.files[0]} ${i.name}:${i.tag}@${i.digest.slice(7, 8)}`).sort(), [
      '.github/actions/build-module/action.yml eclipse-temurin:25-jre@4',
      '.github/workflows/ci.yml mono:6.12@3',
      'Dockerfile swift:6.3@1',
      'rust/server/Dockerfile gcr.io/distroless/static-debian13:nonroot@2',
    ]);
  } finally {
    r.done();
  }
});

test('only a digest head pins and base does not is checked', () => {
  const image = (name, tag, digest, file) => ({ name, tag, digest, files: [file] });
  const base = [image('swift', '6.3', D('a'), 'ci.yml'), image('mono', '6.12', D('b'), 'ci.yml')];
  const head = [
    // Moved to another file, or retagged in its comment: the same bytes.
    image('swift', '6.3', D('a'), 'nightly.yml'),
    image('mono', '6.12.0', D('b'), 'ci.yml'),
    image('mono', '6.12', D('c'), 'ci.yml'),
    // The same digest under another name is another registry's copy.
    image('ghcr.io/x/swift', '6.3', D('a'), 'ci.yml'),
  ];
  assert.deepEqual(introduced(base, head).map((i) => `${i.name}@${i.digest.slice(7, 8)}`), ['mono@c', 'ghcr.io/x/swift@a']);
  assert.deepEqual(introduced(head, base), [], 'a removed digest is not checked');
});

test('a gcr.io digest under seven days old fails, naming it and its upload time', async () => {
  const r = repo([{ 'rust/server/Dockerfile': distroless(D('a')) }, { 'rust/server/Dockerfile': distroless(D('b')) }]);
  try {
    const fake = registries({ gcr: { 'distroless/static-debian13': { [D('a')]: ago(20), [D('b')]: ago(3.5) } } });
    const young = await run(fake, { dir: r.dir, base: r.shas[0], head: r.shas[1] });
    assert.equal(young.code, 1, young.out);
    assert.equal(
      young.lines[0],
      `::error::rust/server/Dockerfile: gcr.io/distroless/static-debian13:nonroot@${D('b')} was pushed 2026-11-01T00:00:00.000Z ` +
        '(gcr.io timeUploadedMs), under 7 days ago; re-run this check after 2026-11-08T00:00:00.000Z',
    );
    assert.equal(young.lines.at(-1), 'image-age-check: 1 new digest(s), 1 younger than 7 days');
    // The same range, run after the cooldown, passes.
    const later = await run(fake, { dir: r.dir, base: r.shas[0], head: r.shas[1], now: NOW + 4 * 24 * 60 * 60 * 1000 });
    assert.equal(later.code, 0, later.out);
    // The old digest is never looked up: one request for the new one.
    assert.deepEqual([...new Set(fake.urls)], ['https://gcr.io/v2/distroless/static-debian13/tags/list']);
    // A digest gcr.io does not hold is a warning, not a pass in silence.
    const gone = await run(registries({ gcr: {} }), { dir: r.dir, base: r.shas[0], head: r.shas[1] });
    assert.equal(gone.code, 0);
    assert.match(gone.lines[0], /^::warning::rust\/server\/Dockerfile: .*: age unknown \(gcr\.io lists no such digest/);
  } finally {
    r.done();
  }
});

test("a Docker Hub digest is dated by the PR's tag when the tag names it", async () => {
  const r = repo([{ 'tools/reproduce/Dockerfile': debian(D('a')) }, { 'tools/reproduce/Dockerfile': debian(D('b')) }]);
  const range = { dir: r.dir, base: r.shas[0], head: r.shas[1] };
  const tag = (pushed, images = []) => ({ tags: { 'library/debian:trixie-slim': { name: 'trixie-slim', digest: D('b'), tag_last_pushed: pushed, last_updated: pushed, images } } });
  try {
    const young = await run(registries(tag(ago(2))), range);
    assert.equal(young.code, 1);
    assert.match(young.lines[0], new RegExp(`^::error::tools/reproduce/Dockerfile: debian:trixie-slim@${D('b')} was pushed ${ago(2)} \\(Docker Hub, tag trixie-slim\\)`));
    const old = await run(registries(tag(ago(9))), range);
    assert.equal(old.code, 0, old.out);
    assert.equal(old.lines[0], `tools/reproduce/Dockerfile: debian:trixie-slim@${D('b')}: pushed ${ago(9)} (Docker Hub, tag trixie-slim)`);
    // A platform digest takes that platform image's own push time.
    const platform = registries({ tags: { 'library/debian:trixie-slim': { digest: D('c'), tag_last_pushed: ago(1), images: [{ digest: D('b'), last_pushed: ago(12) }] } } });
    assert.equal((await run(platform, range)).code, 0);
  } finally {
    r.done();
  }
});

test('a Docker Hub digest its tag no longer names is looked for in the tags list, newest first', async () => {
  const r = repo([{ 'tools/reproduce/Dockerfile': debian(D('a')) }, { 'tools/reproduce/Dockerfile': debian(D('b')) }]);
  const range = { dir: r.dir, base: r.shas[0], head: r.shas[1] };
  const moved = { 'library/debian:trixie-slim': { digest: D('f'), tag_last_pushed: ago(0.5), images: [] } };
  // 250 tags, one pushed every hour, newest first: 168 fall inside the week.
  const rows = (named) =>
    Array.from({ length: 250 }, (_, i) => {
      const pushed = ago(i / 24);
      return { name: `t${i}`, digest: named.includes(i) ? D('b') : D('e'), tag_last_pushed: pushed, last_updated: pushed, images: [] };
    });
  const list = (named) => registries({ tags: moved, lists: { 'library/debian': rows(named) } });
  try {
    // Named by two tags this week: the earlier push counts, and it is young.
    const young = await run(list([3, 100]), range);
    assert.equal(young.code, 1);
    assert.match(young.lines[0], new RegExp(`was pushed ${ago(100 / 24)} \\(Docker Hub, tag t100\\)`));
    // Also named by a tag from before the cooldown: old enough.
    const old = await run(list([3, 200]), range);
    assert.equal(old.code, 0, old.out);
    assert.match(old.lines[0], /: pushed .* \(Docker Hub, tag t200\)$/);
    // An old match ends the scan: page 3 is never read for hour 180.
    const early = list([180]);
    assert.equal((await run(early, range)).code, 0);
    assert.equal(early.urls.filter((u) => u.includes('/tags?')).length, 2);
    // Named by no tag: unknown, after the whole list.
    const none = list([]);
    const unknown = await run(none, range);
    assert.equal(unknown.code, 0);
    assert.match(unknown.lines[0], /age unknown \(none of the 250 newest tags on Docker Hub names it\)/);
    assert.equal(none.urls.filter((u) => u.includes('/tags?')).length, 3);
    // The tag itself is gone: the list is read just the same.
    const deleted = registries({ lists: { 'library/debian': rows([5]) } });
    assert.equal((await run(deleted, range)).code, 1);
  } finally {
    r.done();
  }
});

test('the Docker Hub scan reads at most HUB_PAGES pages', async () => {
  const r = repo([{ 'tools/reproduce/Dockerfile': debian(D('a')) }, { 'tools/reproduce/Dockerfile': debian(D('b')) }]);
  // Ten thousand tags, none naming the digest.
  const rows = Array.from({ length: 10_000 }, (_, i) => ({ name: `t${i}`, digest: D('e'), tag_last_pushed: ago(0), last_updated: ago(0), images: [] }));
  const fake = registries({ lists: { 'library/debian': rows } });
  try {
    const result = await run(fake, { dir: r.dir, base: r.shas[0], head: r.shas[1] });
    assert.equal(result.code, 0);
    assert.match(result.lines[0], new RegExp(`age unknown \\(none of the ${HUB_PAGES * 100} newest tags`));
    assert.equal(fake.urls.filter((u) => u.includes('/tags?')).length, HUB_PAGES);
  } finally {
    r.done();
  }
});

test('ghcr.io and other registries give no push time: a warning, not a failure', async () => {
  const uv = (digest) => `          - { image: "ghcr.io/astral-sh/uv:python3.12-alpine@${digest}" }\n`;
  const quay = (digest) => `    container: quay.io/x/y:1@${digest}\n`;
  const r = repo([
    { '.github/workflows/ci.yml': uv(D('a')) + quay(D('c')) },
    { '.github/workflows/ci.yml': uv(D('b')) + quay(D('d')) },
  ]);
  try {
    const fake = registries();
    const result = await run(fake, { dir: r.dir, base: r.shas[0], head: r.shas[1] });
    assert.equal(result.code, 0, result.out);
    assert.match(result.lines[0], /^::warning::\.github\/workflows\/ci\.yml: ghcr\.io\/astral-sh\/uv:python3\.12-alpine@.*age unknown \(ghcr\.io gives no push time\)/);
    assert.match(result.lines[1], /^::warning::.*quay\.io\/x\/y:1@.*age unknown \(no push time is read from quay\.io\)/);
    assert.deepEqual(fake.urls, []);
  } finally {
    r.done();
  }
});

test('a range that adds no digest passes without asking a registry', async () => {
  const r = repo([
    { 'rust/server/Dockerfile': distroless(D('a')), 'README.md': 'a\n' },
    // A comment above the pin changes, and a digest leaves.
    { 'rust/server/Dockerfile': `# runtime\n${distroless(D('a'))}`, 'README.md': `gcr.io/distroless/static-debian13:nonroot@${D('b')}\n` },
    { 'rust/server/Dockerfile': null },
  ]);
  try {
    const fake = registries();
    for (const [base, head] of [[0, 1], [1, 2], [0, 0]]) {
      const result = await run(fake, { dir: r.dir, base: r.shas[base], head: r.shas[head] });
      assert.equal(result.code, 0);
      assert.equal(result.out, `image-age-check: no digest-pinned image is new between ${r.shas[base]} and ${r.shas[head]}`);
    }
    assert.deepEqual(fake.urls, []);
  } finally {
    r.done();
  }
});

test('a registry that fails fails the run, so the CLI exits 2 and never passes', async () => {
  const r = repo([{ 'rust/server/Dockerfile': distroless(D('a')) }, { 'rust/server/Dockerfile': distroless(D('b')) }]);
  try {
    await assert.rejects(run(registries({ fail: 'gcr.io' }), { dir: r.dir, base: r.shas[0], head: r.shas[1] }), /HTTP 500/);
    await assert.rejects(run(registries(), { dir: r.dir, base: 'no-such-rev', head: r.shas[1] }));
  } finally {
    r.done();
  }
});

test('reads --now and the two commits from the command line', () => {
  assert.deepEqual(parseArgs(['--now=2026-11-04T00:00:00Z', 'a', 'b']), { now: Date.parse('2026-11-04T00:00:00Z'), base: 'a', head: 'b' });
  assert.deepEqual(parseArgs(['a', 'b']), { base: 'a', head: 'b' });
  assert.throws(() => parseArgs(['--now=yesterday', 'a', 'b']), /not a time/);
  assert.throws(() => parseArgs(['a']), /usage/);
  assert.throws(() => parseArgs(['--since=1', 'a', 'b']), /unknown option/);
});

test("ci.yml runs the check when a file it reads changed, and ci-ok waits for it", () => {
  const ci = readFileSync(new URL('../../.github/workflows/ci.yml', import.meta.url), 'utf8');
  // The changes job's filter must be this script's PATHSPECS exactly, or
  // a digest in a file only one of them knows would skip the check.
  assert.ok(ci.includes(`git diff --quiet "$BASE_SHA" HEAD -- ${PATHSPECS.map((p) => `'${p}'`).join(' ')}`), 'the changes filter and PATHSPECS differ');
  assert.match(ci, /\n {2}image-age:\n {4}needs: changes\n {4}if: needs\.changes\.outputs\.images == 'true'\n/);
  assert.match(ci, /node tools\/image-age-check\.mjs "\$BASE_SHA" HEAD\n/);
});
