// Holds a container image digest out of a pull request until it is seven
// days old, the cooldown .github/dependabot.yml sets for every ecosystem.
// Dependabot can date only a Docker Hub image. For any other registry it
// proposes the new digest at once, with the warning "Cooldown could not be
// applied", as it did for gcr.io/distroless in rust/server/Dockerfile. A
// person moving a digest by hand gets no cooldown at all. This check covers
// both.
//
// It reads every digest-pinned image (`name:tag@sha256:...`, or
// `name@sha256:...  # name:tag`, as toolchain-watch reads them) in the
// files PATHSPECS names, at <base> and at <head>, and dates each one that
// is in head and not in base:
//
//   gcr.io      `timeUploadedMs` of the digest in GET /v2/<repo>/tags/list.
//               gcr.io keeps every digest it has, so the time is there even
//               after the tag has moved on.
//   Docker Hub  The PR's tag first, as Dependabot reads it: its
//               `tag_last_pushed` when the tag still names the digest, or a
//               platform image's `last_pushed` when the digest is one of the
//               tag's `images[]`. Otherwise, the repository's tags list,
//               newest push first, at most HUB_PAGES pages, matched the same
//               way on each tag. Every match is a time the digest already
//               existed, so the earliest one counts: a match from before the
//               cooldown passes at once. Matches only inside it fail, though
//               an old digest re-tagged this week, under no tag the scan
//               reaches, reads as young: that holds the PR, the safe side.
//               No match is an unknown age.
//   ghcr.io     No push time without a personal access token: unknown.
//   any other   Unknown.
//
// The image config's `created` is never used: distroless sets it to 1970.
//
// Usage: node tools/image-age-check.mjs [--now=<ISO time>] <base> <head>
//
// <base> and <head> are commits, compared as trees. In CI <head> is the
// pull request's merge commit, so base..head is what the PR changes.
// --now replaces the current time, to replay a past run.
//
// Prints one line per new digest. Exits 1 when any is younger than seven
// days, naming it, its file and the time it was pushed. An unknown age is
// a warning, exit 0: review that digest by hand. A network or HTTP
// failure and any error in this script exit 2, as in toolchain-watch.
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  COOLDOWN_DAYS,
  DAY,
  cutoff,
  gcrManifests,
  gcrUploaded,
  get,
  hubPushed,
  hubRepository,
  hubTag,
  readImages,
  registryOf,
} from './toolchain-watch.mjs';

// The files read, as git pathspecs. ci.yml's `changes` job runs this check
// only when one of them changed, with the same list.
export const PATHSPECS = [
  ':(glob)**/Dockerfile',
  ':(glob).github/workflows/*.yml',
  ':(glob).github/workflows/*.yaml',
  ':(glob).github/actions/*/action.yml',
];

// Pages of 100 tags read before giving up on a Docker Hub digest.
export const HUB_PAGES = 20;

const git = (root, args) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

// Every digest-pinned image in PATHSPECS at `rev`, as readImages gives them.
export function imagesAt(root, rev) {
  const sha = git(root, ['rev-parse', '--verify', `${rev}^{commit}`]).trim();
  let listed = '';
  try {
    listed = git(root, ['grep', '-l', '-I', '-E', '@sha256:[0-9a-f]{64}', sha, '--', ...PATHSPECS]);
  } catch (error) {
    if (error.status !== 1) throw error; // 1: no file matched
  }
  const files = listed.split('\n').filter(Boolean).map((line) => line.slice(sha.length + 1));
  return readImages(files.map((file) => ({ file, text: git(root, ['show', `${sha}:${file}`]) })));
}

// The images of `head` whose name and digest `base` does not pin anywhere.
// A digest moved from one file to another is not new.
export function introduced(base, head) {
  const pinned = new Set(base.map((i) => `${i.name}@${i.digest}`));
  return head.filter((i) => !pinned.has(`${i.name}@${i.digest}`));
}

// The time a Docker Hub tag puts on `digest`, or null.
function hubTime(tag, digest) {
  if (tag.digest === digest) return hubPushed(tag);
  return (tag.images ?? []).find((i) => i.digest === digest)?.last_pushed ?? null;
}

async function hubPushedAt(repo, tag, digest, now) {
  try {
    const time = hubTime(await hubTag(repo, tag), digest);
    if (time) return { date: time, source: `Docker Hub, tag ${tag}` };
  } catch (error) {
    if (!/: HTTP 404$/.test(error.message)) throw error;
  }
  let url = `${hubRepository(repo)}/tags?page_size=100&ordering=last_updated`;
  let earliest = null;
  let read = 0;
  for (let page = 0; url && page < HUB_PAGES; page += 1) {
    const body = await get(url);
    for (const row of body.results) {
      const time = hubTime(row, digest);
      if (time && (earliest === null || Date.parse(time) < Date.parse(earliest.date))) {
        earliest = { date: time, source: `Docker Hub, tag ${row.name}` };
      }
    }
    if (earliest && Date.parse(earliest.date) <= cutoff(now)) return earliest;
    read += body.results.length;
    url = body.next;
  }
  return earliest ?? { date: null, why: `none of the ${read} newest tags on Docker Hub names it` };
}

// When `digest` was pushed: { date, source }, or { date: null, why }.
export async function pushedAt({ name, tag, digest }, now) {
  const { registry, repo } = registryOf(name);
  if (registry === 'gcr.io') {
    const m = (await gcrManifests(repo))[digest];
    if (!m) return { date: null, why: `gcr.io lists no such digest under ${name}` };
    return { date: gcrUploaded(m), source: 'gcr.io timeUploadedMs' };
  }
  if (registry === 'docker.io') return hubPushedAt(repo, tag, digest, now);
  if (registry === 'ghcr.io') return { date: null, why: 'ghcr.io gives no push time' };
  return { date: null, why: `no push time is read from ${registry}` };
}

export async function main({ root = fileURLToPath(new URL('..', import.meta.url)), base, head, now = Date.now() }) {
  const fresh = introduced(imagesAt(root, base), imagesAt(root, head));
  if (fresh.length === 0) {
    console.log(`image-age-check: no digest-pinned image is new between ${base} and ${head}`);
    return 0;
  }
  const ages = await Promise.all(fresh.map((image) => pushedAt(image, now)));
  let young = 0;
  fresh.forEach((image, i) => {
    const { date, source, why } = ages[i];
    const what = `${image.files.join(', ')}: ${image.name}:${image.tag}@${image.digest}`;
    if (date === null) {
      console.log(`::warning::${what}: age unknown (${why}); check by hand that it is ${COOLDOWN_DAYS} days old`);
    } else if (Date.parse(date) > cutoff(now)) {
      young += 1;
      const clears = new Date(Date.parse(date) + COOLDOWN_DAYS * DAY).toISOString();
      console.log(`::error::${what} was pushed ${date} (${source}), under ${COOLDOWN_DAYS} days ago; re-run this check after ${clears}`);
    } else {
      console.log(`${what}: pushed ${date} (${source})`);
    }
  });
  console.log(`image-age-check: ${fresh.length} new digest(s), ${young} younger than ${COOLDOWN_DAYS} days`);
  return young > 0 ? 1 : 0;
}

// [--now=<ISO time>] <base> <head>
export function parseArgs(argv) {
  const options = {};
  const positional = [];
  for (const arg of argv) {
    if (arg.startsWith('--now=')) {
      options.now = Date.parse(arg.slice('--now='.length));
      if (Number.isNaN(options.now)) throw new Error(`not a time: ${arg}`);
    } else if (arg.startsWith('-')) {
      throw new Error(`unknown option ${arg}`);
    } else {
      positional.push(arg);
    }
  }
  if (positional.length !== 2) throw new Error('usage: node tools/image-age-check.mjs [--now=<ISO time>] <base> <head>');
  return { ...options, base: positional[0], head: positional[1] };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exit(await main(parseArgs(process.argv.slice(2))));
  } catch (error) {
    console.error(`image-age-check: ${error.stack ?? error}`);
    process.exit(2);
  }
}
