// Watches what Apple publishes about the certificates and rules our
// verifier depends on, so a change reaches the owner before it makes the
// verifier refuse genuine data. It only reports: nothing here feeds the
// verifier, whose roots and rules change only by a reviewed commit.
//
// Usage: node tools/apple-pki-watch.mjs [--write]
//
// It builds a snapshot of
//   pki        every .cer linked from Apple's PKI page, with the SHA-256 of
//              the downloaded file;
//   cps        the document the WWDR CPS link resolves to (the version is in
//              its filename);
//   libraries  for each of Apple's App Store Server Libraries, the latest
//              release tag and, at that tag, the trimmed lines of the
//              verifier source that name an Apple marker OID or compute the
//              date the chain is checked at (no line numbers, so an edit
//              elsewhere in the file causes no diff);
//   news       Apple developer news items since NEWS_SINCE whose title
//              mentions certificates, receipts or StoreKit.
//
// --write stores the snapshot in tools/apple-pki-watch.json. Without it the
// snapshot is compared against that file: the differences are printed and
// the exit status is 1 when there are any, 0 when there are none. A news
// item that has scrolled out of Apple's feed is not a change; only a new one
// is. Any network or HTTP failure, and any error in this script, exits 2
// with the reason, never 0 or 1.
// GITHUB_TOKEN, when set, authenticates the GitHub API calls.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

const SNAPSHOT = new URL('apple-pki-watch.json', import.meta.url);
const PKI_PAGE = 'https://www.apple.com/certificateauthority/';
const WWDR_CPS = 'https://www.apple.com/certificateauthority/WWDR_CPS';
const NEWS_RSS = 'https://developer.apple.com/news/rss/news.rss';
const NEWS_SINCE = '2026-01-01';
const NEWS_TOPIC = /certificat|receipt|intermediate|App Store Server|StoreKit/i;

// An Apple marker OID, written dotted (Python, Java, Node) or as an array
// literal (Swift).
const OID = /\b1(?:\.|,\s*)2(?:\.|,\s*)840(?:\.|,\s*)113635\b/;
// The date the chain is validated at: signedDate, or receiptCreationDate
// for an app transaction, unless online checks force "now". The first
// branch matches an assignment that starts the (trimmed) line, not a
// keyword argument passing the value on.
const DATE = /^(?:\w+\s+)*(?:effective_?date|validationTime|signed_date)\s*=(?!=)|\b(?:signedDate|receiptCreationDate)\b.*\?/i;

const LIBRARIES = {
  'app-store-server-library-python': ['appstoreserverlibrary/signed_data_verifier.py'],
  'app-store-server-library-java': [
    'src/main/java/com/apple/itunes/storekit/verification/AppleExtensionCertPathChecker.java',
    'src/main/java/com/apple/itunes/storekit/verification/SignedDataVerifier.java',
  ],
  'app-store-server-library-node': ['jws_verification.ts'],
  'app-store-server-library-swift': ['Sources/AppStoreServerLibrary/ChainVerifier.swift'],
};

// Node exits 1 on an uncaught error, which would read as "Apple changed
// something". A bug in this script is not a change: exit 2.
process.on('uncaughtException', (error) => {
  console.error(`apple-pki-watch: ${error.stack ?? error}`);
  process.exit(2);
});

class NotFound extends Error {}

async function get(url, headers = {}) {
  let response;
  try {
    response = await fetch(url, {
      headers: { 'User-Agent': 'apple-purchase-receipt-verifier apple-pki-watch', ...headers },
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    throw new Error(`${url}: ${error.cause?.message ?? error.message}`);
  }
  if (response.status === 404) throw new NotFound(`${url}: HTTP 404`);
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return response;
}

async function pki() {
  const html = await (await get(PKI_PAGE)).text();
  const urls = [...html.matchAll(/href\s*=\s*["']([^"']+\.cer)["']/gi)].map((m) => new URL(m[1], PKI_PAGE).href);
  if (urls.length === 0) throw new Error(`${PKI_PAGE}: no .cer links found; the page layout changed`);
  const certificates = await Promise.all(
    [...new Set(urls)].sort().map(async (url) => {
      const bytes = Buffer.from(await (await get(url)).arrayBuffer());
      return { url, sha256: createHash('sha256').update(bytes).digest('hex') };
    }),
  );
  return certificates;
}

async function cps() {
  const response = await get(WWDR_CPS);
  // The link answers with HTTP redirects and then a meta refresh to the PDF.
  const refresh = /<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"']+)["']/i;
  const type = response.headers.get('content-type') ?? '';
  const match = type.includes('html') ? refresh.exec(await response.text()) : null;
  return match ? new URL(match[1].trim(), response.url).href : response.url;
}

async function libraries() {
  const token = process.env.GITHUB_TOKEN;
  const api = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
  const result = {};
  for (const [repo, paths] of Object.entries(LIBRARIES)) {
    const release = await (await get(`https://api.github.com/repos/apple/${repo}/releases/latest`, api)).json();
    const tag = release.tag_name;
    if (typeof tag !== 'string' || tag === '') throw new Error(`apple/${repo}: the latest release has no tag_name`);
    const files = {};
    for (const path of paths) {
      try {
        const source = await (await get(`https://raw.githubusercontent.com/apple/${repo}/${encodeURIComponent(tag)}/${path}`)).text();
        files[path] = source
          .split('\n')
          .map((line) => line.trim())
          .filter((line) => OID.test(line) || DATE.test(line));
      } catch (error) {
        // A moved file is a change to report, not a network failure.
        if (!(error instanceof NotFound)) throw error;
        files[path] = null;
      }
    }
    result[repo] = { tag, files };
  }
  return result;
}

function decode(text) {
  return text
    .replace(/^<!\[CDATA\[([\s\S]*)\]\]>$/, '$1')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&amp;/g, '&')
    .trim();
}

async function news() {
  const xml = await (await get(NEWS_RSS)).text();
  const items = [...xml.matchAll(/<item>([\s\S]*?)<\/item>/g)].map(([, item]) => {
    const field = (name) => decode(new RegExp(`<${name}>([\\s\\S]*?)</${name}>`).exec(item)?.[1] ?? '');
    const date = new Date(field('pubDate'));
    return { date: Number.isNaN(date.getTime()) ? '' : date.toISOString().slice(0, 10), title: field('title'), link: field('link') };
  });
  if (items.length === 0) throw new Error(`${NEWS_RSS}: no items found; the feed format changed`);
  return items
    .filter((item) => item.date >= NEWS_SINCE && NEWS_TOPIC.test(item.title))
    .sort((a, b) => a.date.localeCompare(b.date) || a.title.localeCompare(b.title));
}

function compare(before, after) {
  const out = [];
  const oldPki = new Map(before.pki.map((c) => [c.url, c.sha256]));
  const newPki = new Map(after.pki.map((c) => [c.url, c.sha256]));
  for (const [url, sha] of newPki) {
    if (!oldPki.has(url)) out.push(`pki: new certificate ${url} (sha256 ${sha})`);
    else if (oldPki.get(url) !== sha) out.push(`pki: changed bytes ${url}\n  was ${oldPki.get(url)}\n  now ${sha}`);
  }
  for (const url of oldPki.keys()) if (!newPki.has(url)) out.push(`pki: removed certificate ${url}`);

  if (before.cps !== after.cps) out.push(`cps: WWDR CPS moved\n  was ${before.cps}\n  now ${after.cps}`);

  for (const repo of new Set([...Object.keys(before.libraries), ...Object.keys(after.libraries)])) {
    const a = before.libraries[repo];
    const b = after.libraries[repo];
    if (!a || !b) {
      out.push(`libraries: apple/${repo} ${a ? 'no longer watched' : 'newly watched'}`);
      continue;
    }
    // A release alone is not a change: only the watched lines are.
    for (const path of new Set([...Object.keys(a.files), ...Object.keys(b.files)])) {
      const was = a.files[path];
      const now = b.files[path];
      if (JSON.stringify(was) === JSON.stringify(now)) continue;
      out.push(`libraries: apple/${repo} ${path} at ${b.tag}`);
      if (now === null || now === undefined) {
        out.push('  file not found at this tag');
        continue;
      }
      for (const line of was ?? []) if (!now.includes(line)) out.push(`  - ${line}`);
      for (const line of now) if (!(was ?? []).includes(line)) out.push(`  + ${line}`);
    }
  }

  const seen = new Set(before.news.map((item) => `${item.date} ${item.title}`));
  for (const item of after.news) {
    if (!seen.has(`${item.date} ${item.title}`)) out.push(`news: ${item.date} ${item.title}\n  ${item.link}`);
  }
  return out;
}

let args;
try {
  args = parseArgs({ options: { write: { type: 'boolean' } } });
} catch (error) {
  console.error(`apple-pki-watch: ${error.message}\nusage: node tools/apple-pki-watch.mjs [--write]`);
  process.exit(2);
}

let snapshot;
try {
  const [pkiResult, cpsResult, librariesResult, newsResult] = await Promise.all([pki(), cps(), libraries(), news()]);
  snapshot = { pki: pkiResult, cps: cpsResult, libraries: librariesResult, news: newsResult };
} catch (error) {
  console.error(`apple-pki-watch: could not read Apple's sources: ${error.message}`);
  process.exit(2);
}

if (args.values.write) {
  writeFileSync(SNAPSHOT, `${JSON.stringify(snapshot, null, 2)}\n`);
  console.log(`apple-pki-watch: wrote ${SNAPSHOT.pathname}`);
  process.exit(0);
}

let before;
try {
  before = JSON.parse(readFileSync(SNAPSHOT, 'utf8'));
} catch (error) {
  console.error(`apple-pki-watch: cannot read ${SNAPSHOT.pathname}: ${error.message}`);
  process.exit(2);
}
const changes = compare(before, snapshot);
if (changes.length === 0) {
  console.log('apple-pki-watch: no change since tools/apple-pki-watch.json');
  process.exit(0);
}
console.log(changes.join('\n'));
process.exit(1);
