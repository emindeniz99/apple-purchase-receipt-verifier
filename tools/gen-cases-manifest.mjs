#!/usr/bin/env node
/**
 * Flattens fixtures/cases.json into a line-oriented manifest a compiled
 * harness can read without a JSON parser.
 *
 *   node tools/gen-cases-manifest.mjs <outdir>
 *
 * It exists for rust/ffi/examples/cpp/conformance.cpp, which drives the C ABI
 * over the same normative vectors every port answers. A C++17 program with no
 * dependencies cannot parse cases.json, base64-decode a fixture or hash one,
 * so this does all three first and hands over plain files:
 *
 *   <outdir>/cases.tsv                 one case per line
 *   <outdir>/fixtures/<id>.bin         the DECODED logical bytes of a fixture
 *   <outdir>/requests/<case>.json      the verifyReceipt request body
 *
 * Every registered fixture is re-hashed against its contentSha256 before
 * anything is written, exactly as tools/lint-cases.mjs and each port's own
 * adapter do: a fixture that drifted must fail loudly here rather than have
 * the harness quietly verify different bytes than the vectors describe.
 *
 * FORMAT. Each line is TAB-separated `key=value` pairs; the key is what
 * precedes the first `=`, so a value may contain `=` freely. Repeated keys
 * are a list. A `field` value is `<path>~><tag>:<text>`, where the tag is
 * `s` (string), `n` (number) or `z` (absent or null); `~>` is the separator
 * because an expected field path may itself contain `=`, `.` and `[]`, but
 * never a tilde.
 *
 *   id                  the case id
 *   op                  verifyTransaction | verifyAppTransaction | verifyRaw
 *                       | verifyReceipt | verifyReceiptBase64
 *                       | verifyReceiptEndpoint
 *   input               path to the decoded input bytes
 *   request             path to the endpoint request body (endpoint cases)
 *   roots               "builtin" or "files"
 *   root                path to one DER anchor (repeated, roots=files)
 *   bundleId            verifier bundle id
 *   envs                the accepted-environment BITMASK, already computed
 *   appAppleId          0 when unset
 *   maxSignedAgeSecs    0 when unset
 *   deviceGuidHex       absent when the case pins no device GUID
 *   endpointEnv         1 (Production) or 2 (Sandbox), endpoint cases
 *   expect              ok | error
 *   reason              the canonical token, error cases only
 *   field               one expected top-level field (repeated)
 *   skippedFields       how many expected field paths this manifest DROPPED
 *   unsupported         set when the C ABI cannot run the case at all
 *
 * WHAT IS DROPPED, and why it is counted rather than hidden:
 *
 *   - a case that pins a `clock`. The C ABI has no clock argument: the Rust
 *     builders take one, but injecting a `dyn Clock` across a C boundary
 *     would mean a callback, and the surface is deliberately callback-free.
 *     Marked `unsupported=clock`, and the harnesses report the count.
 *   - an expected field path that is not a top-level scalar or an
 *     `<array>.length` — `receipt.bundle_id`,
 *     `inAppPurchases[productId=x].quantity`, `unknownAttributes[9999][0]`.
 *     Counted in `skippedFields`. rust/ffi/tests/conformance.py checks all of
 *     them; it has a JSON parser and this manifest exists because C++ does
 *     not.
 */

import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURES_DIR = join(REPO, 'fixtures');

const ENVIRONMENT_BITS = {
  Production: 1,
  Sandbox: 2,
  Xcode: 4,
  LocalTesting: 8,
};

const SCALAR_PATH = /^[A-Za-z_][A-Za-z0-9_]*$/;
const LENGTH_PATH = /^[A-Za-z_][A-Za-z0-9_]*\.length$/;
const SEPARATOR = '~>';

function fail(message) {
  console.error(`gen-cases-manifest: ${message}`);
  process.exit(1);
}

/** The decoded logical bytes of a fixture, checked against its digest. */
function fixtureBytes(entry, id) {
  const raw = readFileSync(join(FIXTURES_DIR, entry.path));
  let bytes;
  switch (entry.codec) {
    case 'raw':
    case 'text':
      bytes = raw;
      break;
    case 'utf8':
      bytes = Buffer.from(raw.toString('utf8').trim(), 'utf8');
      break;
    case 'base64':
      bytes = Buffer.from(raw.toString('utf8').replace(/\s+/g, ''), 'base64');
      break;
    default:
      fail(`fixture "${id}" has unknown codec "${entry.codec}"`);
  }
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== entry.contentSha256) {
    fail(
      `fixture "${id}" (${entry.path}, codec ${entry.codec}) has drifted: ` +
        `cases.json records ${entry.contentSha256}, the decoded bytes hash to ${actual}`,
    );
  }
  return bytes;
}

function safeName(id) {
  return id.replace(/[^A-Za-z0-9._-]/g, '_');
}

function encodeField(path, value) {
  let tagged;
  if (value === null) tagged = 'z:';
  else if (typeof value === 'number') tagged = `n:${value}`;
  else if (typeof value === 'string') tagged = `s:${value}`;
  else fail(`expected field "${path}" has unsupported type ${typeof value}`);
  const encoded = `${path}${SEPARATOR}${tagged}`;
  if (/[\t\n\r]/.test(encoded)) {
    fail(`expected field "${path}" carries a tab or newline, which the manifest cannot hold`);
  }
  if (path.includes(SEPARATOR)) {
    fail(`expected field path "${path}" contains the manifest separator`);
  }
  return encoded;
}

function main() {
  const outDir = process.argv[2];
  if (!outDir) fail('usage: node tools/gen-cases-manifest.mjs <outdir>');

  const file = JSON.parse(readFileSync(join(FIXTURES_DIR, 'cases.json'), 'utf8'));
  if (file.schemaVersion !== 1) {
    fail(`cases.json is schemaVersion ${file.schemaVersion}, this generator implements 1`);
  }

  const out = resolve(outDir);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(join(out, 'fixtures'), { recursive: true });
  mkdirSync(join(out, 'requests'), { recursive: true });

  // The whole registry first, so a fixture no case references cannot drift
  // unnoticed — the guarantee is over the registry, not over what is used.
  const decoded = new Map();
  for (const [id, entry] of Object.entries(file.fixtures)) {
    const bytes = fixtureBytes(entry, id);
    decoded.set(id, bytes);
    writeFileSync(join(out, 'fixtures', `${safeName(id)}.bin`), bytes);
  }

  const lines = [];
  let unsupported = 0;
  let skippedFields = 0;

  for (const kase of file.cases) {
    const parts = [`id=${kase.id}`, `op=${kase.operation}`];
    const config = kase.config;

    if (kase.clock) {
      // Not a skip list: the reason is machine-readable and the harnesses add
      // it up, so a case going unsupported for a NEW reason shows up as an
      // unknown token rather than as one fewer test quietly running.
      parts.push('unsupported=clock');
      unsupported += 1;
    }

    const inputBytes = decoded.get(kase.input.fixture);
    if (inputBytes === undefined) fail(`case "${kase.id}" names an unregistered input fixture`);
    parts.push(`input=${join(out, 'fixtures', `${safeName(kase.input.fixture)}.bin`)}`);

    const roots = config.trustedRoots;
    if (roots.source === 'builtin') {
      if (roots.name !== 'apple-jws-roots' && roots.name !== 'apple-receipt-roots') {
        fail(`case "${kase.id}" names unknown builtin root set "${roots.name}"`);
      }
      parts.push('roots=builtin');
    } else if (roots.source === 'fixtures') {
      parts.push('roots=files');
      for (const id of roots.fixtures ?? []) {
        if (!decoded.has(id)) fail(`case "${kase.id}" names an unregistered anchor "${id}"`);
        parts.push(`root=${join(out, 'fixtures', `${safeName(id)}.bin`)}`);
      }
    } else {
      fail(`case "${kase.id}" has unknown trustedRoots source "${roots.source}"`);
    }

    // verifyRaw enforces no claim, so its cases may omit both. The
    // placeholders match nothing any fixture carries, so a claim check that
    // leaked into verify_raw fails the case instead of passing it — the same
    // choice rust/tests/conformance.rs makes, for the same reason.
    parts.push(`bundleId=${config.bundleId ?? 'conformance.unset.bundle.id'}`);
    let mask = 0;
    for (const name of config.acceptedEnvironments ?? ['LocalTesting']) {
      const bit = ENVIRONMENT_BITS[name];
      if (bit === undefined) fail(`case "${kase.id}" names unknown environment "${name}"`);
      mask |= bit;
    }
    parts.push(`envs=${mask}`);
    parts.push(`appAppleId=${config.appAppleId ?? 0}`);
    parts.push(`maxSignedAgeSecs=${config.maxSignedAgeSeconds ?? 0}`);
    if (config.deviceGuidHex) parts.push(`deviceGuidHex=${config.deviceGuidHex}`);

    if (kase.operation === 'verifyReceiptEndpoint') {
      const bit = ENVIRONMENT_BITS[config.environment];
      if (bit !== 1 && bit !== 2) {
        fail(`case "${kase.id}" has endpoint environment "${config.environment}"`);
      }
      parts.push(`endpointEnv=${bit}`);
      // A "text" fixture carries the exact string a client sent; raw and
      // base64 fixtures have no client-facing string of their own, so they
      // are re-encoded as canonical base64. Same rule as every other port.
      const codec = file.fixtures[kase.input.fixture].codec;
      const receiptData =
        codec === 'text' ? inputBytes.toString('utf8') : inputBytes.toString('base64');
      const requestPath = join(out, 'requests', `${safeName(kase.id)}.json`);
      writeFileSync(requestPath, JSON.stringify({ 'receipt-data': receiptData }));
      parts.push(`request=${requestPath}`);
    }

    parts.push(`expect=${kase.expected.status}`);
    if (kase.expected.status === 'error') {
      if (!kase.expected.reason) fail(`case "${kase.id}" is an error case with no reason`);
      parts.push(`reason=${kase.expected.reason}`);
    }

    let dropped = 0;
    for (const [path, value] of Object.entries(kase.expected.fields ?? {})) {
      if (SCALAR_PATH.test(path) || LENGTH_PATH.test(path)) {
        parts.push(`field=${encodeField(path, value)}`);
      } else {
        dropped += 1;
      }
    }
    parts.push(`skippedFields=${dropped}`);
    skippedFields += dropped;

    for (const part of parts) {
      if (part.includes('\t') || part.includes('\n')) {
        fail(`case "${kase.id}" produced a manifest field containing a tab or newline`);
      }
    }
    lines.push(parts.join('\t'));
  }

  writeFileSync(join(out, 'cases.tsv'), `${lines.join('\n')}\n`);
  process.stdout.write(
    `${lines.length} cases -> ${join(out, 'cases.tsv')} ` +
      `(${unsupported} the C ABI cannot run, ${skippedFields} nested field paths dropped)\n`,
  );
}

main();
