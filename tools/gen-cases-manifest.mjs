#!/usr/bin/env node
/**
 * Flattens fixtures/cases.json into a line-oriented manifest a compiled
 * harness can read without a JSON parser.
 *
 *   node tools/gen-cases-manifest.mjs <outdir>
 *
 * It exists for rust/ffi/examples/cpp/conformance.cpp and the Elixir NIF
 * example, which drive the C ABI over the same normative vectors every port
 * answers. A C++17 program with no dependencies cannot parse the vector
 * file, base64-encode a fixture or hash one, so this does all of that first
 * and hands over plain files:
 *
 *   <outdir>/cases.tsv                 one case per line
 *   <outdir>/inputs/<case>.txt         the exact string the case passes
 *   <outdir>/requests/<case>.json      the verifyReceipt request body
 *   <outdir>/tojson/<case>.json        the toJson() value a case pins, as JSON
 *   <outdir>/fixtures/<id>.bin         the DECODED logical bytes of a fixture
 *
 * Every registered fixture is re-hashed against its contentSha256 before
 * anything is written, exactly as each port's own runner does: a fixture
 * that drifted must fail loudly here rather than have the harness quietly
 * verify different bytes than the vectors describe.
 *
 * FORMAT. Each line is TAB-separated `key=value` pairs; the key is what
 * precedes the first `=`, so a value may contain `=` freely. Repeated keys
 * are a list. A `field` value is `<pointer>~><tag>:<text>`, where the tag is
 * `s` (string), `n` (number), `b` (true or false) or `z` (absent or null);
 * a `length` value is `<pointer>~><count>`. An `n` value carries the
 * number's DIGITS rather than a double's rendering of them: the vectors pin
 * a download id of 2^63 - 1, which `JSON.parse` on its own hands on as
 * 9223372036854775808.
 *
 *   id                  the case id
 *   op                  verifyReceipt | verifySignedData
 *                       | verifyReceiptEndpoint | decodeBase64
 *   input               path to the exact input string (verifyReceipt,
 *                       verifySignedData)
 *   request             path to the endpoint request body (endpoint cases)
 *   endpointEnv         1 (PRODUCTION) or 2 (SANDBOX), endpoint cases
 *   roots               "defaults" or "files"
 *   root                path to one DER anchor (repeated, roots=files)
 *   clockUnixMillis     the pinned `clock.now`, already parsed to epoch
 *                       milliseconds; absent when the case pins none
 *   expect              ok | error | oneof | body (an endpoint case, which
 *                       always answers a body and pins its fields)
 *   reason              the canonical token, error cases only
 *   oneOf               the outcomes a oneof case allows, "ok" or reason
 *                       tokens joined by "|"
 *   field               one expected top-level field (repeated)
 *   length              one expected top-level array length (repeated)
 *   toJson              path to JSON whose value toJson() must equal (the
 *                       bytes may differ; a harness without a JSON parser
 *                       skips it)
 *   maxMillis           a wall-clock budget for the call: the harness runs the
 *                       case once to warm up, then times a second run
 *   skippedFields       how many expected pointers this manifest DROPPED
 *   abiUnreachable      set on every decodeBase64 group, and only there: the
 *                       group calls a port's base64 decoders directly and
 *                       the ABI exposes none, so the line carries nothing
 *                       but its id, op and this reason. The harnesses count
 *                       these as not reachable, never as passed.
 *
 * WHAT IS DROPPED, and why it is counted rather than hidden: an expected
 * pointer below the top level, such as `/receipt/bundle_id` or
 * `/in_app/[product_id=x]/quantity`. Counted in `skippedFields`.
 * rust/ffi/tests/conformance.py checks all of them; it has a JSON parser and
 * this manifest exists because C++ does not.
 */

import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURES_DIR = join(REPO, 'fixtures');

const ENDPOINT_ENVIRONMENTS = { PRODUCTION: 1, SANDBOX: 2 };

const TOP_LEVEL = /^\/[^/[\]~]+$/;
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

/**
 * An integer literal whose digits a JavaScript number cannot hold. The
 * vectors pin a `download_id` of 2^63 - 1 on purpose, and `JSON.parse`
 * answers 9223372036854775808 for it, the nearest double. The digits are
 * kept as text instead, so no harness is failed for being right.
 */
class ExactInteger {
  constructor(digits) {
    this.digits = digits;
  }
}

/**
 * `JSON.parse` with the source text of each primitive (the third reviver
 * argument, Node >= 22), so an integer literal that does not survive the
 * round trip through a double keeps its digits.
 */
function parseCasesKeepingExactIntegers(text) {
  let sourceSeen = false;
  const parsed = JSON.parse(text, function reviver(key, value, context) {
    if (typeof value !== 'number') return value;
    const source = context?.source;
    if (source === undefined) return value;
    sourceSeen = true;
    if (String(value) === source || !/^-?\d+$/.test(source)) return value;
    return new ExactInteger(source);
  });
  if (!sourceSeen) {
    fail(
      'this Node build does not hand JSON.parse revivers the source text, so an integer ' +
        'wider than a double would be silently rounded; Node 22 or newer is required',
    );
  }
  return parsed;
}

function checkPart(id, text) {
  if (/[\t\n\r]/.test(text)) fail(`case "${id}" produced a manifest value with a tab or newline`);
  return text;
}

function encodeField(id, pointer, value) {
  let tagged;
  if (value === null) tagged = 'z:';
  else if (value instanceof ExactInteger) tagged = `n:${value.digits}`;
  else if (typeof value === 'number') tagged = `n:${value}`;
  else if (typeof value === 'boolean') tagged = `b:${value}`;
  else if (typeof value === 'string') tagged = `s:${value}`;
  else fail(`case "${id}": expected field "${pointer}" has unsupported type ${typeof value}`);
  return checkPart(id, `${pointer}${SEPARATOR}${tagged}`);
}

/**
 * The exact string a case passes. A receipt, and the endpoint's
 * receipt-data: a text fixture verbatim, exactly as a client sent it; any
 * other fixture holds DER, encoded as canonical base64 with padding. A JWS:
 * the fixture's logical bytes (utf8 trims, text does not).
 */
function inputString(kase, entry, bytes) {
  if (kase.operation === 'verifySignedData' || entry.codec === 'text') return bytes;
  return Buffer.from(bytes.toString('base64'), 'utf8');
}

function main() {
  const outDir = process.argv[2];
  if (!outDir) fail('usage: node tools/gen-cases-manifest.mjs <outdir>');

  const casesText = readFileSync(join(FIXTURES_DIR, 'cases.json'), 'utf8');
  const file = parseCasesKeepingExactIntegers(casesText);
  if (file.schemaVersion !== 2) {
    fail(`cases.json is schemaVersion ${file.schemaVersion}, this generator implements 2`);
  }

  const out = resolve(outDir);
  rmSync(out, { recursive: true, force: true });
  for (const dir of ['fixtures', 'inputs', 'requests', 'tojson']) {
    mkdirSync(join(out, dir), { recursive: true });
  }

  // The whole registry first, so a fixture no case references cannot drift
  // unnoticed: the guarantee is over the registry, not over what is used.
  const decoded = new Map();
  for (const [id, entry] of Object.entries(file.fixtures)) {
    const bytes = fixtureBytes(entry, id);
    decoded.set(id, bytes);
    writeFileSync(join(out, 'fixtures', `${safeName(id)}.bin`), bytes);
  }

  const lines = [];
  let pinnedClocks = 0;
  let skippedFields = 0;
  let unreachable = 0;
  for (const kase of file.cases) {
    const parts = [checkPart(kase.id, `id=${kase.id}`), `op=${kase.operation}`];
    if (kase.operation === 'decodeBase64') {
      parts.push('abiUnreachable=the C ABI exposes no base64 decoder');
      lines.push(parts.join('\t'));
      unreachable += 1;
      continue;
    }
    const name = safeName(kase.id);

    if (kase.maxMillis !== undefined) parts.push(`maxMillis=${kase.maxMillis}`);

    if (kase.clock) {
      // Parsed here, once, so no harness has to read ISO-8601.
      const millis = Date.parse(kase.clock.now);
      if (!Number.isFinite(millis)) {
        fail(`case "${kase.id}" pins an unparseable clock "${kase.clock.now}"`);
      }
      parts.push(`clockUnixMillis=${millis}`);
      pinnedClocks += 1;
    }

    const roots = kase.config.trustedRoots;
    if (roots.source === 'defaults') {
      parts.push('roots=defaults');
    } else if (roots.source === 'fixtures') {
      parts.push('roots=files');
      for (const id of roots.fixtures ?? []) {
        if (!decoded.has(id)) fail(`case "${kase.id}" names an unregistered anchor "${id}"`);
        parts.push(`root=${join(out, 'fixtures', `${safeName(id)}.bin`)}`);
      }
    } else {
      fail(`case "${kase.id}" has unknown trustedRoots source "${roots.source}"`);
    }

    if (kase.operation === 'verifyReceiptEndpoint') {
      const bit = ENDPOINT_ENVIRONMENTS[kase.config.environment];
      if (bit === undefined) {
        fail(`case "${kase.id}" has endpoint environment "${kase.config.environment}"`);
      }
      parts.push(`endpointEnv=${bit}`);
      const requestPath = join(out, 'requests', `${name}.json`);
      if (kase.input.requestBody !== undefined) {
        const body = decoded.get(kase.input.requestBody);
        if (body === undefined) fail(`case "${kase.id}" names an unregistered request body`);
        writeFileSync(requestPath, body);
      } else {
        const bytes = decoded.get(kase.input.fixture);
        if (bytes === undefined) fail(`case "${kase.id}" names an unregistered input fixture`);
        const receiptData = inputString(kase, file.fixtures[kase.input.fixture], bytes);
        writeFileSync(requestPath, JSON.stringify({ 'receipt-data': receiptData.toString('utf8') }));
      }
      parts.push(`request=${requestPath}`);
    } else if (kase.operation === 'verifyReceipt' || kase.operation === 'verifySignedData') {
      const bytes = decoded.get(kase.input.fixture);
      if (bytes === undefined) fail(`case "${kase.id}" names an unregistered input fixture`);
      const inputPath = join(out, 'inputs', `${name}.txt`);
      writeFileSync(inputPath, inputString(kase, file.fixtures[kase.input.fixture], bytes));
      parts.push(`input=${inputPath}`);
    } else {
      fail(`case "${kase.id}" has unknown operation "${kase.operation}"`);
    }

    const expected = kase.expected;
    if (expected.oneOf) {
      parts.push('expect=oneof', `oneOf=${expected.oneOf.join('|')}`);
    } else if (kase.operation === 'verifyReceiptEndpoint') {
      parts.push('expect=body');
    } else {
      parts.push(`expect=${expected.status}`);
      if (expected.status === 'error') {
        if (!expected.reason) fail(`case "${kase.id}" is an error case with no reason`);
        parts.push(`reason=${expected.reason}`);
      }
    }

    let dropped = 0;
    for (const [pointer, value] of Object.entries(expected.fields ?? {})) {
      if (TOP_LEVEL.test(pointer)) parts.push(`field=${encodeField(kase.id, pointer, value)}`);
      else dropped += 1;
    }
    for (const [pointer, count] of Object.entries(expected.lengths ?? {})) {
      if (TOP_LEVEL.test(pointer)) {
        parts.push(checkPart(kase.id, `length=${pointer}${SEPARATOR}${count}`));
      } else {
        dropped += 1;
      }
    }
    if (expected.toJson !== undefined) {
      const path = join(out, 'tojson', `${name}.json`);
      writeFileSync(path, expected.toJson, 'utf8');
      parts.push(`toJson=${path}`);
    }
    parts.push(`skippedFields=${dropped}`);
    skippedFields += dropped;
    lines.push(parts.join('\t'));
  }

  // One line per case in the parsed file, so a harness that checks every
  // manifest id ran is checking every case id in cases.json.
  if (lines.length !== file.cases.length) {
    fail(`wrote ${lines.length} lines for ${file.cases.length} cases`);
  }
  writeFileSync(join(out, 'cases.tsv'), `${lines.join('\n')}\n`);
  process.stdout.write(
    `${lines.length} cases -> ${join(out, 'cases.tsv')} ` +
      `(${pinnedClocks} pin a clock, ${skippedFields} nested pointers dropped, ` +
      `${unreachable} decodeBase64 groups the ABI cannot reach)\n`,
  );
}

main();
