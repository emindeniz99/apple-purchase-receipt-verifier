#!/usr/bin/env node
/**
 * Lints fixtures/cases.json — the normative cross-language conformance vectors
 * (schema version 2, the 0.7 API).
 *
 *   node tools/lint-cases.mjs
 *
 * Needs `npm ci --prefix tools` (ajv, pinned in tools/package-lock.json), as
 * tools/validate-wire.mjs does. Ajv validates the file against
 * fixtures/cases.schema.json (JSON Schema 2020-12); this script adds the
 * checks a schema cannot express. The port runners re-hash the fixtures
 * they use, but none validates the file against its schema or looks for
 * files nothing registers, so this stays the one place that does.
 *
 * It fails, listing EVERY problem rather than the first, when:
 *   - cases.json does not match cases.schema.json structurally
 *   - a registered fixture file is missing, or its contentSha256 is wrong
 *   - a file under fixtures/generated-0.7/ or fixtures/public-receipts/ is
 *     not registered
 *   - a fixture with role "input" is referenced by no case
 *   - two cases share an id
 *   - a case references an unregistered fixture
 *   - an expected reason, or a oneOf outcome, is outside the 0.7 Reason set,
 *     or is INTERNAL_ERROR, which no correct library answers to any input
 *   - a requestBody fixture's codec is not "text"
 *   - a decodeBase64 case lists a decoder twice, lists a spelling another
 *     decodeBase64 case already lists, or holds a spelling whose answer
 *     disagrees with the base64 rule as stated here independently
 *
 * SCOPE NOTE — only generated-0.7/ and public-receipts/ are scanned for
 * unregistered files, because those two tiers exist solely to feed these
 * vectors. fixtures/generated/ also keeps 0.6-era receipts that port unit
 * tests, fuzz harnesses and smoke programs read directly; fixtures/limits/
 * keeps inputs for the port bounds tests; fixtures/apple-official/ is
 * vendored verbatim from Apple's app-store-server-library-java. Only the
 * files from those three that cases.json uses are registered.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { readFixture } from './lib/fixtures.mjs';

const require = createRequire(import.meta.url);
let Ajv2020;
try {
  Ajv2020 = require('ajv/dist/2020.js');
} catch (e) {
  if (e.code !== 'MODULE_NOT_FOUND') throw e;
  console.error('lint-cases: ajv is missing; run `npm ci --prefix tools` first');
  process.exit(2);
}

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURES_DIR = join(REPO, 'fixtures');
const CASES_PATH = join(FIXTURES_DIR, 'cases.json');
const SCHEMA_PATH = join(FIXTURES_DIR, 'cases.schema.json');
const SCANNED_TIERS = ['generated-0.7', 'public-receipts'];

// The 0.7 Reason set (docs/design/0.7-api.md, Result). INTERNAL_ERROR is a
// reason a port can return, but never one a case may expect.
const REASONS = [
  'MALFORMED', 'TOO_LARGE', 'INVALID_SIGNATURE', 'UNTRUSTED_CHAIN',
  'INVALID_CERTIFICATE', 'INVALID_CERTIFICATE_PURPOSE', 'UNREADABLE_PAYLOAD',
  'INTERNAL_ERROR',
];
const EXPECTABLE = REASONS.filter((reason) => reason !== 'INTERNAL_ERROR');

const problems = [];
const fail = (where, message) => problems.push(`${where}: ${message}`);

function typeOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (Number.isInteger(value)) return 'integer';
  return typeof value; // string | number | boolean | object
}

// Validates cases.json against cases.schema.json with Ajv, one line per
// problem. Strict mode makes an unknown keyword in the schema an error, so
// a typo cannot silently validate everything. strictTypes and
// strictRequired stay off: both reject valid 2020-12 the schema relies on,
// an untyped `then: { required: ["fault"] }` and a union `type`. verbose
// puts the data and the oneOf branches on each error, for explain().
function lintSchema(schema, doc) {
  const ajv = new Ajv2020({
    strict: true, strictTypes: false, strictRequired: false, allErrors: true, verbose: true,
  });
  const validate = ajv.compile(schema);
  // A failed oneOf is explained by validating against each branch, found by
  // the oneOf's place in the schema. Ajv's errors carry a copy of the
  // schema value, not the object, so the lookup is by content.
  const pointers = new Map();
  (function walk(node, pointer) {
    if (node === null || typeof node !== 'object') return;
    if (!pointers.has(JSON.stringify(node))) pointers.set(JSON.stringify(node), pointer);
    for (const [key, child] of Object.entries(node)) {
      walk(child, `${pointer}/${key.replace(/~/g, '~0').replace(/\//g, '~1')}`);
    }
  })(schema, '');
  const branch = (oneOf, i) =>
    ajv.getSchema(`${schema.$id}#${pointers.get(JSON.stringify(oneOf))}/${i}`);

  for (const error of explain(validate, doc, '', branch)) {
    const index = /^\/cases\/(\d+)(\/|$)/.exec(error.instancePath)?.[1];
    const id = index === undefined ? undefined : doc.cases[index]?.id;
    const where = index === undefined ? 'cases.json'
      : `case #${index}${typeof id === 'string' ? ` "${id}"` : ''}`;
    fail(where, `${error.instancePath || '/'} ${describe(error)}`);
  }
}

// Ajv's errors for data, with instance paths under `at`, one per problem.
// A oneOf that matched nothing carries every branch's errors; it is
// replaced by the errors of its closest branch (the one with the fewest),
// so a case reports what is wrong with the shape it was meant to have, not
// how it differs from every other shape. The errors of if and
// propertyNames only restate the inner error beside them, so they go.
function explain(validate, data, at, branch) {
  if (validate(data)) return [];
  const errors = validate.errors
    .map((e) => ({ ...e, instancePath: at + e.instancePath }))
    .filter((e) => e.keyword !== 'if' && e.keyword !== 'propertyNames');
  const isOneOf = (e) => e.keyword === 'oneOf';
  const inside = (e, o) =>
    e.instancePath === o.instancePath || e.instancePath.startsWith(`${o.instancePath}/`);
  // Ajv reports a oneOf after the oneOfs inside its branches, so a oneOf is
  // outermost when no later one encloses its data.
  const outer = errors.filter((e, i) =>
    isOneOf(e) && !errors.some((o, j) => j > i && isOneOf(o) && inside(e, o)));
  const result = [];
  for (const e of errors) {
    if (outer.includes(e) && e.params.passingSchemas !== null) {
      result.push(e);
    } else if (outer.includes(e)) {
      const explained = e.schema.map((_, i) =>
        explain(branch(e.schema, i), e.data, e.instancePath, branch));
      result.push(...explained.reduce((a, b) => (b.length < a.length ? b : a)));
    } else if (!outer.some((o) => inside(e, o))) {
      result.push(e);
    }
  }
  return result;
}

function describe(error) {
  const { params } = error;
  if (error.keyword === 'oneOf') {
    return `matches ${params.passingSchemas.length} allowed shapes at once `
      + `(oneOf branches ${params.passingSchemas.join(', ')})`;
  }
  const subject = error.propertyName === undefined
    ? '' : `property name ${JSON.stringify(error.propertyName)} `;
  let detail = '';
  if (params.additionalProperty !== undefined) {
    detail = `: ${JSON.stringify(params.additionalProperty)}`;
  } else if (params.allowedValue !== undefined) {
    detail = ` ${JSON.stringify(params.allowedValue)}`;
  } else if (params.allowedValues !== undefined) {
    detail = ` ${params.allowedValues.map((v) => JSON.stringify(v)).join(', ')}`;
  }
  const got = ['type', 'const', 'enum', 'pattern'].includes(error.keyword)
    && error.propertyName === undefined ? `, got ${JSON.stringify(error.data)}` : '';
  return `${subject}${error.message}${detail}${got}`;
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    fail(relative(REPO, path), `cannot be read as JSON — ${e.message}`);
    return null;
  }
}

// The receipt-data / x5c base64 rule, stated independently of every port:
// non-empty, a multiple of four, the standard alphabet followed by at most
// two '='. Trailing bits are not checked. Returns the bytes, or null.
const CANONICAL_BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
function ruleDecode(text) {
  if (text.length === 0 || text.length % 4 !== 0 || !CANONICAL_BASE64.test(text)) return null;
  return Buffer.from(text, 'base64');
}

// Every decodeBase64 spelling appears once across all groups, so the list
// stays a union rather than growing copies.
const base64Spellings = new Map();

function lintDecodeBase64(where, testCase) {
  const decoders = testCase.decoders;
  if (Array.isArray(decoders) && new Set(decoders).size !== decoders.length) {
    fail(where, `decoders lists a decoder twice: ${JSON.stringify(decoders)}`);
  }
  const texts = testCase.input?.texts;
  if (!Array.isArray(texts)) return;
  const expected = testCase.expected ?? {};
  texts.forEach((text, index) => {
    if (typeof text !== 'string') return;
    const spot = `${where} texts[${index}] ${JSON.stringify(text)}`;
    if (base64Spellings.has(text)) {
      fail(spot, `is already listed by ${base64Spellings.get(text)}`);
    } else {
      base64Spellings.set(text, where);
    }
    const decoded = ruleDecode(text);
    if (expected.status === 'ok' && decoded === null) {
      fail(spot, 'is in an ok group, but the rule refuses it');
    } else if (expected.status === 'ok' && decoded.toString('hex') !== expected.bytesHex) {
      fail(spot, `decodes to ${decoded.toString('hex')} under the rule, not ${expected.bytesHex}`);
    } else if (expected.status === 'error' && decoded !== null) {
      fail(spot, `is in an error group, but the rule decodes it to ${decoded.toString('hex')}`);
    }
  });
}

const schema = readJson(SCHEMA_PATH);
const doc = readJson(CASES_PATH);

if (schema && doc) {
  try {
    lintSchema(schema, doc);
  } catch (e) {
    fail('schema', `the schema itself could not be applied — ${e.message}`);
  }
}

if (doc && typeOf(doc.fixtures) === 'object' && Array.isArray(doc.cases)) {
  const fixtures = doc.fixtures;

  // Registered fixture files: present, and hashed over their DECODED bytes.
  for (const [id, fixture] of Object.entries(fixtures)) {
    if (typeOf(fixture) !== 'object' || typeof fixture.path !== 'string') continue;
    try {
      readFixture(FIXTURES_DIR, fixture, id);
    } catch (e) {
      problems.push(e.message);
    }
  }

  // Every file in the tiers this file owns must be registered.
  const registeredPaths = new Set(
    Object.values(fixtures).map((f) => f?.path).filter((p) => typeof p === 'string'));
  for (const tier of SCANNED_TIERS) {
    const dir = join(FIXTURES_DIR, tier);
    let files;
    try {
      files = readdirSync(dir, { recursive: true, withFileTypes: true })
        .map((entry) => join(entry.parentPath, entry.name))
        .filter((path) => statSync(path).isFile());
    } catch {
      fail(`tier "${tier}"`, `fixtures/${tier}/ does not exist`);
      continue;
    }
    for (const file of files) {
      const rel = relative(FIXTURES_DIR, file).split('\\').join('/');
      if (!registeredPaths.has(rel)) {
        fail(`tier "${tier}"`, `fixtures/${rel} exists but is registered by no fixture entry`);
      }
    }
  }

  // Case-level checks.
  const seenIds = new Map();
  const referenced = new Set();
  doc.cases.forEach((testCase, index) => {
    const where = `case #${index}${typeof testCase?.id === 'string' ? ` "${testCase.id}"` : ''}`;
    if (typeOf(testCase) !== 'object') return;

    if (typeof testCase.id === 'string') {
      if (seenIds.has(testCase.id)) {
        fail(where, `duplicate id — already used by case #${seenIds.get(testCase.id)}`);
      } else {
        seenIds.set(testCase.id, index);
      }
    }

    const refs = [];
    if (typeOf(testCase.input) === 'object' && typeof testCase.input.fixture === 'string') {
      refs.push(['input', testCase.input.fixture]);
    }
    if (typeOf(testCase.input) === 'object' && typeof testCase.input.requestBody === 'string') {
      refs.push(['input.requestBody', testCase.input.requestBody]);
      const codec = fixtures[testCase.input.requestBody]?.codec;
      if (codec !== undefined && codec !== 'text') {
        fail(where, `a requestBody is handed to the raw-body entry point verbatim, so its fixture must have codec `
          + `"text" (got ${JSON.stringify(codec)})`);
      }
    }
    const roots = testCase.config?.trustedRoots;
    if (typeOf(roots) === 'object' && Array.isArray(roots.fixtures)) {
      for (const id of roots.fixtures) refs.push(['config.trustedRoots', id]);
    }
    for (const [slot, id] of refs) {
      referenced.add(id);
      if (!Object.prototype.hasOwnProperty.call(fixtures, id)) {
        fail(where, `${slot} references fixture "${id}", which is not registered`);
      }
    }

    if (testCase.operation === 'decodeBase64') lintDecodeBase64(where, testCase);

    const expected = testCase.expected;
    const outcomes = [];
    if (typeOf(expected) === 'object' && expected.status === 'error') outcomes.push(expected.reason);
    // An endpoint case's oneOf lists /status values, which the schema's
    // enum checks; every other oneOf lists "ok" or a reason.
    if (typeOf(expected) === 'object' && Array.isArray(expected.oneOf)
      && testCase.operation !== 'verifyReceiptEndpoint') {
      outcomes.push(...expected.oneOf.filter((outcome) => outcome !== 'ok'));
    }
    for (const reason of outcomes) {
      if (!EXPECTABLE.includes(reason)) {
        fail(where, `expected outcome ${JSON.stringify(reason)} is not one a case may expect `
          + `(${EXPECTABLE.join(', ')})`);
      }
    }
  });

  // Input fixtures nothing uses are dead weight.
  for (const [id, fixture] of Object.entries(fixtures)) {
    if (fixture?.role === 'input' && !referenced.has(id)) {
      fail(`fixture "${id}"`, `has role "input" but is referenced by no case`);
    }
  }
}

if (problems.length > 0) {
  console.error(`lint-cases: ${problems.length} problem${problems.length === 1 ? '' : 's'} in fixtures/cases.json\n`);
  for (const problem of problems) console.error(`  - ${problem}`);
  console.error('');
  process.exit(1);
}

const caseCount = doc.cases.length;
const fixtureCount = Object.keys(doc.fixtures).length;
console.log(`lint-cases: OK — ${caseCount} cases over ${fixtureCount} registered fixtures.`);
