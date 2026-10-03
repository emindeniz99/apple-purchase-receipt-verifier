#!/usr/bin/env node
/**
 * Lints fixtures/cases.json — the normative cross-language conformance vectors
 * (schema version 2, the 0.7 API).
 *
 *   node tools/lint-cases.mjs
 *
 * Dependency-free by design (the tools' Node floor, no npm packages): it carries a small
 * validator covering exactly the JSON Schema keywords fixtures/cases.schema.json
 * uses, plus the checks a schema cannot express. The port runners re-hash the
 * fixtures they use, but none validates the file against its schema or looks
 * for files nothing registers, so this stays the one place that does.
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
import { readFixture } from './lib/fixtures.mjs';

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

/* ------------------------------------------------------------------ */
/* A small JSON Schema (draft 2020-12) subset validator.               */
/* Supported: $ref (local), type, enum, const, required, properties,   */
/* additionalProperties, propertyNames, minProperties, minItems,       */
/* uniqueItems, minLength, pattern, items, oneOf, allOf, if/then/else, */
/* minimum, maximum.                                                    */
/* Anything else in the schema is ignored, so an unsupported keyword   */
/* silently weakens the check rather than crashing — keep the schema    */
/* inside this subset.                                                  */
/* ------------------------------------------------------------------ */

function typeOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (Number.isInteger(value)) return 'integer';
  return typeof value; // string | number | boolean | object
}

function typeMatches(value, expected) {
  const actual = typeOf(value);
  if (expected === 'number') return actual === 'number' || actual === 'integer';
  if (expected === 'integer') return actual === 'integer';
  return actual === expected;
}

function deref(schema, root) {
  let current = schema;
  const seen = new Set();
  while (current && typeof current === 'object' && typeof current.$ref === 'string') {
    if (seen.has(current.$ref)) throw new Error(`cyclic $ref ${current.$ref}`);
    seen.add(current.$ref);
    if (!current.$ref.startsWith('#/')) throw new Error(`unsupported $ref ${current.$ref}`);
    let target = root;
    for (const segment of current.$ref.slice(2).split('/')) {
      target = target?.[segment.replace(/~1/g, '/').replace(/~0/g, '~')];
    }
    if (target === undefined) throw new Error(`unresolvable $ref ${current.$ref}`);
    current = target;
  }
  return current;
}

function validate(value, schema, root, path, errors) {
  const s = deref(schema, root);
  if (s === true || s === undefined) return;
  if (s === false) { errors.push(`${path}: nothing is allowed here`); return; }

  if (s.type !== undefined) {
    const allowed = Array.isArray(s.type) ? s.type : [s.type];
    if (!allowed.some((t) => typeMatches(value, t))) {
      errors.push(`${path}: expected type ${allowed.join('|')}, got ${typeOf(value)}`);
      return;
    }
  }
  if (s.const !== undefined && JSON.stringify(value) !== JSON.stringify(s.const)) {
    errors.push(`${path}: expected the constant ${JSON.stringify(s.const)}, got ${JSON.stringify(value)}`);
  }
  if (s.enum !== undefined && !s.enum.some((e) => JSON.stringify(e) === JSON.stringify(value))) {
    errors.push(`${path}: ${JSON.stringify(value)} is not one of ${s.enum.map((e) => JSON.stringify(e)).join(', ')}`);
  }
  if (typeof value === 'string') {
    if (s.pattern !== undefined && !new RegExp(s.pattern).test(value)) {
      errors.push(`${path}: ${JSON.stringify(value)} does not match /${s.pattern}/`);
    }
    if (s.minLength !== undefined && value.length < s.minLength) {
      errors.push(`${path}: shorter than minLength ${s.minLength}`);
    }
  }
  if (typeof value === 'number' && s.minimum !== undefined && value < s.minimum) {
    errors.push(`${path}: ${value} is below the minimum ${s.minimum}`);
  }
  if (typeof value === 'number' && s.maximum !== undefined && value > s.maximum) {
    errors.push(`${path}: ${value} is above the maximum ${s.maximum}`);
  }
  if (Array.isArray(value)) {
    if (s.minItems !== undefined && value.length < s.minItems) {
      errors.push(`${path}: has ${value.length} items, fewer than minItems ${s.minItems}`);
    }
    if (s.uniqueItems === true && new Set(value.map((item) => JSON.stringify(item))).size !== value.length) {
      errors.push(`${path}: items are not unique`);
    }
    if (s.items !== undefined) {
      value.forEach((item, i) => validate(item, s.items, root, `${path}[${i}]`, errors));
    }
  }
  if (value !== null && typeOf(value) === 'object') {
    const keys = Object.keys(value);
    if (s.minProperties !== undefined && keys.length < s.minProperties) {
      errors.push(`${path}: has ${keys.length} properties, fewer than minProperties ${s.minProperties}`);
    }
    for (const required of s.required ?? []) {
      if (!Object.prototype.hasOwnProperty.call(value, required)) {
        errors.push(`${path}: missing required property "${required}"`);
      }
    }
    if (s.propertyNames !== undefined) {
      for (const key of keys) validate(key, s.propertyNames, root, `${path} property name "${key}"`, errors);
    }
    for (const key of keys) {
      if (s.properties && Object.prototype.hasOwnProperty.call(s.properties, key)) {
        validate(value[key], s.properties[key], root, `${path}.${key}`, errors);
      } else if (s.additionalProperties === false) {
        errors.push(`${path}: unexpected property "${key}"`);
      } else if (s.additionalProperties !== undefined) {
        validate(value[key], s.additionalProperties, root, `${path}.${key}`, errors);
      }
    }
  }
  for (const sub of s.allOf ?? []) validate(value, sub, root, path, errors);
  if (s.oneOf !== undefined) {
    const branches = s.oneOf.map((branch) => {
      const branchErrors = [];
      validate(value, branch, root, path, branchErrors);
      return branchErrors;
    });
    const matched = branches.filter((e) => e.length === 0).length;
    if (matched === 0) {
      const best = branches.reduce((a, b) => (b.length < a.length ? b : a));
      errors.push(`${path}: matches no allowed shape; closest one reports: ${best.join('; ')}`);
    } else if (matched > 1) {
      errors.push(`${path}: ambiguous — matches ${matched} allowed shapes at once`);
    }
  }
  if (s.if !== undefined) {
    const ifErrors = [];
    validate(value, s.if, root, path, ifErrors);
    if (ifErrors.length === 0 && s.then !== undefined) validate(value, s.then, root, path, errors);
    if (ifErrors.length !== 0 && s.else !== undefined) validate(value, s.else, root, path, errors);
  }
}

/* ------------------------------------------------------------------ */

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    fail(relative(REPO, path), `cannot be read as JSON — ${e.message}`);
    return null;
  }
}

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
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
  const errors = [];
  try {
    validate(doc, schema, schema, 'cases.json', errors);
  } catch (e) {
    errors.push(`the schema itself could not be applied — ${e.message}`);
  }
  for (const error of errors) fail('schema', error);
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
      files = walk(dir);
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
