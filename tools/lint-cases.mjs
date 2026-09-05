#!/usr/bin/env node
/**
 * Lints fixtures/cases.json — the normative cross-language conformance vectors.
 *
 *   node tools/lint-cases.mjs
 *
 * Dependency-free by design (Node >= 20, no npm packages): it carries a small
 * validator covering exactly the JSON Schema keywords fixtures/cases.schema.json
 * uses, plus the checks a schema cannot express.
 *
 * It fails, listing EVERY problem rather than the first, when:
 *   - cases.json does not match cases.schema.json structurally
 *   - a registered fixture file is missing, or its contentSha256 is wrong
 *   - a file under fixtures/generated/ or fixtures/public-receipts/ is not registered
 *   - a fixture with role "input" is referenced by no case
 *   - two cases share an id
 *   - a case references an unregistered fixture
 *   - an expected reason is outside the canonical vocabulary
 *   - a verifyReceiptBase64 case names a fixture whose codec is not "text"
 *
 * SCOPE NOTE — fixtures/apple-official/ is deliberately NOT scanned for
 * unregistered files. That tier is vendored verbatim from Apple's
 * app-store-server-library-java and carries material this project draws no
 * expectation from (the testInvalid* certificates, mock_signed_data/legacyTransaction,
 * three further xcode/* artifacts). Only the apple-official files that cases.json
 * actually uses are registered; the rest stay unregistered on purpose, and adding a
 * new one there will not be flagged here. Every file under generated/ and
 * public-receipts/ IS required to be registered, because those two tiers exist
 * solely to feed these vectors.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURES_DIR = join(REPO, 'fixtures');
const CASES_PATH = join(FIXTURES_DIR, 'cases.json');
const SCHEMA_PATH = join(FIXTURES_DIR, 'cases.schema.json');
const SCANNED_TIERS = ['generated', 'public-receipts'];

const REASONS = [
  'INVALID_JWS_FORMAT', 'INVALID_CERTIFICATE', 'INVALID_CERTIFICATE_PURPOSE',
  'INVALID_CHAIN', 'INVALID_SIGNATURE', 'WRONG_BUNDLE_ID', 'WRONG_ENVIRONMENT',
  'WRONG_APP_APPLE_ID', 'INVALID_RECEIPT_FORMAT', 'DEVICE_HASH_MISMATCH',
  'STALE_PAYLOAD',
];

const problems = [];
const fail = (where, message) => problems.push(`${where}: ${message}`);

/* ------------------------------------------------------------------ */
/* A small JSON Schema (draft 2020-12) subset validator.               */
/* Supported: $ref (local), type, enum, const, required, properties,   */
/* additionalProperties, propertyNames, minProperties, minItems,       */
/* minLength, pattern, items, oneOf, allOf, if/then, minimum.          */
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
  if (Array.isArray(value)) {
    if (s.minItems !== undefined && value.length < s.minItems) {
      errors.push(`${path}: has ${value.length} items, fewer than minItems ${s.minItems}`);
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

function decode(bytes, codec) {
  if (codec === 'raw') return bytes;
  if (codec === 'utf8') return Buffer.from(bytes.toString('utf8').trim(), 'utf8');
  if (codec === 'text') return bytes; // verbatim, untrimmed: the string a client sent
  if (codec === 'base64') return Buffer.from(bytes.toString('utf8').replace(/\s+/g, ''), 'base64');
  throw new Error(`unknown codec ${codec}`);
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
    const full = join(FIXTURES_DIR, fixture.path);
    let bytes;
    try {
      bytes = readFileSync(full);
    } catch {
      fail(`fixture "${id}"`, `file fixtures/${fixture.path} does not exist`);
      continue;
    }
    let decoded;
    try {
      decoded = decode(bytes, fixture.codec);
    } catch (e) {
      fail(`fixture "${id}"`, e.message);
      continue;
    }
    const digest = createHash('sha256').update(decoded).digest('hex');
    if (digest !== fixture.contentSha256) {
      fail(`fixture "${id}"`,
        `contentSha256 is wrong for fixtures/${fixture.path} (codec ${fixture.codec})\n`
        + `    registered: ${fixture.contentSha256}\n`
        + `    actual:     ${digest}`);
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

    if (testCase.operation === 'verifyReceiptBase64') {
      const codec = fixtures[testCase.input?.fixture]?.codec;
      if (codec !== 'text') {
        fail(where, `verifyReceiptBase64 hands the fixture to the string entry point verbatim, so its fixture must `
          + `have codec "text" (got ${JSON.stringify(codec)}) -- any other codec makes the runner decode it first`);
      }
    }

    const expected = testCase.expected;
    if (typeOf(expected) === 'object' && expected.status === 'error') {
      if (!REASONS.includes(expected.reason)) {
        fail(where, `expected reason ${JSON.stringify(expected.reason)} is outside the canonical vocabulary `
          + `(${REASONS.join(', ')})`);
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
