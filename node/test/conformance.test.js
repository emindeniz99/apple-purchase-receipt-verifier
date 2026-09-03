import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  JwsVerifier, ReceiptVerifier, VerificationError, VerifyReceiptEndpoint,
  appleJwsRoots, appleReceiptRoots,
} from '../dist/index.js';

// Runs fixtures/cases.json — the normative cross-language conformance
// vectors — against this implementation. The adapter below knows nothing
// about any individual case: it loads the file, resolves fixture ids to
// bytes, builds a verifier from the generic config, dispatches on
// "operation", normalizes the result and reads the reason off a failure.
// A vector that disagrees with the library is a bug report against one of
// the two; it is never something to special-case here.

const fixtureUrl = (path) => fileURLToPath(new URL(`../../fixtures/${path}`, import.meta.url));

const CASES = JSON.parse(readFileSync(fixtureUrl('cases.json'), 'utf8'));

/** Decodes a registered fixture to its logical bytes (fixture.codec). */
function decodeFixture(entry) {
  const raw = readFileSync(fixtureUrl(entry.path));
  switch (entry.codec) {
    case 'raw': return raw;
    case 'base64': return Buffer.from(raw.toString('ascii').replace(/\s+/g, ''), 'base64');
    case 'utf8': return Buffer.from(raw.toString('utf8').trim(), 'utf8');
    default: throw new Error(`harness error: unknown fixture codec "${entry.codec}"`);
  }
}

/**
 * The decoded bytes of a registered fixture, checked against the digest the
 * registry records for them. contentSha256 is the anti-drift guarantee for
 * the vectors: a fixture that is regenerated, re-encoded or silently edited
 * changes the bytes every port verifies, and the expected fields would then
 * be pinned to something no other port ever saw. Verifying it here is what
 * makes that guarantee load-bearing rather than documentary — the digest is
 * over the LOGICAL bytes (post-codec), the same bytes handed to the library.
 */
function fixtureBytes(id) {
  const entry = CASES.fixtures[id];
  if (entry === undefined) {
    throw new Error(`harness error: cases.json registers no fixture "${id}"`);
  }
  const cached = FIXTURE_CACHE.get(id);
  if (cached !== undefined) {
    return cached;
  }
  const bytes = decodeFixture(entry);
  if (typeof entry.contentSha256 !== 'string') {
    throw new Error(`fixture "${id}" (${entry.path}) records no contentSha256`);
  }
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== entry.contentSha256) {
    throw new Error(`fixture "${id}" (${entry.path}, codec ${entry.codec}) has drifted: `
      + `cases.json records contentSha256 ${entry.contentSha256}, `
      + `the decoded bytes hash to ${actual}`);
  }
  FIXTURE_CACHE.set(id, bytes);
  return bytes;
}

const FIXTURE_CACHE = new Map();

// Read before any case runs: a fixture no case happens to reference would
// otherwise drift unnoticed, and the registry is the thing being guarded.
test('every fixture cases.json registers matches its recorded contentSha256', () => {
  const ids = Object.keys(CASES.fixtures);
  assert.ok(ids.length > 0, 'cases.json must register fixtures');
  for (const id of ids) {
    fixtureBytes(id);
  }
});

const BUILTIN_ROOTS = {
  'apple-jws-roots': appleJwsRoots,
  'apple-receipt-roots': appleReceiptRoots,
};

function trustedRoots(spec) {
  if (spec.source === 'builtin') {
    const roots = BUILTIN_ROOTS[spec.name];
    if (roots === undefined) {
      throw new Error(`harness error: unknown builtin root set "${spec.name}"`);
    }
    return roots();
  }
  return spec.fixtures.map(fixtureBytes);
}

// verifyRaw enforces no claim, so its cases may omit bundleId and
// acceptedEnvironments — but this constructor still demands both. The
// placeholders match nothing the fixtures carry, so a claim check that
// leaked into verifyRaw would surface as a failure, not as a pass.
const UNMATCHABLE_BUNDLE_ID = 'conformance.unset.bundle.id';
const UNMATCHABLE_ENVIRONMENTS = ['LocalTesting'];

function jwsVerifier(config, clock) {
  return new JwsVerifier({
    trustedRoots: trustedRoots(config.trustedRoots),
    bundleId: config.bundleId ?? UNMATCHABLE_BUNDLE_ID,
    acceptedEnvironments: config.acceptedEnvironments ?? UNMATCHABLE_ENVIRONMENTS,
    appAppleId: config.appAppleId ?? null,
    maxSignedAgeMillis: config.maxSignedAgeSeconds === undefined
      ? null : config.maxSignedAgeSeconds * 1000,
    clock,
  });
}

// Each operation takes the case's clock (null when it pins none) and hands
// it to the library's `clock` option. An operation whose API has no clock
// seam rejects a case that pins one instead of silently running on the
// system clock.
const OPERATIONS = {
  verifyTransaction: (config, input, clock) =>
    jwsVerifier(config, clock).verifyTransaction(input.toString('utf8')),
  verifyAppTransaction: (config, input, clock) =>
    jwsVerifier(config, clock).verifyAppTransaction(input.toString('utf8')),
  verifyRaw: (config, input, clock) =>
    jwsVerifier(config, clock).verifyRaw(input.toString('utf8')),
  verifyReceipt: (config, input, clock) => {
    requireNoClock(clock, 'verifyReceipt');
    const verifier = new ReceiptVerifier({
      trustedRoots: trustedRoots(config.trustedRoots), bundleId: config.bundleId,
    });
    const guid = config.deviceGuidHex === undefined
      ? null : Buffer.from(config.deviceGuidHex, 'hex');
    return verifier.verify(input, guid);
  },
  verifyReceiptEndpoint: (config, input, clock) => new VerifyReceiptEndpoint({
    trustedRoots: trustedRoots(config.trustedRoots), environment: config.environment, clock,
  }).verifyReceipt({ 'receipt-data': input.toString('base64') }),
};

function requireNoClock(clock, operation) {
  if (clock !== null) {
    throw new Error(`harness error: ${operation} has no clock seam, but the case pins one`);
  }
}

// --- result normalization ----------------------------------------------

/** ISO-8601 UTC, dropping milliseconds when they are zero. */
const isoUtc = (date) => date.toISOString().replace(/\.000Z$/, 'Z');

const isBytes = (value) => Buffer.isBuffer(value) || value instanceof Uint8Array;

/**
 * Renders a returned object into the language-neutral shape the field paths
 * are written against: dates as ISO-8601 UTC, binary as lowercase hex (also
 * under `<name>Hex`, the spelling cases.json uses for a byte field), maps as
 * plain objects keyed by the stringified key.
 */
function normalize(value) {
  if (value === null || value === undefined) {
    return null;
  }
  if (value instanceof Date) {
    return isoUtc(value);
  }
  if (isBytes(value)) {
    return Buffer.from(value).toString('hex');
  }
  if (Array.isArray(value)) {
    return value.map(normalize);
  }
  if (value instanceof Map) {
    return Object.fromEntries([...value].map(([key, v]) => [String(key), normalize(v)]));
  }
  if (typeof value === 'object') {
    const out = {};
    for (const [key, v] of Object.entries(value)) {
      out[key] = normalize(v);
      if (isBytes(v)) {
        out[`${key}Hex`] = out[key];
      }
    }
    return out;
  }
  return value;
}

// --- field paths --------------------------------------------------------

// A path step is either a name (`bundleId`, `length`) or a bracket
// (`[9999]`, `[0]`, `[productId=com.example.app.vip]`). Bracket contents may
// hold dots, so the split cannot be a plain `.split('.')`.
const PATH_STEP = /\.?([^.[\]]+)|\[([^\]]+)\]/g;

function pathSteps(path) {
  const steps = [];
  let consumed = 0;
  for (const match of path.matchAll(PATH_STEP)) {
    if (match.index !== consumed) {
      throw new Error(`harness error: unparseable field path "${path}"`);
    }
    consumed += match[0].length;
    steps.push(match[1] === undefined
      ? { bracket: true, value: match[2] } : { bracket: false, value: match[1] });
  }
  if (consumed !== path.length) {
    throw new Error(`harness error: unparseable field path "${path}"`);
  }
  return steps;
}

function resolvePath(root, path) {
  let current = root;
  for (const step of pathSteps(path)) {
    if (current === null || current === undefined) {
      return undefined;
    }
    if (!step.bracket) {
      current = step.value === 'length' && Array.isArray(current)
        ? current.length : current[step.value];
      continue;
    }
    const separator = step.value.indexOf('=');
    if (separator > 0) {
      const key = step.value.slice(0, separator);
      const wanted = step.value.slice(separator + 1);
      assert.ok(Array.isArray(current), `${path}: [${step.value}] does not select from a list`);
      const matches = current.filter(
        (element) => element !== null && typeof element === 'object' && element[key] === wanted);
      assert.equal(matches.length, 1,
        `${path}: [${step.value}] must select exactly one element, selected ${matches.length}`);
      current = matches[0];
    } else {
      current = Array.isArray(current) ? current[Number(step.value)] : current[step.value];
    }
  }
  return current;
}

// --- one case -----------------------------------------------------------

/**
 * The case's pinned instant as the library's `clock` option, or null when
 * the case does not pin one (then the library uses the system clock).
 */
function caseClock(kase) {
  if (kase.clock === undefined) {
    return null;
  }
  const now = new Date(kase.clock.now);
  if (Number.isNaN(now.getTime())) {
    throw new Error(`harness error: unparseable clock "${kase.clock.now}"`);
  }
  return () => now;
}

function runCase(kase) {
  const operation = OPERATIONS[kase.operation];
  if (operation === undefined) {
    throw new Error(`harness error: no adapter for operation "${kase.operation}"`);
  }
  const input = fixtureBytes(kase.input.fixture);
  let result;
  try {
    result = operation(kase.config, input, caseClock(kase));
  } catch (error) {
    // Only a VerificationError carries a canonical Reason. Anything else is
    // a defect in the library or in this harness, and must never be read as
    // one of the expected reasons.
    if (!(error instanceof VerificationError)) {
      throw new Error(`harness error: ${kase.operation} threw `
        + `${error?.constructor?.name ?? typeof error} (${error?.message}), `
        + 'which is not a VerificationError', { cause: error });
    }
    assert.equal(kase.expected.status, 'error',
      `expected success but threw ${error.reason}`);
    assert.equal(error.reason, kase.expected.reason, 'reason');
    return;
  }
  assert.equal(kase.expected.status, 'ok',
    `expected ${kase.expected.reason} but the call returned a value`);
  const actual = normalize(result);
  for (const [path, expected] of Object.entries(kase.expected.fields)) {
    const value = resolvePath(actual, path);
    if (expected === null) {
      // null means "absent or unset".
      assert.ok(value === null || value === undefined,
        `${path}: expected absent, got ${JSON.stringify(value)}`);
    } else {
      assert.equal(value, expected, path);
    }
  }
}

for (const kase of CASES.cases) {
  test(`cases.json ${kase.id}`, () => runCase(kase));
}
