import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  JwsVerifier,
  ReceiptVerifier,
  VerificationError,
  VerifyReceiptEndpoint,
  appleJwsRoots,
  appleReceiptRoots,
} from '../dist/index.js';
// The decodeBase64 groups call the two decoders directly: the receipt-data
// decoder of each build, and the x5c-entry decoder both builds share.
import { decodeReceiptDataString } from '../dist/receipt.js';
import { decodeReceiptDataString as webDecodeReceiptDataString } from '../dist/web/receipt.js';
import { x5cBase64Decode } from '../dist/bytes.js';

// Runs fixtures/cases.json — the normative cross-language conformance
// vectors — against this implementation. The adapter below knows nothing
// about any individual case: it loads the file, resolves fixture ids to
// bytes, builds a verifier from the generic config, dispatches on
// "operation", normalizes the result and reads the reason off a failure.
// A vector that disagrees with the library is a bug report against one of
// the two; it is never something to special-case here.

const fixtureUrl = (path) => fileURLToPath(new URL(`../../fixtures/${path}`, import.meta.url));

// `JSON.parse` reads every number as a double, so the download id the
// receipt-ids vectors pin — 9223372036854775807, a nineteen-digit, eight-byte
// integer a double rounds to 9223372036854775808 — would arrive here rounded
// and the expectation would be a value no port ever produces. Node 20, this
// package's engines floor, has neither `JSON.rawJSON` nor a reviver that can
// see the source text, so the lift happens before the parse: every number
// literal outside a string that is an integer a double cannot hold is
// rewritten into a tagged string, and the reviver turns it back into a
// BigInt. Every other literal is handed to `JSON.parse` untouched.
// `assert.equal` then compares a BigInt against the library's BigInt
// exactly — and against a number
// mathematically, so a rounded value cannot compare equal to this one.
const BIG_INT_TAG = '__bigint__:';
const JSON_STRING_OR_NUMBER = /"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;

function parseWithBigInts(text) {
  const tagged = text.replace(JSON_STRING_OR_NUMBER, (literal) =>
    literal.startsWith('"') || !/^-?\d+$/.test(literal) || Number.isSafeInteger(Number(literal))
      ? literal
      : `"${BIG_INT_TAG}${literal}"`,
  );
  return JSON.parse(tagged, (_key, value) =>
    typeof value === 'string' && value.startsWith(BIG_INT_TAG)
      ? BigInt(value.slice(BIG_INT_TAG.length))
      : value,
  );
}

const CASES_TEXT = readFileSync(fixtureUrl('cases.json'), 'utf8');
const CASES = parseWithBigInts(CASES_TEXT);

/** Decodes a registered fixture to its logical bytes (fixture.codec). */
function decodeFixture(entry) {
  const raw = readFileSync(fixtureUrl(entry.path));
  switch (entry.codec) {
    case 'raw':
      return raw;
    case 'base64':
      return Buffer.from(raw.toString('ascii').replace(/\s+/g, ''), 'base64');
    case 'utf8':
      return Buffer.from(raw.toString('utf8').trim(), 'utf8');
    case 'text':
      // The file bytes verbatim, untrimmed — several vectors are about
      // whitespace, and one is 0 bytes, so this must NOT trim like utf8.
      return raw;
    default:
      throw new Error(`harness error: unknown fixture codec "${entry.codec}"`);
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
    throw new Error(
      `fixture "${id}" (${entry.path}, codec ${entry.codec}) has drifted: ` +
        `cases.json records contentSha256 ${entry.contentSha256}, ` +
        `the decoded bytes hash to ${actual}`,
    );
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

// Guarded the way the fixture digests are, and for the same reason: a vector
// that pins an integer past 2^53 is pinning its digits, and a plain
// `JSON.parse` would round them into an expectation no port can meet — one
// that a port rounding the same way would nonetheless "pass". Finding none
// at all means the lift above stopped working, not that the vectors changed.
test('cases.json expectations keep the integers a double cannot hold', () => {
  const big = [];
  const walk = (value) => {
    if (typeof value === 'bigint') {
      big.push(value);
    } else if (Array.isArray(value)) {
      value.forEach(walk);
    } else if (value !== null && typeof value === 'object') {
      Object.values(value).forEach(walk);
    }
  };
  walk(CASES);
  assert.ok(big.length > 0, 'no vector pins an integer past 2^53 any more');
  for (const value of big) {
    assert.ok(!Number.isSafeInteger(Number(value)), `${value} fits in a double after all`);
    assert.ok(CASES_TEXT.includes(String(value)), `${value} is not what cases.json says`);
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
  requireNoClock(clock, 'JwsVerifier');
  return new JwsVerifier({
    trustedRoots: trustedRoots(config.trustedRoots),
    bundleId: config.bundleId ?? UNMATCHABLE_BUNDLE_ID,
    acceptedEnvironments: config.acceptedEnvironments ?? UNMATCHABLE_ENVIRONMENTS,
    appAppleId: config.appAppleId ?? null,
  });
}

// Each operation takes the case's clock (null when it pins none) and hands
// it to the library's `clock` option. Only the endpoint has one; an
// operation whose API has no clock seam rejects a case that pins one instead of silently running on the
// system clock. `fixture` is the input's registry entry (codec included),
// needed only by the two operations whose wire form depends on it; `spec` is
// the case's `input`, which only the endpoint reads (for `requestBody`).
const OPERATIONS = {
  verifyTransaction: (config, input, clock) =>
    jwsVerifier(config, clock).verifyTransaction(input.toString('utf8')),
  verifyAppTransaction: (config, input, clock) =>
    jwsVerifier(config, clock).verifyAppTransaction(input.toString('utf8')),
  verifyRaw: (config, input, clock) => jwsVerifier(config, clock).verifyRaw(input.toString('utf8')),
  verifyReceipt: (config, input, clock) => {
    requireNoClock(clock, 'verifyReceipt');
    const verifier = new ReceiptVerifier({
      trustedRoots: trustedRoots(config.trustedRoots),
      bundleId: config.bundleId,
    });
    const guid =
      config.deviceGuidHex === undefined ? null : Buffer.from(config.deviceGuidHex, 'hex');
    return verifier.verify(input, guid);
  },
  // The string entry point: the fixture must be a text fixture (the raw
  // characters a client sent), handed to verify() as a string, never
  // pre-decoded by this harness — that decoding is exactly what this
  // operation pins.
  verifyReceiptBase64: (config, input, clock, fixture) => {
    requireNoClock(clock, 'verifyReceiptBase64');
    if (fixture.codec !== 'text') {
      throw new Error('harness error: verifyReceiptBase64 case must name a text fixture');
    }
    const verifier = new ReceiptVerifier({
      trustedRoots: trustedRoots(config.trustedRoots),
      bundleId: config.bundleId,
    });
    const guid =
      config.deviceGuidHex === undefined ? null : Buffer.from(config.deviceGuidHex, 'hex');
    return verifier.verify(input.toString('utf8'), guid);
  },
  // Returns the result itself: runCase reads failureReason off it and then
  // checks the fields against its response.
  verifyReceiptEndpoint: (config, input, clock, fixture, spec) => {
    const endpoint = new VerifyReceiptEndpoint({
      trustedRoots: trustedRoots(config.trustedRoots),
      environment: config.environment,
      clock,
    });
    if (spec.requestBody !== undefined) {
      // The whole raw body, verbatim, through the entry point that parses
      // it: never wrapped in an envelope, never trimmed.
      return endpoint.verifyReceiptResult(input.toString('utf8'));
    }
    return endpoint.verifyReceiptResult({
      // A text fixture's bytes ARE the client-sent string, verbatim; a
      // raw/base64 fixture is DER, which this harness re-encodes as
      // canonical base64 the way a normal client would.
      'receipt-data': fixture.codec === 'text' ? input.toString('utf8') : input.toString('base64'),
    });
  },
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
    steps.push(
      match[1] === undefined
        ? { bracket: true, value: match[2] }
        : { bracket: false, value: match[1] },
    );
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
      current =
        step.value === 'length' && Array.isArray(current) ? current.length : current[step.value];
      continue;
    }
    const separator = step.value.indexOf('=');
    if (separator > 0) {
      const key = step.value.slice(0, separator);
      const wanted = step.value.slice(separator + 1);
      assert.ok(Array.isArray(current), `${path}: [${step.value}] does not select from a list`);
      const matches = current.filter(
        (element) => element !== null && typeof element === 'object' && element[key] === wanted,
      );
      assert.equal(
        matches.length,
        1,
        `${path}: [${step.value}] must select exactly one element, selected ${matches.length}`,
      );
      current = matches[0];
    } else {
      current = Array.isArray(current) ? current[Number(step.value)] : current[step.value];
    }
  }
  return current;
}

// --- decodeBase64 -------------------------------------------------------

// Each decoder a decodeBase64 group can name, with the reason its refusal
// carries. An error group states INVALID_RECEIPT_FORMAT, the receipt-data
// answer; x5c answers INVALID_CERTIFICATE. x5cBase64Decode throws a plain
// Error that both JWS verifiers turn into INVALID_CERTIFICATE, so that
// translation happens here.
const BASE64_DECODERS = {
  'receipt-data': [
    { build: 'node', decode: decodeReceiptDataString, refusal: 'INVALID_RECEIPT_FORMAT' },
    { build: 'web', decode: webDecodeReceiptDataString, refusal: 'INVALID_RECEIPT_FORMAT' },
  ],
  x5c: [
    {
      build: 'node+web',
      decode: (text) => {
        try {
          return x5cBase64Decode(text);
        } catch (error) {
          throw new VerificationError('INVALID_CERTIFICATE', error.message);
        }
      },
      refusal: 'INVALID_CERTIFICATE',
    },
  ],
};

/**
 * Runs every text of a decodeBase64 group through every decoder it names and
 * reports every text that got the wrong answer, by case id, decoder, index
 * and quoted text, rather than stopping at the first.
 */
function runDecodeBase64(kase) {
  const { texts } = kase.input;
  assert.ok(Array.isArray(texts) && texts.length > 0, 'harness error: input.texts is empty');
  assert.ok(Array.isArray(kase.decoders) && kase.decoders.length > 0, 'harness error: no decoders');
  const { status, bytesHex, reason } = kase.expected;
  if (status === 'error') {
    assert.equal(
      reason,
      'INVALID_RECEIPT_FORMAT',
      'harness error: an error group states the receipt-data reason',
    );
  }
  const failures = [];
  for (const name of kase.decoders) {
    const decoders = BASE64_DECODERS[name];
    if (decoders === undefined) {
      throw new Error(`harness error: no decoder "${name}"`);
    }
    for (const { build, decode, refusal } of decoders) {
      texts.forEach((text, index) => {
        const where = `${kase.id}: ${name} (${build}) texts[${index}] ${JSON.stringify(text)}`;
        let decoded;
        try {
          decoded = Buffer.from(decode(text)).toString('hex');
        } catch (error) {
          if (!(error instanceof VerificationError)) {
            failures.push(
              `${where}: harness error: threw ${error?.constructor?.name} (${error?.message})`,
            );
          } else if (status === 'ok') {
            failures.push(`${where} was refused (${error.reason}), want ${bytesHex}`);
          } else if (error.reason !== refusal) {
            failures.push(`${where}: reason ${error.reason}, want ${refusal}`);
          }
          return;
        }
        if (status === 'error') {
          failures.push(`${where} was accepted (decoded to ${decoded})`);
        } else if (decoded !== bytesHex) {
          failures.push(`${where} decoded to ${decoded}, want ${bytesHex}`);
        }
      });
    }
  }
  assert.deepEqual(failures, [], failures.join('\n'));
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
  if (kase.operation === 'decodeBase64') {
    runDecodeBase64(kase);
    return;
  }
  const operation = OPERATIONS[kase.operation];
  if (operation === undefined) {
    throw new Error(`harness error: no adapter for operation "${kase.operation}"`);
  }
  // A requestBody names a fixture too: the whole raw request body.
  const fixtureId = kase.input.requestBody ?? kase.input.fixture;
  const input = fixtureBytes(fixtureId);
  const fixture = CASES.fixtures[fixtureId];
  let result;
  try {
    result = operation(kase.config, input, caseClock(kase), fixture, kase.input);
  } catch (error) {
    // Only a VerificationError carries a canonical Reason. Anything else is
    // a defect in the library or in this harness, and must never be read as
    // one of the expected reasons.
    if (!(error instanceof VerificationError)) {
      throw new Error(
        `harness error: ${kase.operation} threw ` +
          `${error?.constructor?.name ?? typeof error} (${error?.message}), ` +
          'which is not a VerificationError',
        { cause: error },
      );
    }
    assert.equal(kase.expected.status, 'error', `expected success but threw ${error.reason}`);
    assert.equal(error.reason, kase.expected.reason, 'reason');
    return;
  }
  assert.equal(
    kase.expected.status,
    'ok',
    `expected ${kase.expected.reason} but the call returned a value`,
  );
  if (kase.operation === 'verifyReceiptEndpoint') {
    // failureReason is not on Apple's wire, so an endpoint case pins it
    // beside the wire fields rather than among them.
    if (kase.expected.failureReason !== undefined) {
      assert.equal(result.failureReason, kase.expected.failureReason, 'failureReason');
    }
    result = result.toResponse();
  }
  const actual = normalize(result);
  for (const [path, expected] of Object.entries(kase.expected.fields)) {
    const value = resolvePath(actual, path);
    if (expected === null) {
      // null means "absent or unset".
      assert.ok(
        value === null || value === undefined,
        `${path}: expected absent, got ${String(value)}`,
      );
    } else if (typeof value === 'bigint' || typeof expected === 'bigint') {
      // Compared as digits: an id past 2^53 arrives as a BigInt, the vector
      // pins a BigInt or a plain number depending on its size, and the
      // strict `assert.equal` would call 1234567890n and 1234567890
      // different ids. Rounding still fails — "9223372036854775808" is not
      // "9223372036854775807".
      assert.equal(String(value), String(expected), path);
    } else {
      assert.equal(value, expected, path);
    }
  }
}

// Which case ids actually ran, so the coverage check below is a fact rather
// than a loop-shaped assumption.
const RAN = new Set();

for (const kase of CASES.cases) {
  test(`cases.json ${kase.id}`, () => {
    RAN.add(kase.id);
    runCase(kase);
  });
}

// A test filter on the command line is the one thing that may legitimately
// leave cases unrun, so the check stands down for it and says so.
const TEST_FILTER = [...process.execArgv, ...process.argv].find((arg) =>
  /^--test-(name-pattern|skip-pattern|only)\b/.test(arg),
);

// Coverage self-check: every case in the file ran, compared against the
// parsed file and never against a literal count, so a case the loop above
// stopped reaching, or an operation that quietly returned early, fails here.
test('cases.json every case ran', (t) => {
  if (TEST_FILTER !== undefined) {
    t.diagnostic(`${TEST_FILTER} filters tests; the coverage self-check needs a full run`);
    return;
  }
  const missing = CASES.cases.map((kase) => kase.id).filter((id) => !RAN.has(id));
  assert.deepEqual(missing, [], `${missing.length} of ${CASES.cases.length} cases did not run`);
});
