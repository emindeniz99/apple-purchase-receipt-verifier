import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

// Runs fixtures/cases.json — the normative cross-language conformance
// vectors for the 0.7 API — against BOTH entry points (the synchronous
// default one and the Promise-returning /web one), through the same
// adapter. Both run aprv.wasm, so a vector that fails here is a bug report
// against the module or this package's facade over it, never something
// special-cased here.

import * as nodeBuild from '../dist/index.js';
import * as webBuild from '../dist/web/index.js';

const fixtureUrl = (path) => fileURLToPath(new URL(`../../fixtures/${path}`, import.meta.url));

// `JSON.parse` reads every number as a double, so an id past 2^53 (the
// endpoint's download_id, up to 9223372036854775807) would arrive rounded.
// Every number literal outside a string that a double cannot hold exactly is
// rewritten into a tagged string before parsing, then turned back into a
// BigInt by a reviver; every other literal is handed to `JSON.parse`
// untouched.
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

const CASES = parseWithBigInts(readFileSync(fixtureUrl('cases.json'), 'utf8'));

const FIXTURE_CACHE = new Map();

function decodeFixtureFile(entry) {
  const raw = readFileSync(fixtureUrl(entry.path));
  switch (entry.codec) {
    case 'raw':
      return raw;
    case 'base64':
      return Buffer.from(raw.toString('ascii').replace(/\s+/g, ''), 'base64');
    case 'utf8':
      return Buffer.from(raw.toString('utf8').trim(), 'utf8');
    case 'text':
      // The file bytes verbatim, untrimmed.
      return raw;
    default:
      throw new Error(`harness error: unknown fixture codec "${entry.codec}"`);
  }
}

/** The decoded bytes of a registered fixture, checked against its recorded digest. */
function fixtureBytes(id) {
  const entry = CASES.fixtures[id];
  if (entry === undefined) {
    throw new Error(`harness error: cases.json registers no fixture "${id}"`);
  }
  const cached = FIXTURE_CACHE.get(id);
  if (cached !== undefined) {
    return cached;
  }
  const bytes = decodeFixtureFile(entry);
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== entry.contentSha256) {
    throw new Error(
      `fixture "${id}" (${entry.path}, codec ${entry.codec}) has drifted: ` +
        `cases.json records contentSha256 ${entry.contentSha256}, decoded bytes hash to ${actual}`,
    );
  }
  FIXTURE_CACHE.set(id, bytes);
  return bytes;
}

test('every fixture cases.json registers matches its recorded contentSha256', () => {
  const ids = Object.keys(CASES.fixtures);
  assert.ok(ids.length > 0, 'cases.json must register fixtures');
  for (const id of ids) {
    fixtureBytes(id);
  }
});

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
});

// --- field paths ---------------------------------------------------------

// JSON Pointer (RFC 6901): a leading "/" starts the path, then "/"-joined
// tokens; empty string means the whole document.
function pointerSteps(pointer) {
  if (pointer === '') {
    return [];
  }
  if (!pointer.startsWith('/')) {
    throw new Error(`harness error: not a JSON Pointer: "${pointer}"`);
  }
  return pointer
    .slice(1)
    .split('/')
    .map((token) => token.replace(/~1/g, '/').replace(/~0/g, '~'));
}

function resolvePointer(root, pointer) {
  let current = root;
  for (const token of pointerSteps(pointer)) {
    if (current === null || current === undefined) {
      return undefined;
    }
    const bracketMatch = /^\[(.*)]$/.exec(token);
    if (bracketMatch) {
      const inner = bracketMatch[1];
      const eq = inner.indexOf('=');
      if (eq > 0) {
        const key = inner.slice(0, eq);
        const wanted = inner.slice(eq + 1);
        assert.ok(Array.isArray(current), `[${inner}] does not select from a list`);
        const matches = current.filter(
          (element) =>
            element !== null && typeof element === 'object' && String(element[key]) === wanted,
        );
        assert.equal(
          matches.length,
          1,
          `[${inner}] must select exactly one element, selected ${matches.length}`,
        );
        current = matches[0];
        continue;
      }
      current = Array.isArray(current) ? current[Number(inner)] : current[inner];
      continue;
    }
    if (token === 'length' && Array.isArray(current)) {
      current = current.length;
      continue;
    }
    current = current[token];
  }
  return current;
}

// --- input construction ---------------------------------------------------

function receiptInputString(fixtureId) {
  const entry = CASES.fixtures[fixtureId];
  const bytes = fixtureBytes(fixtureId);
  if (entry.codec === 'raw' || entry.codec === 'base64') {
    return bytes.toString('base64');
  }
  return bytes.toString('utf8');
}

function jwsInputString(fixtureId) {
  return fixtureBytes(fixtureId).toString('utf8');
}

function endpointRequestBody(input) {
  if (input.requestBody !== undefined) {
    return fixtureBytes(input.requestBody).toString('utf8');
  }
  return JSON.stringify({ 'receipt-data': receiptInputString(input.fixture) });
}

// --- clock -----------------------------------------------------------------

function caseClockMs(kase) {
  if (kase.clock === undefined) {
    return null;
  }
  const ms = Date.parse(kase.clock.now);
  if (Number.isNaN(ms)) {
    throw new Error(`harness error: unparseable clock "${kase.clock.now}"`);
  }
  return ms;
}

// --- roots -------------------------------------------------------------

function trustedRootsOption(build, spec) {
  if (spec === undefined || spec.source === 'defaults') {
    return undefined;
  }
  return spec.fixtures.map((id) => Buffer.from(fixtureBytes(id)));
}

// --- per-build adapter ---------------------------------------------------

/**
 * Runs one target build (Node or web) against every case, as its own set of
 * `node:test` subtests. `sync` is false for the web build, whose
 * `createConfig`/`createVerifier` calls all return Promises.
 */
const b64url = (text) => Buffer.from(text, 'utf8').toString('base64url');
const X5C_FILLER = 'MA=='; // an empty SEQUENCE: base64 that decodes, and no certificate

/** A JWS whose header carries `x5c0` as its first x5c entry, and nothing else wrong before it. */
function jwsCarrying(x5c0) {
  const header = JSON.stringify({ alg: 'ES256', x5c: [x5c0, X5C_FILLER, X5C_FILLER] });
  return `${b64url(header)}.${b64url('{}')}.${b64url('signature')}`;
}

function defineTargetTests(name, build, async_) {
  const ENV = { PRODUCTION: build.Environment.PRODUCTION, SANDBOX: build.Environment.SANDBOX };

  async function verifierForCase(kase) {
    const opts = {};
    const roots = trustedRootsOption(name, kase.config?.trustedRoots);
    if (roots !== undefined) {
      opts.roots = roots;
    }
    const clockMs = caseClockMs(kase);
    if (clockMs !== null) {
      opts.clock = () => clockMs;
    }
    const cfg = async_ ? await build.createConfig(opts) : build.createConfig(opts);
    return build.createVerifier(cfg);
  }

  async function callOperation(kase) {
    const verifier = await verifierForCase(kase);
    switch (kase.operation) {
      case 'verifyReceipt': {
        const input = receiptInputString(kase.input.fixture);
        return verifier.verifyReceipt(input);
      }
      case 'verifySignedData': {
        const input = jwsInputString(kase.input.fixture);
        return verifier.verifySignedData(input);
      }
      case 'verifyReceiptEndpoint': {
        const body = endpointRequestBody(kase.input);
        const env = ENV[kase.config.environment];
        if (env === undefined) {
          throw new Error(
            `harness error: unknown endpoint environment "${kase.config.environment}"`,
          );
        }
        const text = await verifier.verifyReceiptEndpoint(env, body);
        return { endpointText: text };
      }
      default:
        throw new Error(`harness error: no adapter for operation "${kase.operation}"`);
    }
  }

  function checkFields(actualDoc, fields) {
    for (const [pointer, expected] of Object.entries(fields)) {
      const value = resolvePointer(actualDoc, pointer);
      if (expected === null) {
        assert.ok(
          value === null || value === undefined,
          `${pointer}: expected absent, got ${String(value)}`,
        );
      } else if (typeof value === 'bigint' || typeof expected === 'bigint') {
        assert.equal(String(value), String(expected), pointer);
      } else {
        assert.deepEqual(value, expected, pointer);
      }
    }
  }

  function checkLengths(actualDoc, lengths) {
    for (const [pointer, expected] of Object.entries(lengths)) {
      const value = resolvePointer(actualDoc, pointer);
      assert.ok(Array.isArray(value), `${pointer}: expected an array to measure its length`);
      assert.equal(value.length, expected, `${pointer} length`);
    }
  }

  async function runVerifyCase(kase) {
    let result = await callOperation(kase);
    if (kase.operation === 'verifyReceiptEndpoint') {
      const text = result.endpointText;
      assert.equal(
        kase.expected.status,
        undefined,
        'harness error: endpoint cases have no status field',
      );
      const doc = parseWithBigInts(text);
      if (kase.expected.fields) {
        checkFields(doc, kase.expected.fields);
      }
      if (kase.expected.lengths) {
        checkLengths(doc, kase.expected.lengths);
      }
      return;
    }
    if (kase.expected.oneOf) {
      // Port-defined within a list: "ok" or the reason must be listed. A
      // crash would have thrown from callOperation already.
      const outcome = result.verified ? 'ok' : result.failure.reason;
      assert.ok(
        kase.expected.oneOf.includes(outcome),
        `answered ${outcome}, want one of ${kase.expected.oneOf}`,
      );
      return;
    }
    if (kase.expected.status === 'error') {
      assert.equal(
        result.verified,
        false,
        `expected ${kase.expected.reason} but the call verified`,
      );
      assert.equal(result.failure.reason, kase.expected.reason, 'reason');
      if (kase.expected.messageMustNotContain) {
        for (const codePoint of kase.expected.messageMustNotContain) {
          assert.ok(
            !result.failure.message.includes(String.fromCodePoint(codePoint)),
            `message must not contain U+${codePoint.toString(16)}: ${JSON.stringify(result.failure.message)}`,
          );
        }
      }
      return;
    }
    assert.equal(
      result.verified,
      true,
      `expected ok but failed: ${result.failure && result.failure.reason}`,
    );
    const json = kase.operation === 'verifyReceipt' ? result.payload.toJson() : result.payload.json;
    const doc = parseWithBigInts(json);
    if (kase.expected.toJson !== undefined) {
      // Same value, not same bytes: whitespace, key order and escaping
      // style are free (docs/design/0.7-api.md "Our JSON").
      assert.deepStrictEqual(doc, parseWithBigInts(kase.expected.toJson), 'toJson value');
    }
    if (kase.expected.fields) {
      checkFields(doc, kase.expected.fields);
    }
    if (kase.expected.lengths) {
      checkLengths(doc, kase.expected.lengths);
    }
  }

  // --- decodeBase64 -------------------------------------------------------
  //
  // The package has no base64 decoder of its own: the module decodes. So,
  // as docs/rust-core/SURFACE.md §6 has it, a `receipt-data` text runs
  // through verifyReceipt, and an `x5c` text runs through verifySignedData
  // as the first x5c entry of a JWS that is otherwise well formed. A text
  // the rule accepts decodes to bytes that are no receipt and no
  // certificate, so both groups fail; what tells them apart is whether the
  // failure is the base64 refusal (the decoder's reason, and a message that
  // names base64) or a later one.

  const DECODERS = {
    'receipt-data': {
      run: (verifier, text) => verifier.verifyReceipt(text),
      refusal: 'MALFORMED',
    },
    x5c: {
      run: (verifier, text) => verifier.verifySignedData(jwsCarrying(text)),
      refusal: 'INVALID_CERTIFICATE',
    },
  };

  async function runDecodeBase64Case(kase) {
    const { texts } = kase.input;
    const { status } = kase.expected;
    const verifier = build.createVerifier(await build.createConfig());
    const failures = [];
    for (const decoderName of kase.decoders) {
      const decoder = DECODERS[decoderName];
      if (decoder === undefined) {
        throw new Error(`harness error: no decoder "${decoderName}"`);
      }
      for (const [index, text] of texts.entries()) {
        const where = `${kase.id}: ${decoderName} texts[${index}] ${JSON.stringify(text)}`;
        // oxlint-disable-next-line no-await-in-loop -- one text at a time, so a failure names its text
        const result = await decoder.run(verifier, text);
        if (result.verified) {
          failures.push(`${where} verified`);
          continue;
        }
        const { reason, message } = result.failure;
        const refused = reason === decoder.refusal && /base64/i.test(message);
        if (status === 'ok' && refused) {
          failures.push(`${where} was refused by the base64 rule (${reason}: ${message})`);
        } else if (status === 'error' && !refused) {
          failures.push(`${where} got past the base64 rule (${reason}: ${message})`);
        }
      }
    }
    assert.deepEqual(failures, [], failures.join('\n'));
  }

  // --- run every case ------------------------------------------------------

  const RAN = new Set();

  for (const kase of CASES.cases) {
    test(`${name} ${kase.id}`, async () => {
      RAN.add(kase.id);
      if (kase.operation === 'decodeBase64') {
        await runDecodeBase64Case(kase);
        return;
      }
      if (kase.maxMillis !== undefined) {
        await runVerifyCase(kase); // warm-up
        const start = performance.now();
        await runVerifyCase(kase);
        const elapsed = performance.now() - start;
        assert.ok(
          elapsed <= kase.maxMillis,
          `${kase.id} took ${elapsed.toFixed(1)}ms, over the ${kase.maxMillis}ms budget`,
        );
        return;
      }
      await runVerifyCase(kase);
    });
  }

  const TEST_FILTER = [...process.execArgv, ...process.argv].find((arg) =>
    /^--test-(name-pattern|skip-pattern|only)\b/.test(arg),
  );

  test(`${name}: every case in cases.json ran`, (t) => {
    if (TEST_FILTER !== undefined) {
      t.diagnostic(`${TEST_FILTER} filters tests; the coverage self-check needs a full run`);
      return;
    }
    const missing = CASES.cases.map((k) => k.id).filter((id) => !RAN.has(id));
    assert.deepEqual(
      missing,
      [],
      `${missing.length} of ${CASES.cases.length} cases did not run (${name})`,
    );
  });
}

defineTargetTests('node', nodeBuild, false);
defineTargetTests('web', webBuild, true);
