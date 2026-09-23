// VerifyReceiptResult: one verification, then any number of renders.
//
// What matters here is what a caller builds a retry on. The receipt must
// survive a 21007/21008 so the other environment can be rendered without a
// second verification, and that re-render must recompute the status from the
// receipt itself: a result from a production endpoint must never be turned
// into a production 0 for a sandbox receipt, or the 21007 routing that keeps
// sandbox purchases out of production would be one method call away from
// being bypassed.
//
// Both builds run the same table; the web build answers with Promises, and
// `await` on the Node build's plain values changes nothing.
// oxlint-disable no-await-in-loop -- the calls run one at a time on purpose: the clock tests count reads per call, and a failure names the row it came from
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as node from '../dist/index.js';
import * as web from '../dist/web/index.js';

const BUILDS = [
  ['node', node],
  ['web', web],
];

const repo = (path) => fileURLToPath(new URL(`../../fixtures/${path}`, import.meta.url));
const gen = (name) => readFileSync(repo(`generated/${name}`));
const b64 = (name) => gen(name).toString('base64');

const CLOCK_NOW = new Date('2026-01-01T00:00:00Z');
const EXPLICIT = new Date('2025-06-15T12:34:56.789Z');
const ENVIRONMENTS = ['Production', 'Sandbox'];

function endpoint(build, environment, root = 'receipt-root.der', clock = () => CLOCK_NOW) {
  return new build.VerifyReceiptEndpoint({ trustedRoots: [gen(root)], environment, clock });
}

function assertInvariant(result, label) {
  assert.equal(
    result.receipt === null,
    result.failureReason !== null,
    `${label}: exactly one of receipt and failureReason must be set`,
  );
  assert.equal(result.verified, result.receipt !== null, `${label}: verified means a receipt`);
  assert.equal(
    result.failureReason === 'INTERNAL_ERROR',
    result.failureCause !== null,
    `${label}: failureCause is set exactly for INTERNAL_ERROR`,
  );
  assert.equal(result.toResponse().status, result.status, label);
  assert.ok(result.requestDate instanceof Date, label);
}

const throwingRequest = (error) => ({
  get 'receipt-data'() {
    throw error;
  },
});

for (const [name, build] of BUILDS) {
  test(`${name}: exactly one of receipt and failureReason is set for every status`, async () => {
    const results = {
      '0 sandbox': await endpoint(build, 'Sandbox').verifyReceiptData(b64('receipt.der')),
      '0 production': await endpoint(build, 'Production').verifyReceiptData(
        b64('receipt-type-production.der'),
      ),
      21007: await endpoint(build, 'Production').verifyReceiptData(b64('receipt.der')),
      21008: await endpoint(build, 'Sandbox').verifyReceiptData(b64('receipt-type-production.der')),
      21002: await endpoint(build, 'Sandbox').verifyReceiptData('AQIDBA=='),
      21003: await endpoint(build, 'Sandbox').verifyReceiptData(b64('receipt-foreign.der')),
      21009: await endpoint(build, 'Sandbox').verifyReceiptResult(throwingRequest(new Error('x'))),
    };
    for (const [label, result] of Object.entries(results)) {
      assertInvariant(result, label);
      assert.equal(result.status, Number(label.split(' ')[0]), label);
    }
    // 21007 and 21008 are routing answers, not failures: the receipt
    // verified, so `verified` is not `status === 0`.
    for (const label of ['0 sandbox', '0 production', '21007', '21008']) {
      assert.equal(results[label].verified, true, label);
      assert.equal(results[label].receipt.bundleId, 'com.example.app', label);
    }
  });

  // The whole re-render table, on committed fixtures. A production receipt
  // gives 0 on Production and 21008 on Sandbox; a sandbox receipt (and one
  // with no receipt_type, which fails closed as sandbox) gives 21007 on
  // Production and 0 on Sandbox; a failed result keeps its own status. The
  // table is the same whichever environment the endpoint itself had.
  test(`${name}: re-renders for either environment from the receipt's own type`, async () => {
    const table = [
      // fixture, root, status on Production, status on Sandbox
      ['receipt-type-production.der', 'receipt-root.der', 0, 21008],
      ['receipt-type-vpp.der', 'receipt-root.der', 0, 21008],
      ['receipt.der', 'receipt-root.der', 21007, 0],
      ['receipt-type-vpp-sandbox.der', 'receipt-root.der', 21007, 0],
      ['receipt-no-type.der', 'receipt-root.der', 21007, 0],
      ['receipt-foreign.der', 'receipt-root.der', 21003, 21003],
      ['receipt-tampered-payload.der', 'gaps-receipt-root.der', 21003, 21003],
    ];
    for (const [fixture, root, onProduction, onSandbox] of table) {
      for (const own of ENVIRONMENTS) {
        const result = await endpoint(build, own, root).verifyReceiptData(b64(fixture), EXPLICIT);
        const label = `${fixture} from a ${own} endpoint`;
        assert.equal(result.toResponse('Production').status, onProduction, label);
        assert.equal(result.toResponse('Sandbox').status, onSandbox, label);
        for (const target of ENVIRONMENTS) {
          // Each render equals what an endpoint of that environment answers
          // on its own, byte for byte.
          const direct = await endpoint(build, target, root).verifyReceiptData(
            b64(fixture),
            EXPLICIT,
          );
          assert.equal(result.toJson(target), direct.toJson(), `${label} rendered for ${target}`);
        }
      }
    }
  });

  test(`${name}: a sandbox receipt never renders a production 0`, async () => {
    for (const fixture of ['receipt.der', 'receipt-type-vpp-sandbox.der', 'receipt-no-type.der']) {
      for (const own of ENVIRONMENTS) {
        const result = await endpoint(build, own).verifyReceiptData(b64(fixture));
        assert.equal(result.verified, true, fixture);
        assert.equal(result.toJson('Production'), '{"status":21007}', `${fixture} via ${own}`);
        assert.deepEqual(result.toResponse('Production'), { status: 21007 }, fixture);
      }
    }
  });

  test(`${name}: the status routing does not follow a later write to the receipt`, async () => {
    // The receipt is a plain object the caller holds. Writing "Production"
    // into it must not turn a sandbox receipt into a production 0: the
    // routing was fixed when the bytes were verified.
    const result = await endpoint(build, 'Production').verifyReceiptData(b64('receipt.der'));
    result.receipt.receiptType = 'Production';
    assert.equal(result.status, 21007);
    assert.equal(result.toJson('Production'), '{"status":21007}');
    assert.equal(result.toResponse('Sandbox').status, 0);
  });

  test(`${name}: rendering for an environment Apple does not have is refused`, async () => {
    const result = await endpoint(build, 'Sandbox').verifyReceiptData(b64('receipt.der'));
    for (const environment of ['Xcode', 'LocalTesting', 'production', null, true]) {
      assert.throws(() => result.toResponse(environment), TypeError, String(environment));
      assert.throws(() => result.toJson(environment), TypeError, String(environment));
    }
  });

  test(`${name}: an explicit request date is rendered and the clock is not read`, async () => {
    let reads = 0;
    const counting = () => {
      reads += 1;
      return CLOCK_NOW;
    };
    const ep = endpoint(build, 'Sandbox', 'receipt-root.der', counting);
    const receiptData = b64('receipt.der');
    const explicit = await ep.verifyReceiptResult({ 'receipt-data': receiptData }, EXPLICIT);
    assert.equal(reads, 0);
    assert.equal(explicit.requestDate.getTime(), EXPLICIT.getTime());
    const { receipt } = explicit.toResponse();
    assert.equal(receipt.request_date, '2025-06-15 12:34:56 Etc/GMT');
    assert.equal(receipt.request_date_ms, String(EXPLICIT.getTime()));
    assert.equal(receipt.request_date_pst, '2025-06-15 05:34:56 America/Los_Angeles');
    // Deterministic: the same call renders the same bytes, and so does
    // rendering the same result twice.
    assert.equal(
      explicit.toJson(),
      (await ep.verifyReceiptResult({ 'receipt-data': receiptData }, EXPLICIT)).toJson(),
    );
    assert.equal(explicit.toJson(), explicit.toJson());
    assert.equal(
      (
        await ep.verifyReceiptResult(JSON.stringify({ 'receipt-data': receiptData }), EXPLICIT)
      ).requestDate.getTime(),
      EXPLICIT.getTime(),
    );
    assert.equal(reads, 0, 'an explicit request date replaces the clock');
  });

  test(`${name}: without a request date the clock is read once per call`, async () => {
    let reads = 0;
    const ticking = () => new Date(CLOCK_NOW.getTime() + 1000 * reads++);
    const ep = endpoint(build, 'Sandbox', 'receipt-root.der', ticking);
    const receiptData = b64('receipt.der');
    const calls = [
      () => ep.verifyReceiptResult({ 'receipt-data': receiptData }),
      () => ep.verifyReceiptResult(JSON.stringify({ 'receipt-data': receiptData })),
      () => ep.verifyReceiptData(receiptData),
      () => ep.verifyReceiptData(''),
    ];
    for (const [index, call] of calls.entries()) {
      const before = reads;
      const result = await call();
      assert.equal(reads, before + 1, `call ${index} reads the clock exactly once`);
      // Rendering later neither reads the clock again nor moves the date.
      const first = result.toJson();
      assert.equal(result.toJson(), first);
      assert.equal(reads, before + 1, `call ${index} renders without the clock`);
      assert.equal(result.requestDate.getTime(), CLOCK_NOW.getTime() + 1000 * before);
    }
  });

  test(`${name}: the request date cannot be changed through the result`, async () => {
    const result = await endpoint(build, 'Sandbox').verifyReceiptData(b64('receipt.der'), EXPLICIT);
    result.requestDate.setTime(0);
    assert.equal(result.requestDate.getTime(), EXPLICIT.getTime());
    assert.ok(Object.isFrozen(result));
    assert.throws(() => {
      result.status = 0;
    }, TypeError);
  });

  // Every receipt fixture in the repo, DER and text, genuine and hostile:
  // the bare receipt and the same receipt inside a JSON body must be one
  // answer, byte for byte, on both environments.
  test(`${name}: verifyReceiptData answers what the JSON body path answers`, async () => {
    const roots = [
      ...readdirSync(repo('generated'))
        .filter((file) => file.endsWith('root.der') && file.includes('receipt'))
        .map(gen),
      ...build.appleReceiptRoots(),
    ];
    // The two DER-cap receipts are left out: 3 MiB of DER is 4 MiB of
    // base64, which no request can carry.
    const inputs = [
      ...readdirSync(repo('generated'))
        .filter(
          (file) =>
            file.startsWith('receipt') && file.endsWith('.der') && !file.includes('der-cap'),
        )
        .map((file) => [file, b64(file)]),
      ...readdirSync(repo('generated/receipt-b64')).map((file) => [
        file,
        readFileSync(repo(`generated/receipt-b64/${file}`), 'utf8'),
      ]),
      ...readdirSync(repo('public-receipts'))
        .filter((file) => file.endsWith('.b64'))
        .map((file) => [file, readFileSync(repo(`public-receipts/${file}`), 'ascii').trim()]),
    ];
    assert.ok(inputs.length > 40, `expected the whole corpus, found ${inputs.length}`);
    const statuses = new Set();
    const overRequestCap = new Set();
    for (const environment of ENVIRONMENTS) {
      const ep = new build.VerifyReceiptEndpoint({ trustedRoots: roots, environment });
      for (const [label, receiptData] of inputs) {
        const bare = await ep.verifyReceiptData(receiptData, EXPLICIT);
        const body = JSON.stringify({ 'receipt-data': receiptData });
        const viaJson = await ep.verifyReceiptResult(body, EXPLICIT);
        statuses.add(bare.status);
        // A body over the request cap would be refused before it is parsed
        // while the same receipt handed over bare is still verified. The
        // request cap is Apple's 3 MiB, so no receipt in the corpus, the
        // byte floor (1 MiB of DER, 1.38 MB of base64) included, makes one.
        if (Buffer.byteLength(body) > build.VerifyReceiptEndpoint.MAX_REQUEST_BYTES) {
          overRequestCap.add(label);
          continue;
        }
        assert.equal(bare.toJson(), viaJson.toJson(), `${label} on ${environment}`);
        assert.equal(bare.failureReason, viaJson.failureReason, label);
      }
    }
    assert.deepEqual([...overRequestCap], []);
    // The corpus reaches every status a receipt can produce, so the equality
    // above was checked on verified and failed results alike.
    for (const status of [0, 21002, 21003, 21007, 21008]) {
      assert.ok(statuses.has(status), `no fixture produced ${status}`);
    }
  });

  test(`${name}: verifyReceiptJson is verifyReceiptResult(body).toJson()`, async () => {
    const ep = endpoint(build, 'Sandbox', 'receipt-root.der', () => EXPLICIT);
    for (const body of [
      JSON.stringify({ 'receipt-data': b64('receipt.der') }),
      JSON.stringify({ 'receipt-data': b64('receipt-type-production.der') }),
      'not json',
      '[]',
    ]) {
      assert.equal(
        await ep.verifyReceiptJson(body),
        (await ep.verifyReceiptResult(body)).toJson(),
        body.slice(0, 40),
      );
    }
  });

  test(`${name}: each failure names its reason`, async () => {
    const ep = endpoint(build, 'Sandbox');
    const malformed = {
      'body not JSON': ep.verifyReceiptResult('not json'),
      'body a JSON array': ep.verifyReceiptResult('[{"receipt-data":"AQIDBA=="}]'),
      'body JSON null': ep.verifyReceiptResult('null'),
      'null request': ep.verifyReceiptResult(null),
      'undefined request': ep.verifyReceiptResult(undefined),
      'a number request': ep.verifyReceiptResult(5),
      'receipt-data missing': ep.verifyReceiptResult({}),
      'receipt-data empty': ep.verifyReceiptResult({ 'receipt-data': '' }),
      'receipt-data a number': ep.verifyReceiptResult('{"receipt-data":5}'),
      'receipt-data a list': ep.verifyReceiptResult({ 'receipt-data': ['AQIDBA=='] }),
      'bare receipt null': ep.verifyReceiptData(null),
      'bare receipt empty': ep.verifyReceiptData(''),
    };
    for (const [label, pending] of Object.entries(malformed)) {
      const result = await pending;
      assert.equal(result.failureReason, 'MALFORMED_REQUEST', label);
      assert.equal(result.status, 21002, label);
      assert.equal(result.toJson(), '{"status":21002}', label);
      assertInvariant(result, label);
    }
    for (const receiptData of ['not base64!', 'AQIDBA==', '   ']) {
      const result = await ep.verifyReceiptResult({ 'receipt-data': receiptData });
      assert.equal(result.failureReason, 'INVALID_RECEIPT_FORMAT', receiptData);
      assert.equal(result.status, 21002, receiptData);
    }
    const foreign = await ep.verifyReceiptData(b64('receipt-foreign.der'));
    assert.equal(foreign.failureReason, 'INVALID_CHAIN');
    assert.equal(foreign.status, 21003);
    const tampered = await endpoint(build, 'Sandbox', 'gaps-receipt-root.der').verifyReceiptData(
      b64('receipt-tampered-payload.der'),
    );
    assert.equal(tampered.failureReason, 'INVALID_SIGNATURE');
    assert.equal(tampered.status, 21003);
  });

  // A request whose receipt-data getter throws, and a clock that throws,
  // stand in for any unexpected failure inside the pipeline. The endpoint
  // promises never to throw (and the web one never to reject), so the error
  // comes back as INTERNAL_ERROR, status 21009, kept for logging.
  test(`${name}: an unexpected error is an INTERNAL_ERROR, never a throw`, async () => {
    const boom = new Error('broken request object');
    for (const environment of ENVIRONMENTS) {
      const results = [
        [boom, await endpoint(build, environment).verifyReceiptResult(throwingRequest(boom))],
        [
          boom,
          await endpoint(build, environment, 'receipt-root.der', () => {
            throw boom;
          }).verifyReceiptData(b64('receipt.der')),
        ],
      ];
      for (const [cause, result] of results) {
        assert.equal(result.failureReason, 'INTERNAL_ERROR');
        assert.equal(result.verified, false);
        assert.equal(result.receipt, null);
        assert.equal(result.status, 21009);
        assert.equal(result.failureCause, cause);
        assert.ok(result.requestDate instanceof Date);
        assert.equal(result.toJson(), '{"status":21009}');
        assert.equal(result.toJson('Production'), '{"status":21009}');
        assert.equal(result.toJson('Sandbox'), '{"status":21009}');
      }
    }
  });

  test(`${name}: a status-0 body that cannot be rendered answers 21009`, async () => {
    // An invalid request date makes Intl throw while formatting, the same
    // way a runtime without full ICU does. The endpoint has always answered
    // 21009 for that rather than letting the throw escape.
    const result = await endpoint(build, 'Sandbox').verifyReceiptData(
      b64('receipt.der'),
      new Date(NaN),
    );
    assert.equal(result.verified, true);
    assert.equal(result.status, 0);
    assert.equal(result.toJson(), '{"status":21009}');
    assert.equal(result.toJson('Production'), '{"status":21007}');
  });

  test(`${name}: a caller cannot construct a result`, async () => {
    const result = await endpoint(build, 'Sandbox').verifyReceiptData('AQIDBA==');
    assert.equal(build.VerifyReceiptResult, undefined, 'no runtime export');
    const Constructor = result.constructor;
    assert.throws(
      () => new Constructor(Symbol('VerifyReceiptResult'), 'Production', {}, null, null, 0),
      TypeError,
    );
  });
}
