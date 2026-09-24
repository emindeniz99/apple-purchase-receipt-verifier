// Time: the JWS verifier judges no payload by its age, and the endpoint's
// optional `clock` seam moves request_date and nothing else. Both builds are
// exercised for the JWS side, because a rule that holds on only one of them
// is the drift web-parity.test.js is there to prevent.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as node from '../dist/index.js';
import * as web from '../dist/web/index.js';

const BUNDLE = 'com.example.app';

const fixture = (name) =>
  readFileSync(fileURLToPath(new URL(`../../fixtures/generated/${name}`, import.meta.url)));
const text = (name) => fixture(name).toString('ascii').trim();

// transaction.jws is signed at 2024-08-06T12:00:00Z; the assertions below
// are written against that instant, not against "now".
const SIGNED_AT = 1722945600000;
const TRANSACTION = text('transaction.jws');
const MINUTE = 60_000;

const BUILDS = [
  ['node', node],
  ['web', web],
];

function jwsVerifier(build, options) {
  return new build.JwsVerifier({
    trustedRoots: [fixture('jws-root.der')],
    bundleId: BUNDLE,
    acceptedEnvironments: ['Sandbox'],
    ...options,
  });
}

/** Awaits the web build's promises; the Node build returns values directly. */
async function outcome(run) {
  try {
    return { ok: await run() };
  } catch (error) {
    return { reason: error?.reason ?? `unexpected ${error}` };
  }
}

for (const [name, build] of BUILDS) {
  test(`${name}: a payload is never rejected for its age`, async () => {
    // Freshness is the caller's decision: a payload signed years ago still
    // verifies, and its signedDate is there for the caller to judge.
    const verdict = await outcome(() => jwsVerifier(build, {}).verifyTransaction(TRANSACTION));
    assert.equal(verdict.ok?.signedDate, SIGNED_AT);
  });

  test(`${name}: the removed maxSignedAgeMillis option is refused, not ignored`, () => {
    // A plain-JS caller still passing it must not lose the check silently.
    assert.throws(() => jwsVerifier(build, { maxSignedAgeMillis: MINUTE }), TypeError);
  });
}

// --- verifyReceipt endpoint ---------------------------------------------

test('endpoint: the clock drives request_date', () => {
  const fixedInstant = new Date('2025-03-04T05:06:07Z');
  const response = new node.VerifyReceiptEndpoint({
    trustedRoots: [fixture('receipt-root.der')],
    environment: 'Sandbox',
    clock: () => fixedInstant,
  })
    .verifyReceiptResult({ 'receipt-data': fixture('receipt.der').toString('base64') })
    .toResponse();
  assert.equal(response.status, 0);
  assert.equal(response.receipt.request_date_ms, String(fixedInstant.getTime()));
  assert.equal(response.receipt.request_date, '2025-03-04 05:06:07 Etc/GMT');
});

test('endpoint: omitting the clock stamps request_date from the system clock', () => {
  const before = Date.now();
  const response = new node.VerifyReceiptEndpoint({
    trustedRoots: [fixture('receipt-root.der')],
    environment: 'Sandbox',
  })
    .verifyReceiptResult({ 'receipt-data': fixture('receipt.der').toString('base64') })
    .toResponse();
  assert.equal(response.status, 0);
  const stamped = Number(response.receipt.request_date_ms);
  assert.ok(
    stamped >= before - 1000 && stamped <= Date.now() + 1000,
    `request_date_ms ${stamped} is not the current time`,
  );
});

test('endpoint: the clock does not move the receipt-chain verdict', () => {
  // Same fixed-window argument as the JWS case: validity is judged at the
  // receipt creation date, so the endpoint's answer is clock-independent.
  for (const clock of [
    undefined,
    () => new Date('2020-06-01T00:00:00Z'),
    () => new Date('2999-01-01T00:00:00Z'),
  ]) {
    const endpoint = (receipt) =>
      new node.VerifyReceiptEndpoint({
        trustedRoots: [fixture('receipt-expired-root.der')],
        environment: 'Sandbox',
        clock,
      })
        .verifyReceiptResult({ 'receipt-data': fixture(receipt).toString('base64') })
        .toResponse();
    assert.equal(endpoint('receipt-expired-historical.der').status, 0);
    assert.equal(endpoint('receipt-expired-fresh.der').status, 21003);
  }
});
