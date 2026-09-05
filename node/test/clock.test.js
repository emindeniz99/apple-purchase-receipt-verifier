// The optional `clock` seam: which verdicts it moves, and which it must not.
// Both builds are exercised from the same table, because a seam that exists
// on only one of them is the drift web-parity.test.js is there to prevent.
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

/** Curried Date constructor, so a clock table can list bare millis. */
const at = (millis) => () => new Date(millis);

function jwsVerifier(build, options) {
  return new build.JwsVerifier({
    trustedRoots: [fixture(options.root ?? 'jws-root.der')],
    bundleId: BUNDLE,
    acceptedEnvironments: ['Sandbox'],
    ...options.verifier,
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
  test(`${name}: omitting clock leaves the system clock in charge`, async () => {
    // Two max-ages bracketing the real elapsed time since SIGNED_AT: only a
    // verifier reading the real clock answers differently to the two.
    const elapsed = Date.now() - SIGNED_AT;
    assert.ok(elapsed > MINUTE, 'fixture must be older than a minute for this to bracket');
    const stale = await outcome(() =>
      jwsVerifier(build, {
        verifier: { maxSignedAgeMillis: MINUTE },
      }).verifyTransaction(TRANSACTION),
    );
    assert.equal(stale.reason, 'STALE_PAYLOAD');
    const fresh = await outcome(() =>
      jwsVerifier(build, {
        verifier: { maxSignedAgeMillis: elapsed + 10 * MINUTE },
      }).verifyTransaction(TRANSACTION),
    );
    assert.equal(fresh.ok?.transactionId, '2000000000000001');
  });

  test(`${name}: the injected clock decides STALE_PAYLOAD`, async () => {
    const verify = (clock) =>
      outcome(() =>
        jwsVerifier(build, {
          verifier: { maxSignedAgeMillis: MINUTE, clock },
        }).verifyTransaction(TRANSACTION),
      );

    // 30s after signing: inside the one-minute window, and accepted even
    // though the real clock is years past it.
    const inside = await verify(at(SIGNED_AT + 30_000));
    assert.equal(inside.ok?.signedDate, SIGNED_AT);
    // 61s after signing: outside it.
    assert.equal((await verify(at(SIGNED_AT + MINUTE + 1000))).reason, 'STALE_PAYLOAD');
    // Exactly at the boundary is still fresh — the rule is "older than".
    assert.equal((await verify(at(SIGNED_AT + MINUTE))).ok?.signedDate, SIGNED_AT);
  });

  test(`${name}: no max-signed-age means the clock changes nothing`, async () => {
    const far = await outcome(() =>
      jwsVerifier(build, {
        verifier: { clock: () => new Date('2999-01-01T00:00:00Z') },
      }).verifyTransaction(TRANSACTION),
    );
    assert.equal(far.ok?.signedDate, SIGNED_AT);
  });

  test(`${name}: the clock does not move certificate-validity verdicts`, async () => {
    // The chain behind these two fixtures is valid 2020-01-01..2021-01-01 and
    // is judged at the payload's signedDate (PLAN.md 2.1 step 4), so no clock
    // — real or injected, inside the window or centuries outside it — may
    // change either verdict.
    const clocks = [
      undefined,
      () => new Date('2020-06-01T00:00:00Z'),
      () => new Date('2999-01-01T00:00:00Z'),
      () => new Date(0),
    ];
    await Promise.all(
      clocks.map(async (clock) => {
        const historical = await outcome(() =>
          jwsVerifier(build, {
            root: 'jws-expired-root.der',
            verifier: { clock },
          }).verifyTransaction(text('expired-cert-historical.jws')),
        );
        assert.equal(historical.ok?.signedDate, 1590969600000, 'historical payload must verify');

        const fresh = await outcome(() =>
          jwsVerifier(build, {
            root: 'jws-expired-root.der',
            verifier: { clock },
          }).verifyTransaction(text('expired-cert-fresh.jws')),
        );
        assert.equal(fresh.reason, 'INVALID_CHAIN', 'out-of-window payload must be rejected');
      }),
    );
  });

  test(`${name}: a non-function clock is rejected at construction`, () => {
    assert.throws(() => jwsVerifier(build, { verifier: { clock: SIGNED_AT } }), TypeError);
  });
}

// --- verifyReceipt endpoint (Node build only — it has no web twin) --------

test('endpoint: the clock drives request_date', () => {
  const fixedInstant = new Date('2025-03-04T05:06:07Z');
  const response = new node.VerifyReceiptEndpoint({
    trustedRoots: [fixture('receipt-root.der')],
    environment: 'Sandbox',
    clock: () => fixedInstant,
  }).verifyReceipt({ 'receipt-data': fixture('receipt.der').toString('base64') });
  assert.equal(response.status, 0);
  assert.equal(response.receipt.request_date_ms, String(fixedInstant.getTime()));
  assert.equal(response.receipt.request_date, '2025-03-04 05:06:07 Etc/GMT');
});

test('endpoint: omitting the clock stamps request_date from the system clock', () => {
  const before = Date.now();
  const response = new node.VerifyReceiptEndpoint({
    trustedRoots: [fixture('receipt-root.der')],
    environment: 'Sandbox',
  }).verifyReceipt({ 'receipt-data': fixture('receipt.der').toString('base64') });
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
      }).verifyReceipt({ 'receipt-data': fixture(receipt).toString('base64') });
    assert.equal(endpoint('receipt-expired-historical.der').status, 0);
    assert.equal(endpoint('receipt-expired-fresh.der').status, 21003);
  }
});
