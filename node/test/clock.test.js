// Time: neither verify method judges a payload by its age, and the config
// clock moves only the chain-validity fallback and the endpoint's
// request_date. Both builds are exercised, because a rule that holds on
// only one of them is the drift the shared conformance suite is there to
// prevent for everything else.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as node from '../dist/index.js';
import * as web from '../dist/web/index.js';

const fixture = (name) =>
  readFileSync(fileURLToPath(new URL(`../../fixtures/generated/${name}`, import.meta.url)));
const text = (name) => fixture(name).toString('ascii').trim();
// The receipt endpoint tests need the 0.7-re-minted fixtures (WWDR marker
// on the intermediate); the old fixtures/generated/receipt*.der predate it.
const fixture07 = (name) =>
  readFileSync(fileURLToPath(new URL(`../../fixtures/generated-0.7/${name}`, import.meta.url)));

// transaction.jws is signed at 2024-08-06T12:00:00Z; the assertions below
// are written against that instant, not against "now".
const SIGNED_AT = 1722945600000;
const TRANSACTION = text('transaction.jws');

const BUILDS = [
  ['node', node, (x) => x],
  ['web', web, (x) => Promise.resolve(x)],
];

for (const [name, build, resolved] of BUILDS) {
  test(`${name}: a payload is never rejected for its age`, async () => {
    // Freshness is the caller's decision: a payload signed years ago still
    // verifies, and its signedDate is there for the caller to judge.
    const config = await resolved(build.createConfig({ roots: [fixture('jws-root.der')] }));
    const verifier = build.createVerifier(config);
    const result = await resolved(verifier.verifySignedData(TRANSACTION));
    assert.equal(result.verified, true, result.failure?.reason);
    assert.equal(JSON.parse(result.payload.json).signedDate, SIGNED_AT);
  });

  test(`${name}: the clock fallback only applies when the payload states no date`, async () => {
    // A far-future clock must not move the verdict for a payload that
    // carries its own signedDate.
    const config = await resolved(
      build.createConfig({
        roots: [fixture('jws-root.der')],
        clock: () => Date.parse('2999-01-01T00:00:00Z'),
      }),
    );
    const verifier = build.createVerifier(config);
    const result = await resolved(verifier.verifySignedData(TRANSACTION));
    assert.equal(result.verified, true, result.failure?.reason);
  });
}

// --- verifyReceiptEndpoint -------------------------------------------------

test('node endpoint: the clock drives request_date', () => {
  const fixedMs = Date.parse('2025-03-04T05:06:07Z');
  const config = node.createConfig({
    roots: [fixture07('receipt-root.der')],
    clock: () => fixedMs,
  });
  const verifier = node.createVerifier(config);
  const body = JSON.stringify({ 'receipt-data': fixture07('receipt.der').toString('base64') });
  const response = JSON.parse(verifier.verifyReceiptEndpoint(node.Environment.SANDBOX, body));
  assert.equal(response.status, 0);
  assert.equal(response.receipt.request_date_ms, String(fixedMs));
  assert.equal(response.receipt.request_date, '2025-03-04 05:06:07 Etc/GMT');
});

test('node endpoint: omitting the clock stamps request_date from the system clock', () => {
  const before = Date.now();
  const config = node.createConfig({ roots: [fixture07('receipt-root.der')] });
  const verifier = node.createVerifier(config);
  const body = JSON.stringify({ 'receipt-data': fixture07('receipt.der').toString('base64') });
  const response = JSON.parse(verifier.verifyReceiptEndpoint(node.Environment.SANDBOX, body));
  assert.equal(response.status, 0);
  const stamped = Number(response.receipt.request_date_ms);
  assert.ok(
    stamped >= before - 1000 && stamped <= Date.now() + 1000,
    `request_date_ms ${stamped} is not the current time`,
  );
});
