// verifyReceiptEndpoint, through both builds: the raw wire text a shared case
// sees only after parsing, the clock contract (read at most once per call; a
// clock that fails is the host's fault, 21009, never a throw), and the
// renderings no shared case pins.
// oxlint-disable no-await-in-loop -- the clock tests count reads per call, one call at a time
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as node from '../dist/index.js';
import * as web from '../dist/web/index.js';

const read = (rel) => readFileSync(fileURLToPath(new URL(`../../${rel}`, import.meta.url)));
const gen = (name) => read(`fixtures/generated-0.7/${name}`);
const body = (der) => JSON.stringify({ 'receipt-data': Buffer.from(der).toString('base64') });

const BUILDS = [
  ['node', node],
  ['web', web],
];

for (const [name, build] of BUILDS) {
  const verifierOver = async (rootDer, clock) =>
    build.createVerifier(
      await build.createConfig(
        clock === undefined
          ? { roots: [new Uint8Array(rootDer)] }
          : { roots: [new Uint8Array(rootDer)], clock },
      ),
    );
  const sandbox = async (verifier, requestJson) =>
    verifier.verifyReceiptEndpoint(build.Environment.SANDBOX, requestJson);

  test(`${name}: the wire keeps Apple's types and the receipt's in_app order`, async () => {
    const wire = await sandbox(
      await verifierOver(gen('receipt-root.der')),
      body(gen('receipt.der')),
    );
    // Raw bytes, not just the parse: status is a JSON number and every
    // number-shaped receipt field is a JSON string, as Apple sends them.
    assert.ok(wire.startsWith('{"status":0,'), wire);
    assert.ok(wire.includes('"quantity":"1"'), wire);
    assert.ok(wire.includes('"web_order_line_item_id":"42"'), wire);
    const { receipt } = JSON.parse(wire);
    assert.equal(typeof receipt.receipt_creation_date_ms, 'string');
    assert.equal(typeof receipt.request_date_ms, 'string');
    // The shared cases select in_app entries by product_id, so they pin
    // nothing about order: this receipt carries coins100 first.
    assert.deepEqual(
      receipt.in_app.map((p) => p.product_id),
      ['com.example.app.coins100', 'com.example.app.vip'],
    );
    for (const purchase of receipt.in_app) {
      assert.ok(purchase.purchase_date && purchase.purchase_date_ms && purchase.purchase_date_pst);
    }
    const vip = receipt.in_app.find((p) => p.product_id === 'com.example.app.vip');
    assert.ok(vip.expires_date && vip.expires_date_ms && vip.expires_date_pst);
    assert.ok(receipt.request_date && receipt.request_date_ms && receipt.request_date_pst);
  });

  test(`${name}: is_in_intro_offer_period is the string Apple sends`, async () => {
    const receiptData = read('fixtures/public-receipts/receipt-sandbox-g5.b64')
      .toString('ascii')
      .trim();
    const verifier = build.createVerifier(await build.defaultConfig());
    const wire = await sandbox(verifier, JSON.stringify({ 'receipt-data': receiptData }));
    assert.ok(wire.includes('"is_in_intro_offer_period":"false"'), wire);
    const { receipt } = JSON.parse(wire);
    assert.ok(receipt.in_app.length > 0);
    for (const purchase of receipt.in_app) {
      assert.equal(typeof purchase.is_in_intro_offer_period, 'string');
    }
  });

  test(`${name}: a non-zero status is the status alone`, async () => {
    const verifier = await verifierOver(gen('receipt-root.der'));
    assert.equal(
      await verifier.verifyReceiptEndpoint(build.Environment.PRODUCTION, body(gen('receipt.der'))),
      '{"status":21007}',
    );
    for (const requestJson of ['', 'not json', '{', '[]', 'null', '3', '"receipt"', 'true', '{}']) {
      assert.equal(await sandbox(verifier, requestJson), '{"status":21002}', requestJson);
    }
  });

  test(`${name}: brackets inside JSON strings are not nesting`, async () => {
    // Includes an escaped quote, which must not end the string early.
    const requestJson = `{"receipt-data":"${gen('receipt.der').toString('base64')}","x":"\\"${'['.repeat(200)}{"}`;
    const wire = await sandbox(await verifierOver(gen('receipt-root.der')), requestJson);
    assert.equal(JSON.parse(wire).status, 0, wire);
  });

  test(`${name}: the clock is read once per call, for the chain and request_date alike`, async () => {
    // A dateless receipt needs "now" twice: for the chain instant and for
    // request_date. Both must be one reading.
    let reads = 0;
    const start = Date.parse('2025-01-01T00:00:00Z');
    const ticking = () => start + 3_600_000 * ++reads;
    const verifier = await verifierOver(gen('divergence-receipt-root.der'), ticking);
    const wire = await sandbox(verifier, body(gen('receipt-no-creation-date.der')));
    assert.equal(reads, 1);
    assert.equal(JSON.parse(wire).receipt.request_date_ms, String(start + 3_600_000));
    const result = await verifier.verifyReceipt(
      gen('receipt-no-creation-date.der').toString('base64'),
    );
    assert.equal(result.verified, true, result.failure?.message);
    assert.equal(reads, 2, 'verifyReceipt reads the clock exactly once');
  });

  test(`${name}: a clock that fails is INTERNAL_ERROR and 21009, never a throw`, async () => {
    const boom = new Error('clock backend unavailable');
    const failing = () => {
      throw boom;
    };
    const dateless = await verifierOver(gen('divergence-receipt-root.der'), failing);
    const result = await dateless.verifyReceipt(
      gen('receipt-no-creation-date.der').toString('base64'),
    );
    assert.equal(result.failure?.reason, 'INTERNAL_ERROR');
    assert.equal(result.failure.cause, boom);
    assert.equal(
      await sandbox(dateless, body(gen('receipt-no-creation-date.der'))),
      '{"status":21009}',
    );
    // A dated receipt needs the clock only for request_date.
    const dated = await verifierOver(gen('receipt-root.der'), failing);
    assert.equal(await sandbox(dated, body(gen('receipt.der'))), '{"status":21009}');
    // A clock answering something no date can render is the same failure.
    const nan = await verifierOver(gen('receipt-root.der'), () => Number.NaN);
    assert.equal(await sandbox(nan, body(gen('receipt.der'))), '{"status":21009}');
  });

  test(`${name}: the clock cannot move the chain instant of a dated receipt`, async () => {
    // The clock stands in only for a missing creation date. This receipt
    // states one after its chain expired, and a clock pinned inside the
    // chain's window must not rescue it; its sibling dated inside the window
    // verifies under a clock long past it.
    for (const at of ['2020-06-01T00:00:00Z', '2999-01-01T00:00:00Z']) {
      const verifier = await verifierOver(gen('receipt-expired-root.der'), () => Date.parse(at));
      const fresh = await verifier.verifyReceipt(
        gen('receipt-expired-fresh.der').toString('base64'),
      );
      assert.equal(fresh.failure?.reason, 'INVALID_CERTIFICATE', at);
      assert.equal(
        await sandbox(verifier, body(gen('receipt-expired-fresh.der'))),
        '{"status":21003}',
        at,
      );
      const historical = await verifier.verifyReceipt(
        gen('receipt-expired-historical.der').toString('base64'),
      );
      assert.equal(historical.verified, true, `${at}: ${historical.failure?.message}`);
    }
  });

  test(`${name}: UNREADABLE_PAYLOAD keeps the parser error as its cause`, async () => {
    const verifier = await verifierOver(gen('api-receipt-root.der'), () =>
      Date.parse('2025-01-01T00:00:00Z'),
    );
    const result = await verifier.verifyReceipt(
      gen('receipt-content-not-asn1.der').toString('base64'),
    );
    assert.equal(result.failure?.reason, 'UNREADABLE_PAYLOAD');
    assert.ok(result.failure.cause !== undefined, 'no cause');
    assert.equal(
      await sandbox(verifier, body(gen('receipt-content-not-asn1.der'))),
      '{"status":21009}',
    );
    // Behind a verdict about unauthenticated input the cause is dropped: its
    // text could quote certificate names from the input.
    assert.equal((await verifier.verifyReceipt('AQIDBA==')).failure.cause, undefined);
  });
}
