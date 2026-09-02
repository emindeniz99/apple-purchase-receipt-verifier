import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { VerifyReceiptEndpoint, appleReceiptRoots } from '../dist/index.js';

function fixture(name) {
  return readFileSync(fileURLToPath(new URL(`../../fixtures/generated/${name}`, import.meta.url)));
}

function endpoint(environment) {
  return new VerifyReceiptEndpoint({
    trustedRoots: [fixture('receipt-root.der')], environment,
  });
}

const publicReceipt = (name) => readFileSync(fileURLToPath(
  new URL(`../../fixtures/public-receipts/${name}.b64`, import.meta.url)), 'ascii').trim();

const request = () => ({ 'receipt-data': fixture('receipt.der').toString('base64') });

// request_date is "now": two calls legitimately disagree on it.
function withoutRequestDate(response) {
  const copy = structuredClone(response);
  for (const key of ['request_date', 'request_date_ms', 'request_date_pst']) {
    delete copy.receipt?.[key];
  }
  return copy;
}

test('answers like verifyReceipt for a valid sandbox receipt', () => {
  const response = endpoint('Sandbox').verifyReceipt(request());
  assert.equal(response.status, 0);
  assert.equal(response.environment, 'Sandbox');
  assert.equal(response.receipt.receipt_type, 'ProductionSandbox');
  assert.equal(response.receipt.bundle_id, 'com.example.app');
  assert.equal(response.receipt.receipt_creation_date, '2024-08-06 12:00:00 Etc/GMT');
  assert.equal(response.receipt.receipt_creation_date_ms, '1722945600000');
  assert.equal(response.receipt.receipt_creation_date_pst,
    '2024-08-06 05:00:00 America/Los_Angeles');
  assert.equal(response.receipt.in_app.length, 2);
  assert.equal(response.receipt.in_app[0].quantity, '1');
  assert.equal(response.receipt.in_app[0].web_order_line_item_id, '42');
});

test('routes a sandbox receipt on Production to 21007 and leaks no receipt', () => {
  const response = endpoint('Production').verifyReceipt(request());
  assert.equal(response.status, 21007);
  assert.equal(response.receipt, undefined);
  assert.equal(response.environment, undefined);
});

test('reports malformed requests as 21002', () => {
  assert.equal(endpoint('Sandbox').verifyReceipt({}).status, 21002);
  assert.equal(endpoint('Sandbox').verifyReceipt(null).status, 21002);
  assert.equal(endpoint('Sandbox').verifyReceipt({ 'receipt-data': 'AQIDBA==' }).status, 21002);
});

test('reports unauthentic receipts as 21003', () => {
  const response = endpoint('Sandbox').verifyReceipt({
    'receipt-data': fixture('receipt-foreign.der').toString('base64'),
  });
  assert.equal(response.status, 21003);
});

test('routes receipt_type variants per the Apple matrix (incl. VPP sandbox)', () => {
  const cases = [
    ['receipt-type-production.der', true],
    ['receipt-type-vpp.der', true],
    ['receipt-type-vpp-sandbox.der', false],
    ['receipt-no-type.der', false],
  ];
  for (const [name, isProduction] of cases) {
    const body = { 'receipt-data': fixture(name).toString('base64') };
    assert.equal(endpoint('Production').verifyReceipt(body).status,
      isProduction ? 0 : 21007, `${name} on Production`);
    assert.equal(endpoint('Sandbox').verifyReceipt(body).status,
      isProduction ? 21008 : 0, `${name} on Sandbox`);
  }
});

test('endpoint response carries every field COMPARISON.md advertises as full-fidelity', () => {
  const receipt = endpoint('Sandbox').verifyReceipt(request()).receipt;
  assert.ok(receipt.request_date && receipt.request_date_ms && receipt.request_date_pst);
  assert.equal(receipt.original_application_version, '1.0');
  const coins = receipt.in_app.find((p) => p.product_id === 'com.example.app.coins100');
  assert.equal(coins.transaction_id, '70000000000001');
  assert.equal(coins.original_transaction_id, '70000000000001');
  assert.ok(coins.purchase_date && coins.purchase_date_ms && coins.purchase_date_pst);
  assert.ok(coins.original_purchase_date_ms);
  const vip = receipt.in_app.find((p) => p.product_id === 'com.example.app.vip');
  assert.equal(vip.expires_date, '2030-02-01 09:30:00 Etc/GMT');
  assert.ok(vip.expires_date_ms && vip.expires_date_pst);
});

test('verifyReceiptJson pins the wire types of the response body', () => {
  const json = endpoint('Sandbox').verifyReceiptJson(JSON.stringify(request()));
  // Raw bytes, not just the parse: status is a JSON number and every
  // number-shaped receipt field is a JSON string, as Apple sends them.
  assert.ok(json.includes('"status":0'), json);
  assert.ok(json.includes('"quantity":"1"'), json);
  assert.ok(json.includes('"web_order_line_item_id":"42"'), json);
  const parsed = JSON.parse(json);
  assert.equal(typeof parsed.status, 'number');
  assert.equal(parsed.environment, 'Sandbox');
  assert.equal(typeof parsed.receipt.receipt_creation_date_ms, 'string');
  assert.equal(typeof parsed.receipt.request_date_ms, 'string');
  for (const purchase of parsed.receipt.in_app) {
    assert.equal(typeof purchase.quantity, 'string');
    assert.equal(typeof purchase.web_order_line_item_id, 'string');
    assert.equal(typeof purchase.purchase_date_ms, 'string');
  }
});

test('verifyReceiptJson renders is_in_intro_offer_period as "true"/"false"', () => {
  const ep = new VerifyReceiptEndpoint({
    trustedRoots: appleReceiptRoots(), environment: 'Sandbox',
  });
  const json = ep.verifyReceiptJson(JSON.stringify({
    'receipt-data': publicReceipt('receipt-sandbox-g5'),
  }));
  assert.ok(json.includes('"is_in_intro_offer_period":"false"'), json);
  const { receipt } = JSON.parse(json);
  assert.ok(receipt.in_app.length > 0);
  for (const purchase of receipt.in_app) {
    assert.equal(typeof purchase.is_in_intro_offer_period, 'string');
  }
});

test('verifyReceiptJson omits receipt and environment on a non-zero status', () => {
  assert.equal(endpoint('Production').verifyReceiptJson(JSON.stringify(request())),
    '{"status":21007}');
});

test('verifyReceiptJson answers 21002 for a body that is not a JSON object', () => {
  const ep = endpoint('Sandbox');
  for (const body of ['', 'not json', '{', '[]', '[{"receipt-data":"x"}]', 'null',
    '3', '"receipt"', 'true']) {
    assert.equal(ep.verifyReceiptJson(body), '{"status":21002}', body);
  }
});

test('verifyReceiptJson parses back to exactly what verifyReceipt returns', () => {
  const ep = endpoint('Sandbox');
  const viaMap = ep.verifyReceipt(request());
  const viaJson = JSON.parse(ep.verifyReceiptJson(JSON.stringify(request())));
  assert.deepEqual(withoutRequestDate(viaJson), withoutRequestDate(viaMap));
});
