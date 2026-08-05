import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { VerifyReceiptEndpoint } from '../dist/index.js';

function fixture(name) {
  return readFileSync(fileURLToPath(new URL(`../../fixtures/generated/${name}`, import.meta.url)));
}

function endpoint(environment) {
  return new VerifyReceiptEndpoint({
    trustedRoots: [fixture('receipt-root.der')], environment,
  });
}

const request = () => ({ 'receipt-data': fixture('receipt.der').toString('base64') });

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

test('routes a sandbox receipt on Production to 21007', () => {
  assert.equal(endpoint('Production').verifyReceipt(request()).status, 21007);
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
