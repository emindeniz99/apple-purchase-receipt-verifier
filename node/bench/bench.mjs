// The cross-port benchmark: the same six operations on the same two genuine
// sandbox receipts in every port, named after the Java JMH benchmarks in
// java-bench/ (BENCHMARKS.md at the repository root has the table).
//
//   npm ci --ignore-scripts && npm run build
//   node bench/bench.mjs > node-bench.json
//
// Plain node:perf_hooks, no benchmark dependency. Each benchmark warms up
// for one second, then takes ten samples of at least 100 ms each; the JSON
// on stdout carries the median, minimum and maximum microseconds per
// operation over those samples. It measures the built dist/, so run the
// build first.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import {
  ReceiptVerifier,
  Reason,
  VerifyReceiptEndpoint,
  appleReceiptRoots,
  verifyReceiptCore,
} from '../dist/index.js';
// The library's own receipt-data decoder, which index.js does not export;
// the tests import it the same way.
import { decodeReceiptDataString } from '../dist/receipt.js';

const WARMUP_MS = 1000;
const SAMPLES = 10;
const MIN_SAMPLE_MS = 100;

// Any fixed instant: it only feeds the request_date fields.
const NOW = new Date('2026-01-01T00:00:00Z');

// File under fixtures/public-receipts, and the bundle id, in-app count and
// digest fixtures/cases.json pins for it.
const FIXTURES = [
  [
    'receipt-sandbox-g5',
    'dev.bonzer.weeka.app',
    2,
    'bebb16e2a17104d973eeef08177003f2c3303a19ddced83b42df349b4ac25ee0',
  ],
  [
    'receipt-sandbox-legacy',
    'com.nutcall.alert',
    187,
    'ec62c6bd4a34bd8e56b11e675bf5a28319ce69b71d050e73344bab22f46799a8',
  ],
];

// Keeps each result reachable so no call can be optimized away.
let sink;

function measure(benchmark, fixture, op) {
  const start = performance.now();
  let warmupOps = 0;
  while (performance.now() - start < WARMUP_MS) {
    sink = op();
    warmupOps++;
  }
  const perOp = (performance.now() - start) / warmupOps;
  const ops = Math.max(1, Math.ceil(MIN_SAMPLE_MS / perOp));
  const samples = [];
  for (let s = 0; s < SAMPLES; s++) {
    const t = performance.now();
    for (let i = 0; i < ops; i++) {
      sink = op();
    }
    samples.push(((performance.now() - t) * 1000) / ops);
  }
  samples.sort((a, b) => a - b);
  const median = (samples[SAMPLES / 2 - 1] + samples[SAMPLES / 2]) / 2;
  process.stderr.write(
    `${benchmark.padStart(24)} ${fixture.padEnd(24)} ${median.toFixed(1).padStart(12)} us/op\n`,
  );
  return {
    benchmark,
    fixture,
    us_per_op_median: median,
    us_per_op_min: samples[0],
    us_per_op_max: samples[SAMPLES - 1],
    ops_per_sample: ops,
  };
}

// Flips one bit in the middle of the SignerInfo signature, the byte
// java-bench's flipSignatureByte flips. In both fixtures the signature is a
// 256-byte OCTET STRING that ends the DER (openssl asn1parse shows it), so
// its middle byte is 128 from the end; setup proves the flip landed there by
// requiring INVALID_SIGNATURE.
function tamper(der) {
  const tampered = Buffer.from(der);
  tampered[tampered.length - 128] ^= 0x01;
  return tampered;
}

const roots = appleReceiptRoots();
const results = [];
for (const [name, bundleId, inAppCount, sha256] of FIXTURES) {
  const file = new URL(`../../fixtures/public-receipts/${name}.b64`, import.meta.url);
  const der = Buffer.from(readFileSync(file, 'ascii'), 'base64');
  assert.equal(createHash('sha256').update(der).digest('hex'), sha256, `${name} digest`);
  const base64 = der.toString('base64');
  const request = { 'receipt-data': base64 };
  const requestJson = JSON.stringify(request);
  const tampered = tamper(der);
  const verifier = new ReceiptVerifier({ trustedRoots: roots, bundleId });
  const endpoint = (environment) =>
    new VerifyReceiptEndpoint({ trustedRoots: roots, environment, clock: () => NOW });
  const sandbox = endpoint('Sandbox');
  const production = endpoint('Production');

  // Every call once, with the answer the conformance suite expects, so no
  // benchmark can time a fast failure by accident.
  assert.ok(decodeReceiptDataString(base64).equals(der), 'decodeBase64');
  for (const receipt of [verifyReceiptCore(der, roots), verifier.verify(base64)]) {
    assert.equal(receipt.bundleId, bundleId);
    assert.equal(receipt.inAppPurchases.length, inAppCount);
  }
  const ok = JSON.parse(sandbox.verifyReceiptJson(requestJson));
  assert.equal(ok.status, 0, 'endpointJson');
  assert.equal(ok.receipt.in_app.length, inAppCount, 'endpointJson in_app');
  const retry = JSON.parse(production.verifyReceiptResult(request).toJson('Sandbox'));
  assert.deepEqual([retry.status, retry.environment], [0, 'Sandbox'], 'retryViaResult');
  assert.throws(() => verifyReceiptCore(tampered, roots), { reason: Reason.INVALID_SIGNATURE });

  results.push(
    measure('decodeBase64', name, () => decodeReceiptDataString(base64)),
    measure('core', name, () => verifyReceiptCore(der, roots)),
    measure('verifierBase64', name, () => verifier.verify(base64)),
    measure('endpointJson', name, () => sandbox.verifyReceiptJson(requestJson)),
    measure('retryViaResult', name, () =>
      production.verifyReceiptResult(request).toJson('Sandbox'),
    ),
    measure('rejectTamperedSignature', name, () => {
      try {
        return verifyReceiptCore(tampered, roots);
      } catch (error) {
        return error;
      }
    }),
  );
}
assert.ok(sink !== undefined);

const report = {
  port: 'node',
  tool: 'bench/bench.mjs (node:perf_hooks)',
  runtime: `node ${process.version}`,
  settings: { warmup_s: WARMUP_MS / 1000, samples: SAMPLES, min_sample_s: MIN_SAMPLE_MS / 1000 },
  results,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
