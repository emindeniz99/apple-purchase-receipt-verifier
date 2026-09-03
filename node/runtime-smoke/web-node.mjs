// Baseline runner for the web smoke: Node's own WebCrypto. Node is the only
// runner here that reads files, so it is also the one that proves the
// fixture bytes the other runners embed are the same ones.
//   node runtime-smoke/web-node.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { run } from './web-smoke.mjs';

const read = (rel) => new Uint8Array(readFileSync(fileURLToPath(new URL(rel, import.meta.url))));
const text = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'ascii');

const lines = await run({
  appleRootDer: read('../certs/AppleIncRootCertificate.cer'),
  sandboxReceiptB64: text('../../fixtures/public-receipts/receipt-sandbox-g5.b64'),
  legacyReceiptB64: text('../../fixtures/public-receipts/receipt-sandbox-legacy.b64'),
  jwsRootDer: read('../../fixtures/generated/jws-root.der'),
  transactionJws: text('../../fixtures/generated/transaction.jws'),
  foreignReceiptDer: read('../../fixtures/generated/receipt-foreign.der'),
});
for (const line of lines) {
  console.log(`ok - ${line}`);
}
