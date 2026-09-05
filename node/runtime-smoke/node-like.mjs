// Runner for runtimes that implement node:fs — Node itself, Bun, Deno.
//   node runtime-smoke/node-like.mjs
//   bun  runtime-smoke/node-like.mjs
//   deno run --allow-read runtime-smoke/node-like.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { run } from './smoke.mjs';

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)));

const lines = run({
  appleRootDer: read('../certs/AppleIncRootCertificate.cer'),
  sandboxReceiptB64: read('../../fixtures/public-receipts/receipt-sandbox-g5.b64').toString(
    'ascii',
  ),
  jwsRootDer: read('../../fixtures/generated/jws-root.der'),
  transactionJws: read('../../fixtures/generated/transaction.jws').toString('ascii'),
  foreignReceiptDer: read('../../fixtures/generated/receipt-foreign.der'),
});
for (const l of lines) console.log(`ok - ${l}`);
