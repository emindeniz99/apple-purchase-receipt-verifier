// Writes vectors.mjs for npm/smoke.mjs from the repository's fixtures.
//   node npm/make-vectors.mjs $REPO/fixtures > vectors.mjs
import { readFileSync } from 'node:fs';
const f = process.argv[2];
const v = {
  receiptB64: readFileSync(`${f}/public-receipts/receipt-sandbox-g5.b64`, 'utf8').replace(/\s+/g, ''),
  jws: readFileSync(`${f}/generated/transaction.jws`, 'utf8').trim(),
  jwsRootB64: readFileSync(`${f}/generated/jws-root.der`).toString('base64'),
};
console.log(`export const vectors = ${JSON.stringify(v)};`);
