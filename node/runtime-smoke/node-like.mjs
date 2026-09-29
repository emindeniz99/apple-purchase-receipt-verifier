// Runner for runtimes that implement node:fs: Node, Bun and Deno. Runs the
// smoke through both entry points.
//   node runtime-smoke/node-like.mjs
//   bun  runtime-smoke/node-like.mjs
//   deno run --allow-read --allow-env=JCO_DEBUG runtime-smoke/node-like.mjs
// oxlint-disable no-await-in-loop -- one entry point after the other, so a failure names its entry point
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { run } from './smoke.mjs';
import * as main from '../dist/index.js';
import * as web from '../dist/web/index.js';

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)));
const fx = {
  sandboxReceiptB64: read('../../fixtures/public-receipts/receipt-sandbox-g5.b64').toString(
    'ascii',
  ),
  jwsRootDer: new Uint8Array(read('../../fixtures/generated/jws-root.der')),
  transactionJws: read('../../fixtures/generated/transaction.jws').toString('ascii'),
};
const runtime = globalThis.Deno
  ? `deno ${globalThis.Deno.version.deno}`
  : globalThis.Bun
    ? `bun ${globalThis.Bun.version}`
    : `node ${process.version}`;
console.log(`# ${runtime}`);
for (const [name, api] of [
  ['.', main],
  ['./web', web],
]) {
  for (const line of await run(api, fx)) {
    console.log(`ok - ${name}: ${line}`);
  }
}
