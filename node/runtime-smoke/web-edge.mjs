// Runner for the Vercel Edge runtime, via @edge-runtime/vm — the same
// isolate shape Vercel Edge Functions and Next.js edge middleware run in:
// WebCrypto, TextDecoder, no Buffer, no process, no node:* modules.
//
//   node --experimental-vm-modules runtime-smoke/web-edge.mjs
//
// The flag is needed for vm.SourceTextModule, which is how the ES modules
// are evaluated INSIDE the edge context rather than in Node's own realm.
// Nothing crosses the realm boundary but JSON-shaped fixture data and the
// result strings: every Uint8Array the library sees is built in there, so a
// `x instanceof Uint8Array` check is answered by the edge realm's own
// intrinsics.
import { readFileSync } from 'node:fs';
import { SourceTextModule } from 'node:vm';
import { fileURLToPath } from 'node:url';
import { EdgeVM } from '@edge-runtime/vm';

const here = (rel) => new URL(rel, import.meta.url);
const bytes = (rel) => [...readFileSync(fileURLToPath(here(rel)))];
const text = (rel) => readFileSync(fileURLToPath(here(rel)), 'ascii');

const edge = new EdgeVM();
if (edge.evaluate('typeof Buffer') !== 'undefined' || edge.evaluate('typeof process') !== 'undefined') {
  throw new Error('the edge context is supposed to have neither Buffer nor process');
}

edge.evaluate(`globalThis.__fixtures = ${JSON.stringify({
  appleRootDer: bytes('../certs/AppleIncRootCertificate.cer'),
  sandboxReceiptB64: text('../../fixtures/public-receipts/receipt-sandbox-g5.b64'),
  legacyReceiptB64: text('../../fixtures/public-receipts/receipt-sandbox-legacy.b64'),
  jwsRootDer: bytes('../../fixtures/generated/jws-root.der'),
  transactionJws: text('../../fixtures/generated/transaction.jws'),
  foreignReceiptDer: bytes('../../fixtures/generated/receipt-foreign.der'),
})};`);

const modules = new Map();
function moduleFor(url) {
  const cached = modules.get(url);
  if (cached !== undefined) {
    return cached;
  }
  const module = new SourceTextModule(readFileSync(fileURLToPath(url), 'utf8'), {
    identifier: url, context: edge.context,
  });
  modules.set(url, module);
  return module;
}

const entry = new SourceTextModule(`
  import { run } from '${here('./web-smoke.mjs').href}';
  const raw = globalThis.__fixtures;
  globalThis.__result = await run({
    appleRootDer: new Uint8Array(raw.appleRootDer),
    sandboxReceiptB64: raw.sandboxReceiptB64,
    legacyReceiptB64: raw.legacyReceiptB64,
    jwsRootDer: new Uint8Array(raw.jwsRootDer),
    transactionJws: raw.transactionJws,
    foreignReceiptDer: new Uint8Array(raw.foreignReceiptDer),
  });
`, { identifier: here('./web-edge-entry.mjs').href, context: edge.context });

await entry.link((specifier, referencing) =>
  moduleFor(new URL(specifier, referencing.identifier).href));
await entry.evaluate();

console.log('# @edge-runtime/vm (Vercel Edge runtime)');
for (const line of edge.context.__result) {
  console.log(`ok - ${line}`);
}
