// Runner for the Vercel Edge runtime, via @edge-runtime/vm: the same
// isolate shape Vercel Edge Functions and Next.js edge middleware run in
// (WebCrypto, TextDecoder, no Buffer, no process, no node:* modules).
//
//   node --experimental-vm-modules runtime-smoke/edge.mjs
//
// The package's ES modules are evaluated INSIDE the edge context with
// vm.SourceTextModule. On Vercel the edge-light condition picks
// dist/load/edge-light.js, whose `?module` imports Vercel's bundler turns
// into compiled modules; vm cannot evaluate a Wasm import, so "#aprv-load"
// is supplied here as a module that hands out the same three core modules,
// compiled inside the edge context from the package's files. What runs in
// the edge realm is everything else: the facade, jco's glue and aprv.wasm.
import { readFileSync } from 'node:fs';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import { fileURLToPath } from 'node:url';
import { EdgeVM } from '@edge-runtime/vm';

const here = (rel) => new URL(rel, import.meta.url);
const bytes = (rel) => [...readFileSync(fileURLToPath(here(rel)))];
const text = (rel) => readFileSync(fileURLToPath(here(rel)), 'ascii');

const edge = new EdgeVM();
if (
  edge.evaluate('typeof Buffer') !== 'undefined' ||
  edge.evaluate('typeof process') !== 'undefined'
) {
  throw new Error('the edge context is supposed to have neither Buffer nor process');
}

edge.evaluate(
  `globalThis.raw = ${JSON.stringify({
    core: bytes('../dist/generated/aprv.core.wasm'),
    core2: bytes('../dist/generated/aprv.core2.wasm'),
    core3: bytes('../dist/generated/aprv.core3.wasm'),
    sandboxReceiptB64: text('../../fixtures/public-receipts/receipt-sandbox-g5.b64'),
    jwsRootDer: bytes('../../fixtures/generated/jws-root.der'),
    transactionJws: text('../../fixtures/generated/transaction.jws'),
  })};`,
);
const compiled = edge.evaluate(`new Map([
  ['aprv.core.wasm', new WebAssembly.Module(new Uint8Array(raw.core))],
  ['aprv.core2.wasm', new WebAssembly.Module(new Uint8Array(raw.core2))],
  ['aprv.core3.wasm', new WebAssembly.Module(new Uint8Array(raw.core3))],
])`);

const loader = new SyntheticModule(
  ['getCoreModule'],
  function init() {
    this.setExport('getCoreModule', (name) => {
      const module = compiled.get(name);
      if (module === undefined) {
        throw new Error(`no core module named ${name}`);
      }
      return module;
    });
  },
  { identifier: 'aprv-load:edge', context: edge.context },
);

const modules = new Map();
function moduleFor(url) {
  let module = modules.get(url);
  if (module === undefined) {
    module = new SourceTextModule(readFileSync(fileURLToPath(url), 'utf8'), {
      identifier: url,
      context: edge.context,
    });
    modules.set(url, module);
  }
  return module;
}

const entry = new SourceTextModule(
  `
  import { run } from '${here('./smoke.mjs').href}';
  import * as main from '${here('../dist/index.js').href}';
  import * as web from '${here('../dist/web/index.js').href}';
  const fx = {
    sandboxReceiptB64: raw.sandboxReceiptB64,
    jwsRootDer: new Uint8Array(raw.jwsRootDer),
    transactionJws: raw.transactionJws,
  };
  globalThis.result = [];
  for (const [name, api] of [['.', main], ['./web', web]]) {
    for (const line of await run(api, fx)) globalThis.result.push(name + ': ' + line);
  }
`,
  { identifier: here('./edge-entry.mjs').href, context: edge.context },
);

await entry.link((specifier, referencing) =>
  specifier === '#aprv-load' ? loader : moduleFor(new URL(specifier, referencing.identifier).href),
);
await entry.evaluate();

console.log('# @edge-runtime/vm (Vercel Edge runtime)');
for (const line of edge.context.result) {
  console.log(`ok - ${line}`);
}
