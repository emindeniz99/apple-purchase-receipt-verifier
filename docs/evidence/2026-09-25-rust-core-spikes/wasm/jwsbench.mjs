import { readFileSync } from 'node:fs';
const F = '../../../../fixtures/';
const root = new Uint8Array(readFileSync(F + 'generated/jws-root.der'));
const jws = readFileSync(F + 'generated/transaction.jws', 'utf8').trim();
const n = 500;
{ const { JwsVerifier } = await import('./pkg-nodejs/aprv_wasm.js');
  const v = new JwsVerifier('com.example.app', ['Sandbox'], [root]);
  for (let i = 0; i < 50; i++) v.verifyTransaction(jws);
  const t = performance.now(); for (let i = 0; i < n; i++) v.verifyTransaction(jws);
  console.log('wasm jws', ((performance.now() - t) / n * 1000).toFixed(0), 'us/op'); }
for (const entry of ['apple-purchase-receipt-verifier', 'apple-purchase-receipt-verifier/web']) {
  const m = await import(entry.endsWith('/web') ? './node_modules/apple-purchase-receipt-verifier/dist/web/index.js' : './node_modules/apple-purchase-receipt-verifier/dist/index.js');
  const v = new m.JwsVerifier({ trustedRoots: [entry.endsWith('/web') ? root : Buffer.from(root)], bundleId: 'com.example.app', acceptedEnvironments: ['Sandbox'] });
  for (let i = 0; i < 50; i++) await v.verifyTransaction(jws);
  const t = performance.now(); for (let i = 0; i < n; i++) await v.verifyTransaction(jws);
  console.log(entry, 'jws', ((performance.now() - t) / n * 1000).toFixed(0), 'us/op');
}
