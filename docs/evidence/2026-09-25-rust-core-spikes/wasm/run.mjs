import { readFileSync } from 'node:fs';
const mod = process.argv[2] === 'web' ? await import('./pkg-web/aprv_wasm.js') : await import((process.argv[2]==='o3' ? './pkg-nodejs-o3/aprv_wasm.js' : './pkg-nodejs/aprv_wasm.js'));
if (process.argv[2] === 'web') await mod.default({ module_or_path: readFileSync('./pkg-web/aprv_wasm_bg.wasm') });
const { ReceiptVerifier, JwsVerifier } = mod;
const rd = (p) => new Uint8Array(readFileSync('../../../../fixtures/' + p));
const txt = (p) => readFileSync('../../../../fixtures/' + p, 'utf8');
const rt = typeof Bun !== 'undefined' ? 'bun ' + Bun.version : typeof Deno !== 'undefined' ? 'deno ' + Deno.version.deno : 'node ' + process.version;
console.log('runtime', rt, 'target', process.argv[2] || 'nodejs');
console.log('receipt', new ReceiptVerifier('com.example.app', [rd('generated/receipt-root.der')]).verify(rd('generated/receipt.der')));
const g = new ReceiptVerifier('dev.bonzer.weeka.app'); const b64 = txt('public-receipts/receipt-sandbox-g5.b64').replace(/\s/g, '');
let t = performance.now(), n = 200, r; for (let i = 0; i < n; i++) r = g.verifyBase64(b64);
console.log('genuine g5', r, ((performance.now() - t) / n * 1000).toFixed(0), 'us/op');
try { new ReceiptVerifier('com.other.app', [rd('generated/receipt-root.der')]).verify(rd('generated/receipt.der')); } catch (e) { console.log('error', e.constructor.name, e.reason, e.message); }
console.log('jws', new JwsVerifier('com.example.app', ['Sandbox'], [rd('generated/jws-root.der')]).verifyTransaction(txt('generated/transaction.jws').trim()).slice(0, 60));
try { console.log('no-signed-date', new JwsVerifier('com.example.app', ['Sandbox'], [rd('generated/divergence-jws-root.der')]).verifyTransaction(txt('generated/transaction-no-signed-date.jws').trim()).slice(0,40)); }
catch (e) { console.log('no-signed-date FAILED:', e.constructor.name, String(e.message).split('\n')[0]); }
