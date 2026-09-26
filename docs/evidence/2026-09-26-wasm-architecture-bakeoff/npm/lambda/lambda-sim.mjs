// Spike only. A Lambda-LIKE run of handler.mjs, not AWS Lambda: Node's
// permission model (--permission, --allow-fs-read=<consumer dir> only; no
// fs write, no child_process, no worker, no native addons) stands in for
// the sandbox. Measures cold init, repeated and concurrent invocations and
// proves the restrictions are live by attempting the forbidden operations.
//   node --permission --allow-fs-read=<dir> lambda-sim.mjs
import { vectors } from './vectors.mjs';
const report = { node: process.version, pkg: process.env.APRV_PKG || 'aprv-spike-core' };
const t0 = performance.now();
const { handler } = await import('./handler.mjs');
report.coldImportMs = Math.round((performance.now() - t0) * 10) / 10;
const events = [
  { kind: 'receipt', receiptB64: vectors.receiptB64, bundleId: 'dev.bonzer.weeka.app' },
  { kind: 'receipt', receiptB64: vectors.receiptB64, bundleId: 'com.example.other' },
  { kind: 'transaction', jws: vectors.jws, bundleId: 'com.example.app', environments: ['Sandbox'], rootB64: vectors.jwsRootB64 },
  { kind: 'transaction', jws: vectors.jws, bundleId: 'com.example.app', environments: ['Production'], rootB64: vectors.jwsRootB64 },
];
const t1 = performance.now();
const expected = [];
for (const e of events) expected.push(JSON.stringify(await handler(e)));
report.firstInvocationsMs = Math.round((performance.now() - t1) * 10) / 10;
report.statuses = expected.map((s) => JSON.parse(s).statusCode);
let mismatches = 0;
const t2 = performance.now();
for (let i = 0; i < 200; i++) if (JSON.stringify(await handler(events[i % 4])) !== expected[i % 4]) mismatches++;
report.repeated = { invocations: 200, mismatches, meanMs: Math.round((performance.now() - t2) / 200 * 100) / 100 };
const conc = await Promise.all(Array.from({ length: 64 }, (_, i) => handler(events[i % 4]).then((r) => JSON.stringify(r) === expected[i % 4])));
report.concurrent = { invocations: 64, mismatches: conc.filter((x) => !x).length };
const denied = {};
const tryIt = async (name, fn) => { try { await fn(); denied[name] = 'ALLOWED'; } catch (e) { denied[name] = e.code || String(e); } };
await tryIt('fs.writeFile', async () => (await import('node:fs')).writeFileSync(new URL('./aprv-lambda-probe', import.meta.url), 'x'));
await tryIt('fs.read /etc/hostname', async () => (await import('node:fs')).readFileSync('/etc/hostname'));
await tryIt('child_process.spawnSync', async () => (await import('node:child_process')).spawnSync('true'));
await tryIt('worker_threads.Worker', async () => new (await import('node:worker_threads')).Worker('data:text/javascript,0'));
report.forbiddenOperations = denied;
report.ok = report.statuses.join() === '200,422,200,422' && mismatches === 0 && report.concurrent.mismatches === 0
  && Object.values(denied).every((v) => v !== 'ALLOWED');
console.log(JSON.stringify(report));
