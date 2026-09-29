// Start-up cost of the package in a fresh Node process: importing it, the
// first createVerifier (which compiles aprv.wasm, instantiates it and runs
// init), a second createVerifier (instantiate and init only), and the first
// and a warm verifyReceipt of the genuine g5 receipt.
//
//   npm run build && node bench/startup.mjs [RUNS]
//
// RUNS fresh processes (default 7); the JSON on stdout has each run and the
// median of each step, in milliseconds.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

async function child() {
  const g5 = readFileSync(
    new URL('../../fixtures/public-receipts/receipt-sandbox-g5.b64', import.meta.url),
    'ascii',
  ).trim();
  const t0 = performance.now();
  const api = await import('../dist/index.js');
  const t1 = performance.now();
  const verifier = api.createVerifier(api.defaultConfig());
  const t2 = performance.now();
  api.createVerifier(api.defaultConfig());
  const t3 = performance.now();
  const first = verifier.verifyReceipt(g5);
  const t4 = performance.now();
  verifier.verifyReceipt(g5);
  const t5 = performance.now();
  if (!first.verified) {
    throw new Error(`g5 did not verify: ${first.failure.reason}`);
  }
  process.stdout.write(
    JSON.stringify({
      import: t1 - t0,
      firstCreateVerifier: t2 - t1,
      secondCreateVerifier: t3 - t2,
      firstVerifyReceipt: t4 - t3,
      secondVerifyReceipt: t5 - t4,
    }),
  );
}

if (process.argv[2] === '--child') {
  await child();
} else if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const runs = Number(process.argv[2] ?? 7);
  const rows = [];
  for (let i = 0; i < runs; i++) {
    const { stdout, status, stderr } = spawnSync(
      process.execPath,
      [fileURLToPath(import.meta.url), '--child'],
      { encoding: 'utf8' },
    );
    if (status !== 0) {
      throw new Error(`run ${i} exited ${status}: ${stderr}`);
    }
    rows.push(JSON.parse(stdout));
  }
  const median = {};
  for (const key of Object.keys(rows[0])) {
    const sorted = rows.map((r) => r[key]).toSorted((a, b) => a - b);
    median[key] = Number(sorted[Math.floor(sorted.length / 2)].toFixed(1));
  }
  process.stdout.write(
    `${JSON.stringify({ runtime: `node ${process.version}`, runs, median, rows }, null, 2)}\n`,
  );
}
