// bench/memory.mjs's hostile receipt in workerd: one `workerd test` process
// per row, which makes one call with the default entry point under the
// workerd loader (static Wasm imports, no compatibility flags). Peak RSS is
// the whole workerd process's, read by a python3 wrapper from the child's
// rusage; workerd run locally does not enforce the 128 MB isolate limit.
//
//   npm run build && node bench/memory-workerd.mjs [workerd-spec]
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hostileReceipts } from './memory.mjs';

const spec = process.argv[2] ?? 'workerd@1.20260903.1';
const dist = fileURLToPath(new URL('../dist', import.meta.url));
const DIST_MODULES = ['index', 'config', 'engine', 'environment', 'errors', 'payload', 'verifier'];

// The workerd launcher itself, not npx, so npm's own memory stays out of the
// measurement.
const which = spawnSync('npm', ['exec', '--yes', `--package=${spec}`, '-c', 'command -v workerd'], {
  encoding: 'utf8',
});
const workerd = which.stdout.trim();
if (which.status !== 0 || workerd === '') {
  throw new Error(`could not find workerd from ${spec}: ${which.stderr}`);
}

const work = mkdtempSync(join(tmpdir(), 'aprv-workerd-memory-'));
try {
  cpSync(dist, join(work, 'dist'), { recursive: true });
  const receipts = hostileReceipts();
  console.log(`# ${spec}, one workerd process per row, peak RSS of the whole process`);
  for (const [name, base64] of Object.entries(receipts)) {
    writeFileSync(join(work, `${name}.b64`), base64);
    for (const via of ['verifyReceipt', 'endpoint']) {
      const worker = `import { createVerifier, createConfig, Environment } from 'dist/index.js';
import receipt from 'receipt.b64';
export default {
  async test() {
    const v = createVerifier(createConfig());
    const answer = ${JSON.stringify(via)} === 'endpoint'
      ? JSON.parse(v.verifyReceiptEndpoint(Environment.PRODUCTION, JSON.stringify({ 'receipt-data': receipt }))).status
      : v.verifyReceipt(receipt).failure?.reason;
    console.log('ANSWER ' + answer);
  },
};
`;
      writeFileSync(join(work, 'w.mjs'), worker);
      const modules = [
        '(name = "w.mjs", esModule = embed "w.mjs")',
        ...DIST_MODULES.map((m) => `(name = "dist/${m}.js", esModule = embed "dist/${m}.js")`),
        '(name = "dist/generated/aprv.js", esModule = embed "dist/generated/aprv.js")',
        '(name = "dist/#aprv-load", esModule = embed "dist/load/static.js")',
        ...['aprv.core.wasm', 'aprv.core2.wasm', 'aprv.core3.wasm'].map(
          (w) => `(name = "generated/${w}", wasm = embed "dist/generated/${w}")`,
        ),
        `(name = "receipt.b64", text = embed "${name}.b64")`,
      ];
      writeFileSync(
        join(work, 'w.capnp'),
        `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = ( services = [ (name = "main", worker = .worker) ] );
const worker :Workerd.Worker = ( modules = [ ${modules.join(', ')} ], compatibilityDate = "2026-08-01" );
`,
      );
      const wrapper = `import json, resource, subprocess, sys
r = subprocess.run(sys.argv[1:], capture_output=True, text=True)
answer = [l.split('ANSWER ', 1)[1] for l in (r.stdout + r.stderr).splitlines() if 'ANSWER ' in l]
print(json.dumps({"status": r.returncode, "answer": answer[0] if answer else None,
                  "peakRssMiB": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss // 1024}))`;
      const { stdout, status } = spawnSync(
        'python3',
        ['-c', wrapper, workerd, 'test', join(work, 'w.capnp')],
        { encoding: 'utf8' },
      );
      const row = JSON.parse(stdout);
      if (status !== 0 || row.status !== 0 || row.answer === null) {
        throw new Error(`${name} ${via}: workerd failed (${stdout})`);
      }
      console.log(
        JSON.stringify({
          receipt: name,
          base64Bytes: base64.length,
          via,
          answer: row.answer,
          peakRssMiB: row.peakRssMiB,
        }),
      );
    }
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}
