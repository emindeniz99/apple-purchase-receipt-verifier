// One command for a module drop: build from a directory holding the
// module's release files, then run everything the Node lane checks and
// measures against it.
//
//   node scripts/g1.mjs DROP_DIR
//
// DROP_DIR holds aprv.component.wasm, calls/<corpus>.pinned.jsonl and
// rows/module-<corpus>.jsonl. The steps, in order, stop at the first
// failure: the build (APRV_COMPONENT pointing at the drop), the node:test
// suite, the runtime smoke on Node and on workerd, the corpus against the
// reference rows, then the timings (bench/bench.mjs, bench/startup.mjs) and
// memory (bench/memory.mjs, bench/memory-workerd.mjs). Nothing is written
// into the repository except dist/ and src/generated/.
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const drop = process.argv[2];
if (!drop) {
  console.error('usage: g1.mjs DROP_DIR');
  process.exit(2);
}
const cwd = fileURLToPath(new URL('..', import.meta.url));
const env = { ...process.env, APRV_COMPONENT: join(drop, 'aprv.component.wasm') };
const node = process.execPath;

const steps = [
  ['build', node, ['scripts/build.mjs']],
  ['node:test', node, ['--test', '--test-reporter=dot']],
  ['smoke: node', node, ['runtime-smoke/node-like.mjs']],
  ['smoke: workerd', node, ['runtime-smoke/run-workerd.mjs', 'workerd@1.20260903.1']],
  ['corpus', node, ['scripts/corpus.mjs', join(drop, 'calls'), join(drop, 'rows')]],
  ['bench', node, ['bench/bench.mjs']],
  ['startup', node, ['bench/startup.mjs']],
  ['memory: node', node, ['bench/memory.mjs']],
  ['memory: workerd', node, ['bench/memory-workerd.mjs']],
];
for (const [name, command, args] of steps) {
  console.log(`\n## ${name}`);
  const { status } = spawnSync(command, args, { cwd, env, stdio: 'inherit' });
  if (status !== 0) {
    console.error(`g1: ${name} failed (exit ${status})`);
    process.exit(1);
  }
}
