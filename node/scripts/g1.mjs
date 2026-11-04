// The corpus parity run (DECISIONS.md R35): build from the G1 directory,
// then run the five corpora through the package's host layer and compare
// every row with the module's own.
//
//   node scripts/g1.mjs DROP_DIR
//
// DROP_DIR is the directory tools/corpus.sh g1 assembles (the nightly's
// corpus-reference job); this script reads its aprv.component.wasm, built
// from the commit, the pinned calls/<corpus>.pinned.jsonl and
// rows/module-<corpus>.jsonl, derived from that module. The steps, in
// order, stop at the first failure: the build (APRV_COMPONENT pointing at
// the drop), then the corpus against the reference rows. Rows only: the
// node:test suite and the runtime smokes run in ci.yml against the
// component built from the same commit; the timings and memory scripts in
// bench/ run on their own. Nothing is written into the repository except dist/ and
// src/generated/.
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
  ['corpus', node, ['scripts/corpus.mjs', join(drop, 'calls'), join(drop, 'rows')]],
];
for (const [name, command, args] of steps) {
  console.log(`\n## ${name}`);
  const { status } = spawnSync(command, args, { cwd, env, stdio: 'inherit' });
  if (status !== 0) {
    console.error(`g1: ${name} failed (exit ${status})`);
    process.exit(1);
  }
}
