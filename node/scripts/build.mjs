// Builds dist/: jco transpiles aprv.wasm's component into src/generated/,
// TypeScript compiles the facade, and the generated glue and core modules
// are copied next to it.
//
//   node scripts/build.mjs
//
// The component is wasm/aprv.component.wasm, checked against
// wasm/aprv.component.wasm.sha256, unless APRV_COMPONENT names another
// file (a release build, or the core's own CI build), which is used as
// given and whose SHA-256 is printed. src/generated/ is build output: it is
// not committed, because it must always match the component it came from.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const here = (rel) => fileURLToPath(new URL(`../${rel}`, import.meta.url));
const fail = (message) => {
  console.error(`build: ${message}`);
  process.exit(1);
};
const run = (command, args) => {
  const { status, error } = spawnSync(command, args, { cwd: here(''), stdio: 'inherit' });
  if (error || status !== 0) {
    fail(`${command} ${args.join(' ')} failed${error ? `: ${error.message}` : ''}`);
  }
};

// 1. The component.
const override = process.env.APRV_COMPONENT;
const component = override || here('wasm/aprv.component.wasm');
const sha256 = createHash('sha256').update(readFileSync(component)).digest('hex');
if (override) {
  console.log(`build: component ${override} (APRV_COMPONENT), sha256 ${sha256}`);
} else {
  const pinned = readFileSync(here('wasm/aprv.component.wasm.sha256'), 'ascii').split(/\s/)[0];
  if (pinned !== sha256) {
    fail(`wasm/aprv.component.wasm has sha256 ${sha256}, the .sha256 file pins ${pinned}`);
  }
}

// 2. The bindings: synchronous instantiation (the default entry point is
// synchronous), minified, core modules left as files for the loaders.
rmSync(here('src/generated'), { recursive: true, force: true });
run(here('node_modules/.bin/jco'), [
  'transpile',
  component,
  '-o',
  here('src/generated'),
  '--name',
  'aprv',
  '--instantiation',
  'sync',
  '--minify',
  '--quiet',
]);
const cores = readdirSync(here('src/generated'))
  .filter((f) => f.endsWith('.wasm'))
  .toSorted();
const expected = ['aprv.core.wasm', 'aprv.core2.wasm', 'aprv.core3.wasm'];
if (JSON.stringify(cores) !== JSON.stringify(expected)) {
  fail(`jco wrote core modules ${cores.join(', ')}; src/load/ expects ${expected.join(', ')}`);
}
writeFileSync(here('src/generated/component.sha256'), `${sha256}  aprv.component.wasm\n`);

// 3. The facade, then the glue beside it.
rmSync(here('dist'), { recursive: true, force: true });
run(process.execPath, [here('scripts/typecheck.mjs')]);
cpSync(here('src/generated'), here('dist/generated'), { recursive: true });
