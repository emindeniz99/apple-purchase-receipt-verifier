// Builds dist/: jco transpiles aprv.wasm's component into src/generated/,
// TypeScript compiles the facade, and the generated glue and core modules
// are copied next to it.
//
//   node scripts/build.mjs
//
// The component is read from wasm/aprv.component.wasm, which is gitignored:
// copy it into place (CI takes it from the rust-wasm job). That copy must
// match wasm/aprv.component.wasm.sha256, the component this package was
// last tested against. APRV_COMPONENT names another file instead, used as
// given; the build prints its SHA-256. Either way the hash is recorded in
// dist/generated/component.sha256. src/generated/ is build output: it is not
// committed, because it must always match the component it came from.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
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
if (!existsSync(component)) {
  fail(
    `no component at ${component}: copy aprv.component.wasm there (the rust-wasm job builds it) ` +
      'or set APRV_COMPONENT to its path',
  );
}
const sha256 = createHash('sha256').update(readFileSync(component)).digest('hex');
if (override) {
  // stderr, like every other line here: `npm pack --json` runs this script
  // through prepack and its stdout must stay the JSON a caller parses.
  console.error(`build: component ${override} (APRV_COMPONENT), sha256 ${sha256}`);
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
