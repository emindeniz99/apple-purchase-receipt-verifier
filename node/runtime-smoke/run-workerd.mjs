// Runs the workerd smoke with a pinned workerd from npm:
//
//   node runtime-smoke/run-workerd.mjs workerd@<version>
//
// workerd.capnp sets no compatibility flags: the package uses no Node API
// on workerd, and its core modules are static imports, the only way
// workerd accepts WebAssembly.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const [spec] = process.argv.slice(2);
if (!spec) {
  console.error('usage: run-workerd.mjs <workerd-spec>');
  process.exit(2);
}
const config = fileURLToPath(new URL('./workerd.capnp', import.meta.url));
console.log(`# ${spec}, no compatibility flags`);
execFileSync('npx', ['--yes', spec, 'test', config], { stdio: 'inherit' });
