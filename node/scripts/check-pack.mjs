// Reads `npm pack --json` from stdin and refuses a tarball that lacks the
// entry point, the module jco extracted, its glue or a licence text of the
// code in that module.
//
//   npm pack --dry-run --json | node scripts/check-pack.mjs
//
// 0.1.1 and 0.2.0 shipped with no JavaScript at all: "files" lists dist/,
// but nothing had built it, so the tarball was LICENSE + certs + README and
// every install failed on ERR_MODULE_NOT_FOUND. The release runs this before
// `npm publish`; ci.yml runs it on the tarball its consumer smoke installs.
// A build script that writes to stdout breaks the JSON (0.8.0's release
// run, 2026-10-04), so a parse failure names the stray text.
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  raw += chunk;
});
process.stdin.on('end', () => {
  let packed;
  try {
    packed = JSON.parse(raw)[0].files.map((f) => f.path);
  } catch (error) {
    console.error(`check-pack: npm pack's stdout is not its JSON: ${error.message}`);
    console.error(raw.slice(0, 400));
    process.exit(1);
  }
  const licensesDir = fileURLToPath(new URL('../licenses', import.meta.url));
  const licences = readdirSync(licensesDir).map((f) => `licenses/${f}`);
  const want = [
    'dist/index.js',
    'dist/index.d.ts',
    'dist/generated/aprv.core.wasm',
    'dist/generated/aprv.js',
    ...licences,
  ];
  const missing = want.filter((f) => !packed.includes(f));
  if (missing.length > 0) {
    console.error(`check-pack: refusing to publish: tarball is missing ${missing.join(', ')}`);
    console.error(`check-pack: packed instead: ${packed.join(', ')}`);
    process.exit(1);
  }
  console.log(
    `check-pack: tarball carries ${packed.length} files, entry point, module and licences included`,
  );
});
