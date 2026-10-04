// wrangler's build step: puts what the demo page loads under
// public/vendor/, which is not committed.
//
// - the installed package's dist/ and package.json, so the page runs the
//   same release in the browser that the Worker runs;
// - src/wire.mjs, the envelope both sides share;
// - a public sandbox receipt from this repository's fixtures, when the
//   example sits inside the repository.
import { cpSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const here = (rel) => fileURLToPath(new URL(`../${rel}`, import.meta.url));
const pkg = here('node_modules/apple-purchase-receipt-verifier');

rmSync(here('public/vendor'), { recursive: true, force: true });
mkdirSync(here('public/vendor/aprv'), { recursive: true });
cpSync(`${pkg}/dist`, here('public/vendor/aprv/dist'), {
  recursive: true,
  // The page runs the JavaScript (and, from 0.8, fetches the .wasm); it has no use for the types.
  filter: (source) => !source.endsWith('.d.ts'),
});
cpSync(`${pkg}/package.json`, here('public/vendor/aprv/package.json'));
cpSync(here('src/wire.mjs'), here('public/vendor/wire.mjs'));

const sample = here('../../../fixtures/public-receipts/receipt-sandbox-g5.b64');
if (existsSync(sample)) {
  cpSync(sample, here('public/vendor/sample-receipt.b64'));
}
