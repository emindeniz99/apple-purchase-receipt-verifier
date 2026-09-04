// Runner for Fastly Compute. The runtime has crypto.subtle (SHA-1 included,
// which the legacy receipt chain needs) and neither Buffer nor process, so
// it exercises exactly what the /web entry point claims to need.
//
// Built to wasm by js-compute-runtime and served by viceroy; see
// run-fastly.mjs. Fixtures arrive as a generated module because Compute has
// no filesystem.
import { run } from './web-smoke.mjs';
import * as fixtures from './.web-fixtures.generated.js';

addEventListener('fetch', (event) => event.respondWith(handle()));

async function handle() {
  for (const absent of ['Buffer', 'process']) {
    if (typeof globalThis[absent] !== 'undefined') {
      return new Response(`FAIL ${absent} exists here, so this proves nothing\n`, { status: 500 });
    }
  }
  try {
    const lines = await run(fixtures);
    return new Response(`${lines.map((l) => `ok - ${l}`).join('\n')}\n`);
  } catch (error) {
    const detail = [error && error.reason, error && error.message, error && error.stack]
      .filter(Boolean).join(' | ');
    return new Response(`FAIL ${detail || error}\n`, { status: 500 });
  }
}
