// Builds the web smoke for Fastly Compute and runs it under viceroy,
// Fastly's own local Compute runtime.
//
//   node runtime-smoke/run-fastly.mjs
//
// Needs js-compute-runtime (a devDependency) and viceroy on PATH.
// viceroy is a Rust binary rather than an npm package:
//   cargo install viceroy --locked
// It needs a current Rust; 0.20.1 requires 1.95. Without it this exits 2
// and says so, rather than passing quietly.
import { execFileSync, spawn } from 'node:child_process';
import { rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const here = (rel) => fileURLToPath(new URL(rel, import.meta.url));
const generated = here('./.web-fixtures.generated.js');
const wasm = here('./.web-fastly.generated.wasm');
const PORT = process.env.FASTLY_SMOKE_PORT || '7878';

try {
  execFileSync('viceroy', ['--version'], { stdio: 'ignore' });
} catch {
  console.error('viceroy is not on PATH; install it with: cargo install viceroy --locked');
  process.exit(2);
}

execFileSync('node', [here('./gen-web-fixtures.mjs'), generated], { stdio: 'inherit' });
execFileSync('npx', ['js-compute-runtime', here('./web-fastly.js'), wasm], { stdio: 'inherit' });

const server = spawn('viceroy', ['serve', '--addr', `127.0.0.1:${PORT}`, wasm], {
  stdio: ['ignore', 'ignore', 'inherit'],
});

const cleanup = () => {
  server.kill();
  rmSync(generated, { force: true });
  rmSync(wasm, { force: true });
};

try {
  let body = null;
  // viceroy takes a moment to bind; poll rather than sleep a fixed time.
  // oxlint-disable no-await-in-loop -- a retry-with-delay poll: each attempt
  // must wait for the previous one (and its backoff) before trying again, so
  // there is nothing here to collect into a Promise.all().
  for (let attempt = 0; attempt < 60 && body === null; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${PORT}/`);
      body = { text: await response.text(), ok: response.ok };
    } catch {
      await new Promise((resolve) => {
        setTimeout(resolve, 500);
      });
    }
  }
  // oxlint-enable no-await-in-loop
  if (body === null) {
    throw new Error('viceroy never answered');
  }
  process.stdout.write(body.text);
  if (!body.ok) {
    throw new Error('the Fastly smoke reported a failure');
  }
} finally {
  cleanup();
}
