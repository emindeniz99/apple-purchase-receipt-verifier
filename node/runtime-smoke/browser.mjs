// Runner for browsers, through Playwright: serves the repository over
// local HTTP and runs the smoke in a page that loads the built dist/ as
// plain ES modules. A bundler resolves the package's "#aprv-load" import
// with the browser condition; a page without one maps it itself, as this
// import map does, to the loader that fetches the core modules.
//
//   node runtime-smoke/browser.mjs [--repeat N] [chromium|firefox|webkit ...]
//
// Each browser loads the page N times (default 1), each time in a fresh
// page. Needs the playwright package and its browsers (npx playwright
// install).
//
// When a page fails, the runner prints what is needed to reproduce it: the
// error's name and message (WebKit's `stack` carries neither) and its
// stack, whose `wasm-function[N]` frames map to names through the named
// module of the same build (rust/bindings/abi/README.md); the size of
// every aprv linear memory the page created; every crypto.getRandomValues
// call the page made, with its length; whether a second createVerifier in
// the same page then works; and the browser's crash and console events.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as playwright from 'playwright';

const root = fileURLToPath(new URL('../../', import.meta.url));
const TYPES = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.wasm': 'application/wasm' };

// The page records, before the package loads: each WebAssembly.Instance the
// bindings create (to read its memory size after a failure) and each
// getRandomValues call (the module's one import draws on it).
const PAGE = `<!doctype html>
<script>
  window.diag = { memories: [], random: [] };
  const Instance = WebAssembly.Instance;
  WebAssembly.Instance = function (module, imports) {
    const instance = new Instance(module, imports);
    if (instance.exports.memory instanceof WebAssembly.Memory) {
      window.diag.memories.push(instance.exports.memory);
    }
    return instance;
  };
  WebAssembly.Instance.prototype = Instance.prototype;
  const getRandomValues = crypto.getRandomValues.bind(crypto);
  crypto.getRandomValues = (view) => {
    window.diag.random.push(view.length);
    return getRandomValues(view);
  };
</script>
<script type="importmap">{"imports":{"#aprv-load":"/node/dist/load/fetch.js"}}</script>
<script type="module">
  const text = async (p) => (await fetch(p)).text();
  const bytes = async (p) => new Uint8Array(await (await fetch(p)).arrayBuffer());
  const describe = (e) => ({
    name: e?.name,
    message: e?.message,
    stack: String(e?.stack ?? e),
    constructor: e?.constructor?.name,
  });
  try {
    const { run } = await import('/node/runtime-smoke/smoke.mjs');
    const fx = {
      sandboxReceiptB64: await text('/fixtures/public-receipts/receipt-sandbox-g5.b64'),
      jwsRootDer: await bytes('/fixtures/generated/jws-root.der'),
      transactionJws: await text('/fixtures/generated/transaction.jws'),
    };
    const out = [];
    for (const [name, path] of [['.', '/node/dist/index.js'], ['./web', '/node/dist/web/index.js']]) {
      for (const line of await run(await import(path), fx)) out.push(name + ': ' + line);
    }
    window.result = { out };
  } catch (e) {
    const failure = describe(e);
    failure.memoryBytes = window.diag.memories.map((m) => m.buffer.byteLength);
    failure.randomGetValues = [...window.diag.random];
    try {
      const api = await import('/node/dist/index.js');
      api.createVerifier(api.defaultConfig());
      failure.retry = 'a second createVerifier in the same page worked';
    } catch (again) {
      failure.retry = 'a second createVerifier in the same page failed too: ' + again?.name + ': ' + again?.message;
    }
    window.result = { failure };
  }
</script>`;

const server = createServer(async (req, res) => {
  const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (path === '/') {
    res.writeHead(200, { 'content-type': 'text/html' }).end(PAGE);
    return;
  }
  const file = normalize(`${root}${path}`);
  if (!file.startsWith(root)) {
    res.writeHead(403).end();
    return;
  }
  try {
    const body = await readFile(file);
    res
      .writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' })
      .end(body);
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const url = `http://127.0.0.1:${server.address().port}/`;

const args = process.argv.slice(2);
const repeatAt = args.indexOf('--repeat');
const repeat = repeatAt < 0 ? 1 : Number(args.splice(repeatAt, 2)[1]);
const names = args.length > 0 ? args : ['chromium'];

/** One page load: the smoke's lines, or a failure with its diagnostics. */
async function load(browser) {
  const page = await browser.newPage();
  const events = [];
  page.on('crash', () => events.push('the page crashed'));
  page.on('console', (m) => {
    if (m.type() === 'error' || m.type() === 'warning') {
      events.push(`console ${m.type()}: ${m.text()}`);
    }
  });
  page.on('pageerror', (e) => events.push(`page error: ${e.name}: ${e.message}`));
  try {
    await page.goto(url);
    await page.waitForFunction(() => window.result !== undefined, null, { timeout: 60000 });
    return { ...(await page.evaluate(() => window.result)), events };
  } catch (error) {
    return { failure: { name: 'HarnessError', message: error.message }, events };
  } finally {
    await page.close().catch(() => {});
  }
}

let failed = false;
for (const name of names) {
  // oxlint-disable-next-line no-await-in-loop -- one browser at a time
  const browser = await playwright[name].launch();
  const label = `${name} ${browser.version()}`;
  let failures = 0;
  try {
    for (let i = 0; i < repeat; i++) {
      const result = await load(browser); // oxlint-disable-line no-await-in-loop
      if (i === 0 || result.failure) {
        console.log(`# ${label}${repeat > 1 ? `, page load ${i + 1} of ${repeat}` : ''}`);
      }
      if (result.failure) {
        failed = true;
        failures += 1;
        const f = result.failure;
        console.log(`not ok - ${f.name}: ${f.message}`);
        console.log(JSON.stringify({ browser: label, ...f, events: result.events }, null, 2));
      } else if (i === 0) {
        for (const line of result.out) {
          console.log(`ok - ${line}`);
        }
      }
    }
    if (repeat > 1) {
      console.log(`# ${label}: ${repeat} page loads, ${failures} failed`);
    }
  } finally {
    await browser.close(); // oxlint-disable-line no-await-in-loop
  }
}
server.close();
process.exit(failed ? 1 : 0);
