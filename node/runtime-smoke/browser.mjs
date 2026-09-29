// Runner for browsers, through Playwright: serves the repository over
// local HTTP and runs the smoke in a page that loads the built dist/ as
// plain ES modules. A bundler resolves the package's "#aprv-load" import
// with the browser condition; a page without one maps it itself, as this
// import map does, to the loader that fetches the core modules.
//
//   node runtime-smoke/browser.mjs [chromium|firefox|webkit ...]
//
// Needs the playwright package and its browsers (npx playwright install).
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as playwright from 'playwright';

const root = fileURLToPath(new URL('../../', import.meta.url));
const TYPES = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.wasm': 'application/wasm' };

const PAGE = `<!doctype html>
<script type="importmap">{"imports":{"#aprv-load":"/node/dist/load/fetch.js"}}</script>
<script type="module">
  const text = async (p) => (await fetch(p)).text();
  const bytes = async (p) => new Uint8Array(await (await fetch(p)).arrayBuffer());
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
    window.result = { error: String(e && e.stack || e) };
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

let failed = false;
const names = process.argv.slice(2);
for (const name of names.length > 0 ? names : ['chromium']) {
  // oxlint-disable-next-line no-await-in-loop -- one browser at a time
  const browser = await playwright[name].launch();
  try {
    const page = await browser.newPage(); // oxlint-disable-line no-await-in-loop
    await page.goto(url); // oxlint-disable-line no-await-in-loop
    await page.waitForFunction(() => window.result !== undefined, null, { timeout: 60000 }); // oxlint-disable-line no-await-in-loop
    const result = await page.evaluate(() => window.result); // oxlint-disable-line no-await-in-loop
    console.log(`# ${name} ${browser.version()}`);
    if (result.error) {
      failed = true;
      console.log(`not ok - ${result.error}`);
    }
    for (const line of result.out ?? []) {
      console.log(`${line.includes('SKIP') ? '#' : 'ok -'} ${line}`);
    }
  } finally {
    await browser.close(); // oxlint-disable-line no-await-in-loop
  }
}
server.close();
process.exit(failed ? 1 : 0);
