// Spike only. Serves the page, the artifact and the corpora on 127.0.0.1,
// opens the page in a real headless browser, collects the posted rows.
//
//   node browser/run-browser.mjs <chromium|firefox|webkit> <artifact-dir> <out-prefix> '<query string>'
//
// chromium: Playwright's preinstalled Chromium (PLAYWRIGHT_BROWSERS_PATH).
// firefox:  the stock Firefox release binary in $FIREFOX, started headless
//           on the page URL (no WebDriver; the page reports back by POST).
// webkit:   WebKitGTK MiniBrowser under xvfb-run, same reporting.
// Rows land in <out-prefix>-<corpus>.jsonl; the page's report on stdout.
import http from 'node:http';
import { readFileSync, writeFileSync, existsSync, mkdtempSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { join, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const [browser, artDir, outPrefix, query] = process.argv.slice(2);
const here = dirname(fileURLToPath(import.meta.url));
const roots = { js: join(here, '..', 'js'), browser: here, art: artDir, corpora: process.env.CORPORA };
const types = { '.mjs': 'text/javascript', '.js': 'text/javascript', '.wasm': 'application/wasm', '.html': 'text/html', '.jsonl': 'text/plain' };
let done;
const finished = new Promise((r) => { done = r; });

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (req.method === 'POST') {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      if (url.pathname === '/result') writeFileSync(`${outPrefix}-${url.searchParams.get('corpus')}.jsonl`, body);
      if (url.pathname === '/done') done(body);
      res.end('ok');
    });
    return;
  }
  const [, top, ...rest] = url.pathname.split('/');
  const file = roots[top] && join(roots[top], ...rest);
  if (!file || !existsSync(file)) { res.statusCode = 404; res.end(); return; }
  res.setHeader('content-type', types[extname(file)] || 'application/octet-stream');
  res.end(readFileSync(file));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const pageUrl = `http://127.0.0.1:${server.address().port}/browser/page.html?${query}`;

let stop;
if (browser === 'chromium') {
  const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
  const b = await chromium.launch({ headless: true });
  const page = await b.newPage();
  page.on('pageerror', (e) => console.error('pageerror', e.message));
  await page.goto(pageUrl);
  console.error('browser', b.version());
  stop = () => b.close();
} else if (browser === 'webkit') {
  // WebKitGTK's MiniBrowser (Ubuntu libwebkit2gtk-4.1), under Xvfb. Same
  // engine family as Safari (WebKit/JavaScriptCore); NOT Safari itself.
  const wk = spawn('xvfb-run', ['-a', process.env.MINIBROWSER || '/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/MiniBrowser',
    '--private', '--ignore-host=127.0.0.1', pageUrl], { stdio: 'ignore', detached: true });
  stop = () => { try { process.kill(-wk.pid, 'SIGTERM'); } catch {} };
} else {
  const profile = mkdtempSync(join(tmpdir(), 'aprv-ff-'));
  const ff = spawn(process.env.FIREFOX, ['--headless', '--no-remote', '--profile', profile, pageUrl], { stdio: 'ignore' });
  stop = () => ff.kill('SIGTERM');
}
const timer = setTimeout(() => done(JSON.stringify({ ok: false, error: 'timeout' })), Number(process.env.BROWSER_TIMEOUT_MS || 1800000));
const report = await finished;
clearTimeout(timer);
await stop();
server.close();
console.log(report);
process.exit(0);
