// Serves a consumer directory (node_modules included) and opens
// smoke.html?pkg=<name> in a real browser; prints the page's report.
//   node npm/browser-smoke.mjs <chromium|firefox|webkit> <consumer-dir> <package-name>
import http from 'node:http';
import { readFileSync, existsSync, mkdtempSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { join, extname, normalize } from 'node:path';
import { tmpdir } from 'node:os';
const [browser, dir, pkg] = process.argv.slice(2);
const types = { '.mjs': 'text/javascript', '.js': 'text/javascript', '.wasm': 'application/wasm', '.html': 'text/html' };
let done; const fin = new Promise((r) => { done = r; });
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (req.method === 'POST') { const b = []; req.on('data', (c) => b.push(c)); req.on('end', () => { done(Buffer.concat(b).toString()); res.end(); }); return; }
  const file = join(dir, normalize(url.pathname));
  if (!file.startsWith(dir) || !existsSync(file)) { res.statusCode = 404; res.end(); return; }
  res.setHeader('content-type', types[extname(file)] || 'application/octet-stream');
  res.end(readFileSync(file));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const url = `http://127.0.0.1:${server.address().port}/smoke.html?pkg=${pkg}`;
let stop;
if (browser === 'chromium') {
  const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
  const b = await chromium.launch({ headless: true }); const p = await b.newPage(); await p.goto(url); stop = () => b.close();
} else if (browser === 'webkit') {
  const w = spawn('xvfb-run', ['-a', '/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/MiniBrowser', '--private', url], { stdio: 'ignore', detached: true });
  stop = () => { try { process.kill(-w.pid, 'SIGTERM'); } catch {} };
} else {
  const ff = spawn(process.env.FIREFOX, ['--headless', '--no-remote', '--profile', mkdtempSync(join(tmpdir(), 'aprv-ff-')), url], { stdio: 'ignore' });
  stop = () => ff.kill('SIGTERM');
}
const t = setTimeout(() => done(JSON.stringify({ pkg, ok: false, error: 'timeout' })), 120000);
const rep = await fin; clearTimeout(t); await stop(); server.close();
console.log(JSON.stringify({ browser, ...JSON.parse(rep) }));
process.exit(0);
