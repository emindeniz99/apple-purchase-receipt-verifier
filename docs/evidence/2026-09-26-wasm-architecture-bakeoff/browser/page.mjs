// Spike only. Runs request corpora through a wasm artifact in a real
// browser page and POSTs the rows back to browser/run-browser.mjs.
// Query: kind=core|emscripten|jco, mod=<file under /art/>, corpora=a,b,
// policy=trap|strict. Same driver.mjs and hosts.mjs as every other host.
import { makeDriver, jsonl } from '/js/driver.mjs';
import { instantiateMinimal } from '/js/hosts.mjs';

const q = new URLSearchParams(location.search);
const kind = q.get('kind');
const log = (s) => { document.getElementById('log').textContent += '\n' + s; };
const calls = {};
const merge = (c) => { for (const [k, v] of Object.entries(c)) calls[k] = (calls[k] || 0) + v; };

async function makeInstantiate() {
  if (kind === 'core') {
    // Streaming compile from the network: the normal browser path.
    const module = await WebAssembly.compileStreaming(fetch('/art/' + q.get('mod')));
    let last = null;
    return async () => {
      if (last) merge(last.calls);
      const api = await instantiateMinimal(module, q.get('policy') === 'strict' ? { strictAll: true } : { policy: 'trap' });
      last = api.host;
      globalThis.__aprvHost = api.host;
      return api;
    };
  }
  if (kind === 'emscripten') {
    const { instantiateEmscripten } = await import('/js/emscripten-host.mjs');
    const factory = (await import('/art/' + q.get('mod'))).default;
    const module = await WebAssembly.compileStreaming(fetch('/art/' + q.get('mod').replace(/\.mjs$/, '.wasm')));
    return () => instantiateEmscripten(factory, module, calls);
  }
  if (kind === 'jco') {
    const { makeJcoRunner } = await import('/js/jco-driver.mjs');
    const { instantiate } = await import('/art/' + q.get('mod'));
    const extra = q.get('p2') === 'min' ? (await import('/js/wasi-p2-min.mjs')).wasiP2Min(calls) : {};
    return () => makeJcoRunner(instantiate, (p) => WebAssembly.compileStreaming(fetch('/art/' + p)), calls, extra);
  }
  throw new Error('unknown kind ' + kind);
}

try {
  const inst = await makeInstantiate();
  let runner;
  if (kind === 'jco') runner = await inst();
  else { runner = makeDriver(inst); await runner.init(); }
  for (const c of q.get('corpora').split(',')) {
    const rows = jsonl(await (await fetch('/corpora/' + c + '.jsonl')).text());
    const t = performance.now();
    const out = [];
    for (const r of rows) out.push(JSON.stringify(await runner.run(r)));
    log(`${c}: ${rows.length} rows in ${Math.round(performance.now() - t)} ms`);
    await fetch('/result?corpus=' + c, { method: 'POST', body: out.join('\n') + '\n' });
  }
  if (globalThis.__aprvHost) merge(globalThis.__aprvHost.calls);
  await fetch('/done', { method: 'POST', body: JSON.stringify({ ok: true, userAgent: navigator.userAgent, calls }) });
} catch (e) {
  await fetch('/done', { method: 'POST', body: JSON.stringify({ ok: false, error: String(e && e.stack || e), userAgent: navigator.userAgent }) });
}
