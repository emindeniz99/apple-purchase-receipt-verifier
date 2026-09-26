// Spike only. workerd worker for a CORE wasm module (Route A or C): the
// .wasm arrives as a static module import (workerd refuses
// WebAssembly.compile on bytes), and gets js/hosts.mjs's minimal import
// object. No node:wasi, no WASI runtime.
// POST a JSONL request corpus; the answer is one JSONL row per request.
import wasmModule from './aprv.wasm';
import { makeDriver, jsonl } from './driver.mjs';
import { instantiateMinimal } from './hosts.mjs';
import { POLICY } from './policy.mjs';

let host = null;
const d = makeDriver(async () => {
  const api = await instantiateMinimal(wasmModule, POLICY);
  host = api.host;
  return api;
});
let ready = null;
export default {
  async fetch(request) {
    ready ||= d.init();
    await ready;
    const url = new URL(request.url);
    if (url.pathname === '/imports') {
      return Response.json({ imports: WebAssembly.Module.imports(wasmModule), calls: host.calls });
    }
    const rows = jsonl(await request.text());
    const out = [];
    for (const r of rows) out.push(JSON.stringify(await d.run(r)));
    return new Response(out.join('\n') + '\n');
  },
};
