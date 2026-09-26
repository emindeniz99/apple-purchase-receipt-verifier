// Spike only. workerd worker for an EMSCRIPTEN build (Route B). The .wasm is
// a static module import; Emscripten's own glue (aprv-em.mjs) is kept, and
// its documented Module.instantiateWasm hook hands it the precompiled
// module (js/emscripten-host.mjs), because workerd refuses to compile wasm
// bytes at runtime.
import wasmModule from './aprv-em.wasm';
import createAprv from './aprv-em.mjs';
import { makeDriver, jsonl } from './driver.mjs';
import { instantiateEmscripten } from './emscripten-host.mjs';

const calls = {};
const d = makeDriver(() => instantiateEmscripten(createAprv, wasmModule, calls));
let ready = null;
export default {
  async fetch(request) {
    ready ||= d.init();
    await ready;
    const url = new URL(request.url);
    if (url.pathname === '/imports') {
      return Response.json({ imports: WebAssembly.Module.imports(wasmModule), calls });
    }
    const rows = jsonl(await request.text());
    const out = [];
    for (const r of rows) out.push(JSON.stringify(await d.run(r)));
    return new Response(out.join('\n') + '\n');
  },
};
