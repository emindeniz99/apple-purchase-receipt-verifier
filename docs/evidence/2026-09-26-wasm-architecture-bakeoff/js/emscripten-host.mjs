// Spike only. Instantiates an Emscripten build (Route B) from its own ES
// module glue, handing the glue a precompiled WebAssembly.Module through
// the documented Module.instantiateWasm hook (the only way on workerd, and
// harmless elsewhere). Every JS function the wasm imports is wrapped to
// count its calls under the glue's own function name (e.g. ___syscall_openat).
export async function instantiateEmscripten(factory, wasmModule, calls = {}) {
  const M = await factory({
    print() {}, printErr() {},
    instantiateWasm(imports, done) {
      const wrapped = {};
      for (const [mod, fns] of Object.entries(imports)) {
        wrapped[mod] = {};
        for (const [k, v] of Object.entries(fns)) {
          const name = (typeof v === 'function' && v.name) || `${mod}.${k}`;
          wrapped[mod][k] = typeof v === 'function'
            ? (...a) => { calls[name] = (calls[name] || 0) + 1; return v(...a); } : v;
        }
      }
      const instance = new WebAssembly.Instance(wasmModule, wrapped);
      done(instance, wasmModule);
      return instance.exports;
    },
  });
  if (M._aprv_init) M._aprv_init();
  return { fn: (n) => M['_' + n], buffer: () => M.HEAPU8.buffer, calls };
}
