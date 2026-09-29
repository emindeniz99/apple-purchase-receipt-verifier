// Spike only (Route C package). The ONLY host capabilities the module can
// import: a wall clock, and (OpenSSL builds only) random bytes from
// crypto.getRandomValues. Anything else in the module's import list is a
// build error, reported here rather than stubbed.
export function instantiateCore(module) {
  let memory = null;
  const host = {
    clock_now_ms: () => Date.now(),
    random_get: (ptr, len) => {
      for (let o = 0; o < len; o += 65536) crypto.getRandomValues(new Uint8Array(memory.buffer, ptr + o, Math.min(65536, len - o)));
      return 0;
    },
  };
  const imports = { aprv: {} };
  for (const i of WebAssembly.Module.imports(module)) {
    if (i.module !== 'aprv' || !host[i.name]) throw new Error(`unexpected wasm import ${i.module}.${i.name}`);
    imports.aprv[i.name] = host[i.name];
  }
  const instance = new WebAssembly.Instance(module, imports);
  memory = instance.exports.memory;
  instance.exports._initialize?.();
  instance.exports.aprv_init?.();
  return { fn: (n) => instance.exports[n], buffer: () => memory.buffer };
}
