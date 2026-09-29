// Spike only (Route A package, OpenSSL 4.0.2 CMS path). The module is a
// plain wasm32-wasip1 build; this file answers its WASI preview 1 imports
// with a fixed set, not a WASI runtime: a wall clock, random bytes from
// crypto.getRandomValues, empty arguments and environment, no preopened
// directory, stdout/stderr that discard, and a trap for everything else
// (path_open, fd_read, fd_readdir, ...), so an unexpected call fails loudly
// instead of being answered. Same answers as the harness's js/hosts.mjs
// policy "trap", which ran all 1,179 corpus rows. Same export as the Route C
// package's instantiate.js, so node.js, browser.js and workerd.js are shared.
const ESUCCESS = 0, EBADF = 8;
export function instantiateCore(module) {
  let memory = null;
  const dv = () => new DataView(memory.buffer);
  const wasi = {
    clock_time_get(id, precision, out) { dv().setBigUint64(out, BigInt(Date.now()) * 1000000n, true); return ESUCCESS; },
    clock_res_get(id, out) { dv().setBigUint64(out, 1000000n, true); return ESUCCESS; },
    random_get(ptr, len) {
      for (let o = 0; o < len; o += 65536) crypto.getRandomValues(new Uint8Array(memory.buffer, ptr + o, Math.min(65536, len - o)));
      return ESUCCESS;
    },
    args_sizes_get(n, size) { dv().setUint32(n, 0, true); dv().setUint32(size, 0, true); return ESUCCESS; },
    args_get() { return ESUCCESS; },
    environ_sizes_get(n, size) { dv().setUint32(n, 0, true); dv().setUint32(size, 0, true); return ESUCCESS; },
    environ_get() { return ESUCCESS; },
    fd_prestat_get() { return EBADF; },
    fd_prestat_dir_name() { return EBADF; },
    fd_write(fd, iovs, n, written) {
      if (fd !== 1 && fd !== 2) return EBADF;
      let total = 0;
      for (let i = 0; i < n; i++) total += dv().getUint32(iovs + 8 * i + 4, true);
      dv().setUint32(written, total, true);
      return ESUCCESS;
    },
    proc_exit(code) { throw new WebAssembly.RuntimeError(`proc_exit(${code})`); },
  };
  const imports = {};
  for (const i of WebAssembly.Module.imports(module)) {
    if (i.module !== 'wasi_snapshot_preview1') throw new Error(`unexpected wasm import ${i.module}.${i.name}`);
    (imports[i.module] ||= {})[i.name] = wasi[i.name]
      || (() => { throw new WebAssembly.RuntimeError(`WASI ${i.name} is not provided`); });
  }
  const instance = new WebAssembly.Instance(module, imports);
  memory = instance.exports.memory;
  instance.exports._initialize?.();
  instance.exports.aprv_init?.();
  return { fn: (n) => instance.exports[n], buffer: () => memory.buffer };
}
