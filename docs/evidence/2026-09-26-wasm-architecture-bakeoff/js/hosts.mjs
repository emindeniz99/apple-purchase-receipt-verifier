// Spike only. The import objects the bake-off hands to a core wasm module,
// from smallest to largest. Pure ECMAScript (no node:*), so browsers and
// workerd use the same file.
//
// minimalHost(module, opts) builds an import object for exactly the
// imports the module declares:
//   aprv.clock_now_ms          -> Date.now()
//   wasi_snapshot_preview1.*   -> a TINY hand-written subset (below), not a
//                                 WASI runtime: no files, no sockets, no
//                                 environment, no arguments.
//   anything else              -> depends on opts.policy:
//       "enosys" (default)     returns 52 (ENOSYS) and counts the call
//       "trap"                 throws: proves the import is never called
// Every call is counted in host.calls, so a run reports which imports it
// really used (the classification in results/imports-*.txt).

const ERRNO_SUCCESS = 0;
const ERRNO_BADF = 8;
const ERRNO_NOSYS = 52;

// Fills [ptr, ptr+len) from crypto.getRandomValues, 65,536 bytes at a time
// (the Web Crypto per-call limit). Never Math.random.
function fillRandom(memory, ptr, len) {
  for (let off = 0; off < len; off += 65536) {
    crypto.getRandomValues(new Uint8Array(memory.buffer, ptr + off, Math.min(65536, len - off)));
  }
}

export function minimalHost(module, opts = {}) {
  const policy = opts.policy || 'enosys';
  const now = opts.now || (() => Date.now());
  const calls = {};
  let memory = null;
  const stderr = [];
  const count = (k) => { calls[k] = (calls[k] || 0) + 1; };
  const dv = () => new DataView(memory.buffer);

  const wasi = {
    // Monotonic and realtime both answer the host wall clock in ns.
    clock_time_get(id, precision, out) {
      dv().setBigUint64(out, BigInt(Math.round(now())) * 1000000n, true);
      return ERRNO_SUCCESS;
    },
    clock_res_get(id, out) { dv().setBigUint64(out, 1000000n, true); return ERRNO_SUCCESS; },
    // opts.random: "fail" answers EIO (29), "zero" writes zeros (a
    // deterministic, useless RNG): randomness-investigation modes only.
    random_get(ptr, len) {
      if (opts.random === 'fail') return 29;
      if (opts.random === 'zero') { new Uint8Array(memory.buffer, ptr, len).fill(0); return ERRNO_SUCCESS; }
      fillRandom(memory, ptr, len);
      return ERRNO_SUCCESS;
    },
    // No arguments and no environment: both lists are empty.
    args_sizes_get(argc, bufsz) { dv().setUint32(argc, 0, true); dv().setUint32(bufsz, 0, true); return ERRNO_SUCCESS; },
    args_get() { return ERRNO_SUCCESS; },
    environ_sizes_get(n, bufsz) { dv().setUint32(n, 0, true); dv().setUint32(bufsz, 0, true); return ERRNO_SUCCESS; },
    environ_get() { return ERRNO_SUCCESS; },
    // No preopened directories: wasi-libc stops scanning at the first EBADF.
    fd_prestat_get() { return ERRNO_BADF; },
    fd_prestat_dir_name() { return ERRNO_BADF; },
    // stdout/stderr: bytes are kept (a panic message lands here), nothing
    // is written anywhere. Any other descriptor does not exist.
    fd_write(fd, iovs, iovsLen, nwritten) {
      if (fd !== 1 && fd !== 2) return ERRNO_BADF;
      let n = 0;
      for (let i = 0; i < iovsLen; i++) {
        const p = dv().getUint32(iovs + 8 * i, true);
        const l = dv().getUint32(iovs + 8 * i + 4, true);
        if (stderr.length < 64) stderr.push(new Uint8Array(memory.buffer, p, l).slice());
        n += l;
      }
      dv().setUint32(nwritten, n, true);
      return ERRNO_SUCCESS;
    },
    proc_exit(code) { throw new WebAssembly.RuntimeError(`proc_exit(${code})`); },
    sched_yield() { return ERRNO_SUCCESS; },
  };

  const imports = {};
  for (const imp of WebAssembly.Module.imports(module)) {
    if (imp.kind !== 'function') throw new Error(`non-function import ${imp.module}.${imp.name}`);
    const key = `${imp.module}.${imp.name}`;
    let impl;
    if (imp.module === 'aprv' && imp.name === 'clock_now_ms') impl = () => now();
    else if (imp.module === 'aprv' && imp.name === 'random_get') impl = (p, l) => { fillRandom(memory, p, l); return 0; };
    else if (imp.module === 'wasi_snapshot_preview1' && wasi[imp.name]) impl = wasi[imp.name];
    else if (policy === 'trap') impl = () => { throw new WebAssembly.RuntimeError(`import ${key} called`); };
    else impl = () => ERRNO_NOSYS;
    if (opts.strictAll && !(imp.module === 'aprv' && imp.name === 'clock_now_ms')) {
      // Strict mode: EVERY import except the clock traps when called.
      const k = key;
      impl = () => { throw new WebAssembly.RuntimeError(`import ${k} called`); };
    }
    (imports[imp.module] ||= {})[imp.name] = (...a) => { count(key); return impl(...a); };
  }
  return {
    imports,
    calls,
    stderr: () => stderr.map((b) => new TextDecoder().decode(b)).join(''),
    setMemory(m) { memory = m; },
  };
}

// Instantiates a core module with the minimal host and returns the
// driver's api. _initialize (a WASI reactor's constructors) runs first,
// then aprv_init (installs the host clock where the build has the seam).
export async function instantiateMinimal(module, opts = {}) {
  const host = minimalHost(module, opts);
  const instance = await WebAssembly.instantiate(module, host.imports);
  host.setMemory(instance.exports.memory);
  if (instance.exports._initialize) instance.exports._initialize();
  if (instance.exports.aprv_init) instance.exports.aprv_init();
  return {
    fn: (n) => instance.exports[n],
    buffer: () => instance.exports.memory.buffer,
    host,
  };
}
