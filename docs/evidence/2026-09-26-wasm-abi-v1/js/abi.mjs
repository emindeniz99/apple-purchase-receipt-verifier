// Spike only (ABI v1). The JS bridge: instantiate with exactly the two
// imports, then the lifecycle every bridge follows:
//   alloc -> copy input -> aprv_call -> bounds-check ptr/len -> COPY result
//   -> aprv_result_free -> dealloc input -> (caller) decode.
// No guest pointer leaves call(). A trap throws; the caller discards the
// instance (the bridge runs nothing more in it, not even the dealloc).
// Pure ECMAScript apart from the Node-only runners that import it.
export const ABI_VERSION = 1;
export const OP = { VERIFY_RECEIPT: 1, VERIFY_SIGNED_DATA: 2, ENDPOINT_PRODUCTION: 3, ENDPOINT_SANDBOX: 4 };

function fillRandom(memory, ptr, len) {
  for (let off = 0; off < len; off += 65536) {
    crypto.getRandomValues(new Uint8Array(memory.buffer, ptr + off, Math.min(65536, len - off)));
  }
}

export class AbiError extends Error {}

export async function instantiate(module, opts = {}) {
  const calls = { 'aprv.clock_now_ms': 0, 'aprv.random_get': 0 };
  let memory = null;
  const now = opts.now || (() => Date.now());
  const imports = {
    aprv: {
      clock_now_ms: () => { calls['aprv.clock_now_ms']++; return now(); },
      random_get: (p, l) => {
        calls['aprv.random_get']++;
        if (p < 0 || l < 0 || p + l > memory.buffer.byteLength) throw new WebAssembly.RuntimeError('aprv.random_get out of bounds');
        fillRandom(memory, p, l); return 0;
      },
    },
  };
  for (const imp of WebAssembly.Module.imports(module)) {
    if (!(imp.module === 'aprv' && (imp.name === 'clock_now_ms' || imp.name === 'random_get'))) {
      throw new AbiError(`unexpected import ${imp.module}.${imp.name}`);
    }
  }
  const instance = await WebAssembly.instantiate(module, imports);
  memory = instance.exports.memory;
  const x = instance.exports;
  x._initialize();
  const moduleVersion = x.aprv_abi_version();
  if (moduleVersion !== ABI_VERSION) throw new AbiError(`APRV Wasm ABI mismatch: module=${moduleVersion}, caller=${ABI_VERSION}`);
  return {
    calls, exports: x, memory,
    // The whole lifecycle; returns a fresh Uint8Array owned by the host.
    call(operation, input, abiVersion = ABI_VERSION) {
      const len = input.length;
      const inPtr = x.aprv_alloc(len);
      if (inPtr === 0) throw new AbiError(`aprv_alloc(${len}) failed`);
      // After a trap the instance is discarded, so nothing more runs in it.
      let done = false;
      try {
        new Uint8Array(memory.buffer, inPtr, len).set(input);
        let h;
        try {
          h = x.aprv_call(abiVersion, operation, inPtr, len);
        } catch (e) {
          if (abiVersion !== moduleVersion) throw new AbiError(`APRV Wasm ABI mismatch: module=${moduleVersion}, caller=${abiVersion}`);
          throw e;
        }
        const p = x.aprv_result_ptr(h) >>> 0;
        const n = x.aprv_result_len(h) >>> 0;
        if (p + n > memory.buffer.byteLength) throw new AbiError('result out of bounds');
        const out = new Uint8Array(memory.buffer, p, n).slice();
        x.aprv_result_free(h);
        done = true;
        return out;
      } finally {
        if (done) x.aprv_dealloc(inPtr, len);
      }
    },
  };
}
