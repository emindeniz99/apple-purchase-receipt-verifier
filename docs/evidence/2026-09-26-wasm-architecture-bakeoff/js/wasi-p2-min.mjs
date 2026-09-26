// Spike only. The WHOLE WASI 0.2 host the OpenSSL component needs
// (component/ built through the wasi_snapshot_preview1 reactor adapter,
// with c/wasi-none.c -DAPRV_KEEP_WASI_RANDOM_CLOCK): six interfaces, and of
// them only clocks and random carry data. Not a WASI runtime: no
// filesystem, sockets, environment or arguments exist to be asked for.
// Pure ECMAScript, so the same file serves Node, Bun, Deno, browsers and
// workerd. The official alternative is @bytecodealliance/preview2-shim.
export function wasiP2Min(calls = {}) {
  const c = (k) => { calls[k] = (calls[k] || 0) + 1; };
  class IoError { toDebugString() { return 'error'; } }
  // stderr: the adapter's own diagnostics (a panic message) are dropped.
  class OutputStream {
    blockingWriteAndFlush() { c('wasi:io/streams.blocking-write-and-flush'); }
    checkWrite() { return 4096n; }
    write() {}
    blockingFlush() {}
  }
  return {
    'wasi:io/error': { Error: IoError },
    'wasi:io/streams': { OutputStream },
    'wasi:cli/stderr': { getStderr: () => { c('wasi:cli/stderr.get-stderr'); return new OutputStream(); } },
    'wasi:clocks/monotonic-clock': {
      now: () => { c('wasi:clocks/monotonic-clock.now'); return BigInt(Math.round(performance.now() * 1e6)); },
      resolution: () => 1000n,
    },
    'wasi:clocks/wall-clock': {
      now: () => {
        c('wasi:clocks/wall-clock.now');
        const ms = Date.now();
        return { seconds: BigInt(Math.floor(ms / 1000)), nanoseconds: (ms % 1000) * 1e6 };
      },
      resolution: () => ({ seconds: 0n, nanoseconds: 1e6 }),
    },
    'wasi:random/random': {
      getRandomBytes(len) {
        c('wasi:random/random.get-random-bytes');
        const out = new Uint8Array(Number(len));
        for (let off = 0; off < out.length; off += 65536) crypto.getRandomValues(out.subarray(off, off + 65536));
        return out;
      },
      getRandomU64() {
        c('wasi:random/random.get-random-u64');
        const b = new BigUint64Array(1);
        crypto.getRandomValues(b);
        return b[0];
      },
    },
  };
}
