/**
 * workerd (Cloudflare Workers): the core modules are static imports, which
 * workerd and wrangler turn into compiled `WebAssembly.Module`s at upload.
 * workerd refuses to compile Wasm from bytes at run time, so this is the
 * only way in there.
 */
import core from '../generated/aprv.core.wasm';
import core2 from '../generated/aprv.core2.wasm';
import core3 from '../generated/aprv.core3.wasm';

const compiled = new Map<string, WebAssembly.Module>([
  ['aprv.core.wasm', core],
  ['aprv.core2.wasm', core2],
  ['aprv.core3.wasm', core3],
]);

export function getCoreModule(name: string): WebAssembly.Module {
  const module = compiled.get(name);
  if (module === undefined) {
    throw new Error(`no core module named ${name} in this package`);
  }
  return module;
}
