/**
 * Vercel Edge (the `edge-light` condition): as static.ts, spelled with the
 * `?module` suffix Vercel's bundler uses for a compiled `WebAssembly.Module`
 * import.
 */
import core from '../generated/aprv.core.wasm?module';
import core2 from '../generated/aprv.core2.wasm?module';
import core3 from '../generated/aprv.core3.wasm?module';

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
