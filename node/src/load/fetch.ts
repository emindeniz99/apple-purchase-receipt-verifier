/**
 * Browsers and other runtimes with `fetch` and `import.meta.url`: the core
 * modules are fetched from next to this file and compiled asynchronously
 * while the package loads (top-level `await`), so every call after that is
 * synchronous.
 */
import { CORE_MODULES } from './names.js';

async function compile(name: string): Promise<[string, WebAssembly.Module]> {
  const response = await fetch(new URL(`../generated/${name}`, import.meta.url));
  if (!response.ok) {
    throw new Error(`could not load ${name}: HTTP ${response.status}`);
  }
  return [name, await WebAssembly.compile(await response.arrayBuffer())];
}

const compiled = new Map(await Promise.all(CORE_MODULES.map(compile)));

export function getCoreModule(name: string): WebAssembly.Module {
  const module = compiled.get(name);
  if (module === undefined) {
    throw new Error(`no core module named ${name} in this package`);
  }
  return module;
}
