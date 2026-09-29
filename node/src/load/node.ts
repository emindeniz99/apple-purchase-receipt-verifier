/**
 * Node, Bun and Deno: the core modules are read from the package directory
 * and compiled synchronously, once per process, on first use. Deno needs
 * `--allow-read` for the read.
 */
import { readFileSync } from 'node:fs';
import { CORE_MODULES, type CoreModuleName } from './names.js';

const compiled = new Map<string, WebAssembly.Module>();

export function getCoreModule(name: string): WebAssembly.Module {
  if (!CORE_MODULES.includes(name as CoreModuleName)) {
    throw new Error(`no core module named ${name} in this package`);
  }
  let module = compiled.get(name);
  if (module === undefined) {
    module = new WebAssembly.Module(readFileSync(new URL(`../generated/${name}`, import.meta.url)));
    compiled.set(name, module);
  }
  return module;
}
