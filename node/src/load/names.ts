/**
 * The core modules jco's `--name aprv` transpile writes for aprv.wasm's
 * component: the module itself and two small shims for its one import.
 * scripts/build.mjs fails if a transpile writes any other set.
 */
export const CORE_MODULES = ['aprv.core.wasm', 'aprv.core2.wasm', 'aprv.core3.wasm'] as const;

export type CoreModuleName = (typeof CORE_MODULES)[number];
