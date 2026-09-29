// Types for the imports the build resolves outside TypeScript's own
// resolution: package.json "imports" picks a loader per runtime, and the
// static loaders import compiled core modules.
declare module '#aprv-load' {
  export function getCoreModule(name: string): WebAssembly.Module;
}

declare module '*.wasm' {
  const module: WebAssembly.Module;
  export default module;
}

declare module '*.wasm?module' {
  const module: WebAssembly.Module;
  export default module;
}
