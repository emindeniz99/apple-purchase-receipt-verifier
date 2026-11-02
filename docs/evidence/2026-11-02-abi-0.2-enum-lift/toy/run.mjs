// Calls verify-receipt-endpoint by hand (the canonical ABI, as wazero,
// WasmKit, Endive, wasmtime-py, the gem and .NET do) with env 0..2, 255,
// 2^32-1, and reports value or trap. WASI imports throw, naming themselves.
import { readFileSync } from 'node:fs';
const file = process.argv[2];
const mod = new WebAssembly.Module(readFileSync(file));
const imports = {};
for (const imp of WebAssembly.Module.imports(mod)) {
  imports[imp.module] ??= {};
  imports[imp.module][imp.name] = () => { throw new Error(`import ${imp.module}.${imp.name} called`); };
}
console.log('imports:', WebAssembly.Module.imports(mod).map((i) => `${i.module}.${i.name}`).join(' ') || 'none');
const IFACE = 'aprv:verifier/verify@0.2.0#';
for (const env of [0, 1, 2, 255, 0xffffffff]) {
  const inst = new WebAssembly.Instance(mod, imports);
  const x = inst.exports;
  if (x._initialize) x._initialize();
  const mem = () => new Uint8Array(x.memory.buffer);
  const body = new TextEncoder().encode('{}');
  const p = x.cabi_realloc(0, 0, 1, body.length);
  mem().set(body, p);
  try {
    const ret = x[IFACE + 'verify-receipt-endpoint'](env | 0, -5n, p, body.length) >>> 0;
    const dv = new DataView(x.memory.buffer);
    const ptr = dv.getUint32(ret, true), len = dv.getUint32(ret + 4, true);
    console.log(`env ${env}: value ${JSON.stringify(new TextDecoder().decode(mem().slice(ptr, ptr + len)))}`);
  } catch (e) {
    console.log(`env ${env}: ${e.constructor.name}: ${e.message}`);
  }
}
