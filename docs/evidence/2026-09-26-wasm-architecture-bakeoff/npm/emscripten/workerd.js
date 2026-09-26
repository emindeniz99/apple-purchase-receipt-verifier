// workerd: web-only glue (the node+web glue mistakes workerd for Node) and
// the precompiled module through Emscripten's Module.instantiateWasm hook.
import wasmModule from './aprv-em.wasm';
import createAprv from './aprv-em-web.mjs';
import { makeVerifierApi, VerificationError } from './abi.js';
const M = await createAprv({ instantiateWasm(imports, done) { const i = new WebAssembly.Instance(wasmModule, imports); done(i, wasmModule); return i.exports; } });
M._aprv_init?.();
export const { verifyReceipt, verifyTransaction } = makeVerifierApi(() => ({ fn: (n) => M['_' + n], buffer: () => M.HEAPU8.buffer }));
export { VerificationError };
