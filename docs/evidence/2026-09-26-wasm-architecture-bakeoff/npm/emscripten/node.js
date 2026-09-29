// Node, Bun, Deno: Emscripten's node+web glue; it reads aprv-em.wasm itself.
import createAprv from './aprv-em-node.mjs';
import { makeVerifierApi, VerificationError } from './abi.js';
const M = await createAprv();
M._aprv_init?.();
let first = true;
export const { verifyReceipt, verifyTransaction } = makeVerifierApi(() => {
  if (!first) throw new Error('trap recovery for Emscripten needs a fresh factory call (not wired in this spike)');
  first = false;
  return { fn: (n) => M['_' + n], buffer: () => M.HEAPU8.buffer };
});
export { VerificationError };
