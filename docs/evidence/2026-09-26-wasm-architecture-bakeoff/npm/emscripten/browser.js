// Browsers: web-only glue; it fetches aprv-em.wasm next to itself.
import createAprv from './aprv-em-web.mjs';
import { makeVerifierApi, VerificationError } from './abi.js';
const M = await createAprv();
M._aprv_init?.();
export const { verifyReceipt, verifyTransaction } = makeVerifierApi(() => ({ fn: (n) => M['_' + n], buffer: () => M.HEAPU8.buffer }));
export { VerificationError };
