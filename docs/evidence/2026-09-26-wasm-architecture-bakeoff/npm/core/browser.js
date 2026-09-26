// Browsers and other fetch-capable hosts: streaming compile at import time.
import { makeVerifierApi, VerificationError } from './abi.js';
import { instantiateCore } from './instantiate.js';
const module = await WebAssembly.compileStreaming(fetch(new URL('./aprv.wasm', import.meta.url)));
export const { verifyReceipt, verifyTransaction } = makeVerifierApi(() => instantiateCore(module));
export { VerificationError };
