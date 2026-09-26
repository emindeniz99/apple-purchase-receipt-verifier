// Cloudflare workerd: the .wasm must be a static module import (workerd
// refuses to compile wasm bytes at runtime).
import module from './aprv.wasm';
import { makeVerifierApi, VerificationError } from './abi.js';
import { instantiateCore } from './instantiate.js';
export const { verifyReceipt, verifyTransaction } = makeVerifierApi(() => instantiateCore(module));
export { VerificationError };
