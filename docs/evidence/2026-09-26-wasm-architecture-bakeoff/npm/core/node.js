// Node, Bun, Deno: the .wasm is read from the package directory once.
import { readFileSync } from 'node:fs';
import { makeVerifierApi, VerificationError } from './abi.js';
import { instantiateCore } from './instantiate.js';
const module = new WebAssembly.Module(readFileSync(new URL('./aprv.wasm', import.meta.url)));
export const { verifyReceipt, verifyTransaction } = makeVerifierApi(() => instantiateCore(module));
export { VerificationError };
