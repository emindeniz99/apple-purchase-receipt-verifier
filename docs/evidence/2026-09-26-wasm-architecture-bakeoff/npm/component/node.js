import { readFileSync } from 'node:fs';
import { instantiate } from './aprv.js';
import { makeComponentApi, VerificationError } from './facade.js';
const api = await makeComponentApi(instantiate, (p) => new WebAssembly.Module(readFileSync(new URL('./' + p, import.meta.url))));
export const { verifyReceipt, verifyTransaction } = api;
export { VerificationError };
