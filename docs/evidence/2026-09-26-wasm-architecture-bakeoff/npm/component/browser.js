import { instantiate } from './aprv.js';
import { makeComponentApi, VerificationError } from './facade.js';
const api = await makeComponentApi(instantiate, (p) => WebAssembly.compileStreaming(fetch(new URL('./' + p, import.meta.url))));
export const { verifyReceipt, verifyTransaction } = api;
export { VerificationError };
