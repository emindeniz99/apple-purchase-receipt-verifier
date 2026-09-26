// workerd: jco asks for each core module by name; they are static imports.
import core from './aprv.core.wasm';
import core2 from './aprv.core2.wasm';
import core3 from './aprv.core3.wasm';
import { instantiate } from './aprv.js';
import { makeComponentApi, VerificationError } from './facade.js';
const modules = { 'aprv.core.wasm': core, 'aprv.core2.wasm': core2, 'aprv.core3.wasm': core3 };
const api = await makeComponentApi(instantiate, (p) => modules[p]);
export const { verifyReceipt, verifyTransaction } = api;
export { VerificationError };
