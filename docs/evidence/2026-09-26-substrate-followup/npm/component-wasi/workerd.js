// workerd: jco asks for each core module by name; they are static imports.
// The OpenSSL component has four (the fourth is the WASI adapter's).
import core from './aprv.core.wasm';
import core2 from './aprv.core2.wasm';
import core3 from './aprv.core3.wasm';
import core4 from './aprv.core4.wasm';
import { instantiate } from './aprv.js';
import { makeComponentApi, VerificationError } from './facade.js';
const modules = { 'aprv.core.wasm': core, 'aprv.core2.wasm': core2, 'aprv.core3.wasm': core3, 'aprv.core4.wasm': core4 };
const api = await makeComponentApi(instantiate, (p) => modules[p]);
export const { verifyReceipt, verifyTransaction } = api;
export { VerificationError };
