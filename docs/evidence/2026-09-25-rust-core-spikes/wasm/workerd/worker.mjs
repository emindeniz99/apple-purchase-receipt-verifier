import { initSync, ReceiptVerifier, JwsVerifier } from './aprv_wasm.js';
import wasmModule from './aprv_wasm_bg.wasm';
import g5 from './receipt-sandbox-g5.b64';
import jwsRoot from './jws-root.der';
import jws from './transaction.jws';

export default {
  async test() {
    // 1. dynamic compile from bytes: expected to be refused by workerd
    try {
      await WebAssembly.compile(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
      console.log('dynamic WebAssembly.compile: ALLOWED');
    } catch (e) { console.log('dynamic WebAssembly.compile: REFUSED -', e.message); }
    // 2. statically imported module: the path the npm package must use on workerd
    initSync({ module: wasmModule });
    const r = new ReceiptVerifier('dev.bonzer.weeka.app').verifyBase64(g5.replace(/\s/g, ''));
    console.log('workerd genuine g5', r);
    const p = new JwsVerifier('com.example.app', ['Sandbox'], [new Uint8Array(jwsRoot)]).verifyTransaction(jws.trim());
    console.log('workerd jws', p.slice(0, 50));
    try { new ReceiptVerifier('com.other.app').verifyBase64(g5.replace(/\s/g, '')); } catch (e) { console.log('workerd error', e.reason); }
  },
};
