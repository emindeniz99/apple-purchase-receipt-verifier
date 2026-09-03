// Runner for Cloudflare workerd with NO compatibility flags at all: no
// nodejs_compat, so no node:crypto, no node:buffer, no global Buffer.
// Fixtures arrive as embedded text/data modules declared in
// web-workerd.capnp (the `../fixtures/` names exist only there); data
// modules are ArrayBuffers. `workerd test` invokes `test()`.
import { run } from './web-smoke.mjs';
import appleRootDer from '../fixtures/AppleIncRootCertificate.cer';
import sandboxReceiptB64 from '../fixtures/receipt-sandbox-g5.b64';
import legacyReceiptB64 from '../fixtures/receipt-sandbox-legacy.b64';
import jwsRootDer from '../fixtures/jws-root.der';
import transactionJws from '../fixtures/transaction.jws';
import foreignReceiptDer from '../fixtures/receipt-foreign.der';

export default {
  async test() {
    if (typeof Buffer !== 'undefined' || typeof process !== 'undefined') {
      throw new Error('this worker is meant to run without nodejs_compat');
    }
    const lines = await run({
      appleRootDer: new Uint8Array(appleRootDer),
      sandboxReceiptB64,
      legacyReceiptB64,
      jwsRootDer: new Uint8Array(jwsRootDer),
      transactionJws,
      foreignReceiptDer: new Uint8Array(foreignReceiptDer),
    });
    for (const line of lines) {
      console.log(`ok - ${line}`);
    }
  },
};
