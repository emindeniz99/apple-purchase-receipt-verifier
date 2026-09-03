// Runner for Cloudflare workerd: fixtures arrive as embedded text/data
// modules declared in workerd.capnp (the `../fixtures/` names exist only
// there). Data modules are ArrayBuffers; the library takes Buffers, which
// nodejs_compat provides. `workerd test` invokes `test()`.
import { Buffer } from 'node:buffer';
import { run } from './smoke.mjs';
import appleRootDer from '../fixtures/AppleIncRootCertificate.cer';
import sandboxReceiptB64 from '../fixtures/receipt-sandbox-g5.b64';
import jwsRootDer from '../fixtures/jws-root.der';
import transactionJws from '../fixtures/transaction.jws';
import foreignReceiptDer from '../fixtures/receipt-foreign.der';

export default {
  async test() {
    const lines = run({
      appleRootDer: Buffer.from(appleRootDer),
      sandboxReceiptB64,
      jwsRootDer: Buffer.from(jwsRootDer),
      transactionJws,
      foreignReceiptDer: Buffer.from(foreignReceiptDer),
    });
    for (const l of lines) console.log(`ok - ${l}`);
  },
};
