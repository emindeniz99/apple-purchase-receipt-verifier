// Runner for Cloudflare workerd: fixtures arrive as embedded text and data
// modules declared in workerd.capnp (the `fixtures/` names exist only
// there). `workerd test` invokes `test()`.
import { run } from './smoke.mjs';
import * as main from '../dist/index.js';
import * as web from '../dist/web/index.js';
import sandboxReceiptB64 from '../fixtures/receipt-sandbox-g5.b64';
import jwsRootDer from '../fixtures/jws-root.der';
import transactionJws from '../fixtures/transaction.jws';

export default {
  async test() {
    const fx = { sandboxReceiptB64, jwsRootDer: new Uint8Array(jwsRootDer), transactionJws };
    for (const [name, api] of [
      ['.', main],
      ['./web', web],
    ]) {
      // oxlint-disable-next-line no-await-in-loop -- one entry point after the other
      for (const line of await run(api, fx)) {
        console.log(`${line.startsWith('SKIP') ? '#' : 'ok -'} ${name}: ${line}`);
      }
    }
  },
};
