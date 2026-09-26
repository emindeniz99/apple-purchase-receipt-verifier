import { ReceiptVerifier } from './pkg-deno/aprv_wasm.js';
const b64 = Deno.readTextFileSync('$REPO/fixtures/public-receipts/receipt-sandbox-g5.b64').replace(/\s/g, '');
console.log('deno target genuine g5', new ReceiptVerifier('dev.bonzer.weeka.app').verifyBase64(b64));
