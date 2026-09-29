// Spike only (ABI v1). VERIFY_RECEIPT takes the receipt-data string and
// decodes it inside the module. This runs every text of fixtures/cases.json's
// `base64` group (the decodeBase64 operation, receipt-data decoder) through
// VERIFY_RECEIPT and checks which side of the rule each text lands on:
//   expected ok     -> decoded, so the refusal (the bytes are no receipt)
//                      comes from the DER parser, not the base64 rule;
//   expected error  -> verified=false, INVALID_RECEIPT_FORMAT,
//                      "receipt-data is not valid base64".
// The receipt-base64 group runs with full verdicts in the corpus.
//   node js/base64-rule.mjs module.wasm $REPO/fixtures/cases.json
import { readFileSync } from 'node:fs';
import { instantiate, OP } from './abi.mjs';

const [modPath, casesPath] = process.argv.slice(2);
const inst = await instantiate(new WebAssembly.Module(readFileSync(modPath)));
const REFUSED = 'receipt-data is not valid base64';
const cases = JSON.parse(readFileSync(casesPath, 'utf8')).cases.filter((c) => c.operation === 'decodeBase64' && c.decoders.includes('receipt-data'));
let pass = 0, fail = 0, texts = 0;
for (const c of cases) {
  for (const t of c.input.texts) {
    texts++;
    const out = JSON.parse(new TextDecoder().decode(inst.call(OP.VERIFY_RECEIPT, new TextEncoder().encode(t))));
    const refused = out.verified === false && out.reason === 'INVALID_RECEIPT_FORMAT' && out.message === REFUSED;
    const good = c.expected.status === 'ok' ? out.verified === false && !refused : refused && c.expected.reason === 'INVALID_RECEIPT_FORMAT';
    if (good) pass++; else { fail++; console.log(`FAIL ${c.id} ${JSON.stringify(t).slice(0, 60)} -> ${JSON.stringify(out)}`); }
  }
}
console.log(`base64 rule through VERIFY_RECEIPT: ${cases.length} cases, ${texts} texts, ${pass} as expected, ${fail} not`);
process.exit(fail ? 1 : 0);
