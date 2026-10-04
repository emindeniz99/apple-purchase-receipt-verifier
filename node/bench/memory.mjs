// Peak memory of one verification of a hostile receipt: the payload of
// docs/evidence/2026-09-26-openssl-asn1-payload/py/memory.py ("flat-max",
// a SET of 12-byte attributes of an unmodelled type) wrapped in a CMS
// SignedData with no certificate, as that note's memory_cms.py does, and
// sized so the endpoint's whole request body, `{"receipt-data":"..."}`, is
// within the 3,145,728-byte cap (the receipt's base64 is at least 19 bytes
// under it). The module reads the whole attribute SET for the creation
// date before it finds no signer, so the payload is decoded in full and the
// receipt is then refused.
//
//   npm run build && node bench/memory.mjs
//
// Each row is a fresh Node process that creates one Verifier and makes one
// call; peak RSS is that process's maxRSS. `tiny` (one attribute) is the
// baseline: the runtime, the compiled module and one instance.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const CAP = 3_145_728; // the receipt and request body cap, in bytes
const MAX_DER = Math.floor((CAP - '{"receipt-data":""}'.length) / 4) * 3;

function length(n) {
  if (n < 0x80) {
    return [n];
  }
  const raw = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) {
    raw.unshift(v % 256);
  }
  return [0x80 | raw.length, ...raw];
}

const tlv = (tag, body) => Buffer.concat([Buffer.from([tag, ...length(body.length)]), body]);
const hex = (h) => Buffer.from(h, 'hex');
const ATTR = hex('300a0202270f020101040100'); // SEQUENCE { INTEGER 9999, INTEGER 1, OCTET STRING 00 }
const SHA256 = tlv(0x30, hex('06096086480165030402010500'));
const RSA = tlv(0x30, hex('06092a864886f70d0101010500'));

function cms(payload) {
  const signer = tlv(
    0x30,
    Buffer.concat([
      tlv(0x02, hex('01')),
      tlv(0x30, Buffer.concat([tlv(0x30, Buffer.alloc(0)), tlv(0x02, hex('01'))])),
      SHA256,
      RSA,
      tlv(0x04, hex('00')),
    ]),
  );
  const signed = tlv(
    0x30,
    Buffer.concat([
      tlv(0x02, hex('01')),
      tlv(0x31, SHA256),
      tlv(0x30, Buffer.concat([hex('06092a864886f70d010701'), tlv(0xa0, tlv(0x04, payload))])),
      tlv(0x31, signer),
    ]),
  );
  return tlv(0x30, Buffer.concat([hex('06092a864886f70d010702'), tlv(0xa0, signed)]));
}

const receipt = (count) => cms(tlv(0x31, Buffer.concat(Array(count).fill(ATTR))));

/** The most attributes whose receipt, in a request body, fits the cap. */
function flatMax() {
  let lo = 1;
  let hi = Math.floor(MAX_DER / ATTR.length);
  while (lo < hi) {
    const mid = Math.floor((lo + hi + 1) / 2);
    if (receipt(mid).length <= MAX_DER) {
      lo = mid;
    } else {
      hi = mid - 1;
    }
  }
  return receipt(lo);
}

/** The receipts, as base64: the text an app sends and the ABI takes. */
export function hostileReceipts() {
  return { tiny: receipt(1).toString('base64'), 'flat-max': flatMax().toString('base64') };
}

async function child(name, via) {
  const { createVerifier, createConfig, Environment } = await import('../dist/index.js');
  const base64 = hostileReceipts()[name];
  const verifier = createVerifier(createConfig());
  const answer =
    via === 'endpoint'
      ? JSON.parse(
          verifier.verifyReceiptEndpoint(
            Environment.PRODUCTION,
            JSON.stringify({ 'receipt-data': base64 }),
          ),
        ).status
      : verifier.verifyReceipt(base64).failure?.reason;
  const row = {
    receipt: name,
    base64Bytes: base64.length,
    via,
    answer,
    peakRssMiB: Math.round(process.resourceUsage().maxRSS / 1024),
  };
  process.stdout.write(`${JSON.stringify(row)}\n`);
}

if (process.argv[2] === '--child') {
  await child(process.argv[3], process.argv[4]);
} else if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log(`# node ${process.version}, one fresh process per row`);
  for (const name of ['tiny', 'flat-max']) {
    for (const via of ['verifyReceipt', 'endpoint']) {
      const { stdout, status } = spawnSync(
        process.execPath,
        [fileURLToPath(import.meta.url), '--child', name, via],
        { encoding: 'utf8' },
      );
      if (status !== 0) {
        throw new Error(`${name} ${via}: child exited ${status}`);
      }
      process.stdout.write(stdout);
    }
  }
}
