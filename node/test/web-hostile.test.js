// Adversarial parity: mutations of a genuine receipt and of the shared
// fixtures, fed to both builds. Two properties are asserted on every input —
// nothing but a VerificationError escapes the web build, and its reason and
// message are the Node build's. A divergence here is a verifier that says
// "valid" where its twin says "forged".
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Tag, parse } from '../dist/der.js';
import * as node from '../dist/index.js';
import * as web from '../dist/web/index.js';

const read = (rel) => readFileSync(fileURLToPath(new URL(`../../${rel}`, import.meta.url)));

const GENUINE = Buffer.from(
  read('fixtures/public-receipts/receipt-sandbox-g5.b64').toString('ascii').trim(),
  'base64',
);
const SHARED = read('fixtures/generated/receipt.der');
const SHARED_ROOT = read('fixtures/generated/receipt-root.der');
const LEGACY = Buffer.from(
  read('fixtures/public-receipts/receipt-sandbox-legacy.b64').toString('ascii').trim(),
  'base64',
);

function* mutations(label, receipt, step) {
  for (let cut = 1; cut < receipt.length; cut += 64) {
    yield [`${label} truncated to ${cut} bytes`, receipt.subarray(0, cut)];
  }
  for (let at = 0; at < receipt.length; at += step) {
    const flipped = Buffer.from(receipt);
    flipped[at] ^= 0xff;
    yield [`${label} byte ${at} flipped`, flipped];
  }
}

function* hostileCorpus() {
  yield ['empty', Buffer.alloc(0)];
  yield ['four bytes', Buffer.from([1, 2, 3, 4])];
  yield ['bare indefinite length', Buffer.from([0x30, 0x80])];
  yield ['deep nesting', Buffer.from(Array.from({ length: 200 }, () => 0x30).concat([0x00]))];
  yield* mutations('genuine sandbox receipt', GENUINE, 97);
  yield* mutations('shared receipt fixture', SHARED, 97);
  // The 79 KB legacy receipt is sampled coarsely: it is here for its SHA-1
  // chain, and a 97-byte stride over it would be 800 more RSA checks.
  yield* mutations('genuine legacy receipt', LEGACY, 997);
}

async function reasonOf(run) {
  try {
    await run();
    return { ok: true };
  } catch (error) {
    return { name: error?.constructor?.name, reason: error?.reason, message: error?.message };
  }
}

/**
 * The one tolerated disagreement, and the only one measured: a certificate
 * corrupted somewhere the two parsers look at differently. OpenSSL decodes
 * the whole X.509 template at parse time, so the Node build reports
 * INVALID_RECEIPT_FORMAT; the repo's DER reader only decodes the fields
 * verification needs, so the same bytes parse and the chain walk rejects
 * them as INVALID_CHAIN. It runs both ways (the web build's
 * signatureAlgorithm agreement check is stricter than OpenSSL's parse), and
 * neither build ever accepts such a receipt. The count is asserted so a new
 * class of divergence, or a growing one, fails this test.
 */
const CORRUPT_CERTIFICATE_REASONS = new Set(['INVALID_RECEIPT_FORMAT', 'INVALID_CHAIN']);
const MAX_TOLERATED_DIVERGENCES = 5;

test('web and Node builds agree over a corpus of mutated receipts', async () => {
  const nodeVerifier = new node.ReceiptVerifier({
    trustedRoots: [...node.appleReceiptRoots(), SHARED_ROOT],
    bundleId: '*',
  });
  const webVerifier = new web.ReceiptVerifier({
    trustedRoots: [...web.appleReceiptRoots(), new Uint8Array(SHARED_ROOT)],
    bundleId: '*',
  });
  let checked = 0;
  const divergences = [];
  // oxlint-disable no-await-in-loop -- hostileCorpus() yields 1000+ mutations
  // (see the `checked > 1000` assertion below); Promise.all-ing every verify
  // would fire that many RSA/EC checks at once instead of the bounded,
  // sequential run this is meant to be.
  for (const [what, input] of hostileCorpus()) {
    const fromWeb = await reasonOf(() => webVerifier.verify(new Uint8Array(input)));
    const fromNode = await reasonOf(() => nodeVerifier.verify(Buffer.from(input)));
    // Neither build may accept a mutated receipt, whatever else they say.
    assert.ok(
      fromWeb.ok === undefined && fromNode.ok === undefined,
      `${what} was accepted (web ${fromWeb.ok}, node ${fromNode.ok})`,
    );
    assert.equal(
      fromWeb.name,
      'VerificationError',
      `${what} escaped the web build as ${fromWeb.name}: ${fromWeb.message}`,
    );
    assert.equal(
      fromNode.name,
      'VerificationError',
      `${what} escaped the Node build as ${fromNode.name}: ${fromNode.message}`,
    );
    if (fromWeb.reason !== fromNode.reason || fromWeb.message !== fromNode.message) {
      assert.ok(
        CORRUPT_CERTIFICATE_REASONS.has(fromWeb.reason) &&
          CORRUPT_CERTIFICATE_REASONS.has(fromNode.reason),
        `${what}: node ${fromNode.reason} vs web ${fromWeb.reason}`,
      );
      divergences.push(`${what}: node ${fromNode.reason} vs web ${fromWeb.reason}`);
    }
    checked += 1;
  }
  // oxlint-enable no-await-in-loop
  // The corpus is generated, so a bug that emptied it would otherwise pass.
  assert.ok(checked > 1000, `only ${checked} inputs`);
  assert.ok(
    divergences.length <= MAX_TOLERATED_DIVERGENCES,
    `${divergences.length} divergent verdicts:\n${divergences.join('\n')}`,
  );
});

// --- the embedded-certificate bound ---------------------------------------

function tlv(tag, ...parts) {
  const contents = Buffer.concat(parts);
  const n = contents.length;
  const length =
    n < 0x80
      ? [n]
      : n < 0x100
        ? [0x81, n]
        : n < 0x10000
          ? [0x82, n >> 8, n & 0xff]
          : [0x83, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
  return Buffer.concat([Buffer.from([tag, ...length]), contents]);
}

const OID_SIGNED_DATA = Buffer.from('2a864886f70d010702', 'hex');
const OID_DATA = Buffer.from('2a864886f70d010701', 'hex');

/** The genuine receipt's SignedData children, read with the library's reader. */
const donorSignedData = parse(GENUINE).children[1].children[0].children;
const donorCertificates = donorSignedData
  .slice(3, donorSignedData.length - 1)
  .find((n) => n.tag === Tag.CONTEXT_0).children;
const donorSignerInfos = donorSignedData[donorSignedData.length - 1];

const UNPARSEABLE_CERTIFICATE = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]);

/**
 * A SignedData carrying `count` certificates: copies of the genuine leaf,
 * with the last one unparseable, so reaching the end of the list shows as a
 * parse error and stopping at the count guard shows as INVALID_CHAIN.
 */
function receiptWithCertificates(count) {
  const certificates = Buffer.concat([
    ...Array.from({ length: count - 1 }, () => Buffer.from(donorCertificates[0].raw)),
    UNPARSEABLE_CERTIFICATE,
  ]);
  return tlv(
    Tag.SEQUENCE,
    tlv(Tag.OID, OID_SIGNED_DATA),
    tlv(
      Tag.CONTEXT_0,
      tlv(
        Tag.SEQUENCE,
        tlv(Tag.INTEGER, Buffer.from([1])),
        tlv(Tag.SET),
        tlv(
          Tag.SEQUENCE,
          tlv(Tag.OID, OID_DATA),
          tlv(Tag.CONTEXT_0, tlv(Tag.OCTET_STRING, tlv(Tag.SET))),
        ),
        tlv(Tag.CONTEXT_0, certificates),
        Buffer.from(donorSignerInfos.raw),
      ),
    ),
  );
}

test('the web build enforces the same embedded-certificate bound', async () => {
  const nodeVerifier = new node.ReceiptVerifier({
    trustedRoots: node.appleReceiptRoots(),
    bundleId: '*',
  });
  const webVerifier = new web.ReceiptVerifier({
    trustedRoots: web.appleReceiptRoots(),
    bundleId: '*',
  });
  // 64 is above any bound that could still admit a genuine 3-certificate
  // chain, so the rejection fires wherever the bound is set; the message
  // names it, and both builds must name the same number.
  const flood = receiptWithCertificates(64);
  const fromWeb = await reasonOf(() => webVerifier.verify(new Uint8Array(flood)));
  const fromNode = await reasonOf(() => nodeVerifier.verify(flood));
  assert.equal(fromWeb.reason, 'INVALID_CHAIN');
  assert.match(fromWeb.message, /more than (\d+) certificates/);
  assert.equal(fromWeb.message, fromNode.message);

  // One below the bound is examined rather than refused by the count guard.
  const bound = Number(/more than (\d+) certificates/.exec(fromWeb.message)[1]);
  const examined = await reasonOf(() =>
    webVerifier.verify(new Uint8Array(receiptWithCertificates(bound))),
  );
  assert.equal(examined.reason, 'INVALID_RECEIPT_FORMAT', examined.message);
});
