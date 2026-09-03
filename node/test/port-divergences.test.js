// The four places the four ports were found to disagree, pinned so this
// build cannot drift back. Every case runs against BOTH entry points, because
// a rule that holds on only one of them is exactly the drift being fixed.
//
//   1. The certificate-validity fallback clock is the SYSTEM clock, never an
//      injected one — including for a payload or receipt carrying no date.
//   2. The endpoint's environment is the typed enum, not a boolean.
//   3. verifyReceiptCore is public, and the endpoint uses it rather than a
//      wildcard-bundle-id ReceiptVerifier.
//   4. A receipt attribute TYPE above 2^31 - 1 is INVALID_RECEIPT_FORMAT.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as node from '../dist/index.js';
import * as web from '../dist/web/index.js';

const BUNDLE = 'com.example.app';

const repo = (rel) => readFileSync(fileURLToPath(new URL(`../../${rel}`, import.meta.url)));
const gen = (name) => repo(`fixtures/generated/${name}`);
const genText = (name) => gen(name).toString('ascii').trim();

const BUILDS = [['node', node], ['web', web]];

/** Awaits the web build's promises; the Node build returns values directly. */
async function outcome(run) {
  try {
    return { ok: await run() };
  } catch (error) {
    return {
      reason: error?.reason ?? `unexpected ${error?.name}: ${error?.message}`,
      message: error?.message ?? '',
    };
  }
}

// Clocks that would each move a verdict if any of them reached a
// certificate-validity decision: inside the expired chain's window, far
// past every window, and before every window.
const CLOCKS = [
  ['no clock', undefined],
  ['inside the expired window', () => new Date('2020-06-01T00:00:00Z')],
  ['centuries ahead', () => new Date('2999-01-01T00:00:00Z')],
  ['the epoch', () => new Date(0)],
];

// --- (1) the certificate-validity fallback clock -------------------------

/**
 * The same JWS with its `signedDate` claim deleted, so the verifier has no
 * signing date to anchor chain validity at and must fall back. Re-encoding
 * the payload segment breaks the signature, which is checked AFTER the
 * chain — so the fallback's answer is what surfaces.
 */
function withoutSignedDate(jws) {
  const [header, payload, signature] = jws.split('.');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  assert.equal(typeof claims.signedDate, 'number', 'fixture must carry a signedDate to delete');
  delete claims.signedDate;
  return `${header}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${signature}`;
}

/**
 * The same receipt with attribute 12 (creation date) renumbered to an
 * unmodelled type, in place: `02 01 0C` becomes `02 01 63`, so every DER
 * length stays valid and the verifier simply finds no creation date.
 */
function withoutCreationDate(der) {
  const attribute = Buffer.from([0x02, 0x01, 0x0c, 0x02, 0x01, 0x01, 0x04]);
  const at = der.indexOf(attribute);
  assert.ok(at >= 0, 'fixture must carry a creation-date attribute');
  assert.equal(der.indexOf(attribute, at + 1), -1, 'creation-date attribute must be unambiguous');
  const copy = Buffer.from(der);
  copy[at + 2] = 0x63;
  return copy;
}

for (const [name, build] of BUILDS) {
  const jwsVerifier = (root, clock) => new build.JwsVerifier({
    trustedRoots: [gen(root)], bundleId: BUNDLE,
    acceptedEnvironments: ['Sandbox'], clock,
  });

  test(`${name}: a dateless JWS anchors chain validity on the system clock`, async () => {
    // The expired chain is valid 2020-01-01..2021-01-01 only, so judging a
    // dateless payload at the real "now" rejects it. A clock set inside that
    // window would rescue it — and must not: a caller injecting a clock to
    // test staleness must never thereby accept an expired chain.
    for (const [label, clock] of CLOCKS) {
      const verdict = await outcome(() => jwsVerifier('jws-expired-root.der', clock)
        .verifyTransaction(withoutSignedDate(genText('expired-cert-historical.jws'))));
      assert.equal(verdict.reason, 'INVALID_CHAIN', label);
    }
  });

  test(`${name}: an injected clock cannot expire a dateless JWS either`, async () => {
    // The mirror image: this chain is valid 2024..2050, so at the real "now"
    // the dateless payload gets past the chain and dies at the signature
    // check. A clock outside 2024..2050 would turn that into INVALID_CHAIN.
    for (const [label, clock] of CLOCKS) {
      const verdict = await outcome(() => jwsVerifier('jws-root.der', clock)
        .verifyTransaction(withoutSignedDate(genText('transaction.jws'))));
      assert.equal(verdict.reason, 'INVALID_SIGNATURE', label);
    }
  });

  test(`${name}: a dateless receipt anchors chain validity on the system clock`, async () => {
    const expired = await outcome(() => build.verifyReceiptCore(
      asInput(build, withoutCreationDate(gen('receipt-expired-historical.der'))),
      [gen('receipt-expired-root.der')]));
    assert.equal(expired.reason, 'INVALID_CHAIN');
    // Same input shape against a chain that IS valid now: it reaches the
    // signature check, so the INVALID_CHAIN above is the clock's doing and
    // not something about a dateless receipt generally.
    const current = await outcome(() => build.verifyReceiptCore(
      asInput(build, withoutCreationDate(gen('receipt.der'))), [gen('receipt-root.der')]));
    assert.equal(current.reason, 'INVALID_SIGNATURE');
  });

  test(`${name}: the receipt verifier exposes no clock option at all`, async () => {
    // Structural, not behavioural: an ignored extra property proves nothing
    // in JavaScript, so the published type is what is asserted. The clock
    // seam belongs to the JWS verifier (max signed age) and the endpoint
    // (request_date) — nothing on the receipt path consumes one.
    const declaration = repo(name === 'node'
      ? 'node/dist/receipt.d.ts' : 'node/dist/web/receipt.d.ts').toString('utf8');
    const options = declaration.slice(declaration.indexOf('interface ReceiptVerifierOptions'));
    assert.ok(options.length > 0, 'ReceiptVerifierOptions must be declared');
    assert.doesNotMatch(options.slice(0, options.indexOf('}')), /clock/i);
    // verifyReceiptCore takes bytes and roots, and nothing else.
    assert.equal(build.verifyReceiptCore.length, 2);
    // And passing one anyway changes no verdict.
    const withClock = new build.ReceiptVerifier({
      trustedRoots: [gen('receipt-expired-root.der')], bundleId: BUNDLE,
      clock: () => new Date('2020-06-01T00:00:00Z'),
    });
    const verdict = await outcome(() => withClock.verify(
      asInput(build, gen('receipt-expired-fresh.der'))));
    assert.equal(verdict.reason, 'INVALID_CHAIN');
  });
}

/** The Node build documents Buffer input; the web build documents Uint8Array. */
function asInput(build, buffer) {
  return build === node ? buffer : new Uint8Array(buffer);
}

test('endpoint: no clock can make it accept a dateless receipt on an expired chain', () => {
  const dateless = withoutCreationDate(gen('receipt-expired-historical.der'))
    .toString('base64');
  const dated = gen('receipt-expired-historical.der').toString('base64');
  for (const [label, clock] of CLOCKS) {
    const endpoint = new node.VerifyReceiptEndpoint({
      trustedRoots: [gen('receipt-expired-root.der')], environment: 'Sandbox', clock,
    });
    // The dated receipt is judged at its own creation date and stays OK
    // under every clock; the dateless one falls back to the system clock,
    // which is outside the chain's window, and stays rejected under every
    // clock — including one aimed squarely inside that window.
    assert.equal(endpoint.verifyReceipt({ 'receipt-data': dated }).status, 0, label);
    assert.equal(endpoint.verifyReceipt({ 'receipt-data': dateless }).status, 21003, label);
  }
});

// --- (2) the endpoint's environment parameter ----------------------------

test('endpoint: environment is the typed enum, and nothing else is accepted', () => {
  const build = (environment) => new node.VerifyReceiptEndpoint({
    trustedRoots: [gen('receipt-root.der')], environment,
  });
  const request = { 'receipt-data': gen('receipt-type-production.der').toString('base64') };
  // cases.json's config.environment is this enum, spelled exactly this way.
  assert.equal(build('Production').verifyReceipt(request).environment, 'Production');
  assert.equal(build('Sandbox').verifyReceipt(request).status, 21008);
  // A boolean "production" flag is the other ports' old spelling; taking it
  // silently would make `false` (a common default) mean Production here.
  for (const wrong of [true, false, 'production', 'PRODUCTION', 1, null, undefined]) {
    assert.throws(() => build(wrong), TypeError, `environment: ${String(wrong)}`);
  }
});

// --- (3) verifyReceiptCore visibility ------------------------------------

test('verifyReceiptCore is public on both entry points and checks no bundle id', async () => {
  for (const [name, build] of BUILDS) {
    assert.equal(typeof build.verifyReceiptCore, 'function', name);
    const receipt = await build.verifyReceiptCore(
      asInput(build, gen('receipt.der')), [gen('receipt-root.der')]);
    // The bundle id is returned for the caller to check, not enforced —
    // which is why the endpoint needs no wildcard-bundle-id verifier.
    assert.equal(receipt.bundleId, BUNDLE, name);
  }
});

test('the endpoint accepts any bundle id without a wildcard verifier', () => {
  // Apple's endpoint does not check the bundle id, and neither does this
  // one. Two receipts carrying different bundle ids both verify against one
  // endpoint instance, which has no bundleId option to give it.
  const endpoint = new node.VerifyReceiptEndpoint({
    trustedRoots: node.appleReceiptRoots(), environment: 'Sandbox',
  });
  const bundles = { 'receipt-sandbox-g5': 'dev.bonzer.weeka.app',
    'receipt-sandbox-legacy': 'com.nutcall.alert' };
  for (const [fixture, bundleId] of Object.entries(bundles)) {
    const data = repo(`fixtures/public-receipts/${fixture}.b64`).toString('ascii').trim();
    const response = endpoint.verifyReceipt({ 'receipt-data': data });
    assert.equal(response.status, 0, fixture);
    assert.equal(response.receipt.bundle_id, bundleId);
  }
  assert.ok(!('bundleId' in new node.VerifyReceiptEndpoint({
    trustedRoots: node.appleReceiptRoots(), environment: 'Sandbox',
  })));
});

// --- (4) a receipt attribute type above 2^31 - 1 -------------------------

// A synthetic CMS SignedData whose encapsulated payload is the given bytes.
// The receipt payload is parsed before any certificate work, so nothing here
// needs to be signed or to carry certificates for the parse to be reached.
function tlv(tag, ...parts) {
  const contents = Buffer.concat(parts);
  const n = contents.length;
  const header = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
  return Buffer.concat([Buffer.from([tag, ...header]), contents]);
}

const SEQUENCE = 0x30;
const SET = 0x31;
const CONTEXT_0 = 0xa0;
const INTEGER = 0x02;
const OCTET_STRING = 0x04;
const OID = 0x06;

const OID_SIGNED_DATA = Buffer.from('2a864886f70d010702', 'hex');
const OID_DATA = Buffer.from('2a864886f70d010701', 'hex');
const OID_SHA256 = Buffer.from('608648016503040201', 'hex');

function cmsAround(payload) {
  const signerInfo = tlv(SEQUENCE,
    tlv(INTEGER, Buffer.from([1])),
    tlv(SEQUENCE, tlv(SEQUENCE), tlv(INTEGER, Buffer.from([1]))),
    tlv(SEQUENCE, tlv(OID, OID_SHA256)),
    tlv(SEQUENCE),
    tlv(OCTET_STRING));
  return tlv(SEQUENCE,
    tlv(OID, OID_SIGNED_DATA),
    tlv(CONTEXT_0, tlv(SEQUENCE,
      tlv(INTEGER, Buffer.from([1])),
      tlv(SET),
      tlv(SEQUENCE, tlv(OID, OID_DATA), tlv(CONTEXT_0, tlv(OCTET_STRING, payload))),
      tlv(CONTEXT_0),
      tlv(SET, signerInfo))));
}

/** A one-attribute receipt payload whose type INTEGER is `typeBytes`. */
const payloadWithType = (typeBytes) => tlv(SET, tlv(SEQUENCE,
  tlv(INTEGER, Buffer.from(typeBytes)), tlv(INTEGER, Buffer.from([1])), tlv(OCTET_STRING)));

// 2^31 - 1 is the largest type a port with an int-typed attribute field can
// hold. Above it the value is unrepresentable, and a port that maps it onto
// a sentinel (-1) and files it under unknownAttributes reports a different
// receipt than one that does not — so every port fails closed instead.
// Every case here is INVALID_RECEIPT_FORMAT — the synthetic CMS embeds no
// certificates, so a payload that parses dies on the next check instead. The
// message is what separates "rejected for its type" from "parsed, then
// rejected for something else", so that is what each case asserts.
const ATTRIBUTE_TYPES = [
  ['2^31 - 1', [0x7f, 0xff, 0xff, 0xff], /signer certificate not embedded/],
  ['2^31', [0x00, 0x80, 0x00, 0x00, 0x00], /2147483648 exceeds the 32-bit signed range/],
  ['2^32', [0x01, 0x00, 0x00, 0x00, 0x00], /4294967296 exceeds the 32-bit signed range/],
  ['2^53 - 1', [0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], /exceeds the 32-bit signed range/],
];

for (const [name, build] of BUILDS) {
  for (const [label, typeBytes, message] of ATTRIBUTE_TYPES) {
    test(`${name}: attribute type ${label}`, async () => {
      const der = asInput(build, cmsAround(payloadWithType(typeBytes)));
      const verdict = await outcome(() => build.verifyReceiptCore(der, [gen('receipt-root.der')]));
      assert.equal(verdict.reason, 'INVALID_RECEIPT_FORMAT', label);
      assert.match(verdict.message, message, label);
    });
  }
}

test('both builds reject an oversized attribute type with the same message', async () => {
  const der = cmsAround(payloadWithType([0x00, 0x80, 0x00, 0x00, 0x00]));
  const message = async (build) => {
    try {
      await build.verifyReceiptCore(asInput(build, der), [gen('receipt-root.der')]);
      return null;
    } catch (error) {
      return error.message;
    }
  };
  const fromNode = await message(node);
  assert.match(fromNode, /2147483648 exceeds the 32-bit signed range/);
  assert.equal(await message(web), fromNode);
});
