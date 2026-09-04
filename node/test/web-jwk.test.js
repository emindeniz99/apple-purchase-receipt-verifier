// The SPKI → JWK conversion the web build now depends on, pinned at its own
// level. A conversion that is subtly wrong — a sign byte left on the RSA
// modulus, X and Y split at the wrong offset — does not throw. It produces a
// key that imports fine and then verifies nothing, and the only symptom is an
// INVALID_CHAIN raised somewhere far away from the cause. So each key is
// checked three ways: against the JWK a runtime that DOES implement "spki"
// derives from the same bytes, by importing as "jwk" and verifying a real
// signature through the web build, and by confirming the Node build accepts
// that same signature.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate, webcrypto } from 'node:crypto';
import { parseCertificate } from '../dist/x509.js';
import { spkiToJwk } from '../dist/web/jwk.js';
import { verifyCertificateSignature } from '../dist/web/crypto.js';

const read = (rel) => new Uint8Array(readFileSync(fileURLToPath(new URL(rel, import.meta.url))));
const generatedDir = new URL('../../fixtures/generated/', import.meta.url);

/**
 * Both root sets: the three Apple production roots this package bundles, and
 * every root of the generated fixture PKI. Roots are self-signed, so each one
 * carries a signature its own key must check out against.
 */
const CERTIFICATES = [
  ...['AppleIncRootCertificate.cer', 'AppleRootCA-G2.cer', 'AppleRootCA-G3.cer'].map((name) => ({
    name: `certs/${name}`,
    der: read(`../certs/${name}`),
  })),
  ...readdirSync(fileURLToPath(generatedDir))
    .filter((name) => name.endsWith('-root.der'))
    .toSorted()
    .map((name) => ({
      name: `fixtures/generated/${name}`,
      der: new Uint8Array(readFileSync(fileURLToPath(new URL(name, generatedDir)))),
    })),
];

test('the fixture set covers both key types and is not empty by accident', () => {
  const kinds = new Set(CERTIFICATES.map(({ der }) => spkiToJwk(parseCertificate(der).spki).kty));
  assert.deepEqual([...kinds].toSorted(), ['EC', 'RSA']);
  assert.ok(CERTIFICATES.length >= 8, `only ${CERTIFICATES.length} certificates found`);
});

/** The import parameters the key's own JWK asks for; hash is irrelevant to export. */
function importParams(jwk) {
  return jwk.kty === 'RSA'
    ? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
    : { name: 'ECDSA', namedCurve: jwk.crv };
}

for (const { name, der } of CERTIFICATES) {
  test(`${name}: SPKI converts to the same JWK a native "spki" import exports`, async () => {
    const jwk = spkiToJwk(parseCertificate(der).spki);
    // Node implements both formats, so it can be asked what this SPKI means.
    // Picking the curve from our own crv is not circular: a wrong crv makes
    // this import fail outright, since the point width would not match.
    const native = await webcrypto.subtle.importKey(
      'spki',
      parseCertificate(der).spki,
      importParams(jwk),
      true,
      ['verify'],
    );
    const reference = await webcrypto.subtle.exportKey('jwk', native);
    for (const member of ['kty', 'n', 'e', 'crv', 'x', 'y']) {
      assert.equal(jwk[member], reference[member], `${member} differs`);
    }
  });

  test(`${name}: the JWK imports and verifies the signature Node accepts`, async () => {
    const cert = parseCertificate(der);
    assert.deepEqual(cert.issuerDer, cert.subjectDer, 'expected a self-signed root');

    // Imports under the format the web build now uses, with the usages it asks for.
    const jwk = spkiToJwk(cert.spki);
    await webcrypto.subtle.importKey('jwk', jwk, importParams(jwk), false, ['verify']);

    // The whole web path — convert, import as "jwk", verify — over the root's
    // own signature, and the Node build's verdict on the same signature.
    assert.equal(await verifyCertificateSignature(cert, cert), true);
    const x509 = new X509Certificate(der);
    assert.equal(x509.verify(x509.publicKey), true);
  });
}

test('a compressed EC point is refused, not guessed at', () => {
  const cert = CERTIFICATES.map(({ der }) => parseCertificate(der)).find(
    (c) => spkiToJwk(c.spki).kty === 'EC',
  );
  const spki = Uint8Array.from(cert.spki);
  // Locate the uncompressed marker (0x04) that opens the BIT STRING's point
  // and flip it to a compressed one; nothing else about the key changes.
  const point = spki.length - (spkiToJwk(cert.spki).crv === 'P-256' ? 65 : 97);
  assert.equal(spki[point], 0x04);
  spki[point] = 0x03;
  assert.throws(
    () => spkiToJwk(spki),
    (error) => {
      assert.equal(error.name, 'VerificationError');
      assert.equal(error.reason, 'INVALID_CERTIFICATE');
      assert.match(error.message, /compressed/);
      return true;
    },
  );
});

test('an unknown public key algorithm is an INVALID_CERTIFICATE, not a raw throw', () => {
  // rsaEncryption 1.2.840.113549.1.1.1 with its last arc changed to .10,
  // which is RSASSA-PSS — a real OID this library does not accept.
  const cert = CERTIFICATES.map(({ der }) => parseCertificate(der)).find(
    (c) => spkiToJwk(c.spki).kty === 'RSA',
  );
  const spki = Uint8Array.from(cert.spki);
  const marker = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
  const at = spki.findIndex((_, i) => marker.every((b, j) => spki[i + j] === b));
  assert.ok(at > 0, 'rsaEncryption OID not found in the SPKI');
  spki[at + marker.length - 1] = 0x0a;
  assert.throws(
    () => spkiToJwk(spki),
    (error) => {
      assert.equal(error.reason, 'INVALID_CERTIFICATE');
      assert.match(error.message, /unsupported public key algorithm 1\.2\.840\.113549\.1\.1\.10/);
      return true;
    },
  );
});

test('base64url output is unpadded and uses the URL alphabet', async () => {
  const { base64UrlEncode, base64Decode } = await import('../dist/bytes.js');
  for (let length = 0; length < 64; length += 1) {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i += 1) {
      bytes[i] = (i * 37 + length * 11) & 0xff;
    }
    const encoded = base64UrlEncode(bytes);
    assert.doesNotMatch(encoded, /[+/=]/);
    assert.deepEqual(base64Decode(encoded), bytes);
    assert.equal(encoded, Buffer.from(bytes).toString('base64url'));
  }
});
