/**
 * The only place the web build touches cryptography: `crypto.subtle`, with
 * keys imported as JWKs converted from the SubjectPublicKeyInfo the DER
 * parser hands over (jwk.ts says why not "spki"). No `node:crypto`, no
 * `Buffer`, no polyfill — this file is what makes the build run on
 * WebCrypto-only isolates.
 */
import { ParseError, Tag, parse } from '../der.js';
import type { ParsedCertificate } from '../x509.js';
import { CURVES, OID_EC_PUBLIC_KEY, OID_RSA_ENCRYPTION, spkiToJwk } from './jwk.js';

interface CertSignatureAlgorithm { rsa: boolean; hash: string }

/**
 * Certificate signatureAlgorithm OIDs the chain walk accepts. SHA-1 with RSA
 * is on the list because Apple's own legacy receipt chain is signed that way
 * (Apple Inc. Root CA and the intermediates under it); dropping it would
 * drop legacy receipt support, not harden anything.
 */
const CERT_SIGNATURE_ALGORITHMS = new Map<string, CertSignatureAlgorithm>([
  ['1.2.840.113549.1.1.5', { rsa: true, hash: 'SHA-1' }],
  ['1.2.840.113549.1.1.11', { rsa: true, hash: 'SHA-256' }],
  ['1.2.840.113549.1.1.12', { rsa: true, hash: 'SHA-384' }],
  ['1.2.840.113549.1.1.13', { rsa: true, hash: 'SHA-512' }],
  ['1.2.840.10045.4.3.2', { rsa: false, hash: 'SHA-256' }],
  ['1.2.840.10045.4.3.3', { rsa: false, hash: 'SHA-384' }],
  ['1.2.840.10045.4.3.4', { rsa: false, hash: 'SHA-512' }],
]);

/** WebCrypto digest names for the two digests CMS receipts use. */
const DIGEST_NAMES = new Map<string, string>([['sha1', 'SHA-1'], ['sha256', 'SHA-256']]);

/**
 * `BufferSource` excludes views over a SharedArrayBuffer, which is what the
 * generic `Uint8Array` the DER parser produces could in principle be backed
 * by; nothing here ever is. The cast is the whole accommodation.
 */
function source(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

export async function digest(name: string, data: Uint8Array): Promise<Uint8Array> {
  const webName = DIGEST_NAMES.get(name);
  if (webName === undefined) {
    throw new ParseError(`unsupported digest algorithm ${name}`);
  }
  return new Uint8Array(await crypto.subtle.digest(webName, source(data)));
}

/** RSASSA-PKCS1-v1_5 over `data`, hash named by the CMS digest algorithm. */
export async function verifyRsaPkcs1(spki: Uint8Array, digestName: string,
  signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  const hash = DIGEST_NAMES.get(digestName);
  if (hash === undefined) {
    return false;
  }
  return verifyWith({ name: 'RSASSA-PKCS1-v1_5', hash }, 'RSASSA-PKCS1-v1_5',
    spki, signature, data);
}

/** ES256: P-256 key, SHA-256, IEEE P1363 (raw r‖s) signature — the JWS form. */
export async function verifyEs256(spki: Uint8Array, signature: Uint8Array,
  data: Uint8Array): Promise<boolean> {
  return verifyWith({ name: 'ECDSA', namedCurve: 'P-256' },
    { name: 'ECDSA', hash: 'SHA-256' }, spki, signature, data);
}

/**
 * Whether `cert`'s signature was made by `issuer`'s key, per the algorithm
 * `cert` names. Mirrors `X509Certificate.verify(issuer.publicKey)`: any
 * failure — unknown algorithm, key/algorithm mismatch, malformed signature —
 * is a false, not a throw.
 */
export async function verifyCertificateSignature(cert: ParsedCertificate,
  issuer: ParsedCertificate): Promise<boolean> {
  const algorithm = CERT_SIGNATURE_ALGORITHMS.get(cert.signatureAlgorithmOid);
  if (algorithm === undefined) {
    return false;
  }
  if (algorithm.rsa) {
    if (issuer.publicKeyAlgorithmOid !== OID_RSA_ENCRYPTION) {
      return false;
    }
    return verifyWith({ name: 'RSASSA-PKCS1-v1_5', hash: algorithm.hash },
      'RSASSA-PKCS1-v1_5', issuer.spki, cert.signatureValue, cert.tbsBytes);
  }
  if (issuer.publicKeyAlgorithmOid !== OID_EC_PUBLIC_KEY) {
    return false;
  }
  const curve = issuer.publicKeyCurveOid === null ? undefined
    : CURVES.get(issuer.publicKeyCurveOid);
  if (curve === undefined) {
    return false;
  }
  let raw: Uint8Array;
  try {
    raw = ecdsaDerToRaw(cert.signatureValue, curve.fieldSize);
  } catch {
    return false;
  }
  return verifyWith({ name: 'ECDSA', namedCurve: curve.name },
    { name: 'ECDSA', hash: algorithm.hash }, issuer.spki, raw, cert.tbsBytes);
}

async function verifyWith(importAlgorithm: AlgorithmIdentifier | EcKeyImportParams
  | RsaHashedImportParams, verifyAlgorithm: AlgorithmIdentifier | EcdsaParams,
  spki: Uint8Array, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey('jwk', spkiToJwk(spki), importAlgorithm,
      false, ['verify']);
    return await crypto.subtle.verify(verifyAlgorithm, key, source(signature), source(data));
  } catch {
    return false;
  }
}

/**
 * X.509 ECDSA signatures are DER `SEQUENCE { INTEGER r, INTEGER s }`;
 * WebCrypto only takes the IEEE P1363 fixed-width `r‖s` form.
 */
function ecdsaDerToRaw(der: Uint8Array, fieldSize: number): Uint8Array {
  const node = parse(der);
  const parts = node.children ?? [];
  if (node.tag !== Tag.SEQUENCE || parts.length !== 2
    || parts[0]!.tag !== Tag.INTEGER || parts[1]!.tag !== Tag.INTEGER) {
    throw new ParseError('not an ECDSA-Sig-Value');
  }
  const raw = new Uint8Array(fieldSize * 2);
  raw.set(fixedWidth(parts[0]!.contents, fieldSize), 0);
  raw.set(fixedWidth(parts[1]!.contents, fieldSize), fieldSize);
  return raw;
}

function fixedWidth(integer: Uint8Array, fieldSize: number): Uint8Array {
  let start = 0;
  while (start < integer.length - 1 && integer[start] === 0x00) {
    start += 1; // DER sign byte, and any other leading zeros
  }
  const value = integer.subarray(start);
  if (value.length > fieldSize) {
    throw new ParseError('ECDSA signature component wider than the field');
  }
  const out = new Uint8Array(fieldSize);
  out.set(value, fieldSize - value.length);
  return out;
}
