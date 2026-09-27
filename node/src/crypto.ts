/**
 * The only place the Node build touches cryptography: `node:crypto`, which
 * does every bit of RSA/ECDSA/RSA-PSS arithmetic and every digest — nothing
 * here hand-rolls a primitive. Algorithm identification (which OID means
 * which scheme) is this library's own, mirroring the Rust port's crypto.rs,
 * so "any receipt signer algorithm" (docs/design/0.7-hardening-parity.md
 * change 3) means whatever OpenSSL, through `node:crypto`, can verify —
 * never a hard-coded allowlist (Q14).
 */
import { createPublicKey, verify as cryptoVerify, constants, type KeyObject } from 'node:crypto';
import { Tag, type ASN1Node } from './der.js';
import { Reason, VerificationError } from './errors.js';
import { oidString } from './x509.js';
import type { ParsedCertificate } from './x509.js';

export type DigestName = 'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512' | 'md5';

/** Pure digest algorithm OIDs, as a CMS SignerInfo's digestAlgorithm names one. */
const DIGEST_OIDS = new Map<string, DigestName>([
  ['1.2.840.113549.2.5', 'md5'],
  ['1.3.14.3.2.26', 'sha1'],
  ['2.16.840.1.101.3.4.2.4', 'sha224'],
  ['2.16.840.1.101.3.4.2.1', 'sha256'],
  ['2.16.840.1.101.3.4.2.2', 'sha384'],
  ['2.16.840.1.101.3.4.2.3', 'sha512'],
]);

export function digestForOid(oid: string): DigestName | null {
  return DIGEST_OIDS.get(oid) ?? null;
}

type Scheme =
  | { kind: 'pkcs1'; digest: DigestName }
  | { kind: 'pss'; digest: DigestName; saltLength: number }
  | { kind: 'ecdsa'; digest: DigestName };

const OID_RSASSA_PSS = '1.2.840.113549.1.1.10';
const OID_MGF1 = '1.2.840.113549.1.1.8';
export const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
export const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';

/**
 * The signatureAlgorithm OIDs this library recognises by name: every
 * hash-and-sign OID a certificate or a CMS SignerInfo may carry (owner,
 * 2026-09-27, Q14: whatever the crypto library verifies, no stricter
 * allowlist — this is identification, not a restriction: an OID absent here
 * simply falls through to the key-type default in
 * {@link schemeForSignerSignature}).
 */
function fixedScheme(oid: string): Scheme | null {
  switch (oid) {
    case '1.2.840.113549.1.1.4':
      return { kind: 'pkcs1', digest: 'md5' };
    case '1.2.840.113549.1.1.5':
      return { kind: 'pkcs1', digest: 'sha1' };
    case '1.2.840.113549.1.1.14':
      return { kind: 'pkcs1', digest: 'sha224' };
    case '1.2.840.113549.1.1.11':
      return { kind: 'pkcs1', digest: 'sha256' };
    case '1.2.840.113549.1.1.12':
      return { kind: 'pkcs1', digest: 'sha384' };
    case '1.2.840.113549.1.1.13':
      return { kind: 'pkcs1', digest: 'sha512' };
    case '1.2.840.10045.4.1':
      return { kind: 'ecdsa', digest: 'sha1' };
    case '1.2.840.10045.4.3.1':
      return { kind: 'ecdsa', digest: 'sha224' };
    case '1.2.840.10045.4.3.2':
      return { kind: 'ecdsa', digest: 'sha256' };
    case '1.2.840.10045.4.3.3':
      return { kind: 'ecdsa', digest: 'sha384' };
    case '1.2.840.10045.4.3.4':
      return { kind: 'ecdsa', digest: 'sha512' };
    default:
      return null;
  }
}

function smallInteger(node: ASN1Node): number | null {
  if (node.tag !== Tag.INTEGER || node.contents.length > 2 || (node.contents[0] ?? 0) >= 0x80) {
    return null;
  }
  let value = 0;
  for (const byte of node.contents) {
    value = (value << 8) | byte;
  }
  return value;
}

function hashAlgorithmOid(node: ASN1Node): DigestName | null {
  const oid = node.children?.[0];
  if (node.tag !== Tag.SEQUENCE || oid?.tag !== 0x06) {
    return null;
  }
  return digestForOid(oidString(oid.contents));
}

/**
 * `RSASSA-PSS-params` (RFC 4055 §3.1): the hash, MGF1 over that same hash
 * (the only mask this library implements, via `node:crypto`'s own MGF1),
 * the salt length and the trailer field 1, each with its DEFAULT when
 * absent.
 */
function pssScheme(params: ASN1Node): Scheme | null {
  if (params.tag !== Tag.SEQUENCE) {
    return null;
  }
  let digest: DigestName = 'sha1';
  let maskDigest: DigestName = 'sha1';
  let saltLength = 20;
  for (const field of params.children ?? []) {
    const inner = field.children?.[0];
    if (inner === undefined) {
      return null;
    }
    switch (field.tag) {
      case Tag.CONTEXT_0: {
        const d = hashAlgorithmOid(inner);
        if (d === null) {
          return null;
        }
        digest = d;
        break;
      }
      case Tag.CONTEXT_1: {
        const parts = inner.children ?? [];
        const mgfOid = parts[0];
        const hashNode = parts[1];
        if (inner.tag !== Tag.SEQUENCE || mgfOid?.tag !== 0x06 || hashNode === undefined) {
          return null;
        }
        if (oidString(mgfOid.contents) !== OID_MGF1) {
          return null;
        }
        const d = hashAlgorithmOid(hashNode);
        if (d === null) {
          return null;
        }
        maskDigest = d;
        break;
      }
      case Tag.CONTEXT_2: {
        const n = smallInteger(inner);
        if (n === null) {
          return null;
        }
        saltLength = n;
        break;
      }
      case Tag.CONTEXT_3: {
        if (smallInteger(inner) !== 1) {
          return null;
        }
        break;
      }
      default:
        return null;
    }
  }
  return digest === maskDigest ? { kind: 'pss', digest, saltLength } : null;
}

function schemeForAlgorithm(oid: string, params: ASN1Node | null): Scheme | null {
  if (oid === OID_RSASSA_PSS) {
    return params === null ? null : pssScheme(params);
  }
  return fixedScheme(oid);
}

function keyFromSpki(spki: Uint8Array): KeyObject | null {
  try {
    return createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
  } catch {
    return null;
  }
}

function verifyWithScheme(
  spki: Uint8Array,
  scheme: Scheme,
  signature: Uint8Array,
  data: Uint8Array,
): boolean {
  const key = keyFromSpki(spki);
  if (key === null) {
    return false;
  }
  try {
    if (scheme.kind === 'pkcs1') {
      return key.asymmetricKeyType === 'rsa' && cryptoVerify(scheme.digest, data, key, signature);
    }
    if (scheme.kind === 'pss') {
      return (
        key.asymmetricKeyType === 'rsa' &&
        cryptoVerify(
          scheme.digest,
          data,
          { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: scheme.saltLength },
          signature,
        )
      );
    }
    // ECDSA: node:crypto takes the DER `ECDSA-Sig-Value` by default, exactly
    // the wire form a certificate signature or a CMS signature already is.
    return key.asymmetricKeyType === 'ec' && cryptoVerify(scheme.digest, data, key, signature);
  } catch {
    return false;
  }
}

/**
 * Refuses a certificate whose key this library cannot build: an RSA or EC
 * SubjectPublicKeyInfo `node:crypto` cannot decode, an unassigned or
 * unimplemented EC curve chief among them. Asked only of a certificate a
 * pinned chain has already vouched for, so the answer is a verdict about
 * the certificate (`INVALID_CERTIFICATE`), never about the chain — before
 * that key is used to check anything (owner, 2026-09-27). A key of any
 * other algorithm is readable and simply not one of ours; that is a
 * different verdict, reached naturally when a signature check with it
 * fails.
 */
export function requireBuildablePublicKey(cert: ParsedCertificate): void {
  if (
    cert.publicKeyAlgorithmOid !== OID_RSA_ENCRYPTION &&
    cert.publicKeyAlgorithmOid !== OID_EC_PUBLIC_KEY
  ) {
    return;
  }
  if (keyFromSpki(cert.spki) === null) {
    throw new VerificationError(
      Reason.INVALID_CERTIFICATE,
      'certificate public key does not decode',
    );
  }
}

/**
 * Whether `cert`'s signature was made by `issuerSpki`, under the algorithm
 * `cert` names. Any failure — an unknown algorithm, a key/algorithm
 * mismatch, a malformed signature — is `false`, never a throw: this is the
 * whole cryptographic content of the chain walk (chain.ts).
 */
export function verifyCertificateSignature(
  cert: ParsedCertificate,
  issuerSpki: Uint8Array,
): boolean {
  const scheme = fixedScheme(cert.signatureAlgorithmOid);
  return (
    scheme !== null && verifyWithScheme(issuerSpki, scheme, cert.signatureValue, cert.tbsBytes)
  );
}

/**
 * A CMS `SignerInfo` signature under the signer's key. RSASSA-PSS when
 * `signatureAlgorithmOid` says so, with the hash its parameters name;
 * otherwise the key type decides, RSASSA-PKCS1-v1_5 for an RSA key and
 * ECDSA for an EC key, with the `SignerInfo`'s own digest. A
 * `signatureAlgorithm` that names a hash must name the digest the
 * `SignerInfo` hashed with, or the signature is `false`: a label that
 * disagrees with what was hashed is not one signature under two names
 * (docs/design/0.7-hardening-parity.md change 3 / Q15).
 */
export function verifySignerSignature(
  signerSpki: Uint8Array,
  signerPublicKeyAlgorithmOid: string,
  digestAlgorithmOid: string,
  signatureAlgorithmOid: string,
  signatureAlgorithmParams: ASN1Node | null,
  signature: Uint8Array,
  data: Uint8Array,
): boolean {
  const digest = digestForOid(digestAlgorithmOid);
  if (digest === null) {
    return false;
  }
  const named = schemeForAlgorithm(signatureAlgorithmOid, signatureAlgorithmParams);
  if (signatureAlgorithmOid === OID_RSASSA_PSS && named === null) {
    return false;
  }
  if (named !== null && named.digest !== digest) {
    return false;
  }
  const scheme: Scheme | null =
    named !== null && named.kind === 'pss'
      ? named
      : signerPublicKeyAlgorithmOid === OID_RSA_ENCRYPTION
        ? { kind: 'pkcs1', digest }
        : signerPublicKeyAlgorithmOid === OID_EC_PUBLIC_KEY
          ? { kind: 'ecdsa', digest }
          : null;
  return scheme !== null && verifyWithScheme(signerSpki, scheme, signature, data);
}

/**
 * `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` built from the
 * JWS's fixed-width `r ‖ s` form (RFC 7515), so verification can ask for
 * the DER encoding `node:crypto` (and every polyfill of it) is guaranteed
 * to support, rather than `dsaEncoding: 'ieee-p1363'`, which workerd's
 * `nodejs_compat` shim does not implement (measured 2026-09-27: identical
 * key and signature bytes verify under native Node and under
 * `crypto.subtle` in the same workerd binary, and fail only through the
 * shim's `ieee-p1363` path).
 */
function rawEcdsaToDer(raw: Uint8Array, fieldSize: number): Uint8Array {
  const r = derInteger(raw.subarray(0, fieldSize));
  const s = derInteger(raw.subarray(fieldSize));
  const contents = new Uint8Array(r.length + s.length);
  contents.set(r, 0);
  contents.set(s, r.length);
  return concatDer(0x30, contents);
}

/** A field element as a minimal DER INTEGER (unsigned; a top bit set gets a leading zero). */
function derInteger(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0x00) {
    start += 1;
  }
  const trimmed = bytes.subarray(start);
  const needsPad = (trimmed[0] ?? 0) >= 0x80;
  const contents = new Uint8Array((needsPad ? 1 : 0) + trimmed.length);
  contents.set(trimmed, needsPad ? 1 : 0);
  return concatDer(0x02, contents);
}

function concatDer(tag: number, contents: Uint8Array): Uint8Array {
  if (contents.length > 127) {
    // Never happens for an ECDSA-Sig-Value over the curves this library
    // uses (P-256/P-384 field elements are well under 127 bytes each).
    throw new Error('DER length too large for a short-form encoding');
  }
  const out = new Uint8Array(2 + contents.length);
  out[0] = tag;
  out[1] = contents.length;
  out.set(contents, 2);
  return out;
}

/** ES256, the JWS payload signature: a P-256 key, SHA-256, raw `r ‖ s` (RFC 7515). */
export function verifyEs256(spki: Uint8Array, signature: Uint8Array, data: Uint8Array): boolean {
  if (signature.length !== 64) {
    return false;
  }
  const key = keyFromSpki(spki);
  if (key === null || key.asymmetricKeyType !== 'ec') {
    return false;
  }
  try {
    return cryptoVerify('sha256', data, key, rawEcdsaToDer(signature, 32));
  } catch {
    return false;
  }
}
