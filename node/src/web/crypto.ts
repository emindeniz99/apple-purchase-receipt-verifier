/**
 * The only place the web build touches cryptography: `crypto.subtle`, with
 * keys imported as JWKs converted from the SubjectPublicKeyInfo the DER
 * parser hands over (jwk.ts says why not "spki"). No `node:crypto`, no
 * `Buffer`, no polyfill — this file is what makes the build run on
 * WebCrypto-only isolates.
 *
 * Algorithm identification (which OID means which scheme) mirrors the Node
 * build's crypto.ts, so "any receipt signer algorithm"
 * (#160, docs/design/0.7-api.md) means whatever
 * `crypto.subtle` can verify — never a hard-coded allowlist (Q14). Every
 * digest and signature scheme the shared conformance cases require (SHA-1,
 * SHA-256, SHA-384, SHA-512, RSASSA-PKCS1-v1_5, RSASSA-PSS, ECDSA P-256)
 * is a standard WebCrypto algorithm.
 */
import { ParseError, Tag, parse, type ASN1Node } from '../der.js';
import { Reason, VerificationError } from '../errors.js';
import { oidString, type ParsedCertificate } from '../x509.js';
import { CURVES, OID_EC_PUBLIC_KEY, OID_RSA_ENCRYPTION, spkiToJwk } from './jwk.js';

export type DigestName = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

/** Pure digest algorithm OIDs a CMS SignerInfo's digestAlgorithm may name. SHA-224 and MD5 are recognised (for the "named hash" comparison) but have no WebCrypto digest, so verifying under them always fails closed. */
const DIGEST_OIDS = new Map<string, DigestName | null>([
  ['1.2.840.113549.2.5', null], // md5
  ['1.3.14.3.2.26', 'SHA-1'],
  ['2.16.840.1.101.3.4.2.4', null], // sha224
  ['2.16.840.1.101.3.4.2.1', 'SHA-256'],
  ['2.16.840.1.101.3.4.2.2', 'SHA-384'],
  ['2.16.840.1.101.3.4.2.3', 'SHA-512'],
]);

function digestForOid(oid: string): DigestName | null | undefined {
  return DIGEST_OIDS.get(oid);
}

type Scheme =
  | { kind: 'pkcs1'; digest: DigestName | null }
  | { kind: 'pss'; digest: DigestName | null; saltLength: number }
  | { kind: 'ecdsa'; digest: DigestName | null };

const OID_RSASSA_PSS = '1.2.840.113549.1.1.10';
const OID_MGF1 = '1.2.840.113549.1.1.8';

function fixedScheme(oid: string): Scheme | null {
  switch (oid) {
    case '1.2.840.113549.1.1.4':
      return { kind: 'pkcs1', digest: null }; // md5
    case '1.2.840.113549.1.1.5':
      return { kind: 'pkcs1', digest: 'SHA-1' };
    case '1.2.840.113549.1.1.14':
      return { kind: 'pkcs1', digest: null }; // sha224
    case '1.2.840.113549.1.1.11':
      return { kind: 'pkcs1', digest: 'SHA-256' };
    case '1.2.840.113549.1.1.12':
      return { kind: 'pkcs1', digest: 'SHA-384' };
    case '1.2.840.113549.1.1.13':
      return { kind: 'pkcs1', digest: 'SHA-512' };
    case '1.2.840.10045.4.1':
      return { kind: 'ecdsa', digest: 'SHA-1' };
    case '1.2.840.10045.4.3.1':
      return { kind: 'ecdsa', digest: null }; // sha224
    case '1.2.840.10045.4.3.2':
      return { kind: 'ecdsa', digest: 'SHA-256' };
    case '1.2.840.10045.4.3.3':
      return { kind: 'ecdsa', digest: 'SHA-384' };
    case '1.2.840.10045.4.3.4':
      return { kind: 'ecdsa', digest: 'SHA-512' };
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

function hashAlgorithmOid(node: ASN1Node): DigestName | null | undefined {
  const oid = node.children?.[0];
  if (node.tag !== Tag.SEQUENCE || oid?.tag !== 0x06) {
    return undefined;
  }
  return digestForOid(oidString(oid.contents));
}

/** `RSASSA-PSS-params` (RFC 4055 §3.1), mirroring the Node build's crypto.ts. */
function pssScheme(params: ASN1Node): Scheme | null {
  if (params.tag !== Tag.SEQUENCE) {
    return null;
  }
  let pssDigest: DigestName | null = 'SHA-1';
  let maskDigest: DigestName | null = 'SHA-1';
  let saltLength = 20;
  for (const field of params.children ?? []) {
    const inner = field.children?.[0];
    if (inner === undefined) {
      return null;
    }
    switch (field.tag) {
      case Tag.CONTEXT_0: {
        const d = hashAlgorithmOid(inner);
        if (d === undefined) {
          return null;
        }
        pssDigest = d;
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
        if (d === undefined) {
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
  return pssDigest === maskDigest ? { kind: 'pss', digest: pssDigest, saltLength } : null;
}

function schemeForAlgorithm(oid: string, params: ASN1Node | null): Scheme | null {
  if (oid === OID_RSASSA_PSS) {
    return params === null ? null : pssScheme(params);
  }
  return fixedScheme(oid);
}

/**
 * `BufferSource` excludes views over a SharedArrayBuffer, which is what the
 * generic `Uint8Array` the DER parser produces could in principle be backed
 * by; nothing here ever is. The cast is the whole accommodation.
 */
function source(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

// Node-style lowercase digest names (as CMS's own OID map produces
// elsewhere in this codebase) to the WebCrypto name, for the message-digest
// attribute check in web/receipt.ts.
const DIGEST_OIDS_BY_NODE_NAME = new Map<string, DigestName>([
  ['sha1', 'SHA-1'],
  ['sha256', 'SHA-256'],
  ['sha384', 'SHA-384'],
  ['sha512', 'SHA-512'],
]);

export async function digest(name: string, data: Uint8Array): Promise<Uint8Array> {
  const webName = DIGEST_OIDS_BY_NODE_NAME.get(name);
  if (webName === undefined) {
    throw new ParseError(`unsupported digest algorithm ${name}`);
  }
  const api = subtle();
  try {
    return new Uint8Array(await api.digest(webName, source(data)));
  } catch (cause) {
    throw new VerificationError(
      Reason.INTERNAL_ERROR,
      `${webName} digest is unavailable in this runtime`,
      cause,
    );
  }
}

/** The Node-style digest name (`sha1`, `sha256`, ...) a digestAlgorithm OID names, or null. */
export function nodeDigestNameForOid(oid: string): string | null {
  const webName = digestForOid(oid);
  if (webName === undefined || webName === null) {
    return null;
  }
  for (const [nodeName, w] of DIGEST_OIDS_BY_NODE_NAME) {
    if (w === webName) {
      return nodeName;
    }
  }
  return null;
}

/**
 * `crypto.subtle`, or INTERNAL_ERROR when the runtime has none. Read
 * outside a verification's own catch so a missing WebCrypto is not reported
 * as a bad signature or chain.
 */
function subtle(): SubtleCrypto {
  if (typeof crypto === 'undefined' || crypto.subtle === undefined) {
    throw new VerificationError(Reason.INTERNAL_ERROR, 'crypto.subtle is unavailable');
  }
  return crypto.subtle;
}

async function importPublicKey(
  spki: Uint8Array,
  importAlgorithm: AlgorithmIdentifier | EcKeyImportParams | RsaHashedImportParams,
): Promise<CryptoKey | null> {
  try {
    return await subtle().importKey('jwk', spkiToJwk(spki), importAlgorithm, false, ['verify']);
  } catch {
    return null;
  }
}

async function verifyWithKey(
  key: CryptoKey,
  verifyAlgorithm: AlgorithmIdentifier | EcdsaParams | RsaPssParams,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  try {
    return await subtle().verify(verifyAlgorithm, key, source(signature), source(data));
  } catch {
    return false;
  }
}

async function verifyScheme(
  spki: Uint8Array,
  publicKeyAlgorithmOid: string,
  scheme: Scheme,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  if (scheme.digest === null) {
    // A recognised-but-unimplemented digest (MD5, SHA-224): never verifies.
    return false;
  }
  if (scheme.kind === 'pkcs1') {
    if (publicKeyAlgorithmOid !== OID_RSA_ENCRYPTION) {
      return false;
    }
    const key = await importPublicKey(spki, { name: 'RSASSA-PKCS1-v1_5', hash: scheme.digest });
    return key !== null && verifyWithKey(key, 'RSASSA-PKCS1-v1_5', signature, data);
  }
  if (scheme.kind === 'pss') {
    if (publicKeyAlgorithmOid !== OID_RSA_ENCRYPTION) {
      return false;
    }
    const key = await importPublicKey(spki, { name: 'RSA-PSS', hash: scheme.digest });
    return (
      key !== null &&
      verifyWithKey(key, { name: 'RSA-PSS', saltLength: scheme.saltLength }, signature, data)
    );
  }
  // ECDSA
  if (publicKeyAlgorithmOid !== OID_EC_PUBLIC_KEY) {
    return false;
  }
  const curveOid = curveOidFor(spki);
  const curve = curveOid === null ? undefined : CURVES.get(curveOid);
  if (curve === undefined) {
    return false;
  }
  let raw: Uint8Array;
  try {
    raw = ecdsaDerToRaw(signature, curve.fieldSize);
  } catch {
    return false;
  }
  const key = await importPublicKey(spki, { name: 'ECDSA', namedCurve: curve.name });
  return key !== null && verifyWithKey(key, { name: 'ECDSA', hash: scheme.digest }, raw, data);
}

function curveOidFor(spki: Uint8Array): string | null {
  try {
    const node = parse(spki);
    const algorithm = node.children?.[0];
    const curveNode = algorithm?.children?.[1];
    return curveNode?.tag === 0x06 ? oidString(curveNode.contents) : null;
  } catch {
    return null;
  }
}

/**
 * A CMS `SignerInfo` signature under the signer's key. RSASSA-PSS when
 * `signatureAlgorithmOid` says so; otherwise the key type decides,
 * RSASSA-PKCS1-v1_5 for an RSA key and ECDSA for an EC key, with the
 * `SignerInfo`'s own digest. A `signatureAlgorithm` that names a hash must
 * name the digest the `SignerInfo` hashed with, or the signature is
 * `false`.
 */
export async function verifySignerSignature(
  signerSpki: Uint8Array,
  signerPublicKeyAlgorithmOid: string,
  digestAlgorithmOid: string,
  signatureAlgorithmOid: string,
  signatureAlgorithmParams: ASN1Node | null,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  const digestName = digestForOid(digestAlgorithmOid);
  if (digestName === undefined) {
    return false;
  }
  const named = schemeForAlgorithm(signatureAlgorithmOid, signatureAlgorithmParams);
  if (signatureAlgorithmOid === OID_RSASSA_PSS && named === null) {
    return false;
  }
  if (named !== null && named.digest !== digestName) {
    return false;
  }
  const scheme: Scheme | null =
    named !== null && named.kind === 'pss'
      ? named
      : signerPublicKeyAlgorithmOid === OID_RSA_ENCRYPTION
        ? { kind: 'pkcs1', digest: digestName }
        : signerPublicKeyAlgorithmOid === OID_EC_PUBLIC_KEY
          ? { kind: 'ecdsa', digest: digestName }
          : null;
  return (
    scheme !== null &&
    verifyScheme(signerSpki, signerPublicKeyAlgorithmOid, scheme, signature, data)
  );
}

/** ES256: P-256 key, SHA-256, IEEE P1363 (raw r‖s) signature — the JWS form. */
export async function verifyEs256(
  spki: Uint8Array,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  if (signature.length !== 64) {
    return false;
  }
  const key = await importPublicKey(spki, { name: 'ECDSA', namedCurve: 'P-256' });
  return key !== null && verifyWithKey(key, { name: 'ECDSA', hash: 'SHA-256' }, signature, data);
}

/**
 * Whether `cert`'s signature was made by `issuer`'s key, per the algorithm
 * `cert` names. Mirrors `X509Certificate.verify(issuer.publicKey)`: any
 * failure is a false, not a throw. The one throw is a runtime with no
 * `crypto.subtle` (INTERNAL_ERROR).
 */
export async function verifyCertificateSignature(
  cert: ParsedCertificate,
  issuer: ParsedCertificate,
): Promise<boolean> {
  const scheme = fixedScheme(cert.signatureAlgorithmOid);
  return (
    scheme !== null &&
    verifyScheme(
      issuer.spki,
      issuer.publicKeyAlgorithmOid,
      scheme,
      cert.signatureValue,
      cert.tbsBytes,
    )
  );
}

/**
 * X.509 and CMS ECDSA signatures are DER `SEQUENCE { INTEGER r, INTEGER s }`;
 * WebCrypto only takes the IEEE P1363 fixed-width `r‖s` form.
 */
function ecdsaDerToRaw(der: Uint8Array, fieldSize: number): Uint8Array {
  const node = parse(der);
  const parts = node.children ?? [];
  if (
    node.tag !== Tag.SEQUENCE ||
    parts.length !== 2 ||
    parts[0]!.tag !== Tag.INTEGER ||
    parts[1]!.tag !== Tag.INTEGER
  ) {
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
