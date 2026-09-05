/**
 * SubjectPublicKeyInfo → JWK, so the web build never asks `importKey` for
 * the "spki" format.
 *
 * "spki" is not universally implemented. Fastly Compute's WebCrypto rejects
 * every SPKI import — `Supplied format is not supported` for RSASSA-PKCS1-v1_5
 * (SHA-1 and SHA-256 alike) and `Supplied format is not yet supported` for
 * ECDSA P-256 — while its "jwk" import works, as it does on Node, the Vercel
 * Edge runtime and workerd. So the SPKI the DER parser hands over is
 * converted here, by hand: the whole job is two integers or one point, and a
 * dependency for that would cost more than it saves.
 *
 * Only the key types Apple's chains actually contain are convertible. This
 * library never repairs input it cannot represent, so anything else — an
 * unknown algorithm, an unknown curve, a compressed point — is rejected as an
 * INVALID_CERTIFICATE rather than guessed at.
 */
import { base64UrlEncode } from '../bytes.js';
import { Tag, parse } from '../der.js';
import { Reason, VerificationError } from '../errors.js';
import { oidString } from '../x509.js';

/** rsaEncryption — the SPKI algorithm of every receipt-signing key. */
export const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
/** id-ecPublicKey — the SPKI algorithm of every App Store JWS signing key. */
export const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';

const BIT_STRING = 0x03;

export interface Curve {
  /** JWK `crv` name, which is also the WebCrypto `namedCurve`. */
  name: string;
  /** Field size in bytes: the width of each of X and Y. */
  fieldSize: number;
}

/** Named curves by OID, for both the JWK `crv` and the P1363 signature width. */
export const CURVES = new Map<string, Curve>([
  ['1.2.840.10045.3.1.7', { name: 'P-256', fieldSize: 32 }],
  ['1.3.132.0.34', { name: 'P-384', fieldSize: 48 }],
  ['1.3.132.0.35', { name: 'P-521', fieldSize: 66 }],
]);

/**
 * A public JWK, with only the members these two key types need. No `alg`,
 * `use` or `key_ops`: WebCrypto validates them against the import call when
 * they are present, and omitting them lets one key be imported under any
 * hash the caller names — which is what the certificate walk does.
 */
export interface PublicJwk {
  kty: 'RSA' | 'EC';
  /** RSA modulus, base64url, minimal unsigned big-endian. */
  n?: string;
  /** RSA public exponent, same encoding. */
  e?: string;
  crv?: string;
  /** EC affine X, base64url, exactly the field size. */
  x?: string;
  /** EC affine Y, same encoding. */
  y?: string;
}

function reject(message: string): never {
  throw new VerificationError(Reason.INVALID_CERTIFICATE, message);
}

/**
 * Refuses a certificate whose key this build cannot build, and refuses
 * nothing else. It is the web build's `void certificate.publicKey`, and it
 * has to be scoped the way OpenSSL's key reader is scoped: a key of an
 * algorithm this build DOES construct must construct, so an unimplemented
 * curve stays a defect of the certificate
 * (receipt/reject-signer-on-an-unimplemented-curve), while a key of any
 * other algorithm is readable and simply not one of ours — a DSA signer is
 * a readable key of the wrong kind, which the "not RSA" check downstream
 * owns and answers INVALID_SIGNATURE. Converting unconditionally instead
 * would make every such key an INVALID_CERTIFICATE here and put the web
 * build at odds with the Node one, which reads a DSA key perfectly well.
 * dotnet settles the same question the same way (RequireUsablePublicKey),
 * as do go and php.
 */
export function requireBuildablePublicKey(algorithmOid: string, spki: Uint8Array): void {
  if (algorithmOid === OID_RSA_ENCRYPTION || algorithmOid === OID_EC_PUBLIC_KEY) {
    spkiToJwk(spki);
  }
}

/**
 * `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
 * subjectPublicKey BIT STRING }`, where the BIT STRING wraps a DER
 * `RSAPublicKey` or an uncompressed EC point.
 */
export function spkiToJwk(spki: Uint8Array): PublicJwk {
  const node = read(spki, 'SubjectPublicKeyInfo');
  const parts = node.children ?? [];
  const algorithm = parts[0];
  const bitString = parts[1];
  if (
    node.tag !== Tag.SEQUENCE ||
    parts.length !== 2 ||
    algorithm?.tag !== Tag.SEQUENCE ||
    bitString?.tag !== BIT_STRING ||
    bitString.contents.length < 2 ||
    bitString.contents[0] !== 0x00
  ) {
    reject('unexpected SubjectPublicKeyInfo layout');
  }
  const algorithmParts = algorithm.children ?? [];
  const algorithmOid = algorithmParts[0];
  if (algorithmOid?.tag !== Tag.OID) {
    reject('unexpected SubjectPublicKeyInfo algorithm');
  }
  const key = bitString.contents.subarray(1); // drop the unused-bits count
  const oid = oidString(algorithmOid.contents);
  if (oid === OID_RSA_ENCRYPTION) {
    return rsaJwk(key);
  }
  if (oid !== OID_EC_PUBLIC_KEY) {
    reject(`unsupported public key algorithm ${oid}`);
  }
  const curveOid =
    algorithmParts[1]?.tag === Tag.OID ? oidString(algorithmParts[1].contents) : null;
  const curve = curveOid === null ? undefined : CURVES.get(curveOid);
  if (curve === undefined) {
    reject(`unsupported elliptic curve ${curveOid ?? '(unnamed)'}`);
  }
  return ecJwk(key, curve);
}

/** `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`. */
function rsaJwk(key: Uint8Array): PublicJwk {
  const node = read(key, 'RSAPublicKey');
  const parts = node.children ?? [];
  if (
    node.tag !== Tag.SEQUENCE ||
    parts.length !== 2 ||
    parts[0]!.tag !== Tag.INTEGER ||
    parts[1]!.tag !== Tag.INTEGER
  ) {
    reject('unexpected RSAPublicKey layout');
  }
  return {
    kty: 'RSA',
    n: base64UrlEncode(unsigned(parts[0]!.contents, 'modulus')),
    e: base64UrlEncode(unsigned(parts[1]!.contents, 'publicExponent')),
  };
}

/**
 * DER INTEGERs are signed, so a modulus whose top bit is set carries a
 * leading 0x00 that is a sign byte and not part of the number. JWK members
 * are unsigned and minimal (RFC 7518 §6.3.1), so it must not survive.
 */
function unsigned(contents: Uint8Array, field: string): Uint8Array {
  if (contents.length === 0 || (contents[0]! & 0x80) !== 0) {
    reject(`RSAPublicKey ${field} is not a positive integer`);
  }
  let start = 0;
  while (start < contents.length - 1 && contents[start] === 0x00) {
    start += 1;
  }
  return contents.subarray(start);
}

/** `ECPoint ::= 0x04 || X || Y`, each coordinate the curve's field size. */
function ecJwk(point: Uint8Array, curve: Curve): PublicJwk {
  if (point.length > 0 && (point[0] === 0x02 || point[0] === 0x03)) {
    // Decompressing needs a modular square root over the curve's prime.
    // Nothing Apple issues is compressed, so this is a refusal, not a gap.
    reject('compressed EC public keys are not supported');
  }
  if (point.length !== 1 + curve.fieldSize * 2 || point[0] !== 0x04) {
    reject(`unexpected ${curve.name} public key point`);
  }
  return {
    kty: 'EC',
    crv: curve.name,
    x: base64UrlEncode(point.subarray(1, 1 + curve.fieldSize)),
    y: base64UrlEncode(point.subarray(1 + curve.fieldSize)),
  };
}

function read(der: Uint8Array, what: string): ReturnType<typeof parse> {
  try {
    return parse(der);
  } catch {
    reject(`${what} is not valid DER`);
  }
}
