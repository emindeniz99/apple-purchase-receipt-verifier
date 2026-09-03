/**
 * X.509 field extraction on top of the repo's own DER reader (der.ts) —
 * everything the WebCrypto entry point needs from a certificate that the
 * Node build gets from `node:crypto`'s `X509Certificate`: the tbsCertificate
 * bytes the signature covers, the issuer/subject names it chains on, the
 * validity window, the SubjectPublicKeyInfo to import as a key, the
 * signature algorithm and bits, and the extensions the CA and Apple marker
 * checks read.
 *
 * Pure and Buffer-free so it loads anywhere; the Node build does not use it.
 */
import { bytesEqual, utf8Decode } from './bytes.js';
import {
  ParseError, Tag, encodeOidContents, isOctetString, octetStringValue, parse, type ASN1Node,
} from './der.js';

const Tags = {
  BOOLEAN: 0x01,
  BIT_STRING: 0x03,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  CONTEXT_2: 0xa2,
} as const;

const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_KEY_USAGE = '2.5.29.15';
const OID_SUBJECT_KEY_ID = '2.5.29.14';
const OID_AUTHORITY_KEY_ID = '2.5.29.35';

/** keyUsage bit 5 (RFC 5280 §4.2.1.3) — the bit `X509_check_ca` insists on. */
export const KEY_CERT_SIGN_BIT = 5;

export interface ParsedCertificate {
  /** Complete DER of the certificate. */
  raw: Uint8Array;
  /** tbsCertificate TLV — exactly the bytes signatureValue covers. */
  tbsBytes: Uint8Array;
  /** serialNumber contents (unsigned big-endian, as encoded). */
  serialNumber: Uint8Array;
  /** issuer Name TLV; chains by byte equality with an issuer's `subjectDer`. */
  issuerDer: Uint8Array;
  /** subject Name TLV. */
  subjectDer: Uint8Array;
  /** notBefore / notAfter as ms since epoch. */
  notBefore: number;
  notAfter: number;
  /** SubjectPublicKeyInfo TLV — the SPKI `crypto.subtle.importKey` takes. */
  spki: Uint8Array;
  /** SPKI algorithm OID (rsaEncryption / id-ecPublicKey). */
  publicKeyAlgorithmOid: string;
  /** Named-curve OID for EC keys, else null. */
  publicKeyCurveOid: string | null;
  /** Certificate signatureAlgorithm OID (the outer one, per RFC 5280). */
  signatureAlgorithmOid: string;
  /** signatureValue, unused-bits byte removed. */
  signatureValue: Uint8Array;
  /** `X509_check_ca(cert) === 1`: basicConstraints CA true, keyUsage permitting. */
  isCa: boolean;
  /** keyUsage bits, or null when the extension is absent. */
  keyUsage: boolean[] | null;
  subjectKeyId: Uint8Array | null;
  /** authorityKeyIdentifier keyIdentifier [0], when present. */
  authorityKeyId: Uint8Array | null;
  /** authorityKeyIdentifier authorityCertSerialNumber [2], when present. */
  authorityCertSerial: Uint8Array | null;
  /** Extension OIDs present, for the Apple marker checks. */
  hasExtension(oid: string): boolean;
}

function children(node: ASN1Node): ASN1Node[] {
  return node.children ?? [];
}

function oidString(contents: Uint8Array): string {
  if (contents.length === 0) {
    throw new ParseError('empty OBJECT IDENTIFIER');
  }
  const first = contents[0]!;
  const parts = [Math.min(Math.floor(first / 40), 2)];
  parts.push(first - parts[0]! * 40);
  let value = 0;
  let started = false;
  for (let i = 1; i < contents.length; i++) {
    const byte = contents[i]!;
    value = value * 128 + (byte & 0x7f);
    started = true;
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
      started = false;
    }
  }
  if (started) {
    throw new ParseError('truncated OBJECT IDENTIFIER');
  }
  return parts.join('.');
}

const TIME_PATTERN = /^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/;

/**
 * RFC 5280 times: UTCTime (2-digit year, 1950-2049) and GeneralizedTime.
 *
 * Contents that are not one of those decode to NaN rather than throwing,
 * which is deliberate parity: OpenSSL stores an ASN1_TIME as an unchecked
 * string, so the Node build parses such a certificate happily and only fails
 * later, when `new Date(cert.validFrom)` yields an Invalid Date and the
 * validity comparison goes false. NaN here produces exactly that — the
 * certificate is never valid at any instant. A wrong *tag* still throws:
 * that is a shape OpenSSL's decoder rejects too.
 */
function decodeTime(node: ASN1Node): number {
  if (node.tag !== Tags.UTC_TIME && node.tag !== Tags.GENERALIZED_TIME) {
    throw new ParseError('unexpected Validity time type');
  }
  const text = utf8Decode(node.contents);
  const match = TIME_PATTERN.exec(text);
  if (!match) {
    return Number.NaN;
  }
  const [, rawYear, month, day, hour, minute, second] = match as unknown as string[];
  let year = Number(rawYear);
  if (node.tag === Tags.UTC_TIME) {
    year += year >= 50 ? 1900 : 2000;
  }
  return Date.UTC(year, Number(month) - 1, Number(day),
    Number(hour), Number(minute), Number(second));
}

function bitStringBits(contents: Uint8Array): boolean[] {
  if (contents.length === 0) {
    throw new ParseError('empty BIT STRING');
  }
  const unused = contents[0]!;
  const bits: boolean[] = [];
  for (let i = 1; i < contents.length; i++) {
    const last = i === contents.length - 1;
    const count = last ? 8 - unused : 8;
    for (let bit = 0; bit < count; bit++) {
      bits.push((contents[i]! & (0x80 >> bit)) !== 0);
    }
  }
  return bits;
}

/** Parses a DER certificate. Throws ParseError on anything unexpected. */
export function parseCertificate(der: Uint8Array): ParsedCertificate {
  const cert = parse(der);
  const top = children(cert);
  if (cert.tag !== Tag.SEQUENCE || top.length < 3) {
    throw new ParseError('not an X.509 certificate');
  }
  const tbs = top[0]!;
  const fields = children(tbs);
  if (tbs.tag !== Tag.SEQUENCE) {
    throw new ParseError('unexpected TBSCertificate layout');
  }
  let index = 0;
  if (fields[index]?.tag === Tag.CONTEXT_0) {
    index += 1; // version [0] EXPLICIT
  }
  const serial = fields[index];
  const innerSignature = fields[index + 1];
  const issuer = fields[index + 2];
  const validity = fields[index + 3];
  const subject = fields[index + 4];
  const spki = fields[index + 5];
  if (serial?.tag !== Tag.INTEGER || issuer?.tag !== Tag.SEQUENCE
    || validity?.tag !== Tag.SEQUENCE || subject?.tag !== Tag.SEQUENCE
    || spki?.tag !== Tag.SEQUENCE) {
    throw new ParseError('unexpected TBSCertificate layout');
  }
  const validityFields = children(validity);
  if (validityFields.length < 2) {
    throw new ParseError('unexpected Validity layout');
  }
  const spkiAlgorithm = children(spki)[0];
  if (spkiAlgorithm?.tag !== Tag.SEQUENCE || children(spkiAlgorithm)[0]?.tag !== Tag.OID) {
    throw new ParseError('unexpected SubjectPublicKeyInfo layout');
  }
  const algorithmParts = children(spkiAlgorithm);
  const publicKeyCurve = algorithmParts[1]?.tag === Tag.OID
    ? oidString(algorithmParts[1]!.contents) : null;

  const signatureAlgorithm = children(top[1]!)[0];
  if (top[1]!.tag !== Tag.SEQUENCE || signatureAlgorithm?.tag !== Tag.OID) {
    throw new ParseError('unexpected signatureAlgorithm layout');
  }
  // RFC 5280 §4.1.1.2: the two AlgorithmIdentifiers must be the same one.
  // Without this, the algorithm the signature is checked under is taken from
  // a field the signature does not cover.
  const innerAlgorithm = innerSignature === undefined ? undefined
    : children(innerSignature)[0];
  if (innerSignature?.tag !== Tag.SEQUENCE || innerAlgorithm?.tag !== Tag.OID
    || !bytesEqual(innerAlgorithm.contents, signatureAlgorithm.contents)) {
    throw new ParseError('signatureAlgorithm disagrees with tbsCertificate.signature');
  }
  if (top[2]!.tag !== Tags.BIT_STRING || top[2]!.contents.length < 2) {
    throw new ParseError('unexpected signatureValue layout');
  }

  let extensions: ASN1Node | null = null;
  for (const field of fields) {
    if (field.tag === Tag.CONTEXT_3) {
      extensions = children(field)[0] ?? null;
    }
  }
  const byOid = new Map<string, Uint8Array>();
  for (const extension of extensions ? children(extensions) : []) {
    const parts = children(extension);
    const oidNode = parts[0];
    const valueNode = parts[parts.length - 1];
    if (oidNode?.tag !== Tag.OID || valueNode === undefined || !isOctetString(valueNode)) {
      throw new ParseError('malformed certificate extension');
    }
    const oid = oidString(oidNode.contents);
    if (!byOid.has(oid)) {
      byOid.set(oid, octetStringValue(valueNode));
    }
  }

  const keyUsageExtension = byOid.get(OID_KEY_USAGE);
  const keyUsage = keyUsageExtension === undefined ? null
    : bitStringBits(parse(keyUsageExtension).contents);

  // X509_check_ca() === 1: basicConstraints present with cA TRUE, and a
  // keyUsage extension (if any) that permits keyCertSign.
  let basicConstraintsCa = false;
  const basicConstraints = byOid.get(OID_BASIC_CONSTRAINTS);
  if (basicConstraints !== undefined) {
    const value = parse(basicConstraints);
    const first = children(value)[0];
    basicConstraintsCa = first?.tag === Tags.BOOLEAN && first.contents[0] !== 0x00;
  }
  const certSignAllowed = keyUsage === null || keyUsage[KEY_CERT_SIGN_BIT] === true;

  const subjectKeyIdExtension = byOid.get(OID_SUBJECT_KEY_ID);
  const authorityKeyIdExtension = byOid.get(OID_AUTHORITY_KEY_ID);
  let authorityKeyId: Uint8Array | null = null;
  let authorityCertSerial: Uint8Array | null = null;
  if (authorityKeyIdExtension !== undefined) {
    for (const part of children(parse(authorityKeyIdExtension))) {
      if (part.tag === Tag.CONTEXT_0) {
        authorityKeyId = part.contents;
      } else if (part.tag === Tags.CONTEXT_2) {
        authorityCertSerial = part.contents;
      }
    }
  }

  return {
    raw: der,
    tbsBytes: tbs.raw,
    serialNumber: serial.contents,
    issuerDer: issuer.raw,
    subjectDer: subject.raw,
    notBefore: decodeTime(validityFields[0]!),
    notAfter: decodeTime(validityFields[1]!),
    spki: spki.raw,
    publicKeyAlgorithmOid: oidString(children(spkiAlgorithm)[0]!.contents),
    publicKeyCurveOid: publicKeyCurve,
    signatureAlgorithmOid: oidString(signatureAlgorithm.contents),
    signatureValue: top[2]!.contents.subarray(1),
    isCa: basicConstraintsCa && certSignAllowed,
    keyUsage,
    subjectKeyId: subjectKeyIdExtension === undefined ? null
      : parse(subjectKeyIdExtension).contents,
    authorityKeyId,
    authorityCertSerial,
    hasExtension(oid: string): boolean {
      const wanted = encodeOidContents(oid);
      for (const extension of extensions ? children(extensions) : []) {
        const oidNode = children(extension)[0];
        if (oidNode?.tag === Tag.OID && bytesEqual(oidNode.contents, wanted)) {
          return true;
        }
      }
      return false;
    },
  };
}
