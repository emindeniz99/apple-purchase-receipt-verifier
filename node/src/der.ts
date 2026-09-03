/**
 * Minimal DER/BER reader — just enough ASN.1 to parse X.509 extension
 * lists, CMS/PKCS#7 SignedData, and Apple receipt payloads. Hand-rolled on
 * purpose (PLAN.md §1 + D8: dependency-light, auditable); supports definite
 * and indefinite (BER) lengths because genuine Apple/Xcode receipts use both.
 */

import { bytesEqual, concatBytes } from './bytes.js';

const MAX_DEPTH = 32;

export class ParseError extends Error {}

/** Parsed ASN.1 node. `contents` are value bytes; `children` when constructed. */
export interface ASN1Node {
  /** Full identifier byte (e.g. 0x30 SEQUENCE, 0xA0 [0] constructed). */
  tag: number;
  constructed: boolean;
  /** Complete TLV slice. */
  raw: Uint8Array;
  contents: Uint8Array;
  children: ASN1Node[] | null;
}

export function parse(buf: Uint8Array): ASN1Node {
  const [node, end] = readNode(buf, 0, 0);
  if (end !== buf.length) {
    throw new ParseError(`trailing bytes after ASN.1 value (${buf.length - end})`);
  }
  return node;
}

function readNode(buf: Uint8Array, off: number, depth: number): [ASN1Node, number] {
  if (depth > MAX_DEPTH) {
    throw new ParseError('maximum ASN.1 nesting depth exceeded');
  }
  if (off + 2 > buf.length) {
    throw new ParseError('truncated ASN.1 value');
  }
  const tag = buf[off]!;
  if ((tag & 0x1f) === 0x1f) {
    throw new ParseError('multi-byte ASN.1 tags are not supported');
  }
  const constructed = (tag & 0x20) !== 0;
  let pos = off + 1;
  const lenByte = buf[pos]!;
  pos += 1;
  let length: number | null;
  if (lenByte < 0x80) {
    length = lenByte;
  } else if (lenByte === 0x80) {
    length = null; // indefinite (BER) — constructed only
    if (!constructed) {
      throw new ParseError('indefinite length on a primitive value');
    }
  } else {
    const numBytes = lenByte & 0x7f;
    if (numBytes > 4 || pos + numBytes > buf.length) {
      throw new ParseError('unsupported ASN.1 length');
    }
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = length * 256 + buf[pos + i]!;
    }
    pos += numBytes;
  }

  if (length !== null) {
    const end = pos + length;
    if (end > buf.length) {
      throw new ParseError('ASN.1 length exceeds input');
    }
    const node: ASN1Node = {
      tag,
      constructed,
      raw: buf.subarray(off, end),
      contents: buf.subarray(pos, end),
      children: null,
    };
    if (constructed) {
      node.children = readChildren(node.contents, depth + 1);
    }
    return [node, end];
  }

  // Indefinite length: children until an end-of-contents (00 00) marker.
  const children: ASN1Node[] = [];
  for (;;) {
    if (pos + 2 > buf.length) {
      throw new ParseError('unterminated indefinite-length value');
    }
    if (buf[pos] === 0x00 && buf[pos + 1] === 0x00) {
      pos += 2;
      break;
    }
    const [child, next] = readNode(buf, pos, depth + 1);
    children.push(child);
    pos = next;
  }
  return [{
    tag,
    constructed: true,
    raw: buf.subarray(off, pos),
    contents: concatBytes(children.map((c) => c.raw)),
    children,
  }, pos];
}

function readChildren(contents: Uint8Array, depth: number): ASN1Node[] {
  const children: ASN1Node[] = [];
  let pos = 0;
  while (pos < contents.length) {
    const [child, next] = readNode(contents, pos, depth);
    children.push(child);
    pos = next;
  }
  return children;
}

/** Value bytes of an OCTET STRING, joining BER constructed chunks. */
export function octetStringValue(node: ASN1Node): Uint8Array {
  if (!node.constructed) {
    return node.contents;
  }
  return concatBytes((node.children ?? []).map((c) => octetStringValue(c)));
}

/** DER-encodes an OBJECT IDENTIFIER dotted string to its contents bytes. */
export function encodeOidContents(oid: string): Uint8Array {
  const parts = oid.split('.').map(Number);
  const bytes: number[] = [40 * parts[0]! + parts[1]!];
  for (let i = 2; i < parts.length; i++) {
    let value = parts[i]!;
    const chunk = [value & 0x7f];
    value = Math.floor(value / 128);
    while (value > 0) {
      chunk.unshift((value & 0x7f) | 0x80);
      value = Math.floor(value / 128);
    }
    bytes.push(...chunk);
  }
  return Uint8Array.from(bytes);
}

export const Tag = {
  INTEGER: 0x02,
  OCTET_STRING: 0x04,
  OCTET_STRING_CONSTRUCTED: 0x24,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  IA5_STRING: 0x16,
  CONTEXT_0: 0xa0,
  CONTEXT_1: 0xa1,
  CONTEXT_3: 0xa3,
} as const;

export function isOctetString(node: ASN1Node): boolean {
  return node.tag === Tag.OCTET_STRING || node.tag === Tag.OCTET_STRING_CONSTRUCTED;
}

interface TbsParts {
  serialNumber: ASN1Node;
  issuer: ASN1Node;
  extensions: ASN1Node | null;
}

/**
 * X.509 helpers built on the parser: positions per RFC 5280
 * Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }.
 */
export function tbsParts(certRaw: Uint8Array): TbsParts {
  const cert = parse(certRaw);
  if (cert.tag !== Tag.SEQUENCE || (cert.children ?? []).length < 3) {
    throw new ParseError('not an X.509 certificate');
  }
  const tbs = cert.children![0]!;
  const tbsChildren = tbs.children ?? [];
  let idx = 0;
  if (tbsChildren[idx]?.tag === Tag.CONTEXT_0) {
    idx += 1; // version [0] EXPLICIT
  }
  const serialNumber = tbsChildren[idx];
  const issuer = tbsChildren[idx + 2];
  if (serialNumber?.tag !== Tag.INTEGER || issuer?.tag !== Tag.SEQUENCE) {
    throw new ParseError('unexpected TBSCertificate layout');
  }
  let extensions: ASN1Node | null = null;
  for (const child of tbsChildren) {
    if (child.tag === Tag.CONTEXT_3) {
      extensions = child.children?.[0] ?? null;
    }
  }
  return { serialNumber, issuer, extensions };
}

/** Whether the certificate carries an extension with the given OID. */
export function hasExtension(certRaw: Uint8Array, oid: string): boolean {
  const { extensions } = tbsParts(certRaw);
  if (!extensions) {
    return false;
  }
  const wanted = encodeOidContents(oid);
  return (extensions.children ?? []).some(
    (ext) => ext.children?.[0]?.tag === Tag.OID && bytesEqual(ext.children[0].contents, wanted),
  );
}
