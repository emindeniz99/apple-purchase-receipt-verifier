/**
 * `verifySignedData(jws)`: any Apple-signed compact JWS (StoreKit 2
 * `jwsRepresentation`, App Store Server `signedTransactionInfo` and
 * `signedRenewalInfo`, app transactions, Server Notifications V2), verified
 * offline.
 *
 * ES256 only, exactly three `x5c` certificates, the chain to a pinned root
 * at the payload's `signedDate` (the clock when it states none), Apple's
 * marker OIDs on leaf and intermediate, then the signature. The order of
 * the checks is observable: an input that fails an early check reports
 * that check's reason, and the shared cases pin it.
 */
import { asciiEncode, base64Decode, base64UrlDecodeStrict, isCanonicalBase64 } from './bytes.js';
import { callClock } from './call-clock.js';
import { validatePair } from './chain.js';
import { requireBuildablePublicKey, verifyEs256 } from './crypto.js';
import { Reason, VerificationError } from './errors.js';
import {
  JsonError,
  asInstantMs,
  asString,
  asStringArray,
  onlyWhitespaceAfter,
  parseOneValue,
  parseWholeObject,
} from './json.js';
import { MAX_JWS_BYTES, utf8LengthExceeds } from './limits.js';
import { quote } from './safe-text.js';
import { decodeStrictUtf8 } from './strict-utf8.js';
import { parseCertificate, type ParsedCertificate } from './x509.js';

/** A verified JWS payload: the JSON object Apple signed, unchanged. */
export interface JsonPayload {
  readonly json: string;
}

/** Builds a {@link JsonPayload} by hand, for callers' own tests. */
export function createJsonPayload(json: string): JsonPayload {
  return { json };
}

const LEAF_OID = '1.2.840.113635.100.6.11.1';
const INTERMEDIATE_OID = '1.2.840.113635.100.6.2.1';

export { MAX_JWS_BYTES };

/**
 * Names only the exception's class (docs/design/0.7-api.md, Result), never
 * its message: an unexpected error here runs on input
 * nobody has vouched for, so its message may itself quote that input.
 */
function describeError(e: unknown): string {
  if (e instanceof Error) {
    return e.constructor.name;
  }
  return typeof e;
}

export function verifySignedData(
  jws: string,
  anchors: readonly ParsedCertificate[],
  now: () => number,
): JsonPayload {
  if (jws === '') {
    throw new VerificationError(Reason.MALFORMED, 'jws is empty');
  }
  if (utf8LengthExceeds(jws, MAX_JWS_BYTES)) {
    throw new VerificationError(
      Reason.TOO_LARGE,
      `jws exceeds the maximum accepted size of ${MAX_JWS_BYTES} bytes`,
    );
  }
  try {
    return verifyUnguarded(jws, anchors, callClock(now));
  } catch (cause) {
    if (cause instanceof VerificationError) {
      throw cause;
    }
    // Contains any unexpected error before the signature has verified
    // (docs/design/0.7-api.md, Setup): everything up to here
    // runs on input nobody has vouched for, so it is MALFORMED, never
    // INTERNAL_ERROR, which would let anyone raise that alert at will.
    throw new VerificationError(
      Reason.MALFORMED,
      `unexpected error: ${describeError(cause)}`,
      cause,
    );
  }
}

function verifyUnguarded(
  jws: string,
  anchors: readonly ParsedCertificate[],
  now: () => number,
): JsonPayload {
  const parts = jws.split('.');
  if (parts.length !== 3) {
    throw new VerificationError(
      Reason.MALFORMED,
      `expected 3 dot-separated segments, got ${parts.length}`,
    );
  }
  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];
  const headerBytes = base64UrlDecodeStrict(headerB64);
  if (headerBytes === null) {
    throw new VerificationError(Reason.MALFORMED, 'header is not canonical base64url');
  }
  const payloadBytes = base64UrlDecodeStrict(payloadB64);
  if (payloadBytes === null) {
    throw new VerificationError(Reason.MALFORMED, 'payload is not canonical base64url');
  }
  const signature = base64UrlDecodeStrict(signatureB64);
  if (signature === null) {
    throw new VerificationError(Reason.MALFORMED, 'signature is not canonical base64url');
  }

  const header = readHeader(headerBytes);
  if (header.alg !== 'ES256') {
    throw new VerificationError(Reason.MALFORMED, `alg must be ES256, got ${quote(header.alg)}`);
  }
  if (header.x5c === null || header.x5c.length !== 3) {
    throw new VerificationError(Reason.MALFORMED, 'x5c must contain exactly 3 certificates');
  }
  const leaf = parseX5cCertificate(header.x5c[0]!);
  const intermediate = parseX5cCertificate(header.x5c[1]!);
  // Parsed and then dropped: the third entry is trusted by nobody, and
  // reading it decides only whether it IS a certificate.
  parseX5cCertificate(header.x5c[2]!);

  const payload = readPayload(payloadBytes);
  // Chain validity is judged at the payload's signing date, so a payload
  // signed with a since-rotated certificate keeps verifying.
  const atMs = payload.signedDateMs ?? now();
  validatePair(leaf, intermediate, anchors, atMs);
  // The marker OIDs after the chain, as on the receipt path (owner,
  // 2026-09-27): a foreign chain is UNTRUSTED_CHAIN whatever it carries, and
  // only a pinned chain can be the wrong kind of Apple certificate. Still
  // before the leaf's key checks the JWS signature.
  if (!leaf.hasExtension(LEAF_OID)) {
    throw new VerificationError(
      Reason.INVALID_CERTIFICATE_PURPOSE,
      `leaf certificate lacks Apple marker OID ${LEAF_OID}`,
    );
  }
  if (!intermediate.hasExtension(INTERMEDIATE_OID)) {
    throw new VerificationError(
      Reason.INVALID_CERTIFICATE_PURPOSE,
      `intermediate certificate lacks Apple marker OID ${INTERMEDIATE_OID}`,
    );
  }
  // The leaf's key is about to check the JWS signature; judged only once
  // trusted, same as the intermediate inside validatePair.
  requireBuildablePublicKey(leaf);
  const signingInput = asciiEncode(`${headerB64}.${payloadB64}`);
  if (!verifyEs256(leaf.spki, signature, signingInput)) {
    throw new VerificationError(
      Reason.INVALID_SIGNATURE,
      'ES256 signature does not match the leaf key',
    );
  }
  if (payload.json === null) {
    throw new VerificationError(
      Reason.UNREADABLE_PAYLOAD,
      `signed payload is not a JSON object: ${payload.problem}`,
    );
  }
  return createJsonPayload(payload.json);
}

interface Header {
  alg: string | null;
  x5c: string[] | null;
}

/**
 * What verification reads from the header: the last `alg` and `x5c`
 * members. The header is outer structure, so anything that stops the read
 * is MALFORMED: bytes that are not strict UTF-8, a byte order mark
 * (RFC 8259 §8.1 forbids one), and anything but whitespace after the
 * object.
 */
function readHeader(bytes: Uint8Array): Header {
  let text: string;
  try {
    text = decodeStrictUtf8(bytes);
  } catch {
    throw new VerificationError(Reason.MALFORMED, 'header is not UTF-8');
  }
  if (text.startsWith('﻿')) {
    throw new VerificationError(Reason.MALFORMED, 'header starts with a byte order mark');
  }
  try {
    const members = parseWholeObject(text);
    return { alg: asString(members.get('alg')), x5c: asStringArray(members.get('x5c')) };
  } catch (cause) {
    if (cause instanceof JsonError) {
      throw new VerificationError(
        Reason.MALFORMED,
        `header is not valid JSON: ${cause.message}`,
        cause,
      );
    }
    throw cause;
  }
}

interface PayloadRead {
  json: string | null;
  problem: string | null;
  signedDateMs: number | null;
}

/**
 * What verification reads from the payload: the text, if it is a JSON
 * object in UTF-8 with nothing but whitespace after it and no byte order
 * mark before it, and its last top-level `signedDate`. Reading it never
 * fails verification by itself; a payload that does not parse is carried to
 * the signature check.
 */
function readPayload(bytes: Uint8Array): PayloadRead {
  let text: string;
  try {
    text = decodeStrictUtf8(bytes);
  } catch {
    return { json: null, problem: 'not UTF-8', signedDateMs: null };
  }
  if (text.startsWith('﻿')) {
    return { json: null, problem: 'starts with a byte order mark', signedDateMs: null };
  }
  let value;
  let end;
  try {
    ({ value, end } = parseOneValue(text));
  } catch {
    return { json: null, problem: 'not valid JSON', signedDateMs: null };
  }
  if (value.kind !== 'object') {
    return { json: null, problem: 'not an object', signedDateMs: null };
  }
  if (!onlyWhitespaceAfter(text, end)) {
    return { json: null, problem: 'content after the object', signedDateMs: null };
  }
  const signedDate = asInstantMs(value.members.get('signedDate'));
  return {
    json: text,
    problem: null,
    signedDateMs: signedDate === null ? null : Number(signedDate),
  };
}

/**
 * Decodes one `x5c` entry: standard base64 with canonical padding
 * (RFC 7515 §4.1.6). Exported so a decodeBase64 conformance case can reach
 * it directly.
 */
export function decodeX5cEntry(text: string): Uint8Array {
  if (!isCanonicalBase64(text)) {
    throw new VerificationError(
      Reason.INVALID_CERTIFICATE,
      'x5c entry is not canonical standard base64',
    );
  }
  return base64Decode(text);
}

/** Only whether the entry IS a certificate; its key is judged once trusted. */
function parseX5cCertificate(entry: string): ParsedCertificate {
  const der = decodeX5cEntry(entry);
  try {
    return parseCertificate(der);
  } catch (cause) {
    throw new VerificationError(
      Reason.INVALID_CERTIFICATE,
      'x5c entry is not a valid certificate',
      cause,
    );
  }
}
