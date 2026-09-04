/**
 * Runtime-neutral byte helpers: everything the shared parsing code used to
 * reach `Buffer` for. Uint8Array only, so the same modules load on Node and
 * on WebCrypto-only isolates (Vercel Edge, flagless Workers) where there is
 * no `Buffer` and no `node:*`.
 */

/** Concatenates byte runs (the `Buffer.concat` the DER reader needs). */
export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) {
    total += part.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Content equality. Not constant time — same as the `Buffer.equals` it replaces. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Constant-time equality for secrets compared against attacker-supplied
 * bytes (the receipt messageDigest and device hash), where the Node build
 * uses `crypto.timingSafeEqual`. Length is compared first, exactly as
 * `timingSafeEqualPadded` does: the lengths are public.
 */
export function timingSafeBytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

const HEX = '0123456789abcdef';

/** Lowercase hex, matching `Buffer.toString('hex')`. */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) {
    out += HEX[byte >> 4]! + HEX[byte & 0x0f]!;
  }
  return out;
}

// ignoreBOM keeps a leading U+FEFF instead of stripping it, which is what
// Buffer.toString('utf8') does; both replace malformed sequences with U+FFFD.
const UTF8 = new TextDecoder('utf-8', { ignoreBOM: true });

/** UTF-8 decode, matching `Buffer.toString('utf8')`. */
export function utf8Decode(bytes: Uint8Array): string {
  return UTF8.decode(bytes);
}

/** ASCII (really Latin-1) encode — JWS signing input, PEM bodies. */
export function asciiEncode(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    out[i] = text.charCodeAt(i) & 0xff;
  }
  return out;
}

// Hand-rolled rather than atob(): atob exists in all four targets, but it
// returns a binary *string* that then has to be walked back into bytes, it
// rejects the unpadded and line-wrapped input real receipts and JWS segments
// carry, and its error behaviour differs across those runtimes. Decoding to
// bytes directly is both shorter and behaviourally identical to the
// `Buffer.from(text, 'base64' | 'base64url')` the Node build uses: characters
// outside the alphabet (whitespace, padding, PEM line breaks) are skipped,
// and both alphabets are accepted, so one function serves base64url too.
const BASE64_VALUES = (() => {
  const table = new Int8Array(128).fill(-1);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (let i = 0; i < alphabet.length; i++) {
    table[alphabet.charCodeAt(i)] = i;
  }
  table['-'.charCodeAt(0)] = 62;
  table['_'.charCodeAt(0)] = 63;
  return table;
})();

/** base64 / base64url decode; skips anything outside both alphabets. */
export function base64Decode(text: string): Uint8Array {
  const out = new Uint8Array(((text.length + 3) >> 2) * 3);
  let length = 0;
  let accumulator = 0;
  let bits = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    const value = code < 128 ? BASE64_VALUES[code]! : -1;
    if (value < 0) {
      continue;
    }
    accumulator = (accumulator << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[length++] = (accumulator >> bits) & 0xff;
    }
  }
  return out.subarray(0, length);
}

// receipt-data as Apple's own client can send it: RFC 4648, either the
// standard (`+/`) or base64url (`-_`) alphabet — never both in the same
// string — padding present or omitted, and CR/LF/space/tab anywhere
// (Foundation's base64EncodedString(options:) line-wraps at 64 or 76
// columns). Unlike base64UrlDecodeStrict this has no canonical-trailing-bits
// check — that is not part of the receipt-data contract.
const RECEIPT_BASE64_PATTERN = /^[A-Za-z0-9+/_-]*={0,2}$/;

/**
 * Strict receipt-data base64 decode (the `verifyReceiptBase64` / `receipt-data`
 * contract, PLAN §receipt-base64). Strips CR, LF, space and tab first, then
 * rejects: any other character; a string mixing the standard and base64url
 * alphabets; anything (beyond the already-stripped whitespace) after the
 * `=` padding; a stripped length congruent to 1 mod 4; a `=` count that
 * does not match what the unpadded data length requires (over- or
 * under-padded); and an empty or whitespace-only string. Returns null
 * rather than throwing.
 */
export function receiptBase64DecodeStrict(text: string): Uint8Array | null {
  const stripped = text.replace(/[\r\n \t]/g, '');
  if (
    stripped.length === 0 ||
    stripped.length % 4 === 1 ||
    !RECEIPT_BASE64_PATTERN.test(stripped)
  ) {
    return null;
  }
  const hasStandard = stripped.includes('+') || stripped.includes('/');
  const hasUrlSafe = stripped.includes('-') || stripped.includes('_');
  if (hasStandard && hasUrlSafe) {
    return null;
  }
  const pad = stripped.length - stripped.replace(/=+$/, '').length;
  const data = stripped.length - pad;
  if (pad !== 0 && pad !== (4 - (data % 4)) % 4) {
    return null;
  }
  return base64Decode(stripped);
}

/**
 * Strict, canonical base64url decode — RFC 7515 §2's compact-JWS segment
 * alphabet (`A-Za-z0-9-_`), no padding. Rejects a character outside that
 * alphabet, an impossible length (`length % 4 === 1`), or a final character
 * whose unused bits are non-zero, by re-encoding the decoded bytes with
 * {@link base64UrlEncode} and requiring an exact match — the same test a
 * lenient decode-then-skip pass cannot make. Returns null rather than
 * throwing; JWS-format callers turn that into their own VerificationError.
 */
export function base64UrlDecodeStrict(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    return null;
  }
  const decoded = base64Decode(text);
  return base64UrlEncode(decoded) === text ? decoded : null;
}

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// Hand-rolled for the same reason base64Decode is, and one more: btoa()
// takes a binary *string*, so bytes have to be walked into one first, and
// it is not present in every runtime this build targets. Unpadded, because
// that is the only form JWK members take (RFC 7515 §2).
/** base64url encode, unpadded — the encoding every JWK member uses. */
export function base64UrlEncode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const chunk = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out +=
      BASE64URL_ALPHABET[(chunk >> 18) & 0x3f]! +
      BASE64URL_ALPHABET[(chunk >> 12) & 0x3f]! +
      BASE64URL_ALPHABET[(chunk >> 6) & 0x3f]! +
      BASE64URL_ALPHABET[chunk & 0x3f]!;
  }
  const left = bytes.length - i;
  if (left === 1) {
    const chunk = bytes[i]! << 16;
    out += BASE64URL_ALPHABET[(chunk >> 18) & 0x3f]! + BASE64URL_ALPHABET[(chunk >> 12) & 0x3f]!;
  } else if (left === 2) {
    const chunk = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out +=
      BASE64URL_ALPHABET[(chunk >> 18) & 0x3f]! +
      BASE64URL_ALPHABET[(chunk >> 12) & 0x3f]! +
      BASE64URL_ALPHABET[(chunk >> 6) & 0x3f]!;
  }
  return out;
}
