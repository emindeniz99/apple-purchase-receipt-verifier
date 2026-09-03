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
