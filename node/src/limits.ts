/**
 * Input size caps, shared by both builds so the default and the web entry
 * point refuse the same inputs at the same numbers. Every one is checked
 * before the step it guards: base64 decoding, ASN.1 parsing and JSON parsing
 * all allocate in proportion to their input, and all of them run before any
 * signature has been checked. The receipt and request caps are Apple's own
 * limit and the same fixed constants in every port.
 */

/**
 * Ceiling on a legacy receipt: the base64 string, in UTF-8 bytes, before it
 * is decoded, and the DER, in bytes, before it is parsed. 3 MiB: Apple's
 * verifyReceipt refuses a request body over 3,145,728 bytes (measured
 * 2026-09-23), so no receipt it would accept is larger. For base64, which is
 * what a receipt string is, bytes and characters are the same count.
 */
export const MAX_RECEIPT_BYTES = 3145728;

/**
 * Ceiling on a raw verifyReceipt JSON request body, in UTF-8 bytes, before
 * it is parsed: 3 MiB, Apple's own limit. Measured on 2026-09-23 against
 * both of Apple's verifyReceipt endpoints, a body of 3,145,728 bytes is
 * answered and one of 3,145,729 bytes gets HTTP 413, and the count is bytes,
 * not characters.
 */
export const MAX_REQUEST_BYTES = 3145728;

/**
 * Ceiling on a compact JWS, in characters, before it is split or decoded.
 * Apple's JWS payloads are a few kilobytes, three certificates included.
 */
export const MAX_JWS_BYTES = 262144;

/**
 * How many arrays and objects a JSON text may have open at once: a
 * verifyReceipt body, and a JWS header or payload. `JSON.parse` has no depth
 * option, so the depth is counted before it runs.
 */
export const MAX_JSON_NESTING_DEPTH = 64;

/**
 * Whether `text` is longer than `max` bytes once encoded as UTF-8, measured
 * without encoding it. A JS string holds UTF-16 code units: every unit costs
 * at least one byte, so more units than `max` is over; every unit costs at
 * most three bytes (a surrogate pair is two units and four bytes), so three
 * times the units within `max` is within it. Only a string between the two
 * is walked, and the walk stops at the first byte past `max`. A lone
 * surrogate counts three bytes, what `TextEncoder` emits for it (U+FFFD).
 */
export function utf8LengthExceeds(text: string, max: number): boolean {
  const units = text.length;
  if (units > max) {
    return true;
  }
  if (units * 3 <= max) {
    return false;
  }
  let bytes = 0;
  for (let i = 0; i < units; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x80) {
      bytes += 1;
    } else if (c < 0x800) {
      bytes += 2;
    } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < units) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        i++;
      } else {
        bytes += 3;
      }
    } else {
      bytes += 3;
    }
    if (bytes > max) {
      return true;
    }
  }
  return false;
}

/**
 * Whether `text` opens more than {@link MAX_JSON_NESTING_DEPTH} arrays and
 * objects at once, counting brackets outside string literals only. Text that
 * is not JSON may be miscounted either way; `JSON.parse` refuses it anyway.
 */
export function jsonNestingExceeds(text: string): boolean {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (c === 0x5c /* \ */) {
        i++;
      } else if (c === 0x22 /* " */) {
        inString = false;
      }
    } else if (c === 0x22) {
      inString = true;
    } else if (c === 0x5b /* [ */ || c === 0x7b /* { */) {
      if (++depth > MAX_JSON_NESTING_DEPTH) {
        return true;
      }
    } else if (c === 0x5d /* ] */ || c === 0x7d /* } */) {
      depth--;
    }
  }
  return false;
}
