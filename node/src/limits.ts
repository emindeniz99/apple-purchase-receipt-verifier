/**
 * Input size caps, shared by both builds so the default and the web entry
 * point refuse the same inputs at the same numbers. Every one is checked
 * before the step it guards: base64 decoding, ASN.1 parsing and JSON parsing
 * all allocate in proportion to their input, and all of them run before any
 * signature has been checked. The numbers are the Java, PHP and Python
 * ports'.
 */

/**
 * Ceiling on a legacy receipt: the base64 string, in characters, before it
 * is decoded, and the DER, in bytes, before it is parsed. It clears the
 * floor in fixtures/cases.json, which requires accepting up to 1 MiB of DER
 * (about 1.38 MB of base64); the largest genuine receipt in the corpus is
 * 79 KB.
 */
export const MAX_RECEIPT_BYTES = 2097152;

/**
 * Ceiling on a raw verifyReceipt JSON request body, in UTF-8 bytes, before
 * it is parsed. Deliberately below {@link MAX_RECEIPT_BYTES}: the JSON path
 * parses the body as well as decoding the receipt inside it.
 */
export const MAX_REQUEST_BYTES = 1048576;

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
 * Whether `text` is longer than `max` bytes once encoded as UTF-8. The
 * encoder only runs when the answer is not already settled by the length in
 * UTF-16 code units, each of which encodes to one to three bytes, so it never
 * sees a string longer than `max`.
 */
export function utf8LengthExceeds(text: string, max: number): boolean {
  if (text.length > max) {
    return true;
  }
  if (text.length * 3 <= max) {
    return false;
  }
  return new TextEncoder().encode(text).length > max;
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
