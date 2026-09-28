/**
 * Strict UTF-8 decode, shared by both builds. `TextDecoder` is lenient by
 * default — an invalid byte sequence becomes U+FFFD instead of failing —
 * which would let a JWS header, a JWS payload or a UTF8String receipt
 * attribute that is not valid UTF-8 "decode" successfully into a
 * replacement-character string. `fatal: true` throws instead;
 * `ignoreBOM: true` keeps a leading U+FEFF in the output rather than
 * stripping it, so callers can detect and reject one themselves (RFC 8259
 * §8.1 forbids a byte order mark on JSON text).
 */
const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Throws when `bytes` is not valid UTF-8. */
export function decodeStrictUtf8(bytes: Uint8Array): string {
  return STRICT_UTF8.decode(bytes);
}
