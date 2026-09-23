<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

/**
 * The two base64 rules this library decodes by, each with PHP's own
 * `base64_decode($s, true)` doing the decoding and a check in front of it
 * for what that function does not enforce.
 *
 * {@see decodeStrict()}: the three segments of a compact JWS, which RFC 7515
 * §2 defines as unpadded canonical base64url. `fixtures/cases.json` pins that
 * a byte outside the alphabet, a `=`, or a noncanonical final character in
 * any of the three makes the JWS `INVALID_JWS_FORMAT`.
 *
 * {@see decodeCanonical()}: `receipt-data` and x5c entries, canonical
 * standard base64 and nothing else. It is the rule Apple's verifyReceipt
 * applies to `receipt-data` (measured 2026-09-23,
 * `docs/evidence/2026-09-23-verifyreceipt-base64.md`) and the one RFC 7515
 * §4.1.6 gives an x5c entry.
 *
 * @internal
 */
final class Base64
{
    private const STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    /**
     * Strict base64url decode for one compact-JWS segment (RFC 7515 §2):
     * the unpadded base64url alphabet only, and the canonical encoding of
     * whatever bytes come out. Returns null — never throws — for anything
     * else, so a caller attaches its own {@see \EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException}
     * message.
     *
     * Rejected: any byte outside `A-Za-z0-9-_` (including `=`), a length
     * with `len % 4 === 1` (impossible for base64), and a final character
     * whose unused low bits are not all zero — checked by re-encoding the
     * decoded bytes and requiring the result to equal the input segment,
     * since PHP's own `base64_decode($s, true)` does not enforce that.
     */
    public static function decodeStrict(string $segment): ?string
    {
        if (preg_match('/\A[A-Za-z0-9_-]*\z/', $segment) !== 1 || strlen($segment) % 4 === 1) {
            return null;
        }
        $padded = strtr($segment, '-_', '+/');
        $padded .= str_repeat('=', (4 - strlen($padded) % 4) % 4);
        $decoded = base64_decode($padded, true);
        if ($decoded === false) {
            return null;
        }
        $reencoded = strtr(rtrim(base64_encode($decoded), '='), '+/', '-_');
        if ($reencoded !== $segment) {
            return null;
        }

        return $decoded;
    }

    /**
     * Decodes non-empty standard base64 (`[A-Za-z0-9+/]`) carrying exactly
     * the canonical `=` padding for its length, and nothing else. Returns
     * null, never throws, for anything else: whitespace anywhere,
     * base64url, omitted or extra padding, text after the padding, the empty
     * string. Unused low bits in the last data character are accepted, as
     * Apple accepts them.
     *
     * `base64_decode($s, true)` enforces the alphabet and the padding run,
     * but it skips CR, LF, space and tab, accepts omitted padding and
     * decodes `''`. So the length and the characters are checked first: a
     * non-zero multiple of four, and only the alphabet before at most two
     * trailing `=`. strspn() rather than a regex, so a 3 MiB receipt is one
     * native scan with no copy.
     */
    public static function decodeCanonical(string $text): ?string
    {
        $length = strlen($text);
        if ($length === 0 || $length % 4 !== 0) {
            return null;
        }
        $pad = $text[$length - 1] !== '=' ? 0 : ($text[$length - 2] !== '=' ? 1 : 2);
        if (strspn($text, self::STANDARD_ALPHABET, 0, $length - $pad) !== $length - $pad) {
            return null;
        }
        $decoded = base64_decode($text, true);

        return $decoded === false ? null : $decoded;
    }
}
