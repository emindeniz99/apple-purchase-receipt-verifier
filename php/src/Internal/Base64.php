<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

/**
 * base64 / base64url decoding, ported from the Node reader.
 *
 * PHP's own `base64_decode($s, true)` is stricter than
 * `Buffer.from(s, 'base64')`: it rejects the unpadded segments a JWS carries,
 * the line breaks a PEM body carries, and the URL-safe alphabet. Rather than
 * pre-massaging the input differently in three call sites — which is how two
 * ports end up disagreeing about which inputs are decodable at all — this
 * mirrors the shared reader in `node/src/bytes.ts`: characters outside both
 * alphabets are skipped, and both alphabets are accepted, so one function
 * serves base64url too.
 *
 * ## The shipped ports do NOT agree about this, and this one follows Node
 *
 * Measured, not assumed. Appending a byte outside the alphabet to a JWS
 * signature segment (86 chars, so length ≡ 2 mod 4):
 *
 * | port   | `\0`, ` `, `!` | `=` |
 * |--------|----------------|-----|
 * | Node   | accepted       | accepted |
 * | PHP    | accepted       | accepted |
 * | Python | rejected (`Incorrect padding` — the pad it appends is computed from the raw length) | accepted |
 * | Java   | rejected (`Illegal base64 character`) | rejected (`wrong 4-byte ending unit`) |
 *
 * So there is no behaviour that matches all four, and even the two strict
 * ports disagree with each other on `=`. The contract's S9 says "reject
 * trailing garbage after the CMS blob" and says nothing about base64 segment
 * leniency; no case in `cases.json` exercises it. This port therefore follows
 * the reader it was ported from rather than inventing a fifth answer, and
 * `Base64Test` pins the choice so it stays deliberate.
 *
 * Leniency here is not a security property, and nothing forgeable rides on
 * it: a JWS signature covers the literal `header.payload` segment TEXT, so
 * garbage tolerated in those two segments changes the signing input and
 * breaks the signature. Only the signature segment is malleable, and altering
 * it cannot change a claim. Nothing downstream trusts a decode having
 * "succeeded" either — the bytes still have to be a parseable certificate,
 * CMS blob or JSON object.
 *
 * ## The three compact-JWS segments no longer go through this leniency
 *
 * `decode()` above still serves `x5c` certificate entries (a PEM/CMS
 * container, not a JWS segment) exactly as measured. The header, payload and
 * signature segments of a compact JWS are decoded by {@see decodeStrict()}
 * instead: RFC 7515 §2 defines them as unpadded canonical base64url, and
 * `fixtures/cases.json` now pins that a byte outside the alphabet, a `=`, or
 * a noncanonical final character in any of the three makes the JWS
 * `INVALID_JWS_FORMAT` — the leniency table above is therefore about
 * `decode()`'s remaining caller, not about compact-JWS segments.
 *
 * ## Receipt base64 is a third, separate rule: {@see decodeReceipt()}
 *
 * `ReceiptVerifier` and `VerifyReceiptEndpoint` no longer route through the
 * Node-derived `decode()` above. `fixtures/cases.json`'s "Receipt base64"
 * paragraph pins Apple's own rule instead — RFC 4648 base64, either alphabet,
 * padding present or omitted, CR/LF/space/tab tolerated anywhere — which is
 * neither this class's skip-and-ignore leniency nor `decodeStrict()`'s
 * no-whitespace canonical rule.
 *
 * @internal
 */
final class Base64
{
    /** @var array<int, int>|null lazily built code point => 6-bit value */
    private static ?array $values = null;

    public static function decode(string $text): string
    {
        $table = self::$values ??= self::table();
        $out = '';
        $accumulator = 0;
        $bits = 0;
        for ($i = 0, $n = strlen($text); $i < $n; ++$i) {
            $value = $table[ord($text[$i])] ?? -1;
            if ($value < 0) {
                continue;
            }
            $accumulator = ($accumulator << 6) | $value;
            $bits += 6;
            if ($bits >= 8) {
                $bits -= 8;
                $out .= chr(($accumulator >> $bits) & 0xff);
            }
        }

        return $out;
    }

    /**
     * Strict base64url decode for one compact-JWS segment (RFC 7515 §2):
     * the unpadded base64url alphabet only, and the canonical encoding of
     * whatever bytes come out. Returns null — never throws — for anything
     * else, so a caller attaches its own {@see \EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException}
     * message; unlike {@see decode()}, this never skips a character.
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
     * Decodes the base64 text a client sends as `receipt-data` (legacy
     * `verify(String)` and the `verifyReceipt` endpoint), per Apple's own
     * rule for what `base64EncodedString(options:)` can emit: RFC 4648
     * Base64, standard `+/` or base64url `-_` (never mixed in one string),
     * padding present or omitted, with CR, LF, space or tab tolerated
     * anywhere. Returns null — never throws — for anything else, including
     * an empty or whitespace-only string, a character outside both
     * alphabets, non-padding text after the padding, or a stripped length
     * with `len % 4 === 1`. There is no canonical-trailing-bits check, unlike
     * {@see decodeStrict()}.
     */
    public static function decodeReceipt(string $text): ?string
    {
        $stripped = preg_replace('/[ \t\r\n]/', '', $text) ?? '';
        if ($stripped === '' || strlen($stripped) % 4 === 1) {
            return null;
        }
        if (preg_match('/\A([A-Za-z0-9+\/_-]*)(=*)\z/', $stripped, $matches) !== 1) {
            // Either a character outside both alphabets, or non-padding text
            // after the padding started.
            return null;
        }
        $body = $matches[1];
        if (str_contains($body, '+') || str_contains($body, '/')) {
            if (str_contains($body, '-') || str_contains($body, '_')) {
                return null; // both alphabets in one string
            }
        }
        $data = strtr($body, '-_', '+/');
        $padded = $data . str_repeat('=', (4 - strlen($data) % 4) % 4);
        $decoded = base64_decode($padded, true);

        return $decoded === false ? null : $decoded;
    }

    /** @return array<int, int> */
    private static function table(): array
    {
        $table = [];
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        for ($i = 0; $i < 64; ++$i) {
            $table[ord($alphabet[$i])] = $i;
        }
        $table[ord('-')] = 62;
        $table[ord('_')] = 63;

        return $table;
    }
}
