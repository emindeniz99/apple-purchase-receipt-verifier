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
