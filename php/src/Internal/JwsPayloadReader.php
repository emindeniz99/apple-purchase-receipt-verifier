<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;

/**
 * The JWS parts of verification that are not cryptography: header
 * requirements and reading `signedDate` out of the payload
 * (docs/design/0.7-api.md §2).
 *
 * `json_decode()` already refuses anything but whitespace after a complete
 * top-level value (RFC 8259 allows leading/trailing whitespace around the
 * document; PHP's decoder enforces exactly that, verified natively), so no
 * separate "trailing content" scan is needed beyond the structural bounds
 * this class checks first.
 *
 * @internal
 */
final class JwsPayloadReader
{
    /** Far above any Apple payload; also what {@see BoundedJson} measures independently. */
    private const JSON_MAX_DEPTH = 65;

    /**
     * The header's `alg` and `x5c`, or throws. Anything that stops the read
     * is {@see Reason::Malformed}: bytes that are not strict UTF-8, a
     * structural bound exceeded, invalid JSON, or content after the object.
     *
     * @return array{?string, ?list<string>}
     *
     * @throws VerificationException
     */
    public static function readHeader(string $headerBytes): array
    {
        if (preg_match('//u', $headerBytes) !== 1) {
            throw new VerificationException(Reason::Malformed, 'header is not UTF-8');
        }
        if (BoundedJson::exceedsBounds($headerBytes)) {
            throw new VerificationException(Reason::Malformed, 'header is nested too deeply');
        }
        // Decoded to objects, not associative arrays: an associative decode
        // turns `[]` and `{}` into the same PHP value, and `{"0":…,"1":…}`
        // into a list, so an array could pass for an object and an object
        // for an array.
        try {
            $decoded = json_decode($headerBytes, false, self::JSON_MAX_DEPTH, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new VerificationException(Reason::Malformed, 'header is not valid JSON', $e);
        }
        if (!$decoded instanceof \stdClass) {
            throw new VerificationException(Reason::Malformed, 'header is not a JSON object');
        }
        $alg = $decoded->alg ?? null;
        $alg = is_string($alg) ? $alg : null;
        $x5c = $decoded->x5c ?? null;
        // A JSON array decodes to a PHP list here, and nothing else does.
        if (!is_array($x5c) || !self::allStrings($x5c)) {
            $x5c = null;
        }

        /** @var list<string>|null $x5c */
        return [$alg, $x5c];
    }

    /**
     * What verification reads from the payload: the text, if it is a JSON
     * object in UTF-8 with nothing but whitespace after it, and its
     * top-level `signedDate`. Reading it never fails verification by
     * itself; a payload that does not parse is carried to the signature
     * check and reported only if the signature verifies.
     *
     * @return array{?string, ?int, ?string} [jsonText, signedDateMs, problem]
     */
    public static function readPayload(string $payloadBytes): array
    {
        if (preg_match('//u', $payloadBytes) !== 1) {
            return [null, null, 'not UTF-8'];
        }
        if (BoundedJson::exceedsBounds($payloadBytes)) {
            return [null, null, 'nested too deeply'];
        }
        $decoded = json_decode($payloadBytes, false, self::JSON_MAX_DEPTH);
        if ($decoded === null && json_last_error() !== JSON_ERROR_NONE) {
            return [null, null, 'not valid JSON'];
        }
        if (!$decoded instanceof \stdClass) {
            return [null, null, 'not an object'];
        }

        return [$payloadBytes, self::signedAtMillis($decoded->signedDate ?? null), null];
    }

    /**
     * The claim as epoch milliseconds, or `null` when no signed 64-bit
     * value holds it: absent, not a number, a bool, or out of range. A
     * fraction or exponent is truncated toward zero when it lies within
     * range (docs/design/0.7-api.md: "a JWS signedDate that is not a
     * representable instant... is then judged at the clock").
     */
    private static function signedAtMillis(mixed $raw): ?int
    {
        if (is_bool($raw) || (!is_int($raw) && !is_float($raw))) {
            return null;
        }
        if (is_int($raw)) {
            return $raw;
        }
        if (!is_finite($raw)) {
            return null;
        }
        // The largest and smallest values a signed 64-bit integer holds, as
        // doubles: `(float) PHP_INT_MAX` rounds UP to 2^63, so the upper
        // bound is exclusive.
        if ($raw < -9.2233720368547758E18 || $raw >= 9.2233720368547758E18) {
            return null;
        }

        return (int) $raw;
    }

    /** @param array<mixed> $values */
    private static function allStrings(array $values): bool
    {
        foreach ($values as $value) {
            if (!is_string($value)) {
                return false;
            }
        }

        return true;
    }
}
