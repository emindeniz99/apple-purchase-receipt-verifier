<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\AppTransactionPayload;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\TransactionPayload;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;

/**
 * The JWS parts of verification that are not cryptography: segment shape,
 * header requirements, claim typing, and the bundle-id / environment /
 * app-Apple-id / staleness checks.
 *
 * @internal
 */
final class JwsClaims
{
    /** Apple marker OID: leaf certificate used for App Store signing. */
    public const LEAF_OID = '1.2.840.113635.100.6.11.1';

    /** Apple marker OID: Worldwide Developer Relations intermediate CA. */
    public const INTERMEDIATE_OID = '1.2.840.113635.100.6.2.1';

    /** Far above any Apple payload; the JSON default of 512 is needlessly deep. */
    private const JSON_MAX_DEPTH = 64;

    /**
     * Splits a compact JWS and applies the header requirements.
     *
     * @return array{string, string, string, list<string>} the base64url
     *         header, payload and signature segments, and the x5c chain
     *
     * @throws VerificationException
     */
    public static function split(string $jws): array
    {
        $parts = explode('.', $jws);
        if (count($parts) !== 3) {
            throw new VerificationException(
                Reason::InvalidJwsFormat,
                'expected 3 dot-separated segments, got ' . count($parts),
            );
        }
        $header = self::parseJsonSegment($parts[0], 'header');
        if (($header['alg'] ?? null) !== 'ES256') {
            throw new VerificationException(Reason::InvalidJwsFormat, 'alg must be ES256');
        }
        $x5c = $header['x5c'] ?? null;
        if (!is_array($x5c) || !array_is_list($x5c) || count($x5c) !== 3) {
            throw new VerificationException(Reason::InvalidJwsFormat, 'x5c must contain exactly 3 certificates');
        }
        foreach ($x5c as $entry) {
            if (!is_string($entry)) {
                throw new VerificationException(Reason::InvalidJwsFormat, 'x5c must contain exactly 3 certificates');
            }
        }

        /** @var list<string> $x5c */
        return [$parts[0], $parts[1], $parts[2], $x5c];
    }

    /**
     * @return array<string, mixed>
     *
     * @throws VerificationException
     */
    public static function parseJsonSegment(string $segment, string $what): array
    {
        $decoded = Base64::decodeStrict($segment);
        if ($decoded === null) {
            throw new VerificationException(Reason::InvalidJwsFormat, "{$what} is not valid base64url");
        }
        try {
            $parsed = json_decode($decoded, true, self::JSON_MAX_DEPTH, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new VerificationException(Reason::InvalidJwsFormat, "{$what} is not valid base64url JSON", $e);
        }
        if (!is_array($parsed) || ($parsed !== [] && array_is_list($parsed))) {
            throw new VerificationException(Reason::InvalidJwsFormat, "{$what} is not a JSON object");
        }

        /** @var array<string, mixed> $parsed */
        return $parsed;
    }

    /**
     * The largest and smallest values a signed 64-bit integer holds, as
     * doubles. `(float) PHP_INT_MAX` rounds UP to 2^63, so the upper bound is
     * exclusive: a float at exactly 2^63 is outside the `int` range even
     * though it compares equal to `(float) PHP_INT_MAX`.
     */
    private const INT64_MIN_AS_FLOAT = -9.2233720368547758E18;
    private const INT64_MAX_EXCLUSIVE_AS_FLOAT = 9.2233720368547758E18;

    /**
     * An integral claim as an `int`, or null when it is absent or cannot be
     * one.
     *
     * `json_decode` types any JSON number written with a decimal point or an
     * exponent as a PHP **float** — `1722945600000.0` and `1.7229456e12` are
     * floats where `1722945600000` is an int — and degrades an integer beyond
     * `PHP_INT_MAX` to a float too. Reading only `is_int()` conflated those two
     * very different things and treated both as ABSENT, which fails OPEN on
     * three separate rules: the `maxSignedAge` replay window stops being
     * enforced, the certificate-validity instant slides to the system clock
     * (PLAN.md §2.1 step 4 reserves that for a payload stating no date at
     * all), and `isActiveAt()` reads a float `expiresDate` as "no expiry".
     * All four shipped ports read the value — Node `typeof === 'number'`,
     * Java `canConvertToLong()`, Python `isinstance(x, (int, float))`, Swift
     * `as? Double`.
     *
     * A float is therefore honoured when it is finite and inside the 64-bit
     * range, truncating toward zero — the same envelope and the same rounding
     * as Java's `canConvertToLong()` / `asLong()`. Outside it the claim stays
     * absent, so a number too large to be an `int` still cannot become a date.
     * The two SIGNING-TIME claims are the exception and do not come through
     * here: see {@see signedAtMillis()}, where "stated but unrepresentable"
     * has to be told apart from "not stated".
     */
    private static function integral(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value;
        }
        if (!is_float($value) || !is_finite($value)) {
            return null;
        }
        if ($value < self::INT64_MIN_AS_FLOAT || $value >= self::INT64_MAX_EXCLUSIVE_AS_FLOAT) {
            return null;
        }

        return (int) $value;
    }

    /**
     * When the payload says it was signed, in epoch milliseconds:
     * `signedDate` for transactions, `receiptCreationDate` for
     * AppTransactions, null when neither is present.
     *
     * @param array<string, mixed> $claims
     */
    public static function signedAtMillis(array $claims): ?int
    {
        foreach (['signedDate', 'receiptCreationDate'] as $key) {
            $value = $claims[$key] ?? null;
            if (!is_int($value) && !is_float($value)) {
                continue;
            }
            $millis = self::integral($value);
            if ($millis === null) {
                // The claim IS stated, it just cannot be represented — 1e300,
                // NaN, Infinity. Reporting it absent would fall through to the
                // caller's current-time anchor, which hands an attacker the
                // instant the certificate windows are judged at. An instant no
                // calendar can express is inside no window.
                throw new VerificationException(
                    Reason::InvalidChain,
                    'payload signing date is not a valid instant',
                );
            }

            return $millis;
        }

        return null;
    }

    /** @param array<string, mixed> $claims */
    private static function str(array $claims, string $key): ?string
    {
        $value = $claims[$key] ?? null;

        return is_string($value) ? $value : null;
    }

    /** @param array<string, mixed> $claims */
    private static function int(array $claims, string $key): ?int
    {
        return self::integral($claims[$key] ?? null);
    }

    /** @param array<string, mixed> $claims */
    public static function toTransaction(array $claims): TransactionPayload
    {
        return new TransactionPayload(
            bundleId: self::str($claims, 'bundleId'),
            environment: self::str($claims, 'environment'),
            productId: self::str($claims, 'productId'),
            transactionId: self::str($claims, 'transactionId'),
            originalTransactionId: self::str($claims, 'originalTransactionId'),
            webOrderLineItemId: self::str($claims, 'webOrderLineItemId'),
            subscriptionGroupIdentifier: self::str($claims, 'subscriptionGroupIdentifier'),
            appAccountToken: self::str($claims, 'appAccountToken'),
            inAppOwnershipType: self::str($claims, 'inAppOwnershipType'),
            type: self::str($claims, 'type'),
            transactionReason: self::str($claims, 'transactionReason'),
            storefront: self::str($claims, 'storefront'),
            currency: self::str($claims, 'currency'),
            offerIdentifier: self::str($claims, 'offerIdentifier'),
            signedDate: self::int($claims, 'signedDate'),
            purchaseDate: self::int($claims, 'purchaseDate'),
            originalPurchaseDate: self::int($claims, 'originalPurchaseDate'),
            expiresDate: self::int($claims, 'expiresDate'),
            revocationDate: self::int($claims, 'revocationDate'),
            price: self::int($claims, 'price'),
            quantity: self::int($claims, 'quantity'),
            offerType: self::int($claims, 'offerType'),
            revocationReason: self::int($claims, 'revocationReason'),
            claims: $claims,
        );
    }

    /** @param array<string, mixed> $claims */
    public static function toAppTransaction(array $claims): AppTransactionPayload
    {
        return new AppTransactionPayload(
            bundleId: self::str($claims, 'bundleId'),
            receiptType: self::str($claims, 'receiptType'),
            applicationVersion: self::str($claims, 'applicationVersion'),
            originalApplicationVersion: self::str($claims, 'originalApplicationVersion'),
            deviceVerification: self::str($claims, 'deviceVerification'),
            deviceVerificationNonce: self::str($claims, 'deviceVerificationNonce'),
            appTransactionId: self::str($claims, 'appTransactionId'),
            appAppleId: self::int($claims, 'appAppleId'),
            receiptCreationDate: self::int($claims, 'receiptCreationDate'),
            originalPurchaseDate: self::int($claims, 'originalPurchaseDate'),
            preorderDate: self::int($claims, 'preorderDate'),
            versionExternalIdentifier: self::int($claims, 'versionExternalIdentifier'),
            claims: $claims,
        );
    }
}
