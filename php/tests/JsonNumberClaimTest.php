<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FrozenClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * How a JSON number that is not written as a bare integer is typed.
 *
 * `json_decode` gives a PHP **float** for any JSON number carrying a decimal
 * point or an exponent, so `1722945600000.0` and `1.7229456e12` are floats
 * where `1722945600000` is an int. Reading only `is_int()` therefore made
 * Apple's own claim vocabulary conditional on its spelling, and every failure
 * was in the accept direction:
 *
 * - `signedDate` as a float disabled the `maxSignedAge` replay window entirely
 *   (`requireFresh()` returns early on a null);
 * - it moved the certificate-validity instant from the payload's stated
 *   signing time to the system clock, which PLAN.md §2.1 step 4 reserves for a
 *   payload that states NO date;
 * - `expiresDate` as a float made `isActiveAt()` answer "no expiry", i.e.
 *   entitled forever.
 *
 * All four shipped ports read the value: Node `typeof === 'number'`, Java
 * `canConvertToLong()`, Python `isinstance(x, (int, float))`, Swift
 * `as? Double`. PHP was the only outlier, so this is a conformance question as
 * well as a security one — no fixture in `cases.json` spells a date this way,
 * so the conformance suite cannot see it.
 *
 * The accepted envelope is Java's: finite, and inside the 64-bit range.
 * Outside it the claim stays ABSENT rather than being coerced into a bogus
 * timestamp, which is what keeps a `signedDate` past `PHP_INT_MAX` from
 * becoming a date.
 */
#[CoversClass(JwsVerifier::class)]
final class JsonNumberClaimTest extends TestCase
{
    private const SIGNED_AT = 1722945600000; // 2024-08-06T12:00:00Z

    /** Signs a JWS over a payload given as raw JSON TEXT, so the literal survives. */
    private static function jwsWithPayloadJson(
        string $payloadJson,
        ?string $leafDer = null,
        ?string $intermediateDer = null,
        ?string $rootDer = null,
        ?OpenSSLAsymmetricKey $leafKey = null,
    ): string {
        $pki = MintedPki::get();
        $header = TestPki::b64url((string) json_encode([
            'alg' => 'ES256',
            'x5c' => array_map(base64_encode(...), [
                $leafDer ?? $pki->jwsLeafDer,
                $intermediateDer ?? $pki->intermediateDer,
                $rootDer ?? $pki->rootDer,
            ]),
        ]));
        $signingInput = $header . '.' . TestPki::b64url($payloadJson);
        openssl_sign($signingInput, $der, $leafKey ?? $pki->jwsLeafKey, OPENSSL_ALGO_SHA256);

        return $signingInput . '.' . TestPki::b64url(TestPki::derToP1363((string) $der));
    }

    /** @return iterable<string, array{string}> */
    public static function signedDateSpellingProvider(): iterable
    {
        yield 'bare integer' => ['1722945600000'];
        yield 'trailing .0' => ['1722945600000.0'];
        yield 'exponent form' => ['1.7229456e12'];
    }

    /**
     * The replay window is the control an attacker most wants switched off,
     * and before the fix two of these three spellings switched it off.
     */
    #[DataProvider('signedDateSpellingProvider')]
    public function testEverySpellingOfSignedDateDrivesTheStalenessRule(string $literal): void
    {
        $jws = self::jwsWithPayloadJson(
            '{"bundleId":"com.example.app","environment":"Sandbox","signedDate":' . $literal . '}',
        );
        $verifier = new JwsVerifier(
            [MintedPki::get()->rootDer],
            'com.example.app',
            [Environment::Sandbox],
            null,
            60,
            new FrozenClock(new DateTimeImmutable('2025-01-01T00:00:00Z')),
        );

        try {
            $verifier->verifyTransaction($jws);
            self::fail("signedDate spelled `{$literal}` did not reach the staleness rule");
        } catch (VerificationException $e) {
            self::assertSame(Reason::StalePayload, $e->reason);
        }
    }

    /** And the value survives onto the typed payload, whatever its spelling. */
    #[DataProvider('signedDateSpellingProvider')]
    public function testEverySpellingOfSignedDateReachesTheTypedPayload(string $literal): void
    {
        $jws = self::jwsWithPayloadJson(
            '{"bundleId":"com.example.app","environment":"Sandbox","signedDate":' . $literal . '}',
        );
        $verifier = new JwsVerifier([MintedPki::get()->rootDer], 'com.example.app', [Environment::Sandbox]);

        self::assertSame(self::SIGNED_AT, $verifier->verifyTransaction($jws)->signedDate);
    }

    /**
     * The certificate-validity instant. The chain here expired in 2020 and the
     * float `signedDate` sits inside its window, so honouring the claim is
     * what makes this verify at all: before the fix the claim read as absent,
     * validity fell back to the system clock, and a payload Apple signed while
     * the chain was live was rejected as `INVALID_CHAIN`.
     */
    public function testAFloatSignedDateIsTheCertificateValidityInstant(): void
    {
        $pki = MintedPki::get();
        $window = TestPki::validity('190101000000Z', '200101000000Z');
        $root = TestPki::certificate('Old Root', 'Old Root', $pki->rootKey, $pki->rootKey, true, [], $window);
        $intermediate = TestPki::certificate(
            'Old WWDR',
            'Old Root',
            $pki->intermediateKey,
            $pki->rootKey,
            true,
            [TestPki::INTERMEDIATE_OID_HEX],
            $window,
        );
        $leaf = TestPki::certificate(
            'Old Leaf',
            'Old WWDR',
            $pki->jwsLeafKey,
            $pki->intermediateKey,
            false,
            [TestPki::LEAF_OID_HEX],
            $window,
        );
        // 2019-06-01T00:00:00Z, written the way json_decode types as a float.
        $jws = self::jwsWithPayloadJson(
            '{"bundleId":"com.example.app","environment":"Sandbox","signedDate":1559347200000.0}',
            $leaf['der'],
            $intermediate['der'],
            $root['der'],
        );

        $payload = (new JwsVerifier([$root['der']], 'com.example.app', [Environment::Sandbox]))
            ->verifyTransaction($jws);

        self::assertSame(1559347200000, $payload->signedDate);
    }

    /**
     * `isActiveAt()` fails OPEN on a missing `expiresDate` — correctly, since a
     * non-subscription has none. So a float `expiresDate` reading as absent
     * turned an expired subscription into a permanent entitlement.
     */
    public function testAFloatExpiresDateStillExpiresTheSubscription(): void
    {
        $jws = self::jwsWithPayloadJson(
            '{"bundleId":"com.example.app","environment":"Sandbox","expiresDate":1722945600000.0}',
        );
        $payload = (new JwsVerifier([MintedPki::get()->rootDer], 'com.example.app', [Environment::Sandbox]))
            ->verifyTransaction($jws);

        self::assertSame(self::SIGNED_AT, $payload->expiresDate);
        self::assertTrue($payload->isActiveAt(new DateTimeImmutable('2024-08-06T11:00:00Z')));
        self::assertFalse(
            $payload->isActiveAt(new DateTimeImmutable('2025-01-01T00:00:00Z')),
            'a float expiresDate left the subscription entitled forever',
        );
    }

    /**
     * The other half of the rule, and the reason the envelope is bounded
     * rather than "any float": a number `json_decode` degraded to a float
     * because it exceeds `PHP_INT_MAX` must stay absent, not become a date in
     * the year 3.9 billion. Java's `canConvertToLong()` draws the same line.
     *
     * @return iterable<string, array{string}>
     */
    public static function unrepresentableNumberProvider(): iterable
    {
        yield 'beyond PHP_INT_MAX' => ['123456789012345678901234567890'];
        yield 'far beyond, in exponent form' => ['1.0e300'];
        yield 'negative and far beyond' => ['-1.0e300'];
    }

    #[DataProvider('unrepresentableNumberProvider')]
    public function testANumberOutsideTheSixtyFourBitRangeStaysAbsent(string $literal): void
    {
        $jws = self::jwsWithPayloadJson(
            '{"bundleId":"com.example.app","environment":"Sandbox","signedDate":' . $literal . '}',
        );
        $verifier = new JwsVerifier(
            [MintedPki::get()->rootDer],
            'com.example.app',
            [Environment::Sandbox],
            null,
            60,
            new FrozenClock(new DateTimeImmutable('2099-01-01T00:00:00Z')),
        );

        // Absent, so the staleness rule does not apply and nothing is coerced.
        $payload = $verifier->verifyTransaction($jws);
        self::assertNull($payload->signedDate);
        self::assertIsFloat($payload->claims['signedDate'], 'the raw claim is still reachable, as a float');
    }

    /** A claim that is not a number at all is still absent, not coerced. */
    public function testANonNumericDateClaimIsAbsentRatherThanCoerced(): void
    {
        $jws = self::jwsWithPayloadJson(
            '{"bundleId":"com.example.app","environment":"Sandbox","signedDate":"1722945600000"}',
        );
        $payload = (new JwsVerifier([MintedPki::get()->rootDer], 'com.example.app', [Environment::Sandbox]))
            ->verifyTransaction($jws);

        self::assertNull($payload->signedDate, 'a numeric STRING must not become a timestamp');
        self::assertSame('1722945600000', $payload->claims['signedDate']);
    }
}
