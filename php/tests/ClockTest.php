<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint;
use EminDeniz99\ApplePurchaseReceiptVerifier\SystemClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FrozenClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use ReflectionClass;
use ReflectionNamedType;

/**
 * What the injected clock may and may not move.
 *
 * The rule the whole design hangs on: the clock drives the staleness rule and
 * the endpoint's `request_date`, and NOTHING else. Certificate validity is
 * judged at the payload's own date, and where a payload states none, at the
 * SYSTEM clock. A caller injecting a clock — to test staleness, or to paper
 * over skew — must not thereby accept an expired chain or expire a live one.
 */
#[CoversClass(JwsVerifier::class)]
#[CoversClass(SystemClock::class)]
final class ClockTest extends TestCase
{
    private const SIGNED_AT = 1722945600000; // 2024-08-06T12:00:00Z

    private function verifier(?ClockInterface $clock, ?int $maxAgeSeconds): JwsVerifier
    {
        return new JwsVerifier(
            [MintedPki::get()->rootDer],
            'com.example.app',
            [Environment::Sandbox],
            null,
            $maxAgeSeconds,
            $clock,
        );
    }

    private static function at(string $iso): FrozenClock
    {
        return new FrozenClock(new DateTimeImmutable($iso));
    }

    /** @return iterable<string, array{string, int, bool}> */
    public static function stalenessProvider(): iterable
    {
        yield 'exactly at the limit' => ['2024-08-06T12:01:00Z', 60, true];
        yield 'one second past the limit' => ['2024-08-06T12:01:01Z', 60, false];
        yield 'one second inside the limit' => ['2024-08-06T12:00:59Z', 60, true];
        yield 'far past the limit' => ['2025-01-01T00:00:00Z', 60, false];
        yield 'before the payload was signed' => ['2024-08-06T11:00:00Z', 60, true];
    }

    #[DataProvider('stalenessProvider')]
    public function testTheClockDrivesTheStalenessRuleAtItsExactBoundary(
        string $now,
        int $maxAgeSeconds,
        bool $accepted,
    ): void {
        $jws = MintedPki::get()->jws(MintedPki::transactionClaims());
        $verifier = $this->verifier(self::at($now), $maxAgeSeconds);

        if ($accepted) {
            self::assertSame(self::SIGNED_AT, $verifier->verifyTransaction($jws)->signedDate);

            return;
        }
        try {
            $verifier->verifyTransaction($jws);
            self::fail('expected STALE_PAYLOAD');
        } catch (VerificationException $e) {
            self::assertSame(Reason::StalePayload, $e->reason);
        }
    }

    public function testWithNoMaxSignedAgeTheClockIsNeverConsulted(): void
    {
        $jws = MintedPki::get()->jws(MintedPki::transactionClaims());

        self::assertSame(
            self::SIGNED_AT,
            $this->verifier(self::at('2099-01-01T00:00:00Z'), null)->verifyTransaction($jws)->signedDate,
        );
    }

    /** A payload with no date of its own can never be stale. */
    public function testAPayloadWithoutASignedDateIsNeverStale(): void
    {
        $jws = MintedPki::get()->jws([
            'bundleId' => 'com.example.app',
            'environment' => 'Sandbox',
            'productId' => 'com.example.app.pro',
        ]);

        $payload = $this->verifier(self::at('2099-01-01T00:00:00Z'), 60)->verifyTransaction($jws);
        self::assertNull($payload->signedDate);
    }

    /**
     * The load-bearing one. The chain here is expired and the payload carries
     * no date, so validity falls back to the system clock. A clock planted
     * inside the expired window must NOT rescue it.
     */
    public function testAnInjectedClockCannotAuthenticateAnExpiredChain(): void
    {
        $pki = MintedPki::get();
        $expiredRoot = TestPki::certificate(
            'Expired Root',
            'Expired Root',
            $pki->rootKey,
            $pki->rootKey,
            true,
            [],
            TestPki::validity('190101000000Z', '200101000000Z'),
        );
        $expiredIntermediate = TestPki::certificate(
            'Expired WWDR',
            'Expired Root',
            $pki->intermediateKey,
            $pki->rootKey,
            true,
            [TestPki::INTERMEDIATE_OID_HEX],
            TestPki::validity('190101000000Z', '200101000000Z'),
        );
        $expiredLeaf = TestPki::certificate(
            'Expired Leaf',
            'Expired WWDR',
            $pki->jwsLeafKey,
            $pki->intermediateKey,
            false,
            [TestPki::LEAF_OID_HEX],
            TestPki::validity('190101000000Z', '200101000000Z'),
        );
        $jws = TestPki::jws(
            ['bundleId' => 'com.example.app', 'environment' => 'Sandbox'],
            [$expiredLeaf['der'], $expiredIntermediate['der'], $expiredRoot['der']],
            $pki->jwsLeafKey,
        );

        $verifier = new JwsVerifier(
            [$expiredRoot['der']],
            'com.example.app',
            [Environment::Sandbox],
            null,
            60,
            self::at('2019-06-01T00:00:00Z'), // inside the expired window
        );

        try {
            $verifier->verifyTransaction($jws);
            self::fail('an injected clock authenticated an expired chain');
        } catch (VerificationException $e) {
            self::assertSame(Reason::InvalidChain, $e->reason);
        }
    }

    /** The mirror image: a clock far in the future must not expire a live chain. */
    public function testAnInjectedClockCannotExpireAValidChain(): void
    {
        $jws = MintedPki::get()->jws(['bundleId' => 'com.example.app', 'environment' => 'Sandbox']);

        self::assertSame(
            'com.example.app',
            $this->verifier(self::at('2099-01-01T00:00:00Z'), 60)->verifyTransaction($jws)->bundleId,
        );
    }

    /**
     * C2/S6, mechanised: `ReceiptVerifier` must have no clock parameter at
     * all. An option with no consumer is an invitation to wire it into the
     * one place it must never reach, so this asserts the seam does not exist
     * rather than that it is unused.
     */
    public function testReceiptVerifierExposesNoClockSeamAnywhere(): void
    {
        $class = new ReflectionClass(ReceiptVerifier::class);
        foreach ($class->getMethods() as $method) {
            foreach ($method->getParameters() as $parameter) {
                $type = $parameter->getType();
                $name = $type instanceof ReflectionNamedType ? $type->getName() : '';
                self::assertNotSame(
                    ClockInterface::class,
                    $name,
                    "ReceiptVerifier::{$method->getName()}() takes a clock; it must not",
                );
                self::assertStringNotContainsStringIgnoringCase(
                    'clock',
                    $parameter->getName(),
                    "ReceiptVerifier::{$method->getName()}() has a clock-shaped parameter",
                );
            }
        }
        self::assertFalse($class->hasProperty('clock'));
    }

    /** The receipt path's fallback reads real time, so it is deterministic. */
    public function testAReceiptWithoutACreationDateIsJudgedAtTheSystemClock(): void
    {
        $pki = MintedPki::get();
        $dateless = TestPki::payload(
            TestPki::utf8Attribute(0, 'ProductionSandbox'),
            TestPki::utf8Attribute(2, 'com.example.app'),
        );

        // The minted chain is valid now, so a dateless receipt verifies.
        $receipt = (new ReceiptVerifier([$pki->rootDer], 'com.example.app'))->verify($pki->receipt($dateless));
        self::assertNull($receipt->creationDate);
        self::assertSame('com.example.app', $receipt->bundleId);
    }

    public function testTheDefaultClockIsTheSystemClock(): void
    {
        $before = (int) (microtime(true) * 1000);
        $now = (int) (new SystemClock())->now()->format('Uv');
        $after = (int) (microtime(true) * 1000);

        self::assertGreaterThanOrEqual($before, $now);
        self::assertLessThanOrEqual($after, $now);
        self::assertSame('UTC', (new SystemClock())->now()->getTimezone()->getName());
    }

    /** The endpoint's clock reaches request_date and nothing else. */
    public function testTheEndpointClockReachesOnlyTheRequestDate(): void
    {
        $pki = MintedPki::get();
        $data = ['receipt-data' => base64_encode($pki->receipt())];

        $past = (new VerifyReceiptEndpoint([$pki->rootDer], Environment::Sandbox, self::at('2000-01-01T00:00:00Z')))
            ->verifyReceipt($data);
        $future = (new VerifyReceiptEndpoint([$pki->rootDer], Environment::Sandbox, self::at('2099-01-01T00:00:00Z')))
            ->verifyReceipt($data);

        self::assertSame(0, $past['status'], 'a clock before the chain existed must not fail it');
        self::assertSame(0, $future['status'], 'a clock after it expires must not fail it either');
        self::assertNotSame($past['receipt']['request_date_ms'], $future['receipt']['request_date_ms']);
        self::assertSame(
            $past['receipt']['receipt_creation_date_ms'],
            $future['receipt']['receipt_creation_date_ms'],
        );
    }
}
