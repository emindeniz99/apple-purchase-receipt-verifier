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
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Shape;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use ReflectionClass;
use ReflectionNamedType;

/**
 * What the injected clock may and may not move.
 *
 * The rule the whole design hangs on: the endpoint's clock drives its
 * `request_date`, and NOTHING else. The JWS and receipt verifiers take no
 * clock, and no payload is rejected for its age (PLAN.md D5). Certificate
 * validity is judged at the payload's own date, and where a payload states
 * none, at the system clock.
 */
#[CoversClass(JwsVerifier::class)]
#[CoversClass(SystemClock::class)]
final class ClockTest extends TestCase
{
    private const SIGNED_AT = 1722945600000; // 2024-08-06T12:00:00Z

    private function verifier(): JwsVerifier
    {
        return new JwsVerifier([MintedPki::get()->rootDer], 'com.example.app', [Environment::Sandbox]);
    }

    private static function at(string $iso): FrozenClock
    {
        return new FrozenClock(new DateTimeImmutable($iso));
    }

    /** Freshness is the caller's decision: a 2024 payload still verifies. */
    public function testAPayloadIsNeverRejectedForItsAge(): void
    {
        $jws = MintedPki::get()->jws(MintedPki::transactionClaims());

        self::assertSame(self::SIGNED_AT, $this->verifier()->verifyTransaction($jws)->signedDate);
    }

    /**
     * PHP passes surplus positional arguments through silently, so a caller
     * still handing over the removed max age and clock must be refused rather
     * than lose the check without a word.
     */
    public function testTheRemovedMaxAgeAndClockArgumentsAreRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new JwsVerifier([MintedPki::get()->rootDer], 'com.example.app', [Environment::Sandbox], null, 60);
    }

    public function testAPayloadWithoutASignedDateVerifies(): void
    {
        $jws = MintedPki::get()->jws([
            'bundleId' => 'com.example.app',
            'environment' => 'Sandbox',
            'productId' => 'com.example.app.pro',
        ]);

        self::assertNull($this->verifier()->verifyTransaction($jws)->signedDate);
    }

    /**
     * The chain here is expired and the payload carries no date, so validity
     * falls back to the system clock, where the chain has expired.
     */
    public function testADatelessPayloadUnderAnExpiredChainIsJudgedAtTheSystemClock(): void
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

        $verifier = new JwsVerifier([$expiredRoot['der']], 'com.example.app', [Environment::Sandbox]);

        try {
            $verifier->verifyTransaction($jws);
            self::fail('a dateless payload under an expired chain verified');
        } catch (VerificationException $e) {
            self::assertSame(Reason::InvalidChain, $e->reason);
        }
    }

    /**
     * C2/S6, mechanised: neither verifier may have a clock parameter at all.
     * An option with no consumer is an invitation to wire it into the one
     * place it must never reach, so this asserts the seam does not exist
     * rather than that it is unused.
     */
    public function testNoVerifierExposesAClockSeamAnywhere(): void
    {
        foreach ([ReceiptVerifier::class, JwsVerifier::class] as $verifier) {
            $class = new ReflectionClass($verifier);
            foreach ($class->getMethods() as $method) {
                foreach ($method->getParameters() as $parameter) {
                    $type = $parameter->getType();
                    $name = $type instanceof ReflectionNamedType ? $type->getName() : '';
                    self::assertNotSame(
                        ClockInterface::class,
                        $name,
                        "{$verifier}::{$method->getName()}() takes a clock; it must not",
                    );
                    self::assertStringNotContainsStringIgnoringCase(
                        'clock',
                        $parameter->getName(),
                        "{$verifier}::{$method->getName()}() has a clock-shaped parameter",
                    );
                }
            }
            self::assertFalse($class->hasProperty('clock'));
        }
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
            ->verifyReceiptResult($data)->toResponse();
        $future = (new VerifyReceiptEndpoint([$pki->rootDer], Environment::Sandbox, self::at('2099-01-01T00:00:00Z')))
            ->verifyReceiptResult($data)->toResponse();

        $pastReceipt = Shape::asArray($past['receipt'], 'receipt');
        $futureReceipt = Shape::asArray($future['receipt'], 'receipt');

        self::assertSame(0, $past['status'], 'a clock before the chain existed must not fail it');
        self::assertSame(0, $future['status'], 'a clock after it expires must not fail it either');
        self::assertNotSame($pastReceipt['request_date_ms'], $futureReceipt['request_date_ms']);
        self::assertSame(
            $pastReceipt['receipt_creation_date_ms'],
            $futureReceipt['receipt_creation_date_ms'],
        );
    }
}
