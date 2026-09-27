<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\SystemClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\CountingClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FrozenClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Shape;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\ThrowingClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use ReflectionClass;
use ReflectionNamedType;
use Throwable;

/**
 * What the configured clock reaches.
 *
 * 0.7 changes the rule 0.6 had: a single {@see Config}-level clock now drives
 * BOTH `request_date` in the endpoint response AND the chain-validity check
 * whenever a receipt or JWS carries no signing date of its own
 * (docs/design/0.7-api.md, "Setup" — "the chain check when the receipt or
 * JWS carries no signing date, and request_date"). It never rejects a
 * payload for its own age: freshness is the caller's decision, and a
 * payload that DOES carry a date is judged at that date regardless of what
 * the clock reads.
 */
#[CoversClass(Verifier::class)]
#[CoversClass(SystemClock::class)]
final class ClockTest extends TestCase
{
    private const SIGNED_AT = 1722945600000; // 2024-08-06T12:00:00Z

    private static function verifierOver(string $rootDer, ?ClockInterface $clock = null): Verifier
    {
        $builder = Config::builder()->roots([$rootDer]);
        if ($clock !== null) {
            $builder = $builder->clock($clock);
        }

        return Verifier::create($builder->build());
    }

    private static function at(string $iso): FrozenClock
    {
        return new FrozenClock(new DateTimeImmutable($iso));
    }

    /** Freshness is the caller's decision: a 2024 payload still verifies. */
    public function testAPayloadIsNeverRejectedForItsAge(): void
    {
        $jws = MintedPki::get()->jws(MintedPki::transactionClaims());

        $result = self::verifierOver(MintedPki::get()->rootDer)->verifySignedData($jws);
        self::assertTrue($result->verified());
        self::assertSame(self::SIGNED_AT, self::signedDateFrom($result->payload->json));
    }

    public function testAPayloadWithoutASignedDateVerifies(): void
    {
        $jws = MintedPki::get()->jws([
            'bundleId' => 'com.example.app',
            'environment' => 'Sandbox',
            'productId' => 'com.example.app.pro',
        ]);

        $result = self::verifierOver(MintedPki::get()->rootDer)->verifySignedData($jws);
        self::assertTrue($result->verified());
        self::assertArrayNotHasKey('signedDate', (array) json_decode($result->payload->json, true));
    }

    /**
     * The chain here is expired by real time (UTCTime's two-digit year rule
     * maps "19"/"20" to 2019/2020, not 1919/1920 — the window is 2019–2020).
     * A dateless JWS
     * falls back to the checked instant, and it is the CONFIGURED clock —
     * not the system clock — that supplies it: frozen inside the window,
     * the chain is judged valid.
     */
    public function testADatelessJwsPayloadFallsBackToTheConfiguredClockNotTheSystemClock(): void
    {
        $expired = self::expiredChain();
        $jws = TestPki::jws(
            ['bundleId' => 'com.example.app', 'environment' => 'Sandbox'],
            $expired['jwsChain'],
            MintedPki::get()->jwsLeafKey,
        );
        $root = $expired['root'];

        $inside = self::verifierOver($root, self::at('2019-06-01T00:00:00Z'))->verifySignedData($jws);
        self::assertTrue($inside->verified(), 'a clock frozen inside the chain\'s validity window must accept it');

        $outside = self::verifierOver($root, self::at('2010-01-01T00:00:00Z'))->verifySignedData($jws);
        self::assertFalse($outside->verified(), 'a clock frozen outside the window must reject it');
        self::assertSame(Reason::InvalidCertificate, $outside->failure?->reason);
    }

    /** The receipt path's fallback reads the same configured clock. */
    public function testADatelessReceiptFallsBackToTheConfiguredClockNotTheSystemClock(): void
    {
        $expired = self::expiredChain();
        $root = $expired['root'];
        $dateless = TestPki::payload(
            TestPki::utf8Attribute(0, 'ProductionSandbox'),
            TestPki::utf8Attribute(2, 'com.example.app'),
        );
        $receipt = TestPki::receipt(
            $dateless,
            $expired['receiptChain'],
            $expired['receiptSignerSid'],
            MintedPki::get()->receiptSignerKey,
        );

        $inside = self::verifierOver($root, self::at('2019-06-01T00:00:00Z'))->verifyReceipt(base64_encode($receipt));
        self::assertTrue($inside->verified(), 'a clock frozen inside the chain\'s validity window must accept it');
        self::assertNull($inside->payload->receiptCreationDateMs);
        self::assertSame('com.example.app', $inside->payload->bundleId);

        $outside = self::verifierOver($root, self::at('2010-01-01T00:00:00Z'))->verifyReceipt(base64_encode($receipt));
        self::assertFalse($outside->verified(), 'a clock frozen outside the window must reject it');
        self::assertSame(Reason::InvalidCertificate, $outside->failure?->reason);
    }

    /**
     * The unified rule, end to end: the SAME clock drives `request_date` and
     * decides whether a dateless receipt's chain is currently valid.
     */
    public function testTheEndpointClockDrivesRequestDateAndTheChainValidityFallbackTogether(): void
    {
        $pki = MintedPki::get();
        $data = json_encode(['receipt-data' => base64_encode($pki->receipt())], JSON_THROW_ON_ERROR);

        $past = self::decode(
            self::verifierOver($pki->rootDer, self::at('2010-01-01T00:00:00Z'))
                ->verifyReceiptEndpoint(Environment::Sandbox, $data),
        );
        $future = self::decode(
            self::verifierOver($pki->rootDer, self::at('2030-01-01T00:00:00Z'))
                ->verifyReceiptEndpoint(Environment::Sandbox, $data),
        );

        $pastReceipt = Shape::asArray($past['receipt'], 'receipt');
        $futureReceipt = Shape::asArray($future['receipt'], 'receipt');

        self::assertSame(0, $past['status']);
        self::assertSame(0, $future['status']);
        self::assertNotSame($pastReceipt['request_date_ms'], $futureReceipt['request_date_ms']);
        self::assertSame(
            $pastReceipt['receipt_creation_date_ms'],
            $futureReceipt['receipt_creation_date_ms'],
            'request_date must move with the clock; the receipt\'s own creation date must not',
        );

        // And the same clock, frozen outside the minted chain's window,
        // fails the chain check for a DATELESS receipt built on it.
        $expired = self::expiredChain();
        $dateless = TestPki::payload(TestPki::utf8Attribute(0, 'ProductionSandbox'), TestPki::utf8Attribute(2, 'com.example.app'));
        $receipt = TestPki::receipt($dateless, $expired['receiptChain'], $expired['receiptSignerSid'], $pki->receiptSignerKey);
        $body = json_encode(['receipt-data' => base64_encode($receipt)], JSON_THROW_ON_ERROR);

        $rejected = self::decode(
            self::verifierOver($expired['root'], self::at('2010-01-01T00:00:00Z'))
                ->verifyReceiptEndpoint(Environment::Sandbox, $body),
        );
        self::assertNotSame(0, $rejected['status'], 'the endpoint clock must also gate a dateless receipt\'s chain');
    }

    public function testTheDefaultClockIsTheSystemClock(): void
    {
        $before = (int) (microtime(true) * 1000);
        $now = (int) (new SystemClock())->now()->format('Uv');
        $after = (int) (microtime(true) * 1000);

        self::assertGreaterThanOrEqual($before, $now);
        self::assertLessThanOrEqual($after, $now);
        self::assertSame('UTC', (new SystemClock())->now()->getTimezone()->getName());
        self::assertInstanceOf(SystemClock::class, Config::defaults()->clock);
    }

    /**
     * Mechanised: {@see Verifier}'s three public methods take no clock
     * parameter at all — the clock lives only in {@see Config}, fixed at
     * `Verifier::create()`, not something a per-call argument could smuggle
     * in to bypass what the chain was validated against.
     */
    public function testNoVerifierMethodExposesAClockSeam(): void
    {
        $class = new ReflectionClass(Verifier::class);
        foreach ($class->getMethods() as $method) {
            if (!$method->isPublic()) {
                continue;
            }
            foreach ($method->getParameters() as $parameter) {
                $type = $parameter->getType();
                $name = $type instanceof ReflectionNamedType ? $type->getName() : '';
                self::assertNotSame(
                    ClockInterface::class,
                    $name,
                    "Verifier::{$method->getName()}() takes a clock; it must not",
                );
            }
        }
    }

    /**
     * All three public methods document "never throws" — a caller-supplied
     * clock is exactly the kind of thing that could break that promise, so
     * a clock that throws on every read must still come back as a typed
     * failure everywhere the clock is read, not escape as a `Throwable`.
     *
     * The receipt and JWS paths read the clock only as part of establishing
     * trust (the chain-validity fallback for a dateless payload), so a
     * throw there is MALFORMED, per hardening parity change #4: nothing
     * unvouched-for may raise the internal-error alarm. `request_date` in
     * the endpoint is not about any one input's trust, so a throw there is
     * INTERNAL_ERROR — and reading it is a REAL BUG this test catches:
     * `verifyReceiptEndpoint()` read its clock before anything else in the
     * method body, outside the try/catch guarding the rest of it. The fix
     * wraps that read in its own try/catch reporting
     * {@see \EminDeniz99\ApplePurchaseReceiptVerifier\AppleStatus::InternalDataAccessError}.
     */
    public function testAThrowingClockNeverEscapesAnyPublicMethod(): void
    {
        $pki = MintedPki::get();
        $verifier = self::verifierOver($pki->rootDer, new ThrowingClock());

        // A dateless payload, so the clock fallback is actually reached:
        // a receipt or JWS carrying its own date never asks the clock at all.
        $datelessReceipt = TestPki::payload(
            TestPki::utf8Attribute(0, 'ProductionSandbox'),
            TestPki::utf8Attribute(2, 'com.example.app'),
        );
        try {
            $result = $verifier->verifyReceipt(base64_encode($pki->receipt($datelessReceipt)));
        } catch (Throwable $e) {
            self::fail('verifyReceipt escaped as ' . $e::class . ': ' . $e->getMessage());
        }
        self::assertFalse($result->verified());
        self::assertSame(Reason::Malformed, $result->failure?->reason);

        $datelessJws = $pki->jws(['bundleId' => 'com.example.app', 'environment' => 'Sandbox']);
        try {
            $jwsResult = $verifier->verifySignedData($datelessJws);
        } catch (Throwable $e) {
            self::fail('verifySignedData escaped as ' . $e::class . ': ' . $e->getMessage());
        }
        self::assertFalse($jwsResult->verified());
        self::assertSame(Reason::Malformed, $jwsResult->failure?->reason);

        $requestJson = json_encode(['receipt-data' => base64_encode($pki->receipt())], JSON_THROW_ON_ERROR);
        try {
            $response = $verifier->verifyReceiptEndpoint(Environment::Sandbox, $requestJson);
        } catch (Throwable $e) {
            self::fail('verifyReceiptEndpoint escaped as ' . $e::class . ': ' . $e->getMessage());
        }
        self::assertSame('{"status":21009}', $response);
    }

    /**
     * `verifyReceiptEndpoint()` reads the clock exactly once per call, for
     * `request_date`: two reads inside one call could stamp one answer with
     * two different instants.
     */
    public function testTheEndpointReadsTheClockExactlyOncePerCall(): void
    {
        $pki = MintedPki::get();
        $clock = new CountingClock();
        $verifier = self::verifierOver($pki->rootDer, $clock);
        $requestJson = json_encode(['receipt-data' => base64_encode($pki->receipt())], JSON_THROW_ON_ERROR);

        $verifier->verifyReceiptEndpoint(Environment::Sandbox, $requestJson);

        self::assertSame(1, $clock->reads);
    }

    /**
     * @return array{root: string, jwsChain: list<string>, receiptChain: list<string>, receiptSignerSid: string}
     */
    private static function expiredChain(): array
    {
        $pki = MintedPki::get();
        $validity = TestPki::validity('190101000000Z', '200101000000Z');
        $root = TestPki::certificate('Expired Root', 'Expired Root', $pki->rootKey, $pki->rootKey, true, [], $validity);
        $intermediate = TestPki::certificate(
            'Expired WWDR',
            'Expired Root',
            $pki->intermediateKey,
            $pki->rootKey,
            true,
            [TestPki::INTERMEDIATE_OID_HEX],
            $validity,
        );
        $jwsLeaf = TestPki::certificate(
            'Expired JWS Leaf',
            'Expired WWDR',
            $pki->jwsLeafKey,
            $pki->intermediateKey,
            false,
            [TestPki::LEAF_OID_HEX],
            $validity,
        );
        $receiptSigner = TestPki::certificate(
            'Expired Receipt Signer',
            'Expired WWDR',
            $pki->receiptSignerKey,
            $pki->intermediateKey,
            false,
            [TestPki::LEAF_OID_HEX],
            $validity,
        );

        return [
            'root' => $root['der'],
            'jwsChain' => [$jwsLeaf['der'], $intermediate['der'], $root['der']],
            'receiptChain' => [$receiptSigner['der'], $intermediate['der'], $root['der']],
            'receiptSignerSid' => $receiptSigner['sid'],
        ];
    }

    private static function signedDateFrom(string $json): ?int
    {
        /** @var array{signedDate?: int} $decoded */
        $decoded = json_decode($json, true, 8, JSON_THROW_ON_ERROR);

        return $decoded['signedDate'] ?? null;
    }

    /** @return array{status: int, receipt?: mixed} */
    private static function decode(string $response): array
    {
        /** @var array{status: int, receipt?: mixed} */
        return json_decode($response, true, 8, JSON_THROW_ON_ERROR);
    }
}
