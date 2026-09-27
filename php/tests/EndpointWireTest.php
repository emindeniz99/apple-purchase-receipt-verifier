<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures07;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FrozenClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;

/**
 * What the shared endpoint cases cannot pin, because their runner compares
 * the response only after `json_decode`: the literal JSON text on the wire,
 * the request bodies that are hostile to PHP's own decoder, and the
 * receipt_type values no shared fixture carries.
 */
#[CoversClass(Verifier::class)]
final class EndpointWireTest extends TestCase
{
    private static function verifier(string $rootDer, ?ClockInterface $clock = null): Verifier
    {
        $builder = Config::builder()->roots([$rootDer]);
        if ($clock !== null) {
            $builder = $builder->clock($clock);
        }

        return Verifier::create($builder->build());
    }

    private static function body(string $der): string
    {
        return json_encode(['receipt-data' => base64_encode($der)], JSON_THROW_ON_ERROR);
    }

    /** @return iterable<string, array{?string}> */
    public static function malformedBodyProvider(): iterable
    {
        yield 'null' => [null];
        yield 'empty' => [''];
        yield 'not JSON' => ['{'];
        yield 'invalid UTF-8' => ["{\"receipt-data\":\"\xff\xfe\"}"];
        yield '100,000 unclosed objects' => [str_repeat('{', 100000)];
        yield '600 nested arrays' => [str_repeat('[', 600) . str_repeat(']', 600)];
        yield 'receipt-data true' => ['{"receipt-data":true}'];
        yield 'receipt-data a list' => ['{"receipt-data":["a"]}'];
        yield 'receipt-data an object' => ['{"receipt-data":{"0":"a"}}'];
        yield 'receipt-data not base64' => ['{"receipt-data":"!!!!!!"}'];
    }

    /**
     * Each of these is a TypeError, a JsonException or a stack overflow
     * waiting to happen in a PHP decoder; the endpoint answers them all
     * with the bare 21002 body.
     */
    #[DataProvider('malformedBodyProvider')]
    public function testAMalformedBodyAnswersTheBare21002Body(?string $body): void
    {
        self::assertSame(
            '{"status":21002}',
            self::verifier(MintedPki::get()->rootDer)->verifyReceiptEndpoint(Environment::Sandbox, $body),
        );
    }

    /** @return iterable<string, array{string, int}> */
    public static function receiptTypeProvider(): iterable
    {
        // Fails closed: only "Production" and "ProductionVPP" count as production.
        yield 'Production' => ['Production', 0];
        yield 'ProductionVPP' => ['ProductionVPP', 0];
        yield 'ProductionSandbox' => ['ProductionSandbox', 21007];
        yield 'ProductionVPPSandbox' => ['ProductionVPPSandbox', 21007];
        yield 'Xcode' => ['Xcode', 21007];
        yield 'a value Apple adds later' => ['SomethingAppleAddsLater', 21007];
        yield 'a different letter case' => ['production', 21007];
    }

    #[DataProvider('receiptTypeProvider')]
    public function testProductionRoutingFailsClosed(string $receiptType, int $expected): void
    {
        $pki = MintedPki::get();
        $payload = TestPki::payload(
            TestPki::utf8Attribute(0, $receiptType),
            TestPki::utf8Attribute(2, 'com.example.app'),
            TestPki::dateAttribute(12, '2024-08-06T12:00:00Z'),
        );
        $response = self::verifier($pki->rootDer)
            ->verifyReceiptEndpoint(Environment::Production, self::body($pki->receipt($payload)));
        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($response, true, 8, JSON_THROW_ON_ERROR);

        self::assertSame($expected, $decoded['status']);
    }

    /**
     * Apple renders in-app quantities, line item ids and the intro-offer flag
     * as STRINGS, which is easy to lose in a refactor and is what a
     * consumer's existing parser expects. The shared cases pin none of the
     * intro-offer flag and only one quantity.
     */
    public function testInAppFieldsKeepAppleWireTypes(): void
    {
        $pki = MintedPki::get();
        $payload = TestPki::payload(
            TestPki::utf8Attribute(0, 'ProductionSandbox'),
            TestPki::utf8Attribute(2, 'com.example.app'),
            TestPki::dateAttribute(12, '2024-08-06T12:00:00Z'),
            TestPki::attribute(17, TestPki::payload(
                TestPki::attribute(1701, TestPki::encodeInteger(2)),
                TestPki::utf8Attribute(1702, 'com.example.app.vip'),
                TestPki::utf8Attribute(1703, '70000000000002'),
                TestPki::dateAttribute(1704, '2024-02-01T09:30:00Z'),
                TestPki::attribute(1711, TestPki::encodeInteger(42)),
                TestPki::attribute(1719, TestPki::encodeInteger(1)),
            )),
        );
        $response = self::verifier($pki->rootDer)
            ->verifyReceiptEndpoint(Environment::Sandbox, self::body($pki->receipt($payload)));

        self::assertStringContainsString('"status":0', $response);
        self::assertStringContainsString('"quantity":"2"', $response);
        self::assertStringContainsString('"web_order_line_item_id":"42"', $response);
        self::assertStringContainsString('"is_in_intro_offer_period":"true"', $response);
        self::assertStringContainsString('"purchase_date_ms":"1706779800000"', $response);
        /** @var array{receipt: array{in_app: list<array<string, mixed>>}} $decoded */
        $decoded = json_decode($response, true, 8, JSON_THROW_ON_ERROR);
        $entry = $decoded['receipt']['in_app'][0];
        self::assertSame('2024-02-01 09:30:00 Etc/GMT', $entry['purchase_date']);
        self::assertSame('2024-02-01 01:30:00 America/Los_Angeles', $entry['purchase_date_pst']);
    }

    /**
     * Apple renders attributes 1 (twice, as adam_id and app_item_id), 15
     * and 16 as JSON numbers. download_id is 2^63-1, a nineteen-digit
     * integer an IEEE-754 double rounds to 2^63: asserting the literal JSON
     * TEXT, not a value json_decode hands back, proves the serializer never
     * routed the id through a float.
     */
    public function testLegacyReceiptIdsAreWireNumbersWithExactDigits(): void
    {
        $response = self::verifier(Fixtures07::bytes('receipt-ids-root'))
            ->verifyReceiptEndpoint(Environment::Production, self::body(Fixtures07::bytes('receipt-ids')));

        self::assertStringContainsString('"adam_id":1234567890', $response);
        self::assertStringContainsString('"app_item_id":1234567890', $response);
        self::assertStringContainsString('"download_id":9223372036854775807', $response);
        self::assertStringContainsString('"version_external_identifier":456789012', $response);
        self::assertStringContainsString('"is_trial_period":"false"', $response);
        self::assertStringContainsString('"is_trial_period":"true"', $response);
    }

    /**
     * The clock stands in only for a missing creation date. A receipt that
     * states one after its chain expired stays refused with the clock
     * pinned inside the chain's window, and its sibling dated inside the
     * window verifies with the clock pinned long after it.
     */
    public function testTheClockCannotMoveTheChainInstantOfADatedReceipt(): void
    {
        $root = Fixtures07::bytes('receipt-expired-root');
        $fresh = base64_encode(Fixtures07::bytes('receipt-expired-fresh'));
        $historical = base64_encode(Fixtures07::bytes('receipt-expired-historical'));

        foreach (['2020-06-01T00:00:00Z', '2099-01-01T00:00:00Z'] as $now) {
            $verifier = self::verifier($root, new FrozenClock(new DateTimeImmutable($now)));

            self::assertTrue($verifier->verifyReceipt($historical)->verified(), $now);
            self::assertSame(Reason::InvalidCertificate, $verifier->verifyReceipt($fresh)->failure?->reason, $now);
            self::assertSame(
                '{"status":21003}',
                $verifier->verifyReceiptEndpoint(
                    Environment::Sandbox,
                    json_encode(['receipt-data' => $fresh], JSON_THROW_ON_ERROR),
                ),
                $now,
            );
        }
    }

    /**
     * UNREADABLE_PAYLOAD tells an operator Apple signed bytes the parser
     * could not read; the parser's own error is what says why, so it
     * survives as the cause (docs/design/0.7-api.md, "cause").
     */
    public function testUnreadablePayloadKeepsTheParserErrorAsItsCause(): void
    {
        $verifier = self::verifier(
            Fixtures07::bytes('api-receipt-root'),
            new FrozenClock(new DateTimeImmutable('2025-01-01T00:00:00Z')),
        );
        $data = base64_encode(Fixtures07::bytes('receipt-content-not-asn1'));
        $failure = $verifier->verifyReceipt($data)->failure;

        self::assertSame(Reason::UnreadablePayload, $failure?->reason);
        self::assertNotNull($failure->cause);
        self::assertSame(
            '{"status":21009}',
            $verifier->verifyReceiptEndpoint(Environment::Sandbox, json_encode(['receipt-data' => $data], JSON_THROW_ON_ERROR)),
        );
    }
}
