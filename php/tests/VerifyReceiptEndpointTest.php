<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FrozenClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\TestPki;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The verifyReceipt wire-compatible endpoint.
 *
 * Its contract is "never throws": every failure is a `status` in the body.
 * Most of what follows is therefore about inputs that would make a normal
 * method throw.
 */
#[CoversClass(VerifyReceiptEndpoint::class)]
final class VerifyReceiptEndpointTest extends TestCase
{
    private function endpoint(
        Environment $environment = Environment::Sandbox,
        ?FrozenClock $clock = null,
        ?string $root = null,
    ): VerifyReceiptEndpoint {
        return new VerifyReceiptEndpoint([$root ?? MintedPki::get()->rootDer], $environment, $clock);
    }

    public function testAnswersZeroAndTheAppleShapedBodyForAGenuineReceipt(): void
    {
        $body = $this->endpoint()->verifyReceipt([
            'receipt-data' => base64_encode(MintedPki::get()->receipt()),
        ]);

        self::assertSame(0, $body['status']);
        self::assertSame('Sandbox', $body['environment']);
        self::assertSame('ProductionSandbox', $body['receipt']['receipt_type']);
        self::assertSame('com.example.app', $body['receipt']['bundle_id']);
        self::assertSame('1.2.3', $body['receipt']['application_version']);
        self::assertSame('1.0', $body['receipt']['original_application_version']);
        self::assertSame('2024-08-06 12:00:00 Etc/GMT', $body['receipt']['receipt_creation_date']);
        self::assertSame('1722945600000', $body['receipt']['receipt_creation_date_ms']);
        self::assertSame('2024-08-06 05:00:00 America/Los_Angeles', $body['receipt']['receipt_creation_date_pst']);
        self::assertSame([], $body['receipt']['in_app']);
    }

    /** @return iterable<string, array{mixed}> */
    public static function malformedBodyProvider(): iterable
    {
        yield 'null' => [null];
        yield 'a scalar' => [42];
        yield 'a string' => ['receipt-data'];
        yield 'a bool' => [true];
        yield 'an empty array' => [[]];
        yield 'a list' => [['a', 'b']];
        yield 'receipt-data absent' => [['password' => 'x']];
        yield 'receipt-data empty' => [['receipt-data' => '']];
        yield 'receipt-data an integer' => [['receipt-data' => 1]];
        yield 'receipt-data true' => [['receipt-data' => true]];
        yield 'receipt-data an array' => [['receipt-data' => ['a']]];
        yield 'receipt-data null' => [['receipt-data' => null]];
        yield 'receipt-data not base64' => [['receipt-data' => '!!!!!!']];
        yield 'receipt-data invalid utf-8' => [['receipt-data' => "\xff\xfe\xfd"]];
    }

    #[DataProvider('malformedBodyProvider')]
    public function testAMalformedBodyAnswers21002(mixed $body): void
    {
        self::assertSame(21002, $this->endpoint()->verifyReceipt($body)['status']);
    }

    public function testAnUnauthenticatedReceiptAnswers21003(): void
    {
        $pki = MintedPki::get();
        $body = $this->endpoint(Environment::Sandbox, null, $pki->foreignRootDer)->verifyReceipt([
            'receipt-data' => base64_encode($pki->receipt()),
        ]);

        self::assertSame(21003, $body['status']);
        self::assertArrayNotHasKey('receipt', $body, 'nothing verified-so-far is returned');
        self::assertArrayNotHasKey('environment', $body);
    }

    public function testPasswordAndExcludeOldTransactionsAreAcceptedAndIgnored(): void
    {
        $data = base64_encode(MintedPki::get()->receipt());
        // A fixed clock, so the only thing that could differ between the two
        // bodies is the effect of the two ignored fields.
        $clock = new FrozenClock(new DateTimeImmutable('2025-01-01T00:00:00Z'));
        $plain = $this->endpoint(Environment::Sandbox, $clock)->verifyReceipt(['receipt-data' => $data]);
        $decorated = $this->endpoint(Environment::Sandbox, $clock)->verifyReceipt([
            'receipt-data' => $data,
            'password' => 'a-shared-secret-we-cannot-check-offline',
            'exclude-old-transactions' => true,
        ]);

        self::assertSame($plain, $decorated);
        self::assertSame(0, $plain['status']);
    }

    public function testRequestDateComesFromTheInjectedClock(): void
    {
        $clock = new FrozenClock(new DateTimeImmutable('2025-01-01T00:00:00Z'));
        $body = $this->endpoint(Environment::Sandbox, $clock)->verifyReceipt([
            'receipt-data' => base64_encode(MintedPki::get()->receipt()),
        ]);

        self::assertSame('2025-01-01 00:00:00 Etc/GMT', $body['receipt']['request_date']);
        self::assertSame('1735689600000', $body['receipt']['request_date_ms']);
        self::assertSame('2024-12-31 16:00:00 America/Los_Angeles', $body['receipt']['request_date_pst']);
    }

    /**
     * The `_pst` rendering is US Pacific, which is a DST-observing zone. Both
     * sides of a transition are pinned so a timezone-database change or a
     * "simplify to UTC-8" refactor shows up here.
     */
    public function testThePstRenderingFollowsUsPacificAcrossADstTransition(): void
    {
        $cases = [
            // 2025-03-09 10:00 UTC is 02:00 PST → 03:00 PDT, just after the spring-forward.
            ['2025-03-09T10:00:00Z', '2025-03-09 03:00:00 America/Los_Angeles'],
            // One hour earlier is still PST.
            ['2025-03-09T09:00:00Z', '2025-03-09 01:00:00 America/Los_Angeles'],
            // 2025-11-02 08:00 UTC is 01:00 PDT; 09:00 UTC is 01:00 PST again.
            ['2025-11-02T08:00:00Z', '2025-11-02 01:00:00 America/Los_Angeles'],
            ['2025-11-02T09:00:00Z', '2025-11-02 01:00:00 America/Los_Angeles'],
            ['2025-07-01T00:00:00Z', '2025-06-30 17:00:00 America/Los_Angeles'],
        ];
        foreach ($cases as [$utc, $expected]) {
            $body = $this->endpoint(Environment::Sandbox, new FrozenClock(new DateTimeImmutable($utc)))
                ->verifyReceipt(['receipt-data' => base64_encode(MintedPki::get()->receipt())]);
            self::assertSame($expected, $body['receipt']['request_date_pst'], $utc);
        }
    }

    /** @return iterable<string, array{string, int}> */
    public static function environmentRoutingProvider(): iterable
    {
        // Fails closed: only "Production" and "ProductionVPP" count as production.
        yield 'Production on Production' => ['Production', 0];
        yield 'ProductionVPP on Production' => ['ProductionVPP', 0];
        yield 'ProductionSandbox on Production' => ['ProductionSandbox', 21007];
        yield 'ProductionVPPSandbox on Production' => ['ProductionVPPSandbox', 21007];
        yield 'Xcode on Production' => ['Xcode', 21007];
        yield 'something new on Production' => ['SomethingAppleAddsLater', 21007];
    }

    #[DataProvider('environmentRoutingProvider')]
    public function testProductionRoutingFailsClosed(string $receiptType, int $expected): void
    {
        $pki = MintedPki::get();
        $payload = TestPki::payload(
            TestPki::utf8Attribute(0, $receiptType),
            TestPki::utf8Attribute(2, 'com.example.app'),
            TestPki::dateAttribute(12, '2024-08-06T12:00:00Z'),
        );

        self::assertSame(
            $expected,
            $this->endpoint(Environment::Production)->verifyReceipt([
                'receipt-data' => base64_encode($pki->receipt($payload)),
            ])['status'],
        );
    }

    public function testTheEnvironmentOptionIsTypedAndConstrainedToTheTwoAppleHas(): void
    {
        $roots = [MintedPki::get()->rootDer];

        self::assertSame(
            'Production',
            (new VerifyReceiptEndpoint($roots, Environment::Production))->verifyReceipt([
                'receipt-data' => base64_encode(MintedPki::get()->receipt(TestPki::payload(
                    TestPki::utf8Attribute(0, 'Production'),
                    TestPki::utf8Attribute(2, 'com.example.app'),
                    TestPki::dateAttribute(12, '2024-08-06T12:00:00Z'),
                ))),
            ])['environment'],
        );

        foreach ([Environment::Xcode, Environment::LocalTesting] as $unsupported) {
            try {
                new VerifyReceiptEndpoint($roots, $unsupported);
                self::fail($unsupported->value . ' should not be a valid endpoint environment');
            } catch (InvalidArgumentException $e) {
                self::assertStringContainsString('Production', $e->getMessage());
            }
        }
    }

    /** @return iterable<string, array{string, int}> */
    public static function jsonBodyProvider(): iterable
    {
        yield 'not JSON' => ['{', 21002];
        yield 'JSON null' => ['null', 21002];
        yield 'JSON array' => ['[1,2,3]', 21002];
        yield 'JSON scalar' => ['42', 21002];
        yield 'JSON string' => ['"receipt"', 21002];
        yield 'empty body' => ['', 21002];
        yield 'object without receipt-data' => ['{"password":"x"}', 21002];
        yield 'invalid UTF-8' => ["{\"receipt-data\":\"\xff\xfe\"}", 21002];
        yield 'deeply nested' => [str_repeat('[', 600) . str_repeat(']', 600), 21002];
    }

    #[DataProvider('jsonBodyProvider')]
    public function testTheJsonEntryPointNeverThrowsAndAnswersAStatus(string $body, int $expected): void
    {
        $response = $this->endpoint()->verifyReceiptJson($body);
        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($response, true);

        self::assertSame($expected, $decoded['status'], $response);
    }

    public function testTheJsonEntryPointRoundTripsAGenuineReceipt(): void
    {
        $request = (string) json_encode(['receipt-data' => base64_encode(MintedPki::get()->receipt())]);
        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($this->endpoint()->verifyReceiptJson($request), true);

        self::assertSame(0, $decoded['status']);
        self::assertSame('com.example.app', $decoded['receipt']['bundle_id']);
    }

    public function testAHugeBodyIsAStatusRatherThanAnException(): void
    {
        self::assertSame(21002, json_decode(
            $this->endpoint()->verifyReceiptJson(str_repeat('{', 100000)),
            true,
        )['status']);
    }

    /**
     * Apple renders in-app quantities, line item ids and the intro-offer flag
     * as STRINGS, which is easy to lose in a refactor and is what a consumer's
     * existing parser expects.
     */
    public function testInAppFieldsKeepAppleWireTypes(): void
    {
        $pki = MintedPki::get();
        $payload = TestPki::payload(
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
        $entry = $this->endpoint()->verifyReceipt([
            'receipt-data' => base64_encode($pki->receipt($payload)),
        ])['receipt']['in_app'][0];

        self::assertSame('2', $entry['quantity']);
        self::assertSame('42', $entry['web_order_line_item_id']);
        self::assertSame('true', $entry['is_in_intro_offer_period']);
        self::assertSame('2024-02-01 09:30:00 Etc/GMT', $entry['purchase_date']);
        self::assertSame('1706779800000', $entry['purchase_date_ms']);
        self::assertArrayNotHasKey('expires_date', $entry, 'an absent date is omitted, not null');
    }
}
