<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FrozenClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Shape;
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
        $body = $this->endpoint()->verifyReceiptResult([
            'receipt-data' => base64_encode(MintedPki::get()->receipt()),
        ])->toResponse();

        $receipt = Shape::asArray($body['receipt'], 'receipt');

        self::assertSame(0, $body['status']);
        self::assertSame('Sandbox', $body['environment']);
        self::assertSame('ProductionSandbox', $receipt['receipt_type']);
        self::assertSame('com.example.app', $receipt['bundle_id']);
        self::assertSame('1.2.3', $receipt['application_version']);
        self::assertSame('1.0', $receipt['original_application_version']);
        self::assertSame('2024-08-06 12:00:00 Etc/GMT', $receipt['receipt_creation_date']);
        self::assertSame('1722945600000', $receipt['receipt_creation_date_ms']);
        self::assertSame('2024-08-06 05:00:00 America/Los_Angeles', $receipt['receipt_creation_date_pst']);
        self::assertSame([], $receipt['in_app']);
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
        self::assertSame(21002, $this->endpoint()->verifyReceiptResult($body)->toResponse()['status']);
    }

    public function testAnUnauthenticatedReceiptAnswers21003(): void
    {
        $pki = MintedPki::get();
        $body = $this->endpoint(Environment::Sandbox, null, $pki->foreignRootDer)->verifyReceiptResult([
            'receipt-data' => base64_encode($pki->receipt()),
        ])->toResponse();

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
        $plain = $this->endpoint(Environment::Sandbox, $clock)->verifyReceiptResult(['receipt-data' => $data])->toResponse();
        $decorated = $this->endpoint(Environment::Sandbox, $clock)->verifyReceiptResult([
            'receipt-data' => $data,
            'password' => 'a-shared-secret-we-cannot-check-offline',
            'exclude-old-transactions' => true,
        ])->toResponse();

        self::assertSame($plain, $decorated);
        self::assertSame(0, $plain['status']);
    }

    public function testRequestDateComesFromTheInjectedClock(): void
    {
        $clock = new FrozenClock(new DateTimeImmutable('2025-01-01T00:00:00Z'));
        $body = $this->endpoint(Environment::Sandbox, $clock)->verifyReceiptResult([
            'receipt-data' => base64_encode(MintedPki::get()->receipt()),
        ])->toResponse();

        $receipt = Shape::asArray($body['receipt'], 'receipt');

        self::assertSame('2025-01-01 00:00:00 Etc/GMT', $receipt['request_date']);
        self::assertSame('1735689600000', $receipt['request_date_ms']);
        self::assertSame('2024-12-31 16:00:00 America/Los_Angeles', $receipt['request_date_pst']);
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
                ->verifyReceiptResult(['receipt-data' => base64_encode(MintedPki::get()->receipt())])->toResponse();
            $receipt = Shape::asArray($body['receipt'], 'receipt');
            self::assertSame($expected, $receipt['request_date_pst'], $utc);
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
            $this->endpoint(Environment::Production)->verifyReceiptResult([
                'receipt-data' => base64_encode($pki->receipt($payload)),
            ])->toResponse()['status'],
        );
    }

    public function testTheEnvironmentOptionIsTypedAndConstrainedToTheTwoAppleHas(): void
    {
        $roots = [MintedPki::get()->rootDer];

        self::assertSame(
            'Production',
            (new VerifyReceiptEndpoint($roots, Environment::Production))->verifyReceiptResult([
                'receipt-data' => base64_encode(MintedPki::get()->receipt(TestPki::payload(
                    TestPki::utf8Attribute(0, 'Production'),
                    TestPki::utf8Attribute(2, 'com.example.app'),
                    TestPki::dateAttribute(12, '2024-08-06T12:00:00Z'),
                ))),
            ])->toResponse()['environment'],
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
        self::assertSame('com.example.app', Shape::asArray($decoded['receipt'], 'receipt')['bundle_id']);
    }

    public function testAHugeBodyIsAStatusRatherThanAnException(): void
    {
        $decoded = Shape::asArray(json_decode(
            $this->endpoint()->verifyReceiptJson(str_repeat('{', 100000)),
            true,
        ), 'response body');

        self::assertSame(21002, $decoded['status']);
    }

    /**
     * The limits are Apple's, fixed in every port by fixtures/cases.json:
     * Apple's verifyReceipt answers a 3,145,728-byte request body and refuses
     * a 3,145,729-byte one (measured 2026-09-23), and no receipt it accepts
     * can be larger than the body that carries it.
     */
    public function testTheBoundsAreApplesThreeMebibytes(): void
    {
        self::assertSame(3145728, VerifyReceiptEndpoint::MAX_REQUEST_BYTES);
        self::assertSame(3145728, ReceiptVerifier::MAX_RECEIPT_BYTES);
    }

    /**
     * Apple's limit counts UTF-8 bytes. A body padded with U+00E9 to one byte
     * over the limit is barely half the limit in characters, so a character
     * count (a port counting code points or UTF-16 units) lets it through;
     * the same shape one byte shorter verifies. A PHP string is bytes, so
     * `strlen()` is the count Apple makes.
     */
    public function testTheRequestBodyIsMeasuredInUtf8BytesNotCharacters(): void
    {
        $limit = VerifyReceiptEndpoint::MAX_REQUEST_BYTES;
        $receipt = base64_encode(MintedPki::get()->receipt());
        $body = static fn (int $padding): string => '{"receipt-data":"' . $receipt . '","password":"'
            . str_repeat("\u{e9}", intdiv($padding, 2)) . ($padding % 2 === 1 ? 'a' : '') . '"}';
        $fixed = strlen($body(0));

        $over = $body($limit + 1 - $fixed);
        self::assertSame($limit + 1, strlen($over));
        // Each two-byte U+00E9 is one character; mbstring is not required.
        $characters = strlen($over) - substr_count($over, "\u{e9}");
        self::assertLessThan(intdiv($limit, 2) + $fixed, $characters);
        $result = $this->endpoint()->verifyReceiptResult($over);
        self::assertSame(Reason::RequestTooLarge, $result->failureReason());
        self::assertSame(VerifyReceiptEndpoint::STATUS_MALFORMED, $result->status());

        $at = $body($limit - $fixed);
        self::assertSame($limit, strlen($at));
        self::assertSame(VerifyReceiptEndpoint::STATUS_OK, $this->endpoint()->verifyReceiptResult($at)->status());
    }

    /**
     * The size is decided before the body is parsed, so a body over the limit
     * is REQUEST_TOO_LARGE however malformed it is, not MALFORMED_REQUEST.
     */
    public function testAnOversizedMalformedBodyIsTooLargeRatherThanMalformed(): void
    {
        $body = str_repeat('[', VerifyReceiptEndpoint::MAX_REQUEST_BYTES + 1);

        self::assertSame(Reason::RequestTooLarge, $this->endpoint()->verifyReceiptResult($body)->failureReason());
        self::assertSame(
            Reason::MalformedRequest,
            $this->endpoint()->verifyReceiptResult(substr($body, 1))->failureReason(),
        );
    }

    /**
     * The receipt cap applies to `receipt-data` in every entry point, so a
     * decoded body whose `receipt-data` is one byte over it is
     * INVALID_RECEIPT_FORMAT, not REQUEST_TOO_LARGE: only a raw body has a
     * request size.
     */
    public function testAReceiptDataOverTheReceiptCapIsAnInvalidReceiptFormat(): void
    {
        $result = $this->endpoint()->verifyReceiptResult([
            'receipt-data' => str_repeat('A', ReceiptVerifier::MAX_RECEIPT_BYTES + 1),
        ]);

        self::assertSame(Reason::InvalidReceiptFormat, $result->failureReason());
        self::assertSame(VerifyReceiptEndpoint::STATUS_MALFORMED, $result->status());
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
        $body = $this->endpoint()->verifyReceiptResult([
            'receipt-data' => base64_encode($pki->receipt($payload)),
        ])->toResponse();
        $inApp = Shape::asArray(Shape::asArray($body['receipt'], 'receipt')['in_app'], 'in_app');
        $entry = Shape::asArray($inApp[0] ?? null, 'in_app[0]');

        self::assertSame('2', $entry['quantity']);
        self::assertSame('42', $entry['web_order_line_item_id']);
        self::assertSame('true', $entry['is_in_intro_offer_period']);
        self::assertSame('2024-02-01 09:30:00 Etc/GMT', $entry['purchase_date']);
        self::assertSame('1706779800000', $entry['purchase_date_ms']);
        self::assertArrayNotHasKey('expires_date', $entry, 'an absent date is omitted, not null');
    }

    /**
     * Apple echoes attribute 1 under both adam_id and app_item_id, as JSON
     * numbers; 15 (download_id) and 16 (version_external_identifier) are
     * JSON numbers too. download_id is 2^63-1, a nineteen-digit, eight-byte
     * integer an IEEE-754 double rounds to 2^63: asserting the literal
     * JSON TEXT (not a value json_decode hands back) proves the serializer
     * never routed the id through a float.
     */
    public function testLegacyReceiptIdsAreWireNumbersWithExactDigits(): void
    {
        $endpoint = new VerifyReceiptEndpoint([Fixtures::bytes('receipt-ids-root')], Environment::Production);
        $json = $endpoint->verifyReceiptJson((string) json_encode([
            'receipt-data' => base64_encode(Fixtures::bytes('receipt-ids')),
        ]));

        self::assertStringContainsString('"adam_id":1234567890', $json);
        self::assertStringContainsString('"app_item_id":1234567890', $json);
        self::assertStringContainsString('"download_id":9223372036854775807', $json);
        self::assertStringContainsString('"version_external_identifier":456789012', $json);
        self::assertStringContainsString('"is_trial_period":"false"', $json);
        self::assertStringContainsString('"is_trial_period":"true"', $json);

        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($json, true, 64, JSON_THROW_ON_ERROR);
        $receipt = Shape::asArray($decoded['receipt'], 'receipt');
        self::assertSame(1234567890, $receipt['adam_id']);
        self::assertSame(1234567890, $receipt['app_item_id']);
        self::assertSame(9223372036854775807, $receipt['download_id']);
        self::assertSame(456789012, $receipt['version_external_identifier']);
        $inApp = Shape::asArray($receipt['in_app'], 'in_app');
        self::assertSame('false', self::inAppEntry($inApp, 'com.example.app.coins100')['is_trial_period']);
        self::assertSame('true', self::inAppEntry($inApp, 'com.example.app.vip')['is_trial_period']);
    }

    /**
     * An attribute the receipt does not carry leaves its key OUT of the
     * answer rather than emitting JSON null.
     */
    public function testLegacyReceiptIdKeysAreOmittedNotNullWhenAbsent(): void
    {
        $endpoint = new VerifyReceiptEndpoint([Fixtures::bytes('receipt-root')], Environment::Sandbox);
        $body = $endpoint->verifyReceiptResult(['receipt-data' => base64_encode(Fixtures::bytes('receipt'))])->toResponse();
        $receipt = Shape::asArray($body['receipt'], 'receipt');

        foreach (['adam_id', 'app_item_id', 'download_id', 'version_external_identifier'] as $key) {
            self::assertArrayNotHasKey($key, $receipt, $key);
        }
        $inApp = Shape::asArray($receipt['in_app'], 'in_app');
        self::assertArrayNotHasKey('is_trial_period', self::inAppEntry($inApp, 'com.example.app.coins100'));
    }

    /**
     * @param array<array-key, mixed> $inApp
     *
     * @return array<array-key, mixed>
     */
    private static function inAppEntry(array $inApp, string $productId): array
    {
        foreach ($inApp as $entry) {
            $entry = Shape::asArray($entry, 'in_app entry');
            if (($entry['product_id'] ?? null) === $productId) {
                return $entry;
            }
        }
        self::fail("no in_app entry with product id {$productId}");
    }
}
