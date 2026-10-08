<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\JsonPayload;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\ReceiptPayload;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\CountingClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FakeTransport;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FrozenClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Outcome;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\ThrowingClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\ModuleFaultException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\Operation;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\ServerProcessException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use InvalidArgumentException;
use JsonException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RangeException;
use RuntimeException;
use TypeError;

/**
 * The façade on its own, over a fake transport: what it reads from the
 * clock, what it sends, and how every way a call can end maps onto the six
 * outcomes of docs/rust-core/ARCHITECTURE.md §4. No verdict is decided
 * here; the module's JSON is canned.
 */
#[CoversNothing]
final class FacadeTest extends TestCase
{
    private const RECEIPT_WIRE = <<<'JSON'
        {"verified":true,"payload":{
          "receipt_type":"ProductionSandbox","app_item_id":"0","bundle_id":"com.example.app",
          "bundle_id_bytes":"Y29tLmV4YW1wbGUuYXBw","application_version":"1.0","opaque_value":"AQIDBA==",
          "sha1_hash":"BQYHCA==","receipt_creation_date_ms":1722945600000,"download_id":"9223372036854775807",
          "version_external_identifier":"-5","original_purchase_date_ms":1722945600000,
          "preorder_date_ms":1719913520000,"original_application_version":"1.0","expiration_date_ms":null,
          "in_app":[{"quantity":1,"product_id":"p1","transaction_id":"t1","purchase_date_ms":1722945600000,
            "original_transaction_id":"t0","original_purchase_date_ms":1722945600000,"expires_date_ms":null,
            "web_order_line_item_id":"1000000123456789","cancellation_date_ms":null,"cancellation_reason":null,"is_trial_period":false,
            "is_in_intro_offer_period":true,"unknown_attributes":{"1799":["/w=="]}}],
          "unknown_attributes":{"7":["Ag=="],"13":["AA==","AQ=="]}},"environment":"Sandbox"}
        JSON;

    private static function verifier(FakeTransport $transport, ?Config $config = null): Verifier
    {
        return Verifier::create($config ?? new Config(), $transport);
    }

    public function testAVerifiedReceiptIsMappedFieldForField(): void
    {
        $result = self::verifier(FakeTransport::answering(self::RECEIPT_WIRE))->verifyReceipt('x');

        self::assertTrue($result->verified());
        /** @var ReceiptPayload $receipt */
        $receipt = $result->payload;
        self::assertSame('ProductionSandbox', $receipt->receiptType);
        self::assertSame(0, $receipt->appItemId);
        self::assertSame('com.example.app', $receipt->bundleId);
        self::assertSame('com.example.app', $receipt->bundleIdBytes);
        self::assertSame("\x01\x02\x03\x04", $receipt->opaqueValue);
        self::assertSame(1722945600000, $receipt->receiptCreationDateMs);
        self::assertSame(PHP_INT_MAX, $receipt->downloadId, 'a 64-bit id survives as an int');
        self::assertSame(-5, $receipt->versionExternalIdentifier, 'a hostile negative id is reported as it is');
        self::assertNull($receipt->expirationDateMs);
        self::assertSame(1719913520000, $receipt->preorderDateMs);
        self::assertSame([7 => ["\x02"], 13 => ["\0", "\x01"]], $receipt->unknownAttributes, 'order within a type is kept');
        self::assertCount(1, $receipt->inApp);
        $purchase = $receipt->inApp[0];
        self::assertSame(1000000123456789, $purchase->webOrderLineItemId);
        self::assertFalse($purchase->isTrialPeriod);
        self::assertTrue($purchase->isInIntroOfferPeriod);
        self::assertSame([1799 => ["\xff"]], $purchase->unknownAttributes);
        self::assertSame(Environment::Sandbox, $receipt->environment, 'the member beside the payload');
    }

    public function testAPayloadBuiltWithoutAPreorderDateWritesItAsNull(): void
    {
        /** @var array<string, mixed> $written */
        $written = json_decode((new ReceiptPayload())->toJson(), true, 32, JSON_THROW_ON_ERROR);
        self::assertArrayHasKey('preorder_date_ms', $written);
        self::assertNull($written['preorder_date_ms']);
        $keys = array_keys($written);
        self::assertSame(array_search('original_purchase_date_ms', $keys, true) + 1, array_search('preorder_date_ms', $keys, true));
    }

    public function testToJsonRoundTripsTheWireValue(): void
    {
        /** @var ReceiptPayload $receipt */
        $receipt = self::verifier(FakeTransport::answering(self::RECEIPT_WIRE))->verifyReceipt('x')->payload;
        /** @var array{payload: array<string, mixed>} $wire */
        $wire = json_decode(self::RECEIPT_WIRE, true, 32, JSON_THROW_ON_ERROR);

        /** @var array<string, mixed> $again */
        $again = json_decode($receipt->toJson(), true, 32, JSON_THROW_ON_ERROR);
        $expected = $wire['payload'];
        self::assertArrayNotHasKey('environment', $again, 'the environment is not part of toJson');
        ksort($expected);
        ksort($again);
        self::assertSame($expected, $again, 'same value, not the same bytes (0.7-api.md "Our JSON")');
    }

    public function testASignedPayloadIsTheJsonStringExactlyAsSigned(): void
    {
        $signed = '{"bundleId":"aé",   "n":1e3}';
        $json = json_encode(['verified' => true, 'payload' => $signed, 'environment' => 'Production'], JSON_THROW_ON_ERROR);
        $result = self::verifier(FakeTransport::answering($json))->verifySignedData('a.b.c');

        self::assertTrue($result->verified());
        self::assertInstanceOf(JsonPayload::class, $result->payload);
        self::assertSame($signed, $result->payload->json);
        self::assertSame(Environment::Production, $result->payload->environment);
    }

    /** @return iterable<string, array{mixed, Environment|null}> */
    public static function environmentProvider(): iterable
    {
        yield 'Production' => ['Production', Environment::Production];
        yield 'Sandbox' => ['Sandbox', Environment::Sandbox];
        yield 'null' => [null, null];
    }

    /** The environment is the module's member beside the payload; the payloads here name another one. */
    #[DataProvider('environmentProvider')]
    public function testTheEnvironmentIsTheModulesMemberBesideThePayload(mixed $member, ?Environment $expected): void
    {
        $receipt = json_encode(['verified' => true, 'payload' => ['receipt_type' => 'Xcode'], 'environment' => $member], JSON_THROW_ON_ERROR);
        $signed = json_encode(['verified' => true, 'payload' => '{"environment":"Xcode"}', 'environment' => $member], JSON_THROW_ON_ERROR);

        $fromReceipt = self::verifier(FakeTransport::answering($receipt))->verifyReceipt('x')->payload;
        $fromJws = self::verifier(FakeTransport::answering($signed))->verifySignedData('x')->payload;
        self::assertInstanceOf(ReceiptPayload::class, $fromReceipt);
        self::assertInstanceOf(JsonPayload::class, $fromJws);
        self::assertSame($expected, $fromReceipt->environment);
        self::assertSame($expected, $fromJws->environment);
    }

    /** @return iterable<string, array{string}> */
    public static function badEnvironmentProvider(): iterable
    {
        yield 'no environment' => [''];
        yield 'Xcode' => [',"environment":"Xcode"'];
        yield 'lowercase' => [',"environment":"sandbox"'];
        yield 'a number' => [',"environment":1'];
    }

    #[DataProvider('badEnvironmentProvider')]
    public function testAVerifiedAnswerWithoutAnEnvironmentOfTheThreeIsAnInternalError(string $member): void
    {
        foreach ([
            self::verifier(FakeTransport::answering('{"verified":true,"payload":{}' . $member . '}'))->verifyReceipt('x'),
            self::verifier(FakeTransport::answering('{"verified":true,"payload":"{}"' . $member . '}'))->verifySignedData('x'),
        ] as $result) {
            self::assertSame(Reason::InternalError, Outcome::failure($result)->reason);
            self::assertInstanceOf(ModuleFaultException::class, Outcome::failure($result)->cause);
            self::assertSame('BAD_ANSWER', Outcome::failure($result)->cause->category);
        }
    }

    /** @return iterable<string, array{string}> */
    public static function reasonProvider(): iterable
    {
        foreach (Reason::cases() as $reason) {
            yield $reason->value => [$reason->value];
        }
    }

    /** A verdict of the module is the module's: the reason and message pass through, and no cause is invented. */
    #[DataProvider('reasonProvider')]
    public function testEveryVerdictPassesThroughWithoutACause(string $token): void
    {
        $json = json_encode(['verified' => false, 'reason' => $token, 'message' => 'why'], JSON_THROW_ON_ERROR);
        foreach ([
            self::verifier(FakeTransport::answering($json))->verifyReceipt('x'),
            self::verifier(FakeTransport::answering($json))->verifySignedData('x'),
        ] as $result) {
            self::assertFalse($result->verified());
            self::assertSame($token, Outcome::failure($result)->reason->value);
            self::assertSame('why', Outcome::failure($result)->message);
            self::assertNull(Outcome::failure($result)->cause, 'the module\'s own INTERNAL_ERROR and UNREADABLE_PAYLOAD carry no PHP cause');
        }
    }

    /** @return iterable<string, array{string}> */
    public static function unreadableAnswerProvider(): iterable
    {
        yield 'not JSON' => ['{nope'];
        yield 'a JSON list' => ['[1,2]'];
        yield 'a scalar' => ['"x"'];
        yield 'an empty object' => ['{}'];
        yield 'verified as a string' => ['{"verified":"true","payload":{}}'];
        yield 'a reason outside the eight' => ['{"verified":false,"reason":"INVALID_JWS_FORMAT","message":"m"}'];
        yield 'a failure without a message' => ['{"verified":false,"reason":"MALFORMED"}'];
        yield 'a verified receipt without a payload' => ['{"verified":true,"environment":null}'];
        yield 'a receipt payload that is a string' => ['{"verified":true,"payload":"x","environment":null}'];
        yield 'a non-decimal id' => ['{"verified":true,"payload":{"app_item_id":"12x"},"environment":null}'];
        yield 'a numeric id' => ['{"verified":true,"payload":{"app_item_id":12},"environment":null}'];
        yield 'an id past 64 bits' => ['{"verified":true,"payload":{"download_id":"9223372036854775808"},"environment":null}'];
        yield 'a date as a string' => ['{"verified":true,"payload":{"receipt_creation_date_ms":"1"},"environment":null}'];
        yield 'bytes that are not base64' => ['{"verified":true,"payload":{"opaque_value":"@@@"},"environment":null}'];
        yield 'an unknown attribute type that is not decimal' => ['{"verified":true,"payload":{"unknown_attributes":{"x":[]}},"environment":null}'];
        yield 'in_app not a list' => ['{"verified":true,"payload":{"in_app":"x"},"environment":null}'];
    }

    #[DataProvider('unreadableAnswerProvider')]
    public function testAnAnswerThatIsNotTheContractIsAnInternalErrorNeverAVerdict(string $json): void
    {
        $result = self::verifier(FakeTransport::answering($json))->verifyReceipt('x');

        self::assertFalse($result->verified());
        self::assertSame(Reason::InternalError, Outcome::failure($result)->reason);
        self::assertInstanceOf(ModuleFaultException::class, Outcome::failure($result)->cause);
        self::assertSame('BAD_ANSWER', Outcome::failure($result)->cause->category);
    }

    public function testASignedPayloadThatIsAnObjectNotAStringIsAnInternalError(): void
    {
        $result = self::verifier(FakeTransport::answering('{"verified":true,"payload":{"a":1},"environment":null}'))->verifySignedData('x');

        self::assertSame(Reason::InternalError, Outcome::failure($result)->reason);
        self::assertInstanceOf(ModuleFaultException::class, Outcome::failure($result)->cause);
    }

    public function testAnEndpointAnswerWithoutAnIntegerStatusIsStatus21009(): void
    {
        foreach (['{}', '{"status":"0"}', 'nope', '[]'] as $json) {
            $answer = self::verifier(FakeTransport::answering($json))->verifyReceiptEndpoint(Environment::Production, '{}');
            self::assertSame('{"status":21009}', $answer, $json);
        }
    }

    public function testAnEndpointAnswerPassesThroughByteForByte(): void
    {
        $apple = '{"status":0, "environment":"Sandbox",  "receipt":{"a":"é"}}';
        $answer = self::verifier(FakeTransport::answering($apple))->verifyReceiptEndpoint(Environment::Sandbox, '{}');
        self::assertSame($apple, $answer);
    }

    // --- the six outcomes ---------------------------------------------------

    public function testAModuleFaultAndAServerProcessFailureAreDistinctCauses(): void
    {
        $trap = self::verifier(new FakeTransport(static fn () => throw new ModuleFaultException('WASM_TRAP', 'trapped')));
        $down = self::verifier(new FakeTransport(static fn () => throw new ServerProcessException('connection refused')));

        foreach (['verifyReceipt', 'verifySignedData'] as $method) {
            $a = $trap->$method('x');
            $b = $down->$method('x');
            self::assertSame(Reason::InternalError, Outcome::failure($a)->reason);
            self::assertSame(Reason::InternalError, Outcome::failure($b)->reason);
            self::assertInstanceOf(ModuleFaultException::class, Outcome::failure($a)->cause);
            self::assertInstanceOf(ServerProcessException::class, Outcome::failure($b)->cause);
            self::assertNotSame(Outcome::failure($a)->message, Outcome::failure($b)->message);
        }
        self::assertSame('{"status":21009}', $trap->verifyReceiptEndpoint(Environment::Production, '{}'));
        self::assertSame('{"status":21009}', $down->verifyReceiptEndpoint(Environment::Sandbox, '{}'));
    }

    /** No throwable of the transport escapes a verify method, whatever it is. */
    public function testNoThrowableEscapesAVerifyMethod(): void
    {
        foreach ([new TypeError('t'), new JsonException('j'), new RuntimeException('r'), new \Error('e')] as $boom) {
            $verifier = self::verifier(new FakeTransport(static fn () => throw $boom));
            $receipt = $verifier->verifyReceipt('x');
            self::assertSame(Reason::InternalError, Outcome::failure($receipt)->reason);
            self::assertSame($boom, Outcome::failure($receipt)->cause);
            self::assertSame(Reason::InternalError, Outcome::failure($verifier->verifySignedData('x'))->reason);
            self::assertSame('{"status":21009}', $verifier->verifyReceiptEndpoint(Environment::Production, '{}'));
        }
    }

    /**
     * An input over the cap is the module's to answer: the transport hands
     * back the module's size refusal and the façade maps it like any other
     * verdict, with the module's message and no cause.
     */
    public function testAnInputOverTheCapIsTheModulesTooLargeAnswer(): void
    {
        $verifier = self::verifier(new FakeTransport(static fn (Operation $operation) => match ($operation) {
            Operation::EndpointProduction, Operation::EndpointSandbox => '{"status":21002}',
            default => '{"verified":false,"reason":"TOO_LARGE","message":"said by the module"}',
        }));

        $receipt = Outcome::failure($verifier->verifyReceipt('x'));
        self::assertSame(Reason::TooLarge, $receipt->reason);
        self::assertSame('said by the module', $receipt->message);
        self::assertNull($receipt->cause);
        self::assertSame(Reason::TooLarge, Outcome::failure($verifier->verifySignedData('x'))->reason);
        self::assertSame('{"status":21002}', $verifier->verifyReceiptEndpoint(Environment::Production, '{}'));
    }

    public function testCallerMisuseIsRaisedAtCreateAsAnArgumentError(): void
    {
        foreach ([[''], [123], [null], [['x']]] as $roots) {
            $transport = FakeTransport::answering('{}');
            try {
                /** @phpstan-ignore-next-line deliberate misuse */
                Verifier::create(new Config($roots, new FrozenClock(new DateTimeImmutable())), $transport);
                self::fail('a bad root must be refused at create');
            } catch (InvalidArgumentException) {
                self::assertSame([], $transport->opened, 'nothing was opened for a bad config');
            }
        }
    }

    public function testATransportThatRefusesTheConfigFailsCreateNotALaterCall(): void
    {
        $refusal = new InvalidArgumentException('the verification module refused the roots');

        $this->expectExceptionObject($refusal);
        Verifier::create(new Config(), new FakeTransport(static fn () => '', $refusal));
    }

    public function testAnAbiMismatchIsAHardFailureAtCreate(): void
    {
        $abi = new RuntimeException('speaks ABI other');
        $this->expectExceptionObject($abi);
        Verifier::create(new Config(), new FakeTransport(static fn () => '', $abi));
    }

    // --- roots and clock -------------------------------------------------------

    public function testTheBuiltInRootsAreNullAndCustomRootsGoThroughAsGiven(): void
    {
        self::assertNull((new Config())->roots, 'a Config that is never given roots keeps the built-in ones');

        $transport = FakeTransport::answering('{}');
        Verifier::create(new Config(roots: new \ArrayIterator(["\x30\x00", "\x01\xff"])), $transport);
        self::assertSame([["\x30\x00", "\x01\xff"]], $transport->opened);

        $builtIn = FakeTransport::answering('{}');
        Verifier::create(new Config(), $builtIn);
        self::assertSame([null], $builtIn->opened, 'no roots given reaches the transport as null, the module\'s built-in roots');
    }

    /**
     * "No roots given" selects the built-in Apple roots; an empty list is a
     * caller's mistake (a list built from a config file that came up empty,
     * say) and must not silently widen to Apple's roots, so it is refused
     * at create, before any transport is touched.
     */
    public function testAnEmptyRootListIsRefusedAtCreateNotReadAsTheBuiltInRoots(): void
    {
        foreach ([
            'a Config given an empty array' => new Config(roots: []),
            'a Config given an empty iterator' => new Config(roots: new \ArrayIterator([])),
            'a Config given an empty list and a clock' => new Config([], new FrozenClock(new DateTimeImmutable())),
        ] as $what => $config) {
            $transport = FakeTransport::answering('{}');
            try {
                Verifier::create($config, $transport);
                self::fail("{$what} must be refused at create");
            } catch (InvalidArgumentException $e) {
                self::assertStringContainsString('root set is empty', $e->getMessage(), $what);
                self::assertSame([], $transport->opened, "{$what}: nothing was opened");
            }
        }
    }

    public function testTheClockIsReadOnceBeforeTheInputAndSentAsEpochMilliseconds(): void
    {
        $transport = FakeTransport::answering('{"status":21002}');
        $clock = new CountingClock();
        $verifier = self::verifier($transport, new Config(clock: $clock));

        $verifier->verifyReceipt('a');
        self::assertSame(1, $clock->reads);
        $verifier->verifySignedData('b');
        $verifier->verifyReceiptEndpoint(Environment::Production, 'c');
        self::assertSame(3, $clock->reads, 'exactly one read per call');

        $first = (int) $clock->first()->format('Uv');
        self::assertSame($first, $transport->calls[0][2]);
        self::assertSame($first + 1000, $transport->calls[1][2], 'each call reads the clock afresh');
    }

    public function testTheClockValueKeepsMillisecondPrecisionAndSurvivesThe2038Boundary(): void
    {
        $transport = FakeTransport::answering('{"status":0}');
        $instant = new DateTimeImmutable('2040-01-02T03:04:05.678912Z');
        self::verifier($transport, new Config(clock: new FrozenClock($instant)))
            ->verifyReceiptEndpoint(Environment::Sandbox, '{}');

        self::assertSame(2209086245678, $transport->calls[0][2]);
    }

    public function testAThrowingClockIsAnInternalErrorAndTheTransportIsNeverCalled(): void
    {
        $clock = new ThrowingClock();
        $transport = FakeTransport::answering('{}');
        $verifier = self::verifier($transport, new Config(clock: $clock));

        $receipt = $verifier->verifyReceipt('x');
        $jws = $verifier->verifySignedData('x');
        self::assertSame(Reason::InternalError, Outcome::failure($receipt)->reason);
        self::assertSame($clock->boom, Outcome::failure($receipt)->cause);
        self::assertSame(Reason::InternalError, Outcome::failure($jws)->reason);
        self::assertSame('{"status":21009}', $verifier->verifyReceiptEndpoint(Environment::Production, '{}'));
        self::assertSame([], $transport->calls);
    }

    public function testAClockBefore1970IsAnInternalErrorBecauseNowMsIsUnsigned(): void
    {
        $transport = FakeTransport::answering('{}');
        $verifier = self::verifier($transport, new Config(clock: new FrozenClock(new DateTimeImmutable('1969-12-31T23:59:59Z'))));

        $result = $verifier->verifyReceipt('x');
        self::assertSame(Reason::InternalError, Outcome::failure($result)->reason);
        self::assertInstanceOf(RangeException::class, Outcome::failure($result)->cause);
        self::assertSame([], $transport->calls);
    }

    // --- the input ---------------------------------------------------------

    public function testInputGoesThroughAsBytesAndNullIsEmptyInput(): void
    {
        $transport = FakeTransport::answering('{"status":21002}');
        $verifier = self::verifier($transport);
        $bytes = "a\0b\xff\xfe\r\n";

        $verifier->verifyReceipt($bytes);
        $verifier->verifySignedData($bytes);
        $verifier->verifyReceiptEndpoint(Environment::Production, $bytes);
        $verifier->verifyReceipt(null);
        $verifier->verifySignedData(null);
        $verifier->verifyReceiptEndpoint(Environment::Sandbox, null);

        self::assertSame([$bytes, $bytes, $bytes, '', '', ''], array_column($transport->calls, 1));
    }

    public function testEachEnvironmentRunsItsOwnEndpointOperation(): void
    {
        $transport = FakeTransport::answering('{"status":0}');
        $verifier = self::verifier($transport);
        $verifier->verifyReceipt('x');
        $verifier->verifySignedData('x');
        $verifier->verifyReceiptEndpoint(Environment::Production, '{}');
        $verifier->verifyReceiptEndpoint(Environment::Sandbox, '{}');

        self::assertSame(
            [Operation::Receipt, Operation::SignedData, Operation::EndpointProduction, Operation::EndpointSandbox],
            array_column($transport->calls, 0),
        );
    }
}
