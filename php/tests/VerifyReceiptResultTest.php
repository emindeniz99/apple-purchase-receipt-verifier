<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptEndpoint;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\VerifyReceiptResult;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\CountingClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Fixtures;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FrozenClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Shape;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\ThrowingClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;
use Error;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use ReflectionClass;

/**
 * {@see VerifyReceiptResult}: one verification, then any number of renders.
 *
 * What matters here is what a caller builds a retry on. The receipt must
 * survive a 21007/21008 so the other environment can be rendered without a
 * second verification, and that re-render must recompute the status from the
 * receipt itself: a result from a production endpoint must never turn into a
 * production 0 for a sandbox receipt, or the 21007 routing that keeps sandbox
 * purchases out of production would be one method call from being bypassed.
 */
#[CoversClass(VerifyReceiptResult::class)]
#[CoversClass(VerifyReceiptEndpoint::class)]
final class VerifyReceiptResultTest extends TestCase
{
    private const CLOCK_NOW = '2026-01-01T00:00:00Z';

    private const EXPLICIT = '2025-06-15T12:34:56.789Z';

    private static function endpoint(
        Environment $environment,
        string $root = 'receipt-root',
        ?ClockInterface $clock = null,
    ): VerifyReceiptEndpoint {
        return new VerifyReceiptEndpoint(
            [Fixtures::bytes($root)],
            $environment,
            $clock ?? new FrozenClock(new DateTimeImmutable(self::CLOCK_NOW)),
        );
    }

    private static function base64(string $fixture): string
    {
        return base64_encode(Fixtures::bytes($fixture));
    }

    private static function explicit(): DateTimeImmutable
    {
        return new DateTimeImmutable(self::EXPLICIT);
    }

    private static function assertInvariant(VerifyReceiptResult $result, string $label): void
    {
        self::assertTrue(
            ($result->receipt() === null) !== ($result->failureReason() === null),
            "{$label}: exactly one of receipt and failureReason must be set",
        );
        self::assertSame($result->receipt() !== null, $result->isVerified(), "{$label}: isVerified must match receipt()");
        self::assertSame(
            $result->failureReason() === Reason::InternalError,
            $result->failureCause() !== null,
            "{$label}: failureCause is set exactly for INTERNAL_ERROR",
        );
        self::assertSame($result->status(), $result->toResponse()['status'], $label);
    }

    public function testExactlyOneOfReceiptAndFailureReasonIsSetForEveryStatus(): void
    {
        $results = [
            '0 sandbox' => self::endpoint(Environment::Sandbox)->verifyReceiptData(self::base64('receipt')),
            '0 production' => self::endpoint(Environment::Production)
                ->verifyReceiptData(self::base64('receipt-type-production')),
            '21007' => self::endpoint(Environment::Production)->verifyReceiptData(self::base64('receipt')),
            '21008' => self::endpoint(Environment::Sandbox)->verifyReceiptData(self::base64('receipt-type-production')),
            '21002' => self::endpoint(Environment::Sandbox)->verifyReceiptData('AQIDBA=='),
            '21003' => self::endpoint(Environment::Sandbox)->verifyReceiptData(self::base64('receipt-foreign')),
            '21009' => self::endpoint(Environment::Sandbox, 'receipt-root', new ThrowingClock())
                ->verifyReceiptData(self::base64('receipt')),
        ];
        foreach ($results as $label => $result) {
            self::assertInvariant($result, (string) $label);
            self::assertSame((int) explode(' ', (string) $label)[0], $result->status(), (string) $label);
        }
        // 21007 and 21008 are routing answers, not failures: the receipt
        // verified, so isVerified() is true there as it is for 0, and false
        // for every failure even though those are non-zero statuses too.
        foreach (['0 sandbox', '0 production', '21007', '21008'] as $verified) {
            self::assertTrue($results[$verified]->isVerified(), $verified);
        }
        foreach (['21002', '21003', '21009'] as $failed) {
            self::assertFalse($results[$failed]->isVerified(), $failed);
        }
    }

    /**
     * The whole re-render table, on committed fixtures, from either
     * endpoint: a production receipt gives 0 on Production and 21008 on
     * Sandbox; a sandbox receipt (and one with no receipt_type, which fails
     * closed as sandbox) gives 21007 on Production and 0 on Sandbox; a failed
     * result keeps its own status. Each render is byte for byte what an
     * endpoint of that environment answers on its own.
     */
    public function testReRendersForEitherEnvironmentFromTheReceiptsOwnType(): void
    {
        $table = [
            // fixture, root, status on Production, status on Sandbox
            ['receipt-type-production', 'receipt-root', 0, 21008],
            ['receipt-type-vpp', 'receipt-root', 0, 21008],
            ['receipt', 'receipt-root', 21007, 0],
            ['receipt-type-vpp-sandbox', 'receipt-root', 21007, 0],
            ['receipt-no-type', 'receipt-root', 21007, 0],
            ['receipt-foreign', 'receipt-root', 21003, 21003],
            ['receipt-tampered-payload', 'gaps-receipt-root', 21003, 21003],
        ];
        foreach ($table as [$fixture, $root, $onProduction, $onSandbox]) {
            foreach ([Environment::Production, Environment::Sandbox] as $own) {
                $result = self::endpoint($own, $root)->verifyReceiptData(self::base64($fixture), self::explicit());
                $label = "{$fixture} from a {$own->value} endpoint";
                self::assertSame($onProduction, $result->toResponse(Environment::Production)['status'], $label);
                self::assertSame($onSandbox, $result->toResponse(Environment::Sandbox)['status'], $label);
                foreach ([Environment::Production, Environment::Sandbox] as $target) {
                    $direct = self::endpoint($target, $root)
                        ->verifyReceiptData(self::base64($fixture), self::explicit())
                        ->toJson();
                    self::assertSame($direct, $result->toJson($target), "{$label} rendered for {$target->value}");
                }
            }
        }
    }

    public function testASandboxReceiptNeverRendersAProductionZero(): void
    {
        foreach (['receipt', 'receipt-type-vpp-sandbox', 'receipt-no-type'] as $fixture) {
            foreach ([Environment::Production, Environment::Sandbox] as $own) {
                $result = self::endpoint($own)->verifyReceiptData(self::base64($fixture));
                self::assertNotNull($result->receipt(), $fixture);
                self::assertSame('{"status":21007}', $result->toJson(Environment::Production), "{$fixture} via {$own->value}");
                self::assertSame(['status' => 21007], $result->toResponse(Environment::Production), $fixture);
            }
        }
    }

    /** Apple has two endpoints; a render for a third is refused as the constructor refuses one. */
    public function testRenderingForAnEnvironmentAppleDoesNotHaveIsRefused(): void
    {
        $results = [
            'verified' => self::endpoint(Environment::Sandbox)->verifyReceiptData(self::base64('receipt')),
            'failed' => self::endpoint(Environment::Sandbox)->verifyReceiptData('AQIDBA=='),
        ];
        foreach ($results as $label => $result) {
            foreach ([Environment::Xcode, Environment::LocalTesting] as $environment) {
                foreach (['toResponse', 'toJson'] as $render) {
                    try {
                        $result->{$render}($environment);
                        self::fail("{$label}: {$render}({$environment->value}) should be refused");
                    } catch (InvalidArgumentException $e) {
                        self::assertSame(
                            'environment must be Environment::Production or Environment::Sandbox',
                            $e->getMessage(),
                        );
                    }
                }
            }
        }
    }

    public function testAnExplicitRequestDateIsRenderedAndWinsOverTheClock(): void
    {
        $clock = new CountingClock();
        $endpoint = self::endpoint(Environment::Sandbox, 'receipt-root', $clock);
        $data = self::base64('receipt');
        $json = (string) json_encode(['receipt-data' => $data]);

        $explicit = $endpoint->verifyReceiptResult(['receipt-data' => $data], self::explicit());
        self::assertEquals(self::explicit(), $explicit->requestDate());
        $receipt = Shape::asArray($explicit->toResponse()['receipt'], 'receipt');
        self::assertSame('2025-06-15 12:34:56 Etc/GMT', $receipt['request_date']);
        self::assertSame('1749990896789', $receipt['request_date_ms']);
        self::assertSame('2025-06-15 05:34:56 America/Los_Angeles', $receipt['request_date_pst']);
        self::assertEquals(self::explicit(), $endpoint->verifyReceiptResult($json, self::explicit())->requestDate());
        self::assertEquals(self::explicit(), $endpoint->verifyReceiptData($data, self::explicit())->requestDate());
        self::assertSame(0, $clock->reads, 'an explicit request date must not read the clock at all');

        // Deterministic: the same call renders the same bytes, and so does
        // rendering one result twice.
        self::assertSame($explicit->toJson(), $endpoint->verifyReceiptResult($json, self::explicit())->toJson());
        self::assertSame($explicit->toJson(), $explicit->toJson());
    }

    /**
     * Without an explicit date the clock is read exactly once per call,
     * before anything else, whatever the outcome, and never again by a
     * render. Two reads could stamp one answer with two instants.
     */
    public function testWithoutOneTheClockIsReadOncePerCall(): void
    {
        $data = self::base64('receipt');
        $calls = [
            'array body' => static fn (VerifyReceiptEndpoint $e) => $e->verifyReceiptResult(['receipt-data' => $data]),
            'JSON body' => static fn (VerifyReceiptEndpoint $e) => $e->verifyReceiptResult(
                (string) json_encode(['receipt-data' => $data]),
            ),
            'bare receipt' => static fn (VerifyReceiptEndpoint $e) => $e->verifyReceiptData($data),
            'malformed body' => static fn (VerifyReceiptEndpoint $e) => $e->verifyReceiptResult('not json'),
            'not base64' => static fn (VerifyReceiptEndpoint $e) => $e->verifyReceiptData('not base64!'),
            'unauthenticated' => static fn (VerifyReceiptEndpoint $e) => $e->verifyReceiptData(
                self::base64('receipt-foreign'),
            ),
        ];
        foreach ($calls as $label => $call) {
            $clock = new CountingClock();
            $result = $call(self::endpoint(Environment::Sandbox, 'receipt-root', $clock));
            self::assertSame(1, $clock->reads, $label);
            self::assertEquals($clock->first(), $result->requestDate(), $label);
            $result->toJson();
            $result->toJson(Environment::Production);
            self::assertSame(1, $clock->reads, "{$label}: a render must not read the clock");
        }
    }

    /** The request date feeds request_date and nothing else: not chain validity. */
    public function testTheRequestDateCannotMoveTheVerdict(): void
    {
        $endpoint = self::endpoint(Environment::Sandbox);
        foreach (['2000-01-01T00:00:00Z', '2099-01-01T00:00:00Z'] as $when) {
            $result = $endpoint->verifyReceiptData(self::base64('receipt'), new DateTimeImmutable($when));
            self::assertSame(0, $result->status(), $when);
        }
        foreach (['receipt-expired-historical', 'receipt-expired-fresh'] as $fixture) {
            $root = Fixtures::bytes('receipt-expired-root');
            $clocked = (new VerifyReceiptEndpoint([$root], Environment::Sandbox))
                ->verifyReceiptData(self::base64($fixture));
            foreach (['2000-01-01T00:00:00Z', '2099-01-01T00:00:00Z'] as $when) {
                $dated = (new VerifyReceiptEndpoint([$root], Environment::Sandbox))
                    ->verifyReceiptData(self::base64($fixture), new DateTimeImmutable($when));
                self::assertSame($clocked->status(), $dated->status(), "{$fixture} at {$when}");
                self::assertSame($clocked->failureReason(), $dated->failureReason(), "{$fixture} at {$when}");
            }
        }
    }

    public function testTheJsonRenderIsWhatVerifyReceiptJsonAnswers(): void
    {
        $endpoint = self::endpoint(Environment::Sandbox);
        $json = (string) json_encode(['receipt-data' => self::base64('receipt')]);

        self::assertSame($endpoint->verifyReceiptJson($json), $endpoint->verifyReceiptResult($json)->toJson());
        self::assertSame(
            $endpoint->verifyReceiptJson($json),
            $endpoint->verifyReceiptResult($json)->toJson(Environment::Sandbox),
        );
    }

    /**
     * Over every receipt fixture in the registry, under every receipt anchor
     * the registry carries plus Apple's own, on both endpoints: the bare
     * base64 answers byte for byte what the same string answers inside an
     * array body and inside a JSON body, except where that JSON body is over
     * MAX_REQUEST_BYTES. The comparison counts are asserted so a registry
     * change cannot quietly empty the loop.
     */
    public function testTheBareReceiptAnswersAsTheSameReceiptInABody(): void
    {
        $inputs = [];
        $roots = ['apple-receipt-roots' => AppleRootCerts::receiptRoots()];
        foreach (Fixtures::registry() as $id => $entry) {
            if ($entry['role'] === 'trust-anchor' && str_contains($id, 'receipt')) {
                $roots[$id] = [Fixtures::bytes($id)];
            }
            if ($entry['role'] === 'input' && str_contains($id, 'receipt')) {
                $bytes = Fixtures::bytes($id);
                // A text fixture is what a client sends; the others are the
                // decoded bytes, which a client would send as base64.
                $inputs[$id] = $entry['codec'] === 'text' ? $bytes : base64_encode($bytes);
            }
        }
        $inputs += ['tiny' => 'AQIDBA==', 'not base64' => 'not base64!', 'empty' => '', 'blank' => " \r\n"];

        $compared = 0;
        $overCap = 0;
        $verified = 0;
        foreach ($roots as $rootId => $anchors) {
            foreach ([Environment::Production, Environment::Sandbox] as $environment) {
                $endpoint = new VerifyReceiptEndpoint(
                    $anchors,
                    $environment,
                    new FrozenClock(new DateTimeImmutable(self::CLOCK_NOW)),
                );
                foreach ($inputs as $id => $data) {
                    $label = "{$id} under {$rootId} on {$environment->value}";
                    $bare = $endpoint->verifyReceiptData($data);
                    $fromArray = $endpoint->verifyReceiptResult(['receipt-data' => $data]);
                    self::assertSame($fromArray->toJson(), $bare->toJson(), $label);
                    self::assertSame($fromArray->failureReason(), $bare->failureReason(), $label);
                    $body = (string) json_encode(['receipt-data' => $data]);
                    $json = $endpoint->verifyReceiptJson($body);
                    if (strlen($body) <= VerifyReceiptEndpoint::MAX_REQUEST_BYTES) {
                        self::assertSame($json, $bare->toJson(), $label);
                        ++$compared;
                    } else {
                        // Only the raw JSON entry point has the request cap,
                        // because only it pays json_decode's amplification.
                        self::assertSame('{"status":21002}', $json, $label);
                        ++$overCap;
                    }
                    self::assertInvariant($bare, $label);
                    $verified += $bare->isVerified() ? 1 : 0;
                }
            }
        }
        self::assertGreaterThan(1000, $compared, 'the fixture set was not reached');
        self::assertGreaterThan(0, $overCap, 'no fixture exercised the request cap');
        self::assertGreaterThan(20, $verified, 'too few fixtures verified for the comparison to cover a status-0 body');
    }

    public function testEachFailureNamesItsReason(): void
    {
        $endpoint = self::endpoint(Environment::Sandbox);
        $tooLarge = '{"receipt-data":"' . str_repeat('AAAA', intdiv(VerifyReceiptEndpoint::MAX_REQUEST_BYTES, 4) + 1) . '"}';

        $malformed = [
            'body not JSON' => $endpoint->verifyReceiptResult('not json'),
            'body a JSON list' => $endpoint->verifyReceiptResult('[{"receipt-data":"AQIDBA=="}]'),
            'body a JSON string' => $endpoint->verifyReceiptResult('"AQIDBA=="'),
            'body null' => $endpoint->verifyReceiptResult(null),
            'body an integer' => $endpoint->verifyReceiptResult(42),
            'receipt-data missing' => $endpoint->verifyReceiptResult([]),
            'receipt-data empty' => $endpoint->verifyReceiptResult(['receipt-data' => '']),
            'receipt-data a number' => $endpoint->verifyReceiptResult('{"receipt-data":5}'),
            'receipt-data a list' => $endpoint->verifyReceiptResult(['receipt-data' => ['AQIDBA==']]),
            'bare receipt null' => $endpoint->verifyReceiptData(null),
            'bare receipt empty' => $endpoint->verifyReceiptData(''),
        ];
        foreach ($malformed as $label => $result) {
            self::assertSame(Reason::MalformedRequest, $result->failureReason(), $label);
            self::assertSame(VerifyReceiptEndpoint::STATUS_MALFORMED, $result->status(), $label);
            self::assertInvariant($result, $label);
        }

        // Over Apple's request limit: 21002 like the malformed bodies, but its
        // own reason, so an HTTP layer can answer 413 where Apple does.
        $tooLargeResult = $endpoint->verifyReceiptResult($tooLarge);
        self::assertSame(Reason::RequestTooLarge, $tooLargeResult->failureReason());
        self::assertSame(VerifyReceiptEndpoint::STATUS_MALFORMED, $tooLargeResult->status());
        self::assertInvariant($tooLargeResult, 'body too large');

        $format = [
            'not base64' => $endpoint->verifyReceiptResult(['receipt-data' => 'not base64!']),
            'blank' => $endpoint->verifyReceiptData(" \r\n"),
            'not a receipt' => $endpoint->verifyReceiptResult(['receipt-data' => 'AQIDBA==']),
            'over the receipt cap' => $endpoint->verifyReceiptResult([
                'receipt-data' => str_repeat('A', ReceiptVerifier::MAX_RECEIPT_BYTES + 4),
            ]),
        ];
        foreach ($format as $label => $result) {
            self::assertSame(Reason::InvalidReceiptFormat, $result->failureReason(), $label);
            self::assertSame(VerifyReceiptEndpoint::STATUS_MALFORMED, $result->status(), $label);
            self::assertInvariant($result, $label);
        }

        $foreign = $endpoint->verifyReceiptData(self::base64('receipt-foreign'));
        self::assertSame(Reason::InvalidChain, $foreign->failureReason());
        self::assertSame(VerifyReceiptEndpoint::STATUS_NOT_AUTHENTICATED, $foreign->status());
        $tampered = self::endpoint(Environment::Sandbox, 'gaps-receipt-root')
            ->verifyReceiptData(self::base64('receipt-tampered-payload'));
        self::assertSame(Reason::InvalidSignature, $tampered->failureReason());
        self::assertSame(VerifyReceiptEndpoint::STATUS_NOT_AUTHENTICATED, $tampered->status());
    }

    /**
     * A clock that throws stands in for any unexpected failure inside a call.
     * The endpoint promises never to throw, so it must come back as
     * INTERNAL_ERROR, status 21009, with the Throwable kept for logging, on
     * every entry point.
     */
    public function testAnUnexpectedThrowableIsAnInternalErrorNotAThrow(): void
    {
        $clock = new ThrowingClock();
        foreach ([Environment::Production, Environment::Sandbox] as $environment) {
            $endpoint = self::endpoint($environment, 'receipt-root', $clock);
            $results = [
                'array body' => $endpoint->verifyReceiptResult(['receipt-data' => self::base64('receipt')]),
                'JSON body' => $endpoint->verifyReceiptResult('{"receipt-data":"AQIDBA=="}'),
                'bare receipt' => $endpoint->verifyReceiptData(self::base64('receipt')),
            ];
            foreach ($results as $label => $result) {
                self::assertSame(Reason::InternalError, $result->failureReason(), $label);
                self::assertNull($result->receipt(), $label);
                self::assertSame(VerifyReceiptEndpoint::STATUS_INTERNAL, $result->status(), $label);
                self::assertSame($clock->boom, $result->failureCause(), $label);
                self::assertSame('{"status":21009}', $result->toJson(), $label);
                self::assertSame('{"status":21009}', $result->toJson(Environment::Production), $label);
                self::assertSame('{"status":21009}', $result->toJson(Environment::Sandbox), $label);
                self::assertInvariant($result, $label);
            }
            self::assertSame('{"status":21009}', $endpoint->verifyReceiptJson('{"receipt-data":"AQIDBA=="}'));
        }
    }

    /**
     * The other road to INTERNAL_ERROR: a trusted signer signed content the
     * library cannot read. Same status, not the client's fault, and the
     * parser's own verdict is the failure cause.
     */
    public function testUnreadableSignedContentIsAnInternalErrorWithItsCause(): void
    {
        foreach ([Environment::Production, Environment::Sandbox] as $environment) {
            $result = self::endpoint($environment, 'verification-order-root')
                ->verifyReceiptData(self::base64('receipt-unreadable-creation-date'));
            self::assertSame(Reason::InternalError, $result->failureReason());
            self::assertSame(VerifyReceiptEndpoint::STATUS_INTERNAL, $result->status());
            $cause = $result->failureCause();
            self::assertInstanceOf(VerificationException::class, $cause);
            self::assertSame(Reason::InvalidReceiptFormat, $cause->reason);
            self::assertSame('{"status":21009}', $result->toJson());
            self::assertInvariant($result, $environment->value);
        }
    }

    /** Only the endpoint creates one, so no caller can fabricate status 0. */
    public function testTheResultTypeHasNoPublicConstructor(): void
    {
        $constructor = (new ReflectionClass(VerifyReceiptResult::class))->getConstructor();
        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $this->expectException(Error::class);
        /** @phpstan-ignore-next-line deliberate misuse */
        new VerifyReceiptResult(Environment::Production, null, null, null, new DateTimeImmutable());
    }
}
