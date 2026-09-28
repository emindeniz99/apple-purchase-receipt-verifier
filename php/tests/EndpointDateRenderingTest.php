<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests;

use DateTimeImmutable;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\FrozenClock;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\MintedPki;
use EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support\Shape;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * `verifyReceiptEndpoint()`'s `_pst` date rendering, which the shared
 * conformance suite pins at only two fixed instants
 * (`endpoint/sandbox-receipt-on-sandbox-answers-0`,
 * `endpoint/request-date-is-the-verification-clock`) — every other endpoint
 * behaviour (routing, wire types, size caps, malformed bodies, id
 * rendering) is covered there far more thoroughly than a hand-written test
 * could add to.
 *
 * `_pst` is US Pacific, a DST-observing zone, so both sides of a transition
 * are pinned here: a timezone-database change or a "simplify to UTC-8"
 * refactor shows up as a wrong hour rather than passing by coincidence.
 */
#[CoversClass(Verifier::class)]
final class EndpointDateRenderingTest extends TestCase
{
    public function testThePstRenderingFollowsUsPacificAcrossADstTransition(): void
    {
        $cases = [
            // 2025-03-09 10:00 UTC is 02:00 PST -> 03:00 PDT, just after the spring-forward.
            ['2025-03-09T10:00:00Z', '2025-03-09 03:00:00 America/Los_Angeles'],
            // One hour earlier is still PST.
            ['2025-03-09T09:00:00Z', '2025-03-09 01:00:00 America/Los_Angeles'],
            // 2025-11-02 08:00 UTC is 01:00 PDT; 09:00 UTC is 01:00 PST again.
            ['2025-11-02T08:00:00Z', '2025-11-02 01:00:00 America/Los_Angeles'],
            ['2025-11-02T09:00:00Z', '2025-11-02 01:00:00 America/Los_Angeles'],
            ['2025-07-01T00:00:00Z', '2025-06-30 17:00:00 America/Los_Angeles'],
        ];
        $pki = MintedPki::get();
        $requestJson = json_encode(['receipt-data' => base64_encode($pki->receipt())], JSON_THROW_ON_ERROR);

        foreach ($cases as [$utc, $expected]) {
            $clock = new FrozenClock(new DateTimeImmutable($utc));
            $verifier = Verifier::create(Config::builder()->roots([$pki->rootDer])->clock($clock)->build());
            $response = $verifier->verifyReceiptEndpoint(Environment::Sandbox, $requestJson);
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($response, true, 8, JSON_THROW_ON_ERROR);
            $receipt = Shape::asArray($decoded['receipt'], 'receipt');

            self::assertSame($expected, $receipt['request_date_pst'], $utc);
        }
    }
}
