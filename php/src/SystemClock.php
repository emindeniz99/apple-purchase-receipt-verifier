<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;

/**
 * The default clock: the host's wall clock, in UTC.
 *
 * Shipped as public API so a caller wiring a test double does not have to
 * write it, and so `symfony/clock`'s `MockClock` (or any other PSR-20
 * implementation) drops straight in.
 *
 * What the clock is allowed to move is deliberately narrow — see
 * {@see \EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier}: the
 * staleness rule and the endpoint's `request_date` triple, and nothing else.
 * Certificate validity is never judged by an injected clock.
 */
final class SystemClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
}
