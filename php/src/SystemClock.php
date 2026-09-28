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
 * The library reads the clock once per call, for two things: the
 * certificate-validity instant when the receipt or JWS states no usable
 * date of its own, and the `request_date` triple of
 * {@see \EminDeniz99\ApplePurchaseReceiptVerifier\Verifier::verifyReceiptEndpoint()}.
 */
final class SystemClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
}
