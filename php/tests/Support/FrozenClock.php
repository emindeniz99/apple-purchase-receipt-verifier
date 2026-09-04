<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * A clock stuck at one instant.
 *
 * The conformance runner injects this rather than faking global time: there
 * is no `uopz`, no `ClockMock`, no monkey-patched `time()` anywhere in this
 * suite. A case that pins a clock is run by handing that instant to the
 * verifier's own clock option, which is the only thing that proves the seam
 * exists.
 */
final class FrozenClock implements ClockInterface
{
    public function __construct(private readonly DateTimeImmutable $now)
    {
    }

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }
}
