<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * A clock that moves one second forward on every read and counts the reads,
 * so a test can tell one read per call from two.
 */
final class CountingClock implements ClockInterface
{
    public const START = '2026-01-01T00:00:00Z';

    public int $reads = 0;

    public function now(): DateTimeImmutable
    {
        ++$this->reads;

        return (new DateTimeImmutable(self::START))->modify("+{$this->reads} seconds");
    }

    /** What the first read returned. */
    public function first(): DateTimeImmutable
    {
        return (new DateTimeImmutable(self::START))->modify('+1 seconds');
    }
}
