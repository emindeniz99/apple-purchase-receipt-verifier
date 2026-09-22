<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use RuntimeException;

/** A clock whose every read throws the same exception. */
final class ThrowingClock implements ClockInterface
{
    public readonly RuntimeException $boom;

    public function __construct()
    {
        $this->boom = new RuntimeException('broken clock');
    }

    public function now(): DateTimeImmutable
    {
        throw $this->boom;
    }
}
