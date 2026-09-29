<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use Psr\Clock\ClockInterface;

/**
 * Builds a {@see Config}, replacing only what is given; anything not set
 * takes {@see Config::defaults()}'s value.
 *
 * ```php
 * $config = Config::builder()->roots($myRootsAsDer)->clock($myClock)->build();
 * ```
 */
final class ConfigBuilder
{
    /** @var list<string>|null */
    private ?array $roots = null;

    private ClockInterface $clock;

    public function __construct()
    {
        $this->clock = new SystemClock();
    }

    /**
     * Not calling this keeps the module's built-in Apple roots. An empty set
     * given here is refused by {@see Verifier::create()}, not read as "built-in".
     *
     * @param iterable<string> $roots DER bytes of the trust anchors
     */
    public function roots(iterable $roots): self
    {
        $this->roots = is_array($roots) ? array_values($roots) : iterator_to_array($roots, false);

        return $this;
    }

    public function clock(ClockInterface $clock): self
    {
        $this->clock = $clock;

        return $this;
    }

    public function build(): Config
    {
        return new Config($this->roots, $this->clock);
    }
}
