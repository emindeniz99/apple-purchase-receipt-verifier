<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use Closure;
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\Operation;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\RevocationState;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\Transport;
use Throwable;

/** A transport that answers from a closure and records what it was asked. */
final class FakeTransport implements Transport
{
    /** @var list<list<string>|null> the roots each open() got, null for the built-in ones */
    public array $opened = [];

    /** @var list<Config> the Config each open() got */
    public array $configs = [];

    /** @var list<array{Operation, string, int}> */
    public array $calls = [];

    /** @param Closure(Operation, string, int): string $responder */
    public function __construct(
        private readonly Closure $responder,
        private readonly ?Throwable $openFails = null,
        private readonly RevocationState $revocation = new RevocationState([], null),
    ) {
    }

    public static function answering(string $json): self
    {
        return new self(static fn (): string => $json);
    }

    public function open(Config $config): RevocationState
    {
        $this->opened[] = $config->roots;
        $this->configs[] = $config;
        if ($this->openFails !== null) {
            throw $this->openFails;
        }

        return $this->revocation;
    }

    public function call(Operation $operation, string $input, int $nowMs): string
    {
        $this->calls[] = [$operation, $input, $nowMs];

        return ($this->responder)($operation, $input, $nowMs);
    }
}
