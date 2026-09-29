<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

use Closure;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\Operation;
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\Transport;
use Throwable;

/** A transport that answers from a closure and records what it was asked. */
final class FakeTransport implements Transport
{
    /** @var list<list<string>> the roots each open() got */
    public array $opened = [];

    /** @var list<array{Operation, string, int}> */
    public array $calls = [];

    /** @param Closure(Operation, string, int): string $responder */
    public function __construct(private readonly Closure $responder, private readonly ?Throwable $openFails = null)
    {
    }

    public static function answering(string $json): self
    {
        return new self(static fn (): string => $json);
    }

    public function open(array $roots): void
    {
        $this->opened[] = $roots;
        if ($this->openFails !== null) {
            throw $this->openFails;
        }
    }

    public function call(Operation $operation, string $input, int $nowMs): string
    {
        $this->calls[] = [$operation, $input, $nowMs];

        return ($this->responder)($operation, $input, $nowMs);
    }
}
