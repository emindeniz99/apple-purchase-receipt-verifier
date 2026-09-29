<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Transport;

use InvalidArgumentException;
use RuntimeException;

/**
 * How the façade reaches `aprv`, the one binary that runs the verification
 * module: {@see CliTransport} starts it once per call, {@see HttpTransport}
 * talks to a server the caller runs. A transport moves bytes and reports
 * how the call ended; it holds no verification logic and takes no decision
 * about a receipt.
 *
 * A transport serves one {@see \EminDeniz99\ApplePurchaseReceiptVerifier\Verifier}:
 * `Verifier::create()` calls {@see open()} once.
 */
interface Transport
{
    /**
     * Checks that `aprv` is reachable and speaks this package's ABI, and
     * that it will run with `$roots`. Called once, by `Verifier::create()`.
     *
     * @param list<string>|null $roots DER bytes; null means the module's built-in Apple roots
     *
     * @throws InvalidArgumentException when the module refuses the roots, or the server refuses the token
     * @throws RuntimeException when the binary or the server cannot be used, or speaks another ABI
     */
    public function open(?array $roots): void;

    /**
     * Runs one operation.
     *
     * @param string $input the request bytes, exactly as the caller gave them
     * @param int $nowMs the call's clock, epoch milliseconds
     *
     * @return string the module's JSON, unchanged
     *
     * @throws InputTooLargeException when `aprv` refused the input for its size before the module saw it
     * @throws ModuleFaultException when the module trapped, broke the interface or answered unreadably
     * @throws ServerProcessException when `aprv` did not answer: it could not start, died, or the connection broke
     */
    public function call(Operation $operation, string $input, int $nowMs): string;
}
