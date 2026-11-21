<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Transport;

use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use InvalidArgumentException;
use LogicException;
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
     * Checks that `aprv` is reachable and speaks this package's ABI, reads
     * the `limits.max_input_bytes` it states, checks that it will run with
     * the roots and revocation settings of `$config`, and returns what the
     * module answered about revocation for them. Called once, by
     * `Verifier::create()`, which has checked each setting's type.
     *
     * @throws InvalidArgumentException when the module refuses the configuration, the server
     *         refuses the token, or the server runs other roots or revocation settings
     * @throws RuntimeException when the binary or the server cannot be used, speaks another ABI
     *         or states no input length or revocation state
     */
    public function open(Config $config): RevocationState;

    /**
     * Runs one operation.
     *
     * @param string $input the request bytes, exactly as the caller gave them;
     *        a transport sends at most the first `max_input_bytes` of them, the
     *        length `aprv` stated at {@see open()} and the cut every Wasm
     *        wrapper makes, which still reaches the module over its cap
     * @param int $nowMs the call's clock, epoch milliseconds
     *
     * @return string the module's JSON, unchanged; for an input over the size
     *         cap, the module's own answer to it (its size refusal)
     *
     * @throws ModuleFaultException when the module trapped, broke the interface or answered unreadably
     * @throws ServerProcessException when `aprv` did not answer: it could not start, died, or the connection broke
     * @throws LogicException when no {@see open()} has succeeded yet
     */
    public function call(Operation $operation, string $input, int $nowMs): string;
}
