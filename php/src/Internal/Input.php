<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

/**
 * How much of an input a transport sends to `aprv`.
 *
 * @internal
 */
final class Input
{
    /**
     * The most bytes of an input either transport sends: one over the core's
     * largest cap (3,145,728 bytes, the receipt and endpoint body cap), the
     * same cut every Wasm wrapper makes before the module, so an input over
     * it still reaches the module over it and the module answers TOO_LARGE
     * (21002 from the endpoint). The server reads no more than this of a
     * body announced past its drain limit and closes after its answer, so
     * sending the rest would meet a reset instead of that answer.
     */
    public const MAX_BYTES = 3_145_729;

    private function __construct()
    {
    }
}
