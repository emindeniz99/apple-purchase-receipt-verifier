<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Transport;

use RuntimeException;

/**
 * The verification module did not produce an answer: it trapped (CLI exit
 * status 70, server `WASM_TRAP`), broke the interface (`ABI_ERROR`), or the
 * JSON it answered is not the shape the wire contract gives. The façade
 * answers `INTERNAL_ERROR` and keeps this as the failure's cause, so it is
 * never mistaken for {@see ServerProcessException}.
 */
final class ModuleFaultException extends RuntimeException
{
    /** @param string $category what `aprv` reported: `WASM_TRAP`, `ABI_ERROR`, `EXIT_70` or `BAD_ANSWER` */
    public function __construct(
        public readonly string $category,
        string $message,
    ) {
        parent::__construct($message);
    }
}
