<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Transport;

use RuntimeException;

/**
 * `aprv` refused the input for its size before the module saw it: exit
 * status 3 of the CLI, HTTP 413 of the server. The façade answers it as the
 * verification module itself answers an input over its cap: `TOO_LARGE`, or
 * status 21002 at the endpoint.
 */
final class InputTooLargeException extends RuntimeException
{
}
