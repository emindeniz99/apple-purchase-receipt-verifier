<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Transport;

use RuntimeException;

/**
 * `aprv` did not answer: the process could not start, ended without a
 * result, timed out, or the connection broke; or the server answered with a
 * problem that is not a verification fault (HTTP 5xx `INTERNAL_ERROR`, a
 * refused token, an unknown route). The façade answers `INTERNAL_ERROR` and
 * keeps this as the failure's cause, so it is never mistaken for
 * {@see ModuleFaultException}.
 */
final class ServerProcessException extends RuntimeException
{
}
