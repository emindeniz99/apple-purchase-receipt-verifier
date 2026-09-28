<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use RuntimeException;
use Throwable;

/**
 * A defect of one receipt attribute's value, as distinct from a defect of
 * the signed payload's outer structure ({@see ParseException}): the typed
 * field stays `null` and the raw value is kept in `unknownAttributes`
 * rather than failing the whole payload. Never escapes
 * {@see ReceiptPayloadDecoder}.
 *
 * @internal
 */
final class PayloadFormatError extends RuntimeException
{
    public function __construct(string $message, ?Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
