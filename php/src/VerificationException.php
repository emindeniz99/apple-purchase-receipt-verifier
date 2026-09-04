<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use RuntimeException;
use Throwable;

/**
 * Thrown when a signed payload fails verification. A payload that throws must
 * be treated as fully untrusted: nothing verified so far is returned.
 *
 * `$e->reason` is the contract. The message is human-readable detail, is
 * formatted `"REASON: detail"` for readability only, and is explicitly NOT
 * part of the API — do not parse it, and do not expect it to be stable.
 * It never contains receipt bytes, claim values or key material (PLAN.md
 * D11: the reason code is the entire observability surface).
 *
 * Misconfiguration is a different thing and raises `\InvalidArgumentException`
 * instead: an empty trust-anchor list is a programming error, not a verdict
 * about a payload.
 */
final class VerificationException extends RuntimeException
{
    public function __construct(
        public readonly Reason $reason,
        string $detail,
        ?Throwable $previous = null,
    ) {
        parent::__construct($reason->value . ': ' . $detail, 0, $previous);
    }
}
