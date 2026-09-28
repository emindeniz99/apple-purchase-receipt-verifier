<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use RuntimeException;
use Throwable;

/**
 * Internal control flow only: {@see \EminDeniz99\ApplePurchaseReceiptVerifier\Verifier}'s
 * three methods never throw (docs/design/0.7-api.md, "Setup"). Every public
 * entry point catches this at the boundary and turns it into a
 * {@see \EminDeniz99\ApplePurchaseReceiptVerifier\Failure}.
 *
 * `$reason` is the {@see Reason}; the message is human-readable detail,
 * formatted `"REASON: detail"` for readability only. It never contains
 * receipt bytes, claim values or key material — anything quoted from the
 * input goes through {@see SafeText} first.
 *
 * @internal
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
