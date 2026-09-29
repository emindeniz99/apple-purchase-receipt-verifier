<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use Throwable;

/**
 * Why a verification failed (docs/design/0.7-api.md, "Result").
 *
 * `$message` is safe to log as is: the module neutralises control characters
 * and bidi controls in anything it quotes from the input. Match on
 * {@see $reason}; the text may change between releases and is not meant to
 * be parsed.
 *
 * `$cause` is set only when this library, not the verification module,
 * produced {@see Reason::InternalError}: a {@see Transport\ModuleFaultException}
 * (the module trapped or answered unreadably), a
 * {@see Transport\ServerProcessException} (`aprv` did not answer) or the
 * exception the configured clock threw. `null` for every verdict of the
 * module, {@see Reason::UnreadablePayload} and the module's own
 * {@see Reason::InternalError} included.
 */
final readonly class Failure
{
    public function __construct(
        public Reason $reason,
        public string $message,
        public ?Throwable $cause = null,
    ) {
    }
}
