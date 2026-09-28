<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use Throwable;

/**
 * Why a verification failed (docs/design/0.7-api.md, "Result").
 *
 * `$message` is safe to log as is: control characters and bidi controls in
 * anything quoted from the input are neutralised ({@see Internal\SafeText}),
 * so it can go into a log line as is. Match on {@see $reason}; the text may
 * change between releases and is not meant to be parsed.
 *
 * `$cause` carries the parser or provider exception behind
 * {@see Reason::UnreadablePayload} and {@see Reason::InternalError}, sanitised
 * (never a raw library message that could quote certificate text). `null`
 * for every other reason.
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
