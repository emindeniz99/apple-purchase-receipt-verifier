<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use InvalidArgumentException;

/**
 * The outcome of one verification (docs/design/0.7-api.md, "Result").
 * Exactly one of {@see $payload} and {@see $failure} is set.
 *
 * @template T
 */
final readonly class VerificationResult
{
    /**
     * Construct directly to mock a verifier in a test:
     * `new VerificationResult(payload: $myPayload)` or
     * `new VerificationResult(failure: $myFailure)`.
     *
     * @param T|null $payload set only when verified
     *
     * @throws InvalidArgumentException unless exactly one of `$payload` and `$failure` is given
     */
    public function __construct(
        public mixed $payload = null,
        public ?Failure $failure = null,
    ) {
        if (($payload === null) === ($failure === null)) {
            throw new InvalidArgumentException('exactly one of payload and failure must be set');
        }
    }

    /** Whether the input verified; exactly when {@see $payload} is set. */
    public function verified(): bool
    {
        return $this->payload !== null;
    }
}
