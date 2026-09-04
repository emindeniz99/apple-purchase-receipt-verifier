<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Jws;

/**
 * The decoded `AppTransaction` claims this library models. The environment
 * lives in `receiptType` here, not in an `environment` claim.
 *
 * Dates are epoch MILLISECONDS, exactly as Apple ships them — see the note on
 * {@see TransactionPayload}. Every claim, modelled or not, stays reachable
 * through {@see $claims}.
 */
final class AppTransactionPayload
{
    /**
     * @param array<string, mixed> $claims every claim in the verified
     *        payload, undecoded — the forward-compatibility escape hatch
     */
    public function __construct(
        public readonly ?string $bundleId,
        public readonly ?string $receiptType,
        public readonly ?string $applicationVersion,
        public readonly ?string $originalApplicationVersion,
        public readonly ?string $deviceVerification,
        public readonly ?string $deviceVerificationNonce,
        public readonly ?string $appTransactionId,
        public readonly ?int $appAppleId,
        public readonly ?int $receiptCreationDate,
        public readonly ?int $originalPurchaseDate,
        public readonly ?int $preorderDate,
        public readonly ?int $versionExternalIdentifier,
        public readonly array $claims,
    ) {
    }
}
