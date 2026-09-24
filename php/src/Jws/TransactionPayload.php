<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Jws;

/**
 * The decoded `JWSTransactionDecodedPayload` claims this library models.
 *
 * **Dates are epoch MILLISECONDS, exactly as Apple ships them**, and that is
 * contractual across every port of this library — do not "improve" them into
 * `DateTimeImmutable`. Converting loses the raw claim and invites a timezone
 * bug in code whose whole job is to agree with four other languages.
 * (Receipt attributes are the opposite case: those carry RFC 3339 text and
 * become `DateTimeImmutable` — see {@see \EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\AppReceipt}.)
 *
 * Every claim Apple sent, modelled or not, stays reachable through
 * {@see $claims}, so a field Apple adds tomorrow needs no library release.
 */
final class TransactionPayload
{
    /**
     * @param array<string, mixed> $claims every claim in the verified
     *        payload, undecoded — the forward-compatibility escape hatch
     */
    public function __construct(
        public readonly ?string $bundleId,
        public readonly ?string $environment,
        public readonly ?string $productId,
        public readonly ?string $transactionId,
        public readonly ?string $originalTransactionId,
        public readonly ?string $webOrderLineItemId,
        public readonly ?string $subscriptionGroupIdentifier,
        public readonly ?string $appAccountToken,
        public readonly ?string $inAppOwnershipType,
        public readonly ?string $type,
        public readonly ?string $transactionReason,
        public readonly ?string $storefront,
        public readonly ?string $currency,
        public readonly ?string $offerIdentifier,
        public readonly ?int $signedDate,
        public readonly ?int $purchaseDate,
        public readonly ?int $originalPurchaseDate,
        public readonly ?int $expiresDate,
        public readonly ?int $revocationDate,
        public readonly ?int $price,
        public readonly ?int $quantity,
        public readonly ?int $offerType,
        public readonly ?int $revocationReason,
        public readonly array $claims,
    ) {
    }
}
