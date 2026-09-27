<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\CanonicalJson;

/**
 * One in-app purchase from a verified legacy app receipt (attribute 17).
 *
 * Dates are epoch milliseconds, UTC, with an `Ms` suffix — receipt dates
 * carry whole seconds, so the last three digits are always `000`
 * (docs/design/0.7-api.md, "Decode rules"). `null` means the attribute was
 * absent, or a date attribute that was present did not parse; the library
 * invents no values.
 */
final readonly class InAppPurchase
{
    /**
     * @param int|null $quantity attribute 1701
     * @param string|null $productId attribute 1702
     * @param string|null $transactionId attribute 1703
     * @param int|null $purchaseDateMs attribute 1704
     * @param string|null $originalTransactionId attribute 1705
     * @param int|null $originalPurchaseDateMs attribute 1706
     * @param int|null $expiresDateMs attribute 1708, set for subscriptions
     * @param int|null $webOrderLineItemId attribute 1711
     * @param int|null $cancellationDateMs attribute 1712, set when Apple support refunded the purchase
     * @param bool|null $isTrialPeriod attribute 1713: 0 is `false`, any other value `true`
     * @param bool|null $isInIntroOfferPeriod attribute 1719: 0 is `false`, any other value `true`
     * @param array<int, list<string>> $unknownAttributes raw value octets of the
     *        attribute types not modelled above, by type, in receipt order —
     *        forward compatibility for fields Apple may add. Verified, but undecoded.
     */
    public function __construct(
        public ?int $quantity = null,
        public ?string $productId = null,
        public ?string $transactionId = null,
        public ?int $purchaseDateMs = null,
        public ?string $originalTransactionId = null,
        public ?int $originalPurchaseDateMs = null,
        public ?int $expiresDateMs = null,
        public ?int $webOrderLineItemId = null,
        public ?int $cancellationDateMs = null,
        public ?bool $isTrialPeriod = null,
        public ?bool $isInIntroOfferPeriod = null,
        public array $unknownAttributes = [],
    ) {
    }

    /** @internal renders this purchase into `$writer`'s parent object as one array element */
    public function writeJson(): string
    {
        return (new CanonicalJson())
            ->number('quantity', $this->quantity)
            ->string('product_id', $this->productId)
            ->string('transaction_id', $this->transactionId)
            ->number('purchase_date_ms', $this->purchaseDateMs)
            ->string('original_transaction_id', $this->originalTransactionId)
            ->number('original_purchase_date_ms', $this->originalPurchaseDateMs)
            ->number('expires_date_ms', $this->expiresDateMs)
            ->id('web_order_line_item_id', $this->webOrderLineItemId)
            ->number('cancellation_date_ms', $this->cancellationDateMs)
            ->bool('is_trial_period', $this->isTrialPeriod)
            ->bool('is_in_intro_offer_period', $this->isInIntroOfferPeriod)
            ->attributes('unknown_attributes', $this->unknownAttributes)
            ->build();
    }
}
