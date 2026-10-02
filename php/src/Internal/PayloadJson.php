<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

use EminDeniz99\ApplePurchaseReceiptVerifier\InAppPurchase;

/**
 * The value rules {@see \EminDeniz99\ApplePurchaseReceiptVerifier\ReceiptPayload::toJson()}
 * encodes with (docs/design/0.7-api.md, "Our JSON").
 *
 * @internal
 */
final class PayloadJson
{
    private function __construct()
    {
    }

    /** A 64-bit id as a decimal string, so JavaScript readers do not round it. */
    public static function id(?int $value): ?string
    {
        return $value === null ? null : (string) $value;
    }

    /** Bytes as padded standard base64. */
    public static function bytes(?string $value): ?string
    {
        return $value === null ? null : base64_encode($value);
    }

    /**
     * Each type as a decimal key, its values base64 in receipt order; an
     * object, so an empty set encodes as `{}` rather than `[]`.
     *
     * @param array<int, list<string>> $attributes
     */
    public static function attributes(array $attributes): \stdClass
    {
        ksort($attributes);
        $out = new \stdClass();
        foreach ($attributes as $type => $values) {
            $out->{(string) $type} = array_map('base64_encode', $values);
        }

        return $out;
    }

    /**
     * One purchase as the value `in_app` holds.
     *
     * @return array<string, mixed>
     */
    public static function inApp(InAppPurchase $purchase): array
    {
        return [
            'quantity' => $purchase->quantity,
            'product_id' => $purchase->productId,
            'transaction_id' => $purchase->transactionId,
            'purchase_date_ms' => $purchase->purchaseDateMs,
            'original_transaction_id' => $purchase->originalTransactionId,
            'original_purchase_date_ms' => $purchase->originalPurchaseDateMs,
            'expires_date_ms' => $purchase->expiresDateMs,
            'web_order_line_item_id' => self::id($purchase->webOrderLineItemId),
            'cancellation_date_ms' => $purchase->cancellationDateMs,
            'is_trial_period' => $purchase->isTrialPeriod,
            'is_in_intro_offer_period' => $purchase->isInIntroOfferPeriod,
            'unknown_attributes' => self::attributes($purchase->unknownAttributes),
        ];
    }
}
