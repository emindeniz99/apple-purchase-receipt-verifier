<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Receipt;

use DateTimeImmutable;

/**
 * One in-app purchase from a verified legacy app receipt (attribute 17).
 *
 * Dates are `DateTimeImmutable` in UTC — receipt attributes carry RFC 3339
 * text, so a native date type is the honest representation. (JWS payload
 * claims are the opposite case: Apple ships those as epoch-millisecond
 * integers and they stay integers — see {@see \EminDeniz99\ApplePurchaseReceiptVerifier\Jws\TransactionPayload}.)
 */
final class InAppPurchase
{
    /**
     * Properties whose value is raw bytes rather than text. PHP spells both
     * `string`, so this is how a generic consumer (a serializer, a debug
     * dumper, the conformance adapter) knows to hex-encode rather than print.
     */
    public const BINARY_PROPERTIES = ['unknownAttributes'];

    /**
     * @param array<int, list<string>> $unknownAttributes raw values of attribute
     *        types this library does not model, keyed by type — forward
     *        compatibility for fields Apple may add (PLAN.md D10). Verified,
     *        but undecoded.
     */
    public function __construct(
        public readonly ?int $quantity,
        public readonly ?string $productId,
        public readonly ?string $transactionId,
        public readonly ?string $originalTransactionId,
        public readonly ?DateTimeImmutable $purchaseDate,
        public readonly ?DateTimeImmutable $originalPurchaseDate,
        public readonly ?DateTimeImmutable $expiresDate,
        public readonly ?DateTimeImmutable $cancellationDate,
        public readonly ?int $webOrderLineItemId,
        public readonly ?int $isInIntroOfferPeriod,
        public readonly array $unknownAttributes,
    ) {
    }
}
