package io.github.emindeniz99.applepurchase.receipt;

import java.time.Instant;

/**
 * One in-app purchase from a legacy app receipt (attribute 17). Field set
 * per Apple's "Validating receipts on the device" attribute table;
 * {@code null} means the attribute was absent from the receipt.
 */
public final class InAppPurchase {

    private final Long quantity;
    private final String productId;
    private final String transactionId;
    private final String originalTransactionId;
    private final Instant purchaseDate;
    private final Instant originalPurchaseDate;
    private final Instant expiresDate;
    private final Instant cancellationDate;
    private final Long webOrderLineItemId;
    private final Long isInIntroOfferPeriod;

    InAppPurchase(Long quantity, String productId, String transactionId,
                  String originalTransactionId, Instant purchaseDate,
                  Instant originalPurchaseDate, Instant expiresDate,
                  Instant cancellationDate, Long webOrderLineItemId,
                  Long isInIntroOfferPeriod) {
        this.quantity = quantity;
        this.productId = productId;
        this.transactionId = transactionId;
        this.originalTransactionId = originalTransactionId;
        this.purchaseDate = purchaseDate;
        this.originalPurchaseDate = originalPurchaseDate;
        this.expiresDate = expiresDate;
        this.cancellationDate = cancellationDate;
        this.webOrderLineItemId = webOrderLineItemId;
        this.isInIntroOfferPeriod = isInIntroOfferPeriod;
    }

    public Long quantity() {
        return quantity;
    }

    public String productId() {
        return productId;
    }

    public String transactionId() {
        return transactionId;
    }

    public String originalTransactionId() {
        return originalTransactionId;
    }

    public Instant purchaseDate() {
        return purchaseDate;
    }

    public Instant originalPurchaseDate() {
        return originalPurchaseDate;
    }

    /** Subscription expiration (attribute 1708), if this is a subscription. */
    public Instant expiresDate() {
        return expiresDate;
    }

    /** Set when Apple customer support cancelled/refunded (attribute 1712). */
    public Instant cancellationDate() {
        return cancellationDate;
    }

    public Long webOrderLineItemId() {
        return webOrderLineItemId;
    }

    public Long isInIntroOfferPeriod() {
        return isInIntroOfferPeriod;
    }
}
