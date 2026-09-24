package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * One in-app purchase from a legacy app receipt (attribute 17). Field set
 * per Apple's "Validating receipts on the device" attribute table;
 * {@code null} means the attribute was absent from the receipt.
 */
public final class InAppPurchase {

    private final @Nullable Long quantity;
    private final @Nullable String productId;
    private final @Nullable String transactionId;
    private final @Nullable String originalTransactionId;
    private final @Nullable Instant purchaseDate;
    private final @Nullable Instant originalPurchaseDate;
    private final @Nullable Instant expiresDate;
    private final @Nullable Instant cancellationDate;
    private final @Nullable Long webOrderLineItemId;
    private final @Nullable Long isTrialPeriod;
    private final @Nullable Long isInIntroOfferPeriod;
    private final Map<Integer, List<byte[]>> unknownAttributes;

    InAppPurchase(
            @Nullable Long quantity,
            @Nullable String productId,
            @Nullable String transactionId,
            @Nullable String originalTransactionId,
            @Nullable Instant purchaseDate,
            @Nullable Instant originalPurchaseDate,
            @Nullable Instant expiresDate,
            @Nullable Instant cancellationDate,
            @Nullable Long webOrderLineItemId,
            @Nullable Long isTrialPeriod,
            @Nullable Long isInIntroOfferPeriod,
            Map<Integer, List<byte[]>> unknownAttributes) {
        this.quantity = quantity;
        this.productId = productId;
        this.transactionId = transactionId;
        this.originalTransactionId = originalTransactionId;
        this.purchaseDate = purchaseDate;
        this.originalPurchaseDate = originalPurchaseDate;
        this.expiresDate = expiresDate;
        this.cancellationDate = cancellationDate;
        this.webOrderLineItemId = webOrderLineItemId;
        this.isTrialPeriod = isTrialPeriod;
        this.isInIntroOfferPeriod = isInIntroOfferPeriod;
        this.unknownAttributes = Collections.unmodifiableMap(unknownAttributes);
    }

    /** Number of units purchased (attribute 1701). */
    public @Nullable Long quantity() {
        return quantity;
    }

    public @Nullable String productId() {
        return productId;
    }

    public @Nullable String transactionId() {
        return transactionId;
    }

    public @Nullable String originalTransactionId() {
        return originalTransactionId;
    }

    /** Purchase date (attribute 1704), an {@link Instant}, not epoch milliseconds. */
    public @Nullable Instant purchaseDate() {
        return purchaseDate;
    }

    /** Purchase date of the original transaction (attribute 1706), an {@link Instant}. */
    public @Nullable Instant originalPurchaseDate() {
        return originalPurchaseDate;
    }

    /** Subscription expiration (attribute 1708), if this is a subscription. */
    public @Nullable Instant expiresDate() {
        return expiresDate;
    }

    /** Set when Apple customer support cancelled/refunded (attribute 1712). */
    public @Nullable Instant cancellationDate() {
        return cancellationDate;
    }

    public @Nullable Long webOrderLineItemId() {
        return webOrderLineItemId;
    }

    /**
     * Attribute 1713 — 1 while the purchase is inside a free trial, 0
     * otherwise. Carried as an integer like
     * {@link #isInIntroOfferPeriod()}, which Apple's verifyReceipt answer
     * renders as the string "true"/"false".
     */
    public @Nullable Long isTrialPeriod() {
        return isTrialPeriod;
    }

    public @Nullable Long isInIntroOfferPeriod() {
        return isInIntroOfferPeriod;
    }

    /**
     * Raw unmodeled attributes by type, so a field Apple adds later is not
     * lost.
     *
     * <p>A fresh copy each call, arrays included, for the same reason as
     * {@link AppReceipt#unknownAttributes()}: the shared {@code byte[]}
     * contents could otherwise be rewritten by one caller for every other.
     */
    public Map<Integer, List<byte[]>> unknownAttributes() {
        return AppReceipt.deepCopy(unknownAttributes);
    }
}
