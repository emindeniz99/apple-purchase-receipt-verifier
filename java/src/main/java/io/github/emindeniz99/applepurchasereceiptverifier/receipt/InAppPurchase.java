package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
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
        this.isInIntroOfferPeriod = isInIntroOfferPeriod;
        this.unknownAttributes = Collections.unmodifiableMap(unknownAttributes);
    }

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

    public @Nullable Instant purchaseDate() {
        return purchaseDate;
    }

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

    public @Nullable Long isInIntroOfferPeriod() {
        return isInIntroOfferPeriod;
    }

    /**
     * Raw unmodeled attributes by type — forward compatibility (PLAN D10).
     *
     * <p>A fresh copy each call, arrays included, for the same reason as
     * {@link AppReceipt#unknownAttributes()}: the shared {@code byte[]}
     * contents could otherwise be rewritten by one caller for every other.
     */
    public Map<Integer, List<byte[]>> unknownAttributes() {
        Map<Integer, List<byte[]>> copy = new LinkedHashMap<Integer, List<byte[]>>(unknownAttributes.size());
        for (Map.Entry<Integer, List<byte[]>> entry : unknownAttributes.entrySet()) {
            List<byte[]> values = new ArrayList<byte[]>(entry.getValue().size());
            for (byte[] value : entry.getValue()) {
                values.add(value.clone());
            }
            copy.put(entry.getKey(), Collections.unmodifiableList(values));
        }
        return Collections.unmodifiableMap(copy);
    }
}
