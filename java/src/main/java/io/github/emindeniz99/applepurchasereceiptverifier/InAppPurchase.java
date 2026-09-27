package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * One in-app purchase from a legacy app receipt (attribute 17). Immutable.
 *
 * <p>Names are the keys of Apple's verifyReceipt response. {@code null} means
 * the attribute was absent, or its value did not decode, in which case its
 * octets are in {@link #unknownAttributes()}; the library invents no
 * values. Dates are epoch milliseconds, UTC.</p>
 */
public final class InAppPurchase {

    private final @Nullable Long quantity;
    private final @Nullable String productId;
    private final @Nullable String transactionId;
    private final @Nullable Long purchaseDateMs;
    private final @Nullable String originalTransactionId;
    private final @Nullable Long originalPurchaseDateMs;
    private final @Nullable Long expiresDateMs;
    private final @Nullable Long webOrderLineItemId;
    private final @Nullable Long cancellationDateMs;
    private final @Nullable Boolean isTrialPeriod;
    private final @Nullable Boolean isInIntroOfferPeriod;
    private final Map<Integer, List<byte[]>> unknownAttributes;

    /** Public so callers can build purchases by hand in their tests. */
    public InAppPurchase(
            @Nullable Long quantity,
            @Nullable String productId,
            @Nullable String transactionId,
            @Nullable Long purchaseDateMs,
            @Nullable String originalTransactionId,
            @Nullable Long originalPurchaseDateMs,
            @Nullable Long expiresDateMs,
            @Nullable Long webOrderLineItemId,
            @Nullable Long cancellationDateMs,
            @Nullable Boolean isTrialPeriod,
            @Nullable Boolean isInIntroOfferPeriod,
            Map<Integer, List<byte[]>> unknownAttributes) {
        this.quantity = quantity;
        this.productId = productId;
        this.transactionId = transactionId;
        this.purchaseDateMs = purchaseDateMs;
        this.originalTransactionId = originalTransactionId;
        this.originalPurchaseDateMs = originalPurchaseDateMs;
        this.expiresDateMs = expiresDateMs;
        this.webOrderLineItemId = webOrderLineItemId;
        this.cancellationDateMs = cancellationDateMs;
        this.isTrialPeriod = isTrialPeriod;
        this.isInIntroOfferPeriod = isInIntroOfferPeriod;
        this.unknownAttributes = RawAttributes.copy(Objects.requireNonNull(unknownAttributes, "unknownAttributes"));
    }

    /** Attribute 1701. */
    public @Nullable Long quantity() {
        return quantity;
    }

    /** Attribute 1702. */
    public @Nullable String productId() {
        return productId;
    }

    /** Attribute 1703. */
    public @Nullable String transactionId() {
        return transactionId;
    }

    /** Attribute 1704. */
    public @Nullable Long purchaseDateMs() {
        return purchaseDateMs;
    }

    /** Attribute 1705. */
    public @Nullable String originalTransactionId() {
        return originalTransactionId;
    }

    /** Attribute 1706. */
    public @Nullable Long originalPurchaseDateMs() {
        return originalPurchaseDateMs;
    }

    /** Attribute 1708, set for subscriptions. */
    public @Nullable Long expiresDateMs() {
        return expiresDateMs;
    }

    /** Attribute 1711. */
    public @Nullable Long webOrderLineItemId() {
        return webOrderLineItemId;
    }

    /** Attribute 1712, set when Apple support refunded the purchase. */
    public @Nullable Long cancellationDateMs() {
        return cancellationDateMs;
    }

    /** Attribute 1713: 0 is {@code false}, any other value {@code true}. */
    public @Nullable Boolean isTrialPeriod() {
        return isTrialPeriod;
    }

    /** Attribute 1719: 0 is {@code false}, any other value {@code true}. */
    public @Nullable Boolean isInIntroOfferPeriod() {
        return isInIntroOfferPeriod;
    }

    /**
     * Raw value octets of the attribute types not modelled above, by type, in
     * receipt order, so a field Apple adds later is not lost. A fresh copy on
     * each call, arrays included.
     */
    public Map<Integer, List<byte[]>> unknownAttributes() {
        return RawAttributes.copy(unknownAttributes);
    }

    /** This purchase's object inside {@code in_app}; see {@link ReceiptPayload#toJson()}. */
    void writeJson(StringBuilder out) {
        CanonicalJson json = CanonicalJson.object(out)
                .number("quantity", quantity)
                .string("product_id", productId)
                .string("transaction_id", transactionId)
                .number("purchase_date_ms", purchaseDateMs)
                .string("original_transaction_id", originalTransactionId)
                .number("original_purchase_date_ms", originalPurchaseDateMs)
                .number("expires_date_ms", expiresDateMs)
                .id("web_order_line_item_id", webOrderLineItemId)
                .number("cancellation_date_ms", cancellationDateMs)
                .bool("is_trial_period", isTrialPeriod)
                .bool("is_in_intro_offer_period", isInIntroOfferPeriod)
                .attributes("unknown_attributes", unknownAttributes);
        json.end();
    }

    /** Equal when {@link #toString()}, the canonical JSON, is. */
    @Override
    public boolean equals(@Nullable Object other) {
        return other instanceof InAppPurchase && toString().equals(other.toString());
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    /** The purchase's canonical JSON object. */
    @Override
    public String toString() {
        StringBuilder out = new StringBuilder(256);
        writeJson(out);
        return out.toString();
    }
}
