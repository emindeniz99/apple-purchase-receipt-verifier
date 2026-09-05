package io.github.emindeniz99.applepurchasereceiptverifier.jws;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.Date;

/**
 * Decoded {@code JWSTransactionDecodedPayload} — the payload of a StoreKit 2
 * {@code Transaction.jwsRepresentation} / App Store Server
 * {@code signedTransactionInfo}. All dates are milliseconds since epoch, as
 * sent by Apple; {@code null} means the claim was absent.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class TransactionPayload {

    private String appAccountToken;
    private String bundleId;
    private String currency;
    private String environment;
    private Long expiresDate;
    private String inAppOwnershipType;
    private String offerIdentifier;
    private Integer offerType;
    private Long originalPurchaseDate;
    private String originalTransactionId;
    private Long price;
    private String productId;
    private Long purchaseDate;
    private Integer quantity;
    private Long revocationDate;
    private Integer revocationReason;
    private Long signedDate;
    private String storefront;
    private String subscriptionGroupIdentifier;
    private String transactionId;
    private String transactionReason;
    private String type;
    private String webOrderLineItemId;

    TransactionPayload() {}

    /**
     * Entitlement helper: {@code true} if this transaction grants access at
     * {@code now} — i.e. not revoked, and (for subscriptions) not expired.
     * This is a point-in-time check on the signed claims only; a later refund
     * or renewal is invisible to it (see INTENT.md — track status via
     * transaction id server-side).
     */
    public boolean isActiveAt(Date now) {
        long t = now.getTime();
        if (revocationDate != null && t >= revocationDate) {
            return false;
        }
        if (expiresDate != null) {
            return t < expiresDate;
        }
        return true;
    }

    public String appAccountToken() {
        return appAccountToken;
    }

    public String bundleId() {
        return bundleId;
    }

    public String currency() {
        return currency;
    }

    public String environment() {
        return environment;
    }

    public Long expiresDate() {
        return expiresDate;
    }

    public String inAppOwnershipType() {
        return inAppOwnershipType;
    }

    public String offerIdentifier() {
        return offerIdentifier;
    }

    public Integer offerType() {
        return offerType;
    }

    public Long originalPurchaseDate() {
        return originalPurchaseDate;
    }

    public String originalTransactionId() {
        return originalTransactionId;
    }

    public Long price() {
        return price;
    }

    public String productId() {
        return productId;
    }

    public Long purchaseDate() {
        return purchaseDate;
    }

    public Integer quantity() {
        return quantity;
    }

    public Long revocationDate() {
        return revocationDate;
    }

    public Integer revocationReason() {
        return revocationReason;
    }

    public Long signedDate() {
        return signedDate;
    }

    public String storefront() {
        return storefront;
    }

    public String subscriptionGroupIdentifier() {
        return subscriptionGroupIdentifier;
    }

    public String transactionId() {
        return transactionId;
    }

    public String transactionReason() {
        return transactionReason;
    }

    public String type() {
        return type;
    }

    public String webOrderLineItemId() {
        return webOrderLineItemId;
    }
}
