package io.github.emindeniz99.applepurchasereceiptverifier.jws;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Date;
import java.util.Objects;

/**
 * Decoded {@code JWSTransactionDecodedPayload} — the payload of a StoreKit 2
 * {@code Transaction.jwsRepresentation} / App Store Server
 * {@code signedTransactionInfo}. All dates are milliseconds since epoch, as
 * sent by Apple; {@code null} means the claim was absent.
 *
 * <p>Immutable, and safe to publish to other threads. The claims arrive
 * through the constructor rather than being written into the object after it
 * exists: Jackson's default field binding leaves every field a non-final write
 * that another thread may or may not see, which is the one way a verified
 * payload could be read blank by the thread it was handed to.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class TransactionPayload {

    private final String appAccountToken;
    private final String bundleId;
    private final String currency;
    private final String environment;
    private final Long expiresDate;
    private final String inAppOwnershipType;
    private final String offerIdentifier;
    private final Integer offerType;
    private final Long originalPurchaseDate;
    private final String originalTransactionId;
    private final Long price;
    private final String productId;
    private final Long purchaseDate;
    private final Integer quantity;
    private final Long revocationDate;
    private final Integer revocationReason;
    private final Long signedDate;
    private final String storefront;
    private final String subscriptionGroupIdentifier;
    private final String transactionId;
    private final String transactionReason;
    private final String type;
    private final String webOrderLineItemId;

    @JsonCreator
    TransactionPayload(
            @JsonProperty("appAccountToken") String appAccountToken,
            @JsonProperty("bundleId") String bundleId,
            @JsonProperty("currency") String currency,
            @JsonProperty("environment") String environment,
            @JsonProperty("expiresDate") Long expiresDate,
            @JsonProperty("inAppOwnershipType") String inAppOwnershipType,
            @JsonProperty("offerIdentifier") String offerIdentifier,
            @JsonProperty("offerType") Integer offerType,
            @JsonProperty("originalPurchaseDate") Long originalPurchaseDate,
            @JsonProperty("originalTransactionId") String originalTransactionId,
            @JsonProperty("price") Long price,
            @JsonProperty("productId") String productId,
            @JsonProperty("purchaseDate") Long purchaseDate,
            @JsonProperty("quantity") Integer quantity,
            @JsonProperty("revocationDate") Long revocationDate,
            @JsonProperty("revocationReason") Integer revocationReason,
            @JsonProperty("signedDate") Long signedDate,
            @JsonProperty("storefront") String storefront,
            @JsonProperty("subscriptionGroupIdentifier") String subscriptionGroupIdentifier,
            @JsonProperty("transactionId") String transactionId,
            @JsonProperty("transactionReason") String transactionReason,
            @JsonProperty("type") String type,
            @JsonProperty("webOrderLineItemId") String webOrderLineItemId) {
        this.appAccountToken = appAccountToken;
        this.bundleId = bundleId;
        this.currency = currency;
        this.environment = environment;
        this.expiresDate = expiresDate;
        this.inAppOwnershipType = inAppOwnershipType;
        this.offerIdentifier = offerIdentifier;
        this.offerType = offerType;
        this.originalPurchaseDate = originalPurchaseDate;
        this.originalTransactionId = originalTransactionId;
        this.price = price;
        this.productId = productId;
        this.purchaseDate = purchaseDate;
        this.quantity = quantity;
        this.revocationDate = revocationDate;
        this.revocationReason = revocationReason;
        this.signedDate = signedDate;
        this.storefront = storefront;
        this.subscriptionGroupIdentifier = subscriptionGroupIdentifier;
        this.transactionId = transactionId;
        this.transactionReason = transactionReason;
        this.type = type;
        this.webOrderLineItemId = webOrderLineItemId;
    }

    /**
     * Entitlement helper: {@code true} if this transaction grants access at
     * {@code now} — i.e. not revoked, and (for subscriptions) not expired.
     * This is a point-in-time check on the signed claims only; a later refund
     * or renewal is invisible to it (see INTENT.md — track status via
     * transaction id server-side).
     *
     * @param now the instant to judge at; required, because there is no
     *            defensible default. Reading it as "now" would make a
     *            time-dependent answer depend on the system clock silently,
     *            and reading it as the epoch would answer "active" for every
     *            revoked transaction.
     * @throws NullPointerException if {@code now} is null
     */
    public boolean isActiveAt(Date now) {
        Objects.requireNonNull(now, "now must not be null: isActiveAt judges the claims at an instant you choose");
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
