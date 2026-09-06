package io.github.emindeniz99.applepurchasereceiptverifier.jws;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Date;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

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

    private final @Nullable String appAccountToken;
    private final @Nullable String bundleId;
    private final @Nullable String currency;
    private final @Nullable String environment;
    private final @Nullable Long expiresDate;
    private final @Nullable String inAppOwnershipType;
    private final @Nullable String offerIdentifier;
    private final @Nullable Integer offerType;
    private final @Nullable Long originalPurchaseDate;
    private final @Nullable String originalTransactionId;
    private final @Nullable Long price;
    private final @Nullable String productId;
    private final @Nullable Long purchaseDate;
    private final @Nullable Integer quantity;
    private final @Nullable Long revocationDate;
    private final @Nullable Integer revocationReason;
    private final @Nullable Long signedDate;
    private final @Nullable String storefront;
    private final @Nullable String subscriptionGroupIdentifier;
    private final @Nullable String transactionId;
    private final @Nullable String transactionReason;
    private final @Nullable String type;
    private final @Nullable String webOrderLineItemId;

    @JsonCreator
    TransactionPayload(
            @JsonProperty("appAccountToken") @Nullable String appAccountToken,
            @JsonProperty("bundleId") @Nullable String bundleId,
            @JsonProperty("currency") @Nullable String currency,
            @JsonProperty("environment") @Nullable String environment,
            @JsonProperty("expiresDate") @Nullable Long expiresDate,
            @JsonProperty("inAppOwnershipType") @Nullable String inAppOwnershipType,
            @JsonProperty("offerIdentifier") @Nullable String offerIdentifier,
            @JsonProperty("offerType") @Nullable Integer offerType,
            @JsonProperty("originalPurchaseDate") @Nullable Long originalPurchaseDate,
            @JsonProperty("originalTransactionId") @Nullable String originalTransactionId,
            @JsonProperty("price") @Nullable Long price,
            @JsonProperty("productId") @Nullable String productId,
            @JsonProperty("purchaseDate") @Nullable Long purchaseDate,
            @JsonProperty("quantity") @Nullable Integer quantity,
            @JsonProperty("revocationDate") @Nullable Long revocationDate,
            @JsonProperty("revocationReason") @Nullable Integer revocationReason,
            @JsonProperty("signedDate") @Nullable Long signedDate,
            @JsonProperty("storefront") @Nullable String storefront,
            @JsonProperty("subscriptionGroupIdentifier") @Nullable String subscriptionGroupIdentifier,
            @JsonProperty("transactionId") @Nullable String transactionId,
            @JsonProperty("transactionReason") @Nullable String transactionReason,
            @JsonProperty("type") @Nullable String type,
            @JsonProperty("webOrderLineItemId") @Nullable String webOrderLineItemId) {
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

    public @Nullable String appAccountToken() {
        return appAccountToken;
    }

    public @Nullable String bundleId() {
        return bundleId;
    }

    public @Nullable String currency() {
        return currency;
    }

    public @Nullable String environment() {
        return environment;
    }

    public @Nullable Long expiresDate() {
        return expiresDate;
    }

    public @Nullable String inAppOwnershipType() {
        return inAppOwnershipType;
    }

    public @Nullable String offerIdentifier() {
        return offerIdentifier;
    }

    public @Nullable Integer offerType() {
        return offerType;
    }

    public @Nullable Long originalPurchaseDate() {
        return originalPurchaseDate;
    }

    public @Nullable String originalTransactionId() {
        return originalTransactionId;
    }

    public @Nullable Long price() {
        return price;
    }

    public @Nullable String productId() {
        return productId;
    }

    public @Nullable Long purchaseDate() {
        return purchaseDate;
    }

    public @Nullable Integer quantity() {
        return quantity;
    }

    public @Nullable Long revocationDate() {
        return revocationDate;
    }

    public @Nullable Integer revocationReason() {
        return revocationReason;
    }

    public @Nullable Long signedDate() {
        return signedDate;
    }

    public @Nullable String storefront() {
        return storefront;
    }

    public @Nullable String subscriptionGroupIdentifier() {
        return subscriptionGroupIdentifier;
    }

    public @Nullable String transactionId() {
        return transactionId;
    }

    public @Nullable String transactionReason() {
        return transactionReason;
    }

    public @Nullable String type() {
        return type;
    }

    public @Nullable String webOrderLineItemId() {
        return webOrderLineItemId;
    }
}
