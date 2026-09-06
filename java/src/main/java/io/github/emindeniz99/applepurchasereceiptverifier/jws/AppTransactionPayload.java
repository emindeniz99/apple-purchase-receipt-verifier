package io.github.emindeniz99.applepurchasereceiptverifier.jws;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

/**
 * Decoded {@code AppTransaction} payload (StoreKit 2, iOS 16+): app-level
 * proof of purchase/download. Environment lives in {@link #receiptType()};
 * dates are milliseconds since epoch; {@code null} means the claim was absent.
 *
 * <p>Immutable, and safe to publish to other threads, for the reason given on
 * {@link TransactionPayload}: the claims arrive through the constructor rather
 * than being written into the object after it exists.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AppTransactionPayload {

    private final @Nullable Long appAppleId;
    private final @Nullable String appTransactionId;
    private final @Nullable String applicationVersion;
    private final @Nullable String bundleId;
    private final @Nullable String deviceVerification;
    private final @Nullable String deviceVerificationNonce;
    private final @Nullable String originalApplicationVersion;
    private final @Nullable Long originalPurchaseDate;
    private final @Nullable Long preorderDate;
    private final @Nullable Long receiptCreationDate;
    private final @Nullable String receiptType;
    private final @Nullable Long versionExternalIdentifier;

    @JsonCreator
    AppTransactionPayload(
            @JsonProperty("appAppleId") @Nullable Long appAppleId,
            @JsonProperty("appTransactionId") @Nullable String appTransactionId,
            @JsonProperty("applicationVersion") @Nullable String applicationVersion,
            @JsonProperty("bundleId") @Nullable String bundleId,
            @JsonProperty("deviceVerification") @Nullable String deviceVerification,
            @JsonProperty("deviceVerificationNonce") @Nullable String deviceVerificationNonce,
            @JsonProperty("originalApplicationVersion") @Nullable String originalApplicationVersion,
            @JsonProperty("originalPurchaseDate") @Nullable Long originalPurchaseDate,
            @JsonProperty("preorderDate") @Nullable Long preorderDate,
            @JsonProperty("receiptCreationDate") @Nullable Long receiptCreationDate,
            @JsonProperty("receiptType") @Nullable String receiptType,
            @JsonProperty("versionExternalIdentifier") @Nullable Long versionExternalIdentifier) {
        this.appAppleId = appAppleId;
        this.appTransactionId = appTransactionId;
        this.applicationVersion = applicationVersion;
        this.bundleId = bundleId;
        this.deviceVerification = deviceVerification;
        this.deviceVerificationNonce = deviceVerificationNonce;
        this.originalApplicationVersion = originalApplicationVersion;
        this.originalPurchaseDate = originalPurchaseDate;
        this.preorderDate = preorderDate;
        this.receiptCreationDate = receiptCreationDate;
        this.receiptType = receiptType;
        this.versionExternalIdentifier = versionExternalIdentifier;
    }

    public @Nullable Long appAppleId() {
        return appAppleId;
    }

    public @Nullable String appTransactionId() {
        return appTransactionId;
    }

    public @Nullable String applicationVersion() {
        return applicationVersion;
    }

    public @Nullable String bundleId() {
        return bundleId;
    }

    public @Nullable String deviceVerification() {
        return deviceVerification;
    }

    public @Nullable String deviceVerificationNonce() {
        return deviceVerificationNonce;
    }

    public @Nullable String originalApplicationVersion() {
        return originalApplicationVersion;
    }

    public @Nullable Long originalPurchaseDate() {
        return originalPurchaseDate;
    }

    public @Nullable Long preorderDate() {
        return preorderDate;
    }

    public @Nullable Long receiptCreationDate() {
        return receiptCreationDate;
    }

    /** The environment claim of an AppTransaction (e.g. {@code "Production"}). */
    public @Nullable String receiptType() {
        return receiptType;
    }

    public @Nullable Long versionExternalIdentifier() {
        return versionExternalIdentifier;
    }
}
