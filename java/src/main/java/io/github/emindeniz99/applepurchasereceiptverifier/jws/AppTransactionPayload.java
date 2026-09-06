package io.github.emindeniz99.applepurchasereceiptverifier.jws;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

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

    private final Long appAppleId;
    private final String appTransactionId;
    private final String applicationVersion;
    private final String bundleId;
    private final String deviceVerification;
    private final String deviceVerificationNonce;
    private final String originalApplicationVersion;
    private final Long originalPurchaseDate;
    private final Long preorderDate;
    private final Long receiptCreationDate;
    private final String receiptType;
    private final Long versionExternalIdentifier;

    @JsonCreator
    AppTransactionPayload(
            @JsonProperty("appAppleId") Long appAppleId,
            @JsonProperty("appTransactionId") String appTransactionId,
            @JsonProperty("applicationVersion") String applicationVersion,
            @JsonProperty("bundleId") String bundleId,
            @JsonProperty("deviceVerification") String deviceVerification,
            @JsonProperty("deviceVerificationNonce") String deviceVerificationNonce,
            @JsonProperty("originalApplicationVersion") String originalApplicationVersion,
            @JsonProperty("originalPurchaseDate") Long originalPurchaseDate,
            @JsonProperty("preorderDate") Long preorderDate,
            @JsonProperty("receiptCreationDate") Long receiptCreationDate,
            @JsonProperty("receiptType") String receiptType,
            @JsonProperty("versionExternalIdentifier") Long versionExternalIdentifier) {
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

    public Long appAppleId() {
        return appAppleId;
    }

    public String appTransactionId() {
        return appTransactionId;
    }

    public String applicationVersion() {
        return applicationVersion;
    }

    public String bundleId() {
        return bundleId;
    }

    public String deviceVerification() {
        return deviceVerification;
    }

    public String deviceVerificationNonce() {
        return deviceVerificationNonce;
    }

    public String originalApplicationVersion() {
        return originalApplicationVersion;
    }

    public Long originalPurchaseDate() {
        return originalPurchaseDate;
    }

    public Long preorderDate() {
        return preorderDate;
    }

    public Long receiptCreationDate() {
        return receiptCreationDate;
    }

    /** The environment claim of an AppTransaction (e.g. {@code "Production"}). */
    public String receiptType() {
        return receiptType;
    }

    public Long versionExternalIdentifier() {
        return versionExternalIdentifier;
    }
}
