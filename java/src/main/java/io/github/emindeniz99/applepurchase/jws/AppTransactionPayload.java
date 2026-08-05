package io.github.emindeniz99.applepurchase.jws;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Decoded {@code AppTransaction} payload (StoreKit 2, iOS 16+): app-level
 * proof of purchase/download. Environment lives in {@link #receiptType()};
 * dates are milliseconds since epoch; {@code null} means the claim was absent.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AppTransactionPayload {

    private Long appAppleId;
    private String appTransactionId;
    private String applicationVersion;
    private String bundleId;
    private String deviceVerification;
    private String deviceVerificationNonce;
    private String originalApplicationVersion;
    private Long originalPurchaseDate;
    private Long preorderDate;
    private Long receiptCreationDate;
    private String receiptType;
    private Long versionExternalIdentifier;

    AppTransactionPayload() {
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
