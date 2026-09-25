package bakeoff.jni;

import java.util.List;

/** A verified app receipt. Any field except {@link #inAppPurchases()} may be null. */
public final class AppReceipt {
    private final String receiptType, bundleId, appVersion, originalAppVersion;
    private final byte[] opaqueValue, sha1Hash;
    private final Long creationDateMs;
    private final List<InAppPurchase> inAppPurchases;

    AppReceipt(String receiptType, String bundleId, String appVersion, String originalAppVersion,
               byte[] opaqueValue, byte[] sha1Hash, Long creationDateMs, List<InAppPurchase> inAppPurchases) {
        this.receiptType = receiptType;
        this.bundleId = bundleId;
        this.appVersion = appVersion;
        this.originalAppVersion = originalAppVersion;
        this.opaqueValue = opaqueValue;
        this.sha1Hash = sha1Hash;
        this.creationDateMs = creationDateMs;
        this.inAppPurchases = inAppPurchases;
    }

    /** @return the receipt type, e.g. ProductionSandbox */
    public String receiptType() { return receiptType; }
    /** @return the bundle identifier */
    public String bundleId() { return bundleId; }
    /** @return the app version */
    public String appVersion() { return appVersion; }
    /** @return the originally purchased app version */
    public String originalAppVersion() { return originalAppVersion; }
    /** @return a copy of the opaque value used in the device hash */
    public byte[] opaqueValue() { return opaqueValue == null ? null : opaqueValue.clone(); }
    /** @return a copy of the SHA-1 device hash */
    public byte[] sha1Hash() { return sha1Hash == null ? null : sha1Hash.clone(); }
    /** @return the receipt creation date, epoch milliseconds */
    public Long creationDateMs() { return creationDateMs; }
    /** @return the in-app purchases, unmodifiable */
    public List<InAppPurchase> inAppPurchases() { return inAppPurchases; }
}
