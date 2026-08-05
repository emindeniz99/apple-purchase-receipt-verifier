package io.github.emindeniz99.applepurchase.receipt;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * A verified legacy app receipt (PKCS#7 payload). Only receipts returned by
 * {@link ReceiptVerifier} should be trusted — this class carries no proof by
 * itself. {@code null} fields were absent from the receipt.
 */
public final class AppReceipt {

    private final String receiptType;
    private final String bundleId;
    private final byte[] bundleIdBytes;
    private final String appVersion;
    private final byte[] opaqueValue;
    private final byte[] sha1Hash;
    private final Instant creationDate;
    private final Instant originalPurchaseDate;
    private final String originalAppVersion;
    private final Instant expirationDate;
    private final List<InAppPurchase> inAppPurchases;
    private final Map<Integer, List<byte[]>> unknownAttributes;

    AppReceipt(String receiptType, String bundleId, byte[] bundleIdBytes, String appVersion,
               byte[] opaqueValue, byte[] sha1Hash, Instant creationDate,
               Instant originalPurchaseDate, String originalAppVersion,
               Instant expirationDate, List<InAppPurchase> inAppPurchases,
               Map<Integer, List<byte[]>> unknownAttributes) {
        this.receiptType = receiptType;
        this.originalPurchaseDate = originalPurchaseDate;
        this.bundleId = bundleId;
        this.bundleIdBytes = bundleIdBytes;
        this.appVersion = appVersion;
        this.opaqueValue = opaqueValue;
        this.sha1Hash = sha1Hash;
        this.creationDate = creationDate;
        this.originalAppVersion = originalAppVersion;
        this.expirationDate = expirationDate;
        this.inAppPurchases = Collections.unmodifiableList(inAppPurchases);
        this.unknownAttributes = Collections.unmodifiableMap(unknownAttributes);
    }

    /** Attribute 0, e.g. "Production" / "ProductionSandbox" (undocumented). */
    public String receiptType() {
        return receiptType;
    }

    /** Attribute 18 (undocumented; community-established). */
    public Instant originalPurchaseDate() {
        return originalPurchaseDate;
    }

    public String bundleId() {
        return bundleId;
    }

    /** Raw DER bytes of attribute 2 — input to the device-hash check. */
    public byte[] bundleIdBytes() {
        return bundleIdBytes == null ? null : bundleIdBytes.clone();
    }

    public String appVersion() {
        return appVersion;
    }

    /** Attribute 4 — device-specific opaque value used in the hash binding. */
    public byte[] opaqueValue() {
        return opaqueValue == null ? null : opaqueValue.clone();
    }

    /** Attribute 5 — SHA-1 of (device GUID ‖ opaque value ‖ bundle id bytes). */
    public byte[] sha1Hash() {
        return sha1Hash == null ? null : sha1Hash.clone();
    }

    /** Attribute 12 — when Apple signed this receipt. */
    public Instant creationDate() {
        return creationDate;
    }

    /** Attribute 19 — version the user originally purchased. */
    public String originalAppVersion() {
        return originalAppVersion;
    }

    /** Attribute 21 — only present in receipts with an expiry (e.g. VPP). */
    public Instant expirationDate() {
        return expirationDate;
    }

    public List<InAppPurchase> inAppPurchases() {
        return inAppPurchases;
    }

    /**
     * Raw values of attribute types this library does not model, keyed by
     * type — forward compatibility for fields Apple may add (PLAN D10).
     * Values are the raw octet-string contents, verified but undecoded.
     */
    public Map<Integer, List<byte[]>> unknownAttributes() {
        return unknownAttributes;
    }
}
