package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * A verified legacy app receipt (PKCS#7 payload). Only receipts returned by
 * {@link ReceiptVerifier} should be trusted — this class carries no proof by
 * itself. {@code null} fields were absent from the receipt.
 */
public final class AppReceipt {

    private final @Nullable String receiptType;
    private final @Nullable String bundleId;
    private final byte @Nullable [] bundleIdBytes;
    private final @Nullable String appVersion;
    private final byte @Nullable [] opaqueValue;
    private final byte @Nullable [] sha1Hash;
    private final @Nullable Instant creationDate;
    private final @Nullable Instant originalPurchaseDate;
    private final @Nullable String originalAppVersion;
    private final @Nullable Instant expirationDate;
    private final List<InAppPurchase> inAppPurchases;
    private final Map<Integer, List<byte[]>> unknownAttributes;

    AppReceipt(
            @Nullable String receiptType,
            @Nullable String bundleId,
            byte @Nullable [] bundleIdBytes,
            @Nullable String appVersion,
            byte @Nullable [] opaqueValue,
            byte @Nullable [] sha1Hash,
            @Nullable Instant creationDate,
            @Nullable Instant originalPurchaseDate,
            @Nullable String originalAppVersion,
            @Nullable Instant expirationDate,
            List<InAppPurchase> inAppPurchases,
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
    public @Nullable String receiptType() {
        return receiptType;
    }

    /** Attribute 18 (undocumented; community-established). */
    public @Nullable Instant originalPurchaseDate() {
        return originalPurchaseDate;
    }

    public @Nullable String bundleId() {
        return bundleId;
    }

    /** Raw DER bytes of attribute 2 — input to the device-hash check. */
    public byte @Nullable [] bundleIdBytes() {
        return bundleIdBytes == null ? null : bundleIdBytes.clone();
    }

    public @Nullable String appVersion() {
        return appVersion;
    }

    /** Attribute 4 — device-specific opaque value used in the hash binding. */
    public byte @Nullable [] opaqueValue() {
        return opaqueValue == null ? null : opaqueValue.clone();
    }

    /** Attribute 5 — SHA-1 of (device GUID ‖ opaque value ‖ bundle id bytes). */
    public byte @Nullable [] sha1Hash() {
        return sha1Hash == null ? null : sha1Hash.clone();
    }

    /** Attribute 12 — when Apple signed this receipt. */
    public @Nullable Instant creationDate() {
        return creationDate;
    }

    /** Attribute 19 — version the user originally purchased. */
    public @Nullable String originalAppVersion() {
        return originalAppVersion;
    }

    /** Attribute 21 — only present in receipts with an expiry (e.g. VPP). */
    public @Nullable Instant expirationDate() {
        return expirationDate;
    }

    public List<InAppPurchase> inAppPurchases() {
        return inAppPurchases;
    }

    /**
     * Raw values of attribute types this library does not model, keyed by
     * type — forward compatibility for fields Apple may add (PLAN D10).
     * Values are the raw octet-string contents, verified but undecoded.
     *
     * <p>A fresh copy each call, arrays included. The unmodifiable wrapper
     * only stops the map being re-keyed: the {@code List} values and the
     * {@code byte[]} inside them were shared, so a caller could rewrite a
     * verified attribute in place and every later reader of the same receipt
     * would see the rewrite. {@link #opaqueValue()} and {@link #sha1Hash()}
     * already clone for that reason.
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
