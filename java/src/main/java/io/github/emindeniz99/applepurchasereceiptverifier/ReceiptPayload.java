package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * The decoded payload of a verified legacy app receipt. Immutable.
 *
 * <p>Names are the keys of Apple's verifyReceipt response, so this class,
 * {@link #toJson()} and Apple's documentation share one vocabulary. The
 * comment on each getter names its receipt attribute type. {@code null} means
 * the attribute was absent (or, for a date, did not parse); the library
 * invents no values. Dates are epoch milliseconds, UTC; receipts carry whole
 * seconds, so they end in {@code 000}.</p>
 *
 * <p>Nothing in here has been checked against anything: the bundle id,
 * environment and purchases are whatever Apple signed, and deciding whether
 * to accept them is the caller's job. {@link Environment#fromReceiptType}
 * reads {@link #receiptType()}; the device-hash check is
 * {@code SHA-1(deviceId || opaqueValue() || bundleIdBytes())} compared with
 * {@link #sha1Hash()}.</p>
 *
 * <p>Byte arrays and {@link #unknownAttributes()} are copied on the way in
 * and on the way out.</p>
 */
public final class ReceiptPayload {

    private final @Nullable String receiptType;
    private final @Nullable Long appItemId;
    private final @Nullable String bundleId;
    private final byte @Nullable [] bundleIdBytes;
    private final @Nullable String applicationVersion;
    private final byte @Nullable [] opaqueValue;
    private final byte @Nullable [] sha1Hash;
    private final @Nullable Long receiptCreationDateMs;
    private final @Nullable Long downloadId;
    private final @Nullable Long versionExternalIdentifier;
    private final List<InAppPurchase> inApp;
    private final @Nullable Long originalPurchaseDateMs;
    private final @Nullable String originalApplicationVersion;
    private final @Nullable Long expirationDateMs;
    private final Map<Integer, List<byte[]>> unknownAttributes;

    /** Public so callers can build payloads by hand in their tests. */
    public ReceiptPayload(
            @Nullable String receiptType,
            @Nullable Long appItemId,
            @Nullable String bundleId,
            byte @Nullable [] bundleIdBytes,
            @Nullable String applicationVersion,
            byte @Nullable [] opaqueValue,
            byte @Nullable [] sha1Hash,
            @Nullable Long receiptCreationDateMs,
            @Nullable Long downloadId,
            @Nullable Long versionExternalIdentifier,
            List<InAppPurchase> inApp,
            @Nullable Long originalPurchaseDateMs,
            @Nullable String originalApplicationVersion,
            @Nullable Long expirationDateMs,
            Map<Integer, List<byte[]>> unknownAttributes) {
        this(
                receiptType,
                appItemId,
                bundleId,
                clone(bundleIdBytes),
                applicationVersion,
                clone(opaqueValue),
                clone(sha1Hash),
                receiptCreationDateMs,
                downloadId,
                versionExternalIdentifier,
                inApp,
                originalPurchaseDateMs,
                originalApplicationVersion,
                expirationDateMs,
                RawAttributes.copy(Objects.requireNonNull(unknownAttributes, "unknownAttributes")),
                true);
    }

    /**
     * For {@link ReceiptDecoder}, which hands over arrays and a map that
     * nothing else references, so the public constructor's defensive copies
     * would only repeat themselves.
     */
    ReceiptPayload(
            @Nullable String receiptType,
            @Nullable Long appItemId,
            @Nullable String bundleId,
            byte @Nullable [] ownedBundleIdBytes,
            @Nullable String applicationVersion,
            byte @Nullable [] ownedOpaqueValue,
            byte @Nullable [] ownedSha1Hash,
            @Nullable Long receiptCreationDateMs,
            @Nullable Long downloadId,
            @Nullable Long versionExternalIdentifier,
            List<InAppPurchase> inApp,
            @Nullable Long originalPurchaseDateMs,
            @Nullable String originalApplicationVersion,
            @Nullable Long expirationDateMs,
            Map<Integer, List<byte[]>> ownedUnknownAttributes,
            boolean owned) {
        this.receiptType = receiptType;
        this.appItemId = appItemId;
        this.bundleId = bundleId;
        this.bundleIdBytes = ownedBundleIdBytes;
        this.applicationVersion = applicationVersion;
        this.opaqueValue = ownedOpaqueValue;
        this.sha1Hash = ownedSha1Hash;
        this.receiptCreationDateMs = receiptCreationDateMs;
        this.downloadId = downloadId;
        this.versionExternalIdentifier = versionExternalIdentifier;
        List<InAppPurchase> purchases = new ArrayList<InAppPurchase>(Objects.requireNonNull(inApp, "inApp"));
        for (InAppPurchase purchase : purchases) {
            Objects.requireNonNull(purchase, "in-app purchase");
        }
        this.inApp = Collections.unmodifiableList(purchases);
        this.originalPurchaseDateMs = originalPurchaseDateMs;
        this.originalApplicationVersion = originalApplicationVersion;
        this.expirationDateMs = expirationDateMs;
        this.unknownAttributes = ownedUnknownAttributes;
    }

    /** Attribute 0, such as {@code Production} or {@code ProductionSandbox}. */
    public @Nullable String receiptType() {
        return receiptType;
    }

    /** Attribute 1, the app's App Store item id; zero in sandbox receipts. */
    public @Nullable Long appItemId() {
        return appItemId;
    }

    /** Attribute 2, decoded. */
    public @Nullable String bundleId() {
        return bundleId;
    }

    /** Attribute 2, the value octets exactly as they sit in the receipt: input to the device hash. */
    public byte @Nullable [] bundleIdBytes() {
        return clone(bundleIdBytes);
    }

    /** Attribute 3. */
    public @Nullable String applicationVersion() {
        return applicationVersion;
    }

    /** Attribute 4, the value octets: input to the device hash. */
    public byte @Nullable [] opaqueValue() {
        return clone(opaqueValue);
    }

    /** Attribute 5, the value octets: the device hash itself. */
    public byte @Nullable [] sha1Hash() {
        return clone(sha1Hash);
    }

    /** Attribute 12, when Apple created the receipt. */
    public @Nullable Long receiptCreationDateMs() {
        return receiptCreationDateMs;
    }

    /** Attribute 15. */
    public @Nullable Long downloadId() {
        return downloadId;
    }

    /** Attribute 16. */
    public @Nullable Long versionExternalIdentifier() {
        return versionExternalIdentifier;
    }

    /** Attribute 17, one entry per purchase, in receipt order; unmodifiable. */
    public List<InAppPurchase> inApp() {
        return inApp;
    }

    /** Attribute 18. */
    public @Nullable Long originalPurchaseDateMs() {
        return originalPurchaseDateMs;
    }

    /** Attribute 19, the version the user originally purchased. */
    public @Nullable String originalApplicationVersion() {
        return originalApplicationVersion;
    }

    /** Attribute 21, set only on receipts that expire (volume purchase). */
    public @Nullable Long expirationDateMs() {
        return expirationDateMs;
    }

    /**
     * Raw value octets of the attribute types not modelled above, by type, in
     * receipt order, so a field Apple adds later is not lost. The attribute's
     * {@code version} integer is not kept. A fresh copy on each call, arrays
     * included.
     */
    public Map<Integer, List<byte[]>> unknownAttributes() {
        return RawAttributes.copy(unknownAttributes);
    }

    /**
     * This payload as canonical JSON, for logging and storage. Every port
     * writes the same bytes: keys in declaration order, snake_case names,
     * dates as numbers with a {@code _ms} suffix, 64-bit ids
     * ({@code app_item_id}, {@code download_id},
     * {@code version_external_identifier}, {@code web_order_line_item_id}) as
     * strings, bytes as padded standard base64, {@code null} for a missing
     * value, no whitespace, only the escapes JSON requires, and non-ASCII
     * characters raw.
     */
    public String toJson() {
        StringBuilder out = new StringBuilder(512 + 512 * inApp.size());
        CanonicalJson json = CanonicalJson.object(out)
                .string("receipt_type", receiptType)
                .id("app_item_id", appItemId)
                .string("bundle_id", bundleId)
                .bytes("bundle_id_bytes", bundleIdBytes)
                .string("application_version", applicationVersion)
                .bytes("opaque_value", opaqueValue)
                .bytes("sha1_hash", sha1Hash)
                .number("receipt_creation_date_ms", receiptCreationDateMs)
                .id("download_id", downloadId)
                .id("version_external_identifier", versionExternalIdentifier);
        json.key("in_app").append('[');
        for (int i = 0; i < inApp.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            inApp.get(i).writeJson(out);
        }
        out.append(']');
        json.number("original_purchase_date_ms", originalPurchaseDateMs)
                .string("original_application_version", originalApplicationVersion)
                .number("expiration_date_ms", expirationDateMs)
                .attributes("unknown_attributes", unknownAttributes)
                .end();
        return out.toString();
    }

    @Override
    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof ReceiptPayload)) {
            return false;
        }
        ReceiptPayload that = (ReceiptPayload) other;
        return Objects.equals(receiptType, that.receiptType)
                && Objects.equals(appItemId, that.appItemId)
                && Objects.equals(bundleId, that.bundleId)
                && Arrays.equals(bundleIdBytes, that.bundleIdBytes)
                && Objects.equals(applicationVersion, that.applicationVersion)
                && Arrays.equals(opaqueValue, that.opaqueValue)
                && Arrays.equals(sha1Hash, that.sha1Hash)
                && Objects.equals(receiptCreationDateMs, that.receiptCreationDateMs)
                && Objects.equals(downloadId, that.downloadId)
                && Objects.equals(versionExternalIdentifier, that.versionExternalIdentifier)
                && inApp.equals(that.inApp)
                && Objects.equals(originalPurchaseDateMs, that.originalPurchaseDateMs)
                && Objects.equals(originalApplicationVersion, that.originalApplicationVersion)
                && Objects.equals(expirationDateMs, that.expirationDateMs)
                && RawAttributes.equal(unknownAttributes, that.unknownAttributes);
    }

    @Override
    public int hashCode() {
        int hash = Objects.hash(
                receiptType,
                appItemId,
                bundleId,
                applicationVersion,
                receiptCreationDateMs,
                downloadId,
                versionExternalIdentifier,
                inApp,
                originalPurchaseDateMs,
                originalApplicationVersion,
                expirationDateMs);
        hash = 31 * hash + Arrays.hashCode(bundleIdBytes);
        hash = 31 * hash + Arrays.hashCode(opaqueValue);
        hash = 31 * hash + Arrays.hashCode(sha1Hash);
        return 31 * hash + RawAttributes.hash(unknownAttributes);
    }

    /** {@link #toJson()}. */
    @Override
    public String toString() {
        return toJson();
    }

    private static byte @Nullable [] clone(byte @Nullable [] bytes) {
        return bytes == null ? null : bytes.clone();
    }
}
