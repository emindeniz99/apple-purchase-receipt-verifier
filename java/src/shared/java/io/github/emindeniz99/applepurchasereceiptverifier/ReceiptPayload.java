package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.json.JsonWriteFeature;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Base64;
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
 * the attribute was absent, or its value did not decode, in which case its
 * octets are in {@link #unknownAttributes()} (for attribute 2, in
 * {@link #bundleIdBytes()} instead). A date Apple wrote as an empty string,
 * its "not set", is also {@code null}, and its octets are not kept. The
 * library invents no values. Dates are epoch milliseconds, UTC; receipts carry whole
 * seconds, so they end in {@code 000}.</p>
 *
 * <p>Nothing in here has been checked against anything: the bundle id,
 * environment and purchases are whatever Apple signed, and deciding whether
 * to accept them is the caller's job. {@link #environment()} states what
 * {@link #receiptType()} names; the device-hash check is
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
    private final @Nullable Long preorderDateMs;
    private final @Nullable String originalApplicationVersion;
    private final @Nullable Long expirationDateMs;
    private final Map<Integer, List<byte[]>> unknownAttributes;
    private final @Nullable Environment environment;

    /**
     * Public so callers can build payloads by hand in their tests. The
     * verifier passes the {@code environment} {@code receiptType} names
     * ({@link #environment()}); a hand-built payload states its own.
     */
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
            @Nullable Long preorderDateMs,
            @Nullable String originalApplicationVersion,
            @Nullable Long expirationDateMs,
            Map<Integer, List<byte[]>> unknownAttributes,
            @Nullable Environment environment) {
        this.receiptType = receiptType;
        this.appItemId = appItemId;
        this.bundleId = bundleId;
        this.bundleIdBytes = clone(bundleIdBytes);
        this.applicationVersion = applicationVersion;
        this.opaqueValue = clone(opaqueValue);
        this.sha1Hash = clone(sha1Hash);
        this.receiptCreationDateMs = receiptCreationDateMs;
        this.downloadId = downloadId;
        this.versionExternalIdentifier = versionExternalIdentifier;
        List<InAppPurchase> purchases = new ArrayList<>(Objects.requireNonNull(inApp, "inApp"));
        for (InAppPurchase purchase : purchases) {
            Objects.requireNonNull(purchase, "in-app purchase");
        }
        this.inApp = Collections.unmodifiableList(purchases);
        this.originalPurchaseDateMs = originalPurchaseDateMs;
        this.preorderDateMs = preorderDateMs;
        this.originalApplicationVersion = originalApplicationVersion;
        this.expirationDateMs = expirationDateMs;
        this.unknownAttributes = RawAttributes.copy(Objects.requireNonNull(unknownAttributes, "unknownAttributes"));
        this.environment = environment;
    }

    /** Attribute 0, such as {@code Production} or {@code ProductionSandbox}. */
    public @Nullable String receiptType() {
        return receiptType;
    }

    /** Attribute 1, the app's App Store item id; zero in sandbox receipts. */
    public @Nullable Long appItemId() {
        return appItemId;
    }

    /** Attribute 2, decoded; {@code null} when it does not decode, its octets then only in {@link #bundleIdBytes()}. */
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

    /**
     * Attribute 17, one entry per purchase that decodes, in receipt order;
     * unmodifiable. A purchase whose structure does not decode is not in this
     * list: its raw bytes are in {@code unknownAttributes().get(17)}, so a
     * caller that needs every purchase checks that key too. A purchase with
     * one unreadable field is listed, with that field {@code null}.
     */
    public List<InAppPurchase> inApp() {
        return inApp;
    }

    /** Attribute 18. */
    public @Nullable Long originalPurchaseDateMs() {
        return originalPurchaseDateMs;
    }

    /**
     * Attribute 32, the pre-order date: when the user pre-ordered the app.
     * Present on receipts for apps that were pre-ordered.
     */
    public @Nullable Long preorderDateMs() {
        return preorderDateMs;
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
     * Raw value octets, by type, in receipt order, of the attribute types not
     * modelled above, of a modelled attribute whose value did not decode
     * (other than attribute 2, whose octets are {@link #bundleIdBytes()}), and
     * of every copy of a modelled attribute after the first. The attribute's
     * {@code version} integer is not kept, nor are the octets of a date
     * written as an empty string. A fresh copy on each call, arrays
     * included.
     */
    public Map<Integer, List<byte[]>> unknownAttributes() {
        return RawAttributes.copy(unknownAttributes);
    }

    /** Whether attribute {@code type} went to {@link #unknownAttributes()}, without copying them. */
    boolean hasUnknownAttribute(int type) {
        return unknownAttributes.containsKey(type);
    }

    /**
     * The environment {@link #receiptType()} names, as the verifier read it:
     * {@code Production} and {@code ProductionVPP} are
     * {@link Environment#PRODUCTION}, {@code ProductionSandbox} and
     * {@code ProductionVPPSandbox} are {@link Environment#SANDBOX}, anything
     * else ({@code Xcode}, a missing value) is {@code null}. It states what
     * Apple's value means and decides nothing. Not part of {@link #toJson()}.
     */
    public @Nullable Environment environment() {
        return environment;
    }

    // Every character outside ASCII is escaped, so the text is ASCII and
    // therefore valid UTF-8, even for a lone surrogate in a hand-built payload.
    static final JsonFactory JSON =
            JsonFactory.builder().enable(JsonWriteFeature.ESCAPE_NON_ASCII).build();

    /**
     * This payload as JSON: snake_case
     * names, dates as numbers with a {@code _ms} suffix, 64-bit ids
     * ({@code app_item_id}, {@code download_id},
     * {@code version_external_identifier}, {@code web_order_line_item_id}) as
     * strings, bytes as padded standard base64 and {@code null} for a missing
     * value.
     * It holds the full purchase data; the caller decides what to
     * write where.
     */
    public String toJson() {
        // A size hint only; clamped, so a cap-sized receipt does not reserve
        // tens of megabytes up front or overflow the multiplication.
        StringWriter out = new StringWriter((int) Math.min(512 + 512L * inApp.size(), 1 << 20));
        try (JsonGenerator json = JSON.createGenerator(out)) {
            json.writeStartObject();
            json.writeObjectField("receipt_type", receiptType);
            json.writeObjectField("app_item_id", appItemId == null ? null : appItemId.toString());
            json.writeObjectField("bundle_id", bundleId);
            json.writeObjectField("bundle_id_bytes", base64(bundleIdBytes));
            json.writeObjectField("application_version", applicationVersion);
            json.writeObjectField("opaque_value", base64(opaqueValue));
            json.writeObjectField("sha1_hash", base64(sha1Hash));
            json.writeObjectField("receipt_creation_date_ms", receiptCreationDateMs);
            json.writeObjectField("download_id", downloadId == null ? null : downloadId.toString());
            json.writeObjectField(
                    "version_external_identifier",
                    versionExternalIdentifier == null ? null : versionExternalIdentifier.toString());
            json.writeArrayFieldStart("in_app");
            for (InAppPurchase purchase : inApp) {
                purchase.writeJson(json);
            }
            json.writeEndArray();
            json.writeObjectField("original_purchase_date_ms", originalPurchaseDateMs);
            json.writeObjectField("preorder_date_ms", preorderDateMs);
            json.writeObjectField("original_application_version", originalApplicationVersion);
            json.writeObjectField("expiration_date_ms", expirationDateMs);
            writeAttributes(json, unknownAttributes);
            json.writeEndObject();
        } catch (IOException e) {
            // A StringWriter does not fail.
            throw new UncheckedIOException(e);
        }
        return out.toString();
    }

    private static @Nullable String base64(byte @Nullable [] bytes) {
        return bytes == null ? null : Base64.getEncoder().encodeToString(bytes);
    }

    /** {@code "unknown_attributes": {"13": ["<base64>", ...]}}, each type's values in receipt order. */
    static void writeAttributes(JsonGenerator json, Map<Integer, List<byte[]>> attributes) throws IOException {
        json.writeObjectFieldStart("unknown_attributes");
        for (Map.Entry<Integer, List<byte[]>> entry : attributes.entrySet()) {
            json.writeArrayFieldStart(entry.getKey().toString());
            for (byte[] value : entry.getValue()) {
                json.writeString(Base64.getEncoder().encodeToString(value));
            }
            json.writeEndArray();
        }
        json.writeEndObject();
    }

    /**
     * Equal when {@link #toJson()} and {@link #environment()} are. This and
     * {@link #hashCode()} render the JSON on every call, so a receipt is a
     * costly map key: key on its transaction ids instead.
     */
    @Override
    public boolean equals(@Nullable Object other) {
        return other instanceof ReceiptPayload
                && toJson().equals(((ReceiptPayload) other).toJson())
                && environment == ((ReceiptPayload) other).environment;
    }

    @Override
    public int hashCode() {
        return 31 * toJson().hashCode() + Objects.hashCode(environment);
    }

    /**
     * {@link #toJson()}: the customer's purchase history, transaction ids,
     * opaque value and hash included. Logging a payload logs all of it.
     */
    @Override
    public String toString() {
        return toJson();
    }

    private static byte @Nullable [] clone(byte @Nullable [] bytes) {
        return bytes == null ? null : bytes.clone();
    }
}
