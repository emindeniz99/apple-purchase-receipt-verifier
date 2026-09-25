package bakeoff.swig;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A verified legacy PKCS#7 app receipt. Immutable.
 *
 * <p>Two ABI entry points produce two different JSON shapes for "the same"
 * receipt, and both are mapped here (see the SWIG entry's report):
 * {@code aprv_verify_receipt_der}/{@code _base64}'s normalised camelCase
 * JSON (opaque/hash bytes present, as lowercase hex), and the classic
 * {@code verifyReceipt} endpoint's snake_case JSON (no opaque value or
 * device-hash bytes at all — Apple's own endpoint never returned them
 * either). {@link #opaqueValue()}/{@link #sha1Hash()} are {@code null} for a
 * receipt built from the endpoint path.
 */
public final class AppReceipt {
    private final String receiptType;
    private final String bundleId;
    private final String appVersion;
    private final String originalAppVersion;
    private final byte[] opaqueValue;
    private final byte[] sha1Hash;
    private final Long creationDateMs;
    private final List<InAppPurchase> inAppPurchases;

    private AppReceipt(String receiptType, String bundleId, String appVersion, String originalAppVersion,
                        byte[] opaqueValue, byte[] sha1Hash, Long creationDateMs,
                        List<InAppPurchase> inAppPurchases) {
        this.receiptType = receiptType;
        this.bundleId = bundleId;
        this.appVersion = appVersion;
        this.originalAppVersion = originalAppVersion;
        this.opaqueValue = opaqueValue;
        this.sha1Hash = sha1Hash;
        this.creationDateMs = creationDateMs;
        this.inAppPurchases = inAppPurchases;
    }

    public String receiptType() { return receiptType; }
    public String bundleId() { return bundleId; }
    public String appVersion() { return appVersion; }
    public String originalAppVersion() { return originalAppVersion; }
    public byte[] opaqueValue() { return opaqueValue; }
    public byte[] sha1Hash() { return sha1Hash; }
    public Long creationDateMs() { return creationDateMs; }
    public List<InAppPurchase> inAppPurchases() { return inAppPurchases; }

    static AppReceipt fromNormalizedJson(Map<String, Object> m) {
        List<Object> iaps = Json.getArray(m, "inAppPurchases");
        List<InAppPurchase> out = new ArrayList<InAppPurchase>();
        if (iaps != null) {
            for (Object o : iaps) {
                out.add(InAppPurchase.fromNormalizedJson(castMap(o)));
            }
        }
        String creationDate = Json.getString(m, "creationDate");
        return new AppReceipt(
                Json.getString(m, "receiptType"),
                Json.getString(m, "bundleId"),
                Json.getString(m, "appVersion"),
                Json.getString(m, "originalAppVersion"),
                hexToBytes(Json.getString(m, "opaqueValue")),
                hexToBytes(Json.getString(m, "sha1Hash")),
                creationDate == null ? null : Instant.parse(creationDate).toEpochMilli(),
                out);
    }

    static AppReceipt fromClassicJson(Map<String, Object> m) {
        List<Object> iaps = Json.getArray(m, "in_app");
        List<InAppPurchase> out = new ArrayList<InAppPurchase>();
        if (iaps != null) {
            for (Object o : iaps) {
                out.add(InAppPurchase.fromClassicJson(castMap(o)));
            }
        }
        String creationMs = Json.getString(m, "receipt_creation_date_ms");
        return new AppReceipt(
                Json.getString(m, "receipt_type"),
                Json.getString(m, "bundle_id"),
                Json.getString(m, "application_version"),
                Json.getString(m, "original_application_version"),
                null, // the classic endpoint response carries no opaque value
                null, // ... or device-hash bytes; Apple's own never did either
                creationMs == null ? null : Long.valueOf(creationMs),
                out);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object o) {
        return (Map<String, Object>) o;
    }

    private static byte[] hexToBytes(String hex) {
        if (hex == null) return null;
        int n = hex.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
