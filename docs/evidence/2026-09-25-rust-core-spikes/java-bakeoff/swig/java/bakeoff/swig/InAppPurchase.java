package bakeoff.swig;

import java.time.Instant;
import java.util.Map;

/** One entry of a legacy app receipt's {@code inAppPurchases} array. Immutable. */
public final class InAppPurchase {
    private final String productId;
    private final String transactionId;
    private final String originalTransactionId;
    private final Long quantity;
    private final Long purchaseDateMs;
    private final Long expiresDateMs;

    private InAppPurchase(String productId, String transactionId, String originalTransactionId,
                           Long quantity, Long purchaseDateMs, Long expiresDateMs) {
        this.productId = productId;
        this.transactionId = transactionId;
        this.originalTransactionId = originalTransactionId;
        this.quantity = quantity;
        this.purchaseDateMs = purchaseDateMs;
        this.expiresDateMs = expiresDateMs;
    }

    public String productId() { return productId; }
    public String transactionId() { return transactionId; }
    public String originalTransactionId() { return originalTransactionId; }
    public Long quantity() { return quantity; }
    public Long purchaseDateMs() { return purchaseDateMs; }
    public Long expiresDateMs() { return expiresDateMs; }

    /** From {@code aprv_verify_receipt_der}/{@code _base64}'s normalised JSON:
     *  camelCase fields, dates as ISO-8601 UTC strings. */
    static InAppPurchase fromNormalizedJson(Map<String, Object> m) {
        Long qty = Json.getLong(m, "quantity");
        return new InAppPurchase(
                Json.getString(m, "productId"),
                Json.getString(m, "transactionId"),
                Json.getString(m, "originalTransactionId"),
                qty,
                parseIso(Json.getString(m, "purchaseDate")),
                parseIso(Json.getString(m, "expiresDate")));
    }

    /** From the classic {@code verifyReceipt} endpoint's {@code in_app} entry:
     *  snake_case fields, numbers given as decimal strings, {@code _ms}
     *  fields already epoch milliseconds. */
    static InAppPurchase fromClassicJson(Map<String, Object> m) {
        String qty = Json.getString(m, "quantity");
        return new InAppPurchase(
                Json.getString(m, "product_id"),
                Json.getString(m, "transaction_id"),
                Json.getString(m, "original_transaction_id"),
                qty == null ? null : Long.valueOf(qty),
                parseMsString(Json.getString(m, "purchase_date_ms")),
                parseMsString(Json.getString(m, "expires_date_ms")));
    }

    private static Long parseIso(String iso) {
        return iso == null ? null : Instant.parse(iso).toEpochMilli();
    }

    private static Long parseMsString(String ms) {
        return ms == null ? null : Long.valueOf(ms);
    }
}
