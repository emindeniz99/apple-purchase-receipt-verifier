package bakeoff.swig;

import java.util.Map;

/** A verified StoreKit 2 JWS transaction claim set. Immutable. */
public final class TransactionPayload {
    private final String bundleId;
    private final String environment;
    private final String productId;
    private final String transactionId;
    private final Long signedDate;
    private final Long purchaseDate;
    private final String claimsJson;

    private TransactionPayload(String bundleId, String environment, String productId, String transactionId,
                                Long signedDate, Long purchaseDate, String claimsJson) {
        this.bundleId = bundleId;
        this.environment = environment;
        this.productId = productId;
        this.transactionId = transactionId;
        this.signedDate = signedDate;
        this.purchaseDate = purchaseDate;
        this.claimsJson = claimsJson;
    }

    public String bundleId() { return bundleId; }
    public String environment() { return environment; }
    public String productId() { return productId; }
    public String transactionId() { return transactionId; }
    public Long signedDate() { return signedDate; }
    public Long purchaseDate() { return purchaseDate; }
    /** The full verified claim set, exactly as the C ABI returned it
     *  (Apple's own claim names, epoch-millisecond dates). */
    public String claimsJson() { return claimsJson; }

    /** {@code claimsJson} is the raw JSON text the ABI returned; {@code m} is
     *  that same text already parsed once by the caller, to avoid parsing it
     *  twice. */
    static TransactionPayload fromJson(String claimsJson, Map<String, Object> m) {
        return new TransactionPayload(
                Json.getString(m, "bundleId"),
                Json.getString(m, "environment"),
                Json.getString(m, "productId"),
                Json.getString(m, "transactionId"),
                Json.getLong(m, "signedDate"),
                Json.getLong(m, "purchaseDate"),
                claimsJson);
    }
}
