package bakeoff.jni;

/** The verified payload of a StoreKit 2 signed transaction. Modelled fields may be null. */
public final class TransactionPayload {
    private final String bundleId, environment, productId, transactionId, claimsJson;
    private final Long signedDate, purchaseDate;

    TransactionPayload(String bundleId, String environment, String productId, String transactionId,
                       Long signedDate, Long purchaseDate, String claimsJson) {
        this.bundleId = bundleId;
        this.environment = environment;
        this.productId = productId;
        this.transactionId = transactionId;
        this.signedDate = signedDate;
        this.purchaseDate = purchaseDate;
        this.claimsJson = claimsJson;
    }

    /** @return the bundle identifier */
    public String bundleId() { return bundleId; }
    /** @return the environment string as signed, e.g. Sandbox */
    public String environment() { return environment; }
    /** @return the product identifier */
    public String productId() { return productId; }
    /** @return the transaction identifier */
    public String transactionId() { return transactionId; }
    /** @return the signing date, epoch milliseconds */
    public Long signedDate() { return signedDate; }
    /** @return the purchase date, epoch milliseconds */
    public Long purchaseDate() { return purchaseDate; }
    /** @return every claim as JSON text */
    public String claimsJson() { return claimsJson; }
}
