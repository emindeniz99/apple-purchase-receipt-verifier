package bakeoff.jni;

/** One in-app purchase record from an app receipt. Any field may be null. */
public final class InAppPurchase {
    private final String productId, transactionId, originalTransactionId;
    private final Long quantity, purchaseDateMs, expiresDateMs;

    InAppPurchase(String productId, String transactionId, String originalTransactionId,
                  Long quantity, Long purchaseDateMs, Long expiresDateMs) {
        this.productId = productId;
        this.transactionId = transactionId;
        this.originalTransactionId = originalTransactionId;
        this.quantity = quantity;
        this.purchaseDateMs = purchaseDateMs;
        this.expiresDateMs = expiresDateMs;
    }

    /** @return the product identifier */
    public String productId() { return productId; }
    /** @return the transaction identifier */
    public String transactionId() { return transactionId; }
    /** @return the original transaction identifier */
    public String originalTransactionId() { return originalTransactionId; }
    /** @return the quantity purchased */
    public Long quantity() { return quantity; }
    /** @return the purchase date, epoch milliseconds */
    public Long purchaseDateMs() { return purchaseDateMs; }
    /** @return the subscription expiry date, epoch milliseconds */
    public Long expiresDateMs() { return expiresDateMs; }
}
