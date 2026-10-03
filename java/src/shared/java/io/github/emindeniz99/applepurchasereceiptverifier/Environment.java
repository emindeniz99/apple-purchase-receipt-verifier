package io.github.emindeniz99.applepurchasereceiptverifier;

/**
 * Apple's two App Store environments: the environment a verified receipt or
 * JWS names ({@link ReceiptPayload#environment()},
 * {@link JsonPayload#environment()}), and the two verifyReceipt URLs
 * {@link Verifier#verifyReceiptEndpoint} imitates. The verifier states what
 * Apple's value means; whether to accept an environment is the caller's
 * decision.
 */
public enum Environment {
    /** The live App Store, and the buy.itunes.apple.com verifyReceipt URL. */
    PRODUCTION("Production"),
    /** Apple's test environment, and the sandbox.itunes.apple.com verifyReceipt URL. */
    SANDBOX("Sandbox");

    private final String value;

    Environment(String value) {
        this.value = value;
    }

    /** The {@code environment} string of a verifyReceipt response. */
    String value() {
        return value;
    }
}
