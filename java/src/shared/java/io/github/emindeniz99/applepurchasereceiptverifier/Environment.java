package io.github.emindeniz99.applepurchasereceiptverifier;

import org.jspecify.annotations.Nullable;

/**
 * Apple's two App Store environments, and the two verifyReceipt URLs
 * {@link Verifier#verifyReceiptEndpoint} imitates. The helpers state what an
 * Apple value means; whether to accept an environment is the caller's
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

    /**
     * Maps a receipt's {@code receipt_type} (attribute 0):
     * {@code Production} and {@code ProductionVPP} to {@link #PRODUCTION},
     * {@code ProductionSandbox} and {@code ProductionVPPSandbox} to
     * {@link #SANDBOX}, anything else, a missing value included, to
     * {@code null}. The endpoint uses the same rule for 21007 and 21008.
     */
    public static @Nullable Environment fromReceiptType(@Nullable String receiptType) {
        if ("Production".equals(receiptType) || "ProductionVPP".equals(receiptType)) {
            return PRODUCTION;
        }
        if ("ProductionSandbox".equals(receiptType) || "ProductionVPPSandbox".equals(receiptType)) {
            return SANDBOX;
        }
        return null;
    }

    /**
     * Maps a JWS {@code environment} claim: {@code Production} to
     * {@link #PRODUCTION}, {@code Sandbox} to {@link #SANDBOX}, anything else
     * ({@code Xcode}, {@code LocalTesting}, a missing claim) to {@code null}.
     */
    public static @Nullable Environment fromJwsEnvironment(@Nullable String environment) {
        if ("Production".equals(environment)) {
            return PRODUCTION;
        }
        if ("Sandbox".equals(environment)) {
            return SANDBOX;
        }
        return null;
    }
}
