package io.github.emindeniz99.applepurchase;

/**
 * The App Store server environment a signed payload was produced in.
 * String values match the {@code environment} / {@code receiptType} claims
 * in Apple's signed payloads.
 */
public enum Environment {
    PRODUCTION("Production"),
    SANDBOX("Sandbox"),
    XCODE("Xcode"),
    LOCAL_TESTING("LocalTesting");

    private final String value;

    Environment(String value) {
        this.value = value;
    }

    /** The claim value as it appears in Apple payloads (e.g. {@code "Production"}). */
    public String value() {
        return value;
    }
}
