package io.github.emindeniz99.applepurchasereceiptverifier;

import org.jspecify.annotations.Nullable;

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

    /**
     * Maps a payload claim value to an Environment, or {@code null} if
     * unknown. The claim is {@code @Nullable} because it comes out of a
     * payload that need not carry it, and an absent claim is as unknown as
     * an unrecognised one.
     */
    @Nullable
    public static Environment fromValue(@Nullable String value) {
        for (Environment e : values()) {
            if (e.value.equals(value)) {
                return e;
            }
        }
        return null;
    }
}
