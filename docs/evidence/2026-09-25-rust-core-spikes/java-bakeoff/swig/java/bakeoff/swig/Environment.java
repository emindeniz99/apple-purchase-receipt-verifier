package bakeoff.swig;

/**
 * The four App Store environments, mirroring {@code AprvEnvironment} bits
 * in the C ABI (production/apple_purchase_receipt_verifier.h).
 */
public enum Environment {
    PRODUCTION(1),
    SANDBOX(2),
    XCODE(4),
    LOCAL_TESTING(8);

    private final long bit;

    Environment(long bit) {
        this.bit = bit;
    }

    /** The {@code AprvEnvironment} bit this value corresponds to. */
    long bit() {
        return bit;
    }

    /** ORs the bits of every environment in {@code envs} into one mask. */
    static long maskOf(java.util.Set<Environment> envs) {
        long mask = 0;
        for (Environment e : envs) mask |= e.bit;
        return mask;
    }

    /** Apple's capitalized spelling ("Production", "Sandbox", ...) as used
     *  inside JWS claims and the classic verifyReceipt response body. */
    static Environment fromAppleWord(String word) {
        if (word == null) return null;
        if (word.equalsIgnoreCase("Production")) return PRODUCTION;
        if (word.equalsIgnoreCase("Sandbox")) return SANDBOX;
        if (word.equalsIgnoreCase("Xcode")) return XCODE;
        if (word.equalsIgnoreCase("LocalTesting")) return LOCAL_TESTING;
        return null;
    }
}
