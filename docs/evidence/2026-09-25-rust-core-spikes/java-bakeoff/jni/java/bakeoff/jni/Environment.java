package bakeoff.jni;

/** An App Store environment. The ordinal is the wire value passed to the native side. */
public enum Environment {
    /** The App Store. */
    PRODUCTION,
    /** The App Store sandbox. */
    SANDBOX,
    /** Xcode's StoreKit testing. */
    XCODE,
    /** Local StoreKit testing. */
    LOCAL_TESTING;

    int mask() { return 1 << ordinal(); }
}
