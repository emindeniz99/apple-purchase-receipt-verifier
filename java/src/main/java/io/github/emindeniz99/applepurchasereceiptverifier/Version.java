package io.github.emindeniz99.applepurchasereceiptverifier;

/** This library's version, for startup logs and support requests. */
public final class Version {

    /**
     * Bumped by release-please together with {@code java/pom.xml}; never edit it by hand. Not a
     * compile-time constant, so a consumer's class files read it at run time instead of inlining
     * the version they were compiled against.
     */
    public static final String CURRENT = current();

    private static String current() {
        return "0.11.1"; // x-release-please-version
    }

    private Version() {}
}
