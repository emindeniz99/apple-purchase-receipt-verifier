package io.github.emindeniz99.applepurchasereceiptverifier;

import org.jspecify.annotations.Nullable;

/**
 * Refuses a classpath that holds both Java artifacts of this library. They
 * share every public class name, so with both present either jar's classes
 * could answer, and a caller could run one implementation believing it runs
 * the other. Each artifact ships a marker resource of its own, and
 * {@link Verifier#create} in either one looks for both.
 *
 * <p>Both artifacts carry this class, byte for byte the same; a test in
 * {@code java-wasm} compares the two copies.</p>
 */
final class ClasspathGuard {

    static final String MAIN = "apple-purchase-receipt-verifier";
    static final String WASM = "apple-purchase-receipt-verifier-wasm";

    /** The marker the main artifact ships. */
    static final String MAIN_MARKER = marker(MAIN);

    /** The marker the {@code -wasm} artifact ships. */
    static final String WASM_MARKER = marker(WASM);

    private ClasspathGuard() {}

    static String marker(String artifactId) {
        return "META-INF/io.github.emindeniz99/" + artifactId + ".marker";
    }

    /** @throws IllegalStateException if {@code loader} sees the markers of both artifacts */
    static void check(@Nullable ClassLoader loader) {
        ClassLoader classLoader = loader != null ? loader : ClassLoader.getSystemClassLoader();
        Object main = classLoader.getResource(MAIN_MARKER);
        Object wasm = classLoader.getResource(WASM_MARKER);
        if (main != null && wasm != null) {
            throw new IllegalStateException("both " + MAIN + " (" + main + ") and " + WASM + " (" + wasm
                    + ") are on the classpath; they share their class names, so either could be answering."
                    + " Depend on exactly one of them.");
        }
    }
}
