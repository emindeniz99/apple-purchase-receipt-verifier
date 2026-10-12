package io.github.emindeniz99.applepurchasereceiptverifier;

import org.jspecify.annotations.Nullable;

/**
 * Refuses a classpath that also holds the main
 * {@code apple-purchase-receipt-verifier} artifact. The two share every
 * public class name, so with both present either jar's classes could
 * answer, and a caller could run one implementation believing it runs the
 * other. The guard runs in this artifact's {@link Verifier#create}, so it
 * fires when this jar's classes load first; when the main jar's load
 * first, its own classes answer and nothing here runs.
 *
 * <p>The main artifact is recognised by a class only it has,
 * {@code ReceiptCore}, its BouncyCastle receipt verifier. This artifact
 * still ships its marker resource,
 * {@code META-INF/io.github.emindeniz99/apple-purchase-receipt-verifier-wasm.marker}:
 * the main artifact's releases up to 0.11 look for it and refuse a
 * classpath that holds this jar too.</p>
 */
final class ClasspathGuard {

    static final String MAIN = "apple-purchase-receipt-verifier";
    static final String WASM = "apple-purchase-receipt-verifier-wasm";

    /** A class file the main artifact ships and this one does not. */
    static final String MAIN_CLASS = "io/github/emindeniz99/applepurchasereceiptverifier/ReceiptCore.class";

    private ClasspathGuard() {}

    /** @throws IllegalStateException if {@code loader} sees the main artifact's {@link #MAIN_CLASS} */
    static void check(@Nullable ClassLoader loader) {
        ClassLoader classLoader = loader != null ? loader : ClassLoader.getSystemClassLoader();
        Object main = classLoader.getResource(MAIN_CLASS);
        if (main != null) {
            throw new IllegalStateException("both " + MAIN + " (" + main + ") and " + WASM
                    + " are on the classpath; they share their class names, so either could be answering."
                    + " Depend on exactly one of them.");
        }
    }
}
