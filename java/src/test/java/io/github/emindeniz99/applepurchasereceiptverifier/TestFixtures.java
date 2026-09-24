package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Where the shared fixtures directory is. Every test reads fixtures through
 * here, so a team that vendors {@code java/} and {@code fixtures/} into a
 * different layout sets one property instead of editing tests.
 *
 * <p>The directory is the {@value #PROPERTY} system property when set, else
 * {@code ../fixtures} relative to the working directory. The pom passes the
 * property to surefire, defaulting to the {@code fixtures} directory next to
 * {@code java/}; override it with {@code -Daprv.fixtures.dir=...}.</p>
 */
public final class TestFixtures {

    /** The system property naming the fixtures directory. */
    public static final String PROPERTY = "aprv.fixtures.dir";

    private TestFixtures() {}

    /** The fixtures directory. */
    public static Path root() {
        String configured = System.getProperty(PROPERTY);
        return configured != null && !configured.isEmpty() ? Paths.get(configured) : Paths.get("..", "fixtures");
    }

    /** {@code generated/} under the fixtures directory. */
    public static Path generated() {
        return root().resolve("generated");
    }

    /** {@code public-receipts/} under the fixtures directory. */
    public static Path publicReceipts() {
        return root().resolve("public-receipts");
    }
}
