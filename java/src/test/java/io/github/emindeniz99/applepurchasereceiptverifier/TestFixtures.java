package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.Files;
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
 *
 * <p>A missing directory fails here, once and with the fix named, rather than
 * as a {@code NoSuchFileException} from each of the test classes that read it.
 * The README section "Vendoring" says which subdirectories the tests use.</p>
 */
public final class TestFixtures {

    /** The system property naming the fixtures directory. */
    public static final String PROPERTY = "aprv.fixtures.dir";

    private TestFixtures() {}

    /** The fixtures directory; fails if it does not exist. */
    public static Path root() {
        String configured = System.getProperty(PROPERTY);
        Path root = configured != null && !configured.isEmpty() ? Paths.get(configured) : Paths.get("..", "fixtures");
        if (!Files.isDirectory(root)) {
            throw new IllegalStateException(
                    "The shared fixtures directory " + root.toAbsolutePath().normalize()
                            + " does not exist. The tests read the repository's fixtures/ (and certs/, its sibling) beside"
                            + " java/, or the directory -D" + PROPERTY + "=... names. Copy them or set the property;"
                            + " java/README.md, section \"Vendoring\", lists the subdirectories the tests use.");
        }
        return root;
    }

    /** {@code certs/}, the sibling of the fixtures directory; fails if it does not exist. */
    public static Path certs() {
        Path certs = root().toAbsolutePath().normalize().resolveSibling("certs");
        if (!Files.isDirectory(certs)) {
            throw new IllegalStateException("The certs directory " + certs
                    + " does not exist. AppleRootCertsTest reads the repository's certs/ as a sibling of the"
                    + " fixtures directory. Copy it there; java/README.md, section \"Vendoring\", says which tests"
                    + " need it.");
        }
        return certs;
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
