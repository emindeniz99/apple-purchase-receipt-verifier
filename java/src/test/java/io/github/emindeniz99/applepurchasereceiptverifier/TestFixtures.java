package io.github.emindeniz99.applepurchasereceiptverifier;

import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.CodeSource;

/**
 * Where the shared fixtures directory is. Every test reads fixtures through
 * here, so a team that vendors {@code java/} and {@code fixtures/} into a
 * different layout sets one property instead of editing tests.
 *
 * <p>The directory is the {@value #PROPERTY} system property when set. The
 * pom passes it to surefire, defaulting to the {@code fixtures} directory next
 * to {@code java/}; override it with {@code -Daprv.fixtures.dir=...}. When it
 * is not set, as under an IDE's own JUnit runner, which applies none of
 * surefire's properties, the directory is {@code ../fixtures} relative to the
 * working directory if that holds {@code cases.json}, else the nearest
 * {@code fixtures/} holding {@code cases.json} in a directory at or above the
 * one this class was loaded from. So an IDE run of a vendored copy with
 * {@code fixtures/} at its project root, or beside it, needs no runner
 * setting. Maven always passes the property, so there a layout other than
 * {@code fixtures/} beside the project directory needs
 * {@code -Daprv.fixtures.dir=...}.</p>
 *
 * <p>A missing directory fails here, once and with the fix named, rather than
 * as a {@code NoSuchFileException} from each of the test classes that read it.
 * The README section "Vendoring" says which subdirectories the tests use.</p>
 */
public final class TestFixtures {

    /** The system property naming the fixtures directory. */
    public static final String PROPERTY = "aprv.fixtures.dir";

    private TestFixtures() {}

    /** The fixtures directory; fails if none is found. */
    public static Path root() {
        String configured = System.getProperty(PROPERTY);
        if (configured != null && !configured.isEmpty()) {
            Path root = Paths.get(configured);
            if (!Files.isDirectory(root)) {
                throw new IllegalStateException(
                        "The shared fixtures directory " + root.toAbsolutePath().normalize() + ", which -D" + PROPERTY
                                + " names, does not exist. java/README.md, section \"Vendoring\", lists the"
                                + " subdirectories the tests use.");
            }
            return root;
        }
        Path beside = Paths.get("..", "fixtures");
        Path loadedFrom = classLocation();
        Path found = withoutProperty(beside, loadedFrom);
        if (found != null) {
            return found;
        }
        throw new IllegalStateException("No shared fixtures directory was found: -D" + PROPERTY + " is not set, "
                + beside.toAbsolutePath().normalize() + " holds no " + CASES + ", and "
                + (loadedFrom == null
                        ? "the runtime does not say where this class was loaded from"
                        : "no directory at or above " + loadedFrom + " has a fixtures/" + CASES)
                + ". The tests read the repository's fixtures/ (and certs/, its sibling). Copy them beside"
                + " java/ or your project, or set the property; java/README.md, section \"Vendoring\", lists"
                + " the subdirectories the tests use.");
    }

    /**
     * The lookup with the property unset: {@code beside} if it holds
     * {@code cases.json}, else the nearest marked {@code fixtures/} at or
     * above {@code loadedFrom} (which may be null); null if neither.
     */
    static Path withoutProperty(Path beside, Path loadedFrom) {
        if (Files.isRegularFile(beside.resolve(CASES))) {
            return beside;
        }
        return loadedFrom == null ? null : findUpward(loadedFrom);
    }

    /** The file that marks a fixtures directory. */
    static final String CASES = "cases.json";

    /** The nearest {@code fixtures/} holding {@code cases.json} in {@code start} or a directory above it, or null. */
    static Path findUpward(Path start) {
        for (Path dir = start.toAbsolutePath().normalize(); dir != null; dir = dir.getParent()) {
            Path candidate = dir.resolve("fixtures");
            if (Files.isRegularFile(candidate.resolve(CASES))) {
                return candidate;
            }
        }
        return null;
    }

    /** The classes directory or jar this class was loaded from, or null when the runtime does not say. */
    static Path classLocation() {
        try {
            CodeSource source = TestFixtures.class.getProtectionDomain().getCodeSource();
            return source == null || source.getLocation() == null
                    ? null
                    : Paths.get(source.getLocation().toURI());
        } catch (URISyntaxException | RuntimeException e) {
            return null;
        }
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
