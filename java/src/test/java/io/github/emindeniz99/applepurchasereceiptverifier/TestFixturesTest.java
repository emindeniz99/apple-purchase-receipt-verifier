package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The fixtures directory is found with no runner help, as under an IDE's own
 * JUnit runner, which applies none of surefire's system properties. The
 * property is cleared around each test, so the unset case runs under Maven
 * too, where the pom would otherwise set it. Maven's working directory is
 * {@code java/}, so {@code root()} takes the {@code ../fixtures} branch there;
 * the class-location fallback is checked through
 * {@link TestFixtures#withoutProperty} on a temporary tree.
 */
class TestFixturesTest {

    private String saved;

    @BeforeEach
    void clearTheProperty() {
        saved = System.getProperty(TestFixtures.PROPERTY);
        System.clearProperty(TestFixtures.PROPERTY);
    }

    @AfterEach
    void restoreTheProperty() {
        if (saved != null) {
            System.setProperty(TestFixtures.PROPERTY, saved);
        }
    }

    @Test
    void rootFindsTheFixturesWithNoPropertySet() {
        assertTrue(
                Files.isRegularFile(TestFixtures.root().resolve(TestFixtures.CASES)),
                "cases.json is not inside the fixtures directory TestFixtures.root() found");
        assertTrue(
                Files.isDirectory(TestFixtures.certs()),
                "certs/ is not beside the fixtures directory TestFixtures.root() found");
    }

    @Test
    void theClassLocationLeadsToTheFixtures() {
        Path loadedFrom = TestFixtures.classLocation();
        assertNotNull(loadedFrom, "the runtime did not say where TestFixtures was loaded from");
        Path found = TestFixtures.findUpward(loadedFrom);
        // A build whose output sits outside the source tree (an IDE output
        // directory, say) has no fixtures above it; root() does not need the
        // fallback there, so this check does not apply.
        assumeTrue(found != null, "no fixtures/cases.json at or above " + loadedFrom);
        assertTrue(Files.isRegularFile(found.resolve(TestFixtures.CASES)));
    }

    @Test
    void withNoMarkedDirectoryBesideTheLookupFallsBackToTheClassLocation(@TempDir Path tmp) throws IOException {
        Path fixtures = marked(tmp.resolve("project/fixtures"));
        Path classes = Files.createDirectories(tmp.resolve("project/build/test-classes"));
        Path beside = Files.createDirectories(tmp.resolve("elsewhere/fixtures"));
        assertEquals(fixtures, TestFixtures.withoutProperty(beside, classes));
        Path besideMarked = marked(tmp.resolve("work/fixtures"));
        assertEquals(
                besideMarked,
                TestFixtures.withoutProperty(besideMarked, classes),
                "a marked ../fixtures wins over the class location");
        assertNull(TestFixtures.withoutProperty(beside, null), "no class location and nothing beside");
    }

    @Test
    void theNearestFixturesHoldingCasesJsonWins(@TempDir Path tmp) throws IOException {
        Path outer = marked(tmp.resolve("fixtures"));
        Path inner = marked(tmp.resolve("a/fixtures"));
        Path start = Files.createDirectories(tmp.resolve("a/b/c"));
        assertEquals(inner, TestFixtures.findUpward(start));
        Files.delete(inner.resolve(TestFixtures.CASES));
        assertEquals(outer, TestFixtures.findUpward(start), "a fixtures/ without cases.json is passed over");
    }

    private static Path marked(Path fixtures) throws IOException {
        Files.createDirectories(fixtures);
        Files.write(fixtures.resolve(TestFixtures.CASES), new byte[] {'{', '}'});
        return fixtures.toAbsolutePath().normalize();
    }
}
