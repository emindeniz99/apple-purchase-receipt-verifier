package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The classpath guard's rule on class loaders built for the test. The same
 * rule against the two real jars is {@code ClasspathGuardJarsTest}.
 */
class ClasspathGuardTest {

    @TempDir
    Path temp;

    private URL markerDirectory(String name, String artifact) throws Exception {
        Path root = temp.resolve(name);
        Path marker = root.resolve(ClasspathGuard.marker(artifact));
        Files.createDirectories(marker.getParent());
        Files.write(marker, "marker\n".getBytes(StandardCharsets.UTF_8));
        return root.toUri().toURL();
    }

    @Test
    void thisArtifactShipsItsMarkerAndNotTheOther() {
        ClassLoader loader = Verifier.class.getClassLoader();
        assertTrue(loader.getResource(ClasspathGuard.WASM_MARKER) != null, ClasspathGuard.WASM_MARKER);
        assertTrue(loader.getResource(ClasspathGuard.MAIN_MARKER) == null, ClasspathGuard.MAIN_MARKER);
    }

    @Test
    void bothArtifactsOnOneClasspathFailInEitherOrder() throws Exception {
        URL main = markerDirectory("main", ClasspathGuard.MAIN);
        URL wasm = markerDirectory("wasm", ClasspathGuard.WASM);
        for (URL[] order : new URL[][] {{main, wasm}, {wasm, main}}) {
            try (URLClassLoader loader = new URLClassLoader(order, null)) {
                IllegalStateException e = assertThrows(IllegalStateException.class, () -> ClasspathGuard.check(loader));
                assertTrue(e.getMessage().contains("Depend on exactly one"), e.getMessage());
                assertTrue(e.getMessage().contains(main.toString()), e.getMessage());
                assertTrue(e.getMessage().contains(wasm.toString()), e.getMessage());
            }
        }
    }

    @Test
    void oneArtifactOrTwoCopiesOfOnePass() throws Exception {
        URL wasm = markerDirectory("wasm", ClasspathGuard.WASM);
        URL wasmAgain = markerDirectory("wasm-again", ClasspathGuard.WASM);
        URL main = markerDirectory("main", ClasspathGuard.MAIN);
        URL other = markerDirectory("other", "something-else");
        for (URL[] urls : new URL[][] {{wasm}, {main}, {wasm, wasmAgain}, {main, other}, {}}) {
            try (URLClassLoader loader = new URLClassLoader(urls, null)) {
                ClasspathGuard.check(loader);
            }
        }
    }

    /** The main artifact carries the same class; the two copies must not drift. */
    @Test
    void theMainArtifactsCopyIsTheSame() throws Exception {
        String path = "src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/ClasspathGuard.java";
        assertEquals(
                new String(Files.readAllBytes(java.nio.file.Paths.get(path)), StandardCharsets.UTF_8),
                new String(
                        Files.readAllBytes(java.nio.file.Paths.get("..", "java").resolve(path)),
                        StandardCharsets.UTF_8));
    }

    /** Verifier.create runs the guard: this classpath holds only this artifact, so create gets past it. */
    @Test
    void createRunsTheGuardFirst() {
        UnsupportedOperationException pending = assertThrows(
                UnsupportedOperationException.class, () -> Verifier.create(Config.defaults(), Engine.server()));
        assertEquals("server engine: pending", pending.getMessage());
    }
}
