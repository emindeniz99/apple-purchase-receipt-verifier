package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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

    /**
     * The main artifact carries the same class. Both compile it from the one
     * copy in ../java/src/shared/java, so it cannot drift: neither artifact may grow a
     * copy of its own again.
     */
    @Test
    void bothArtifactsCompileTheOneSharedCopy() {
        Path file = Paths.get("io", "github", "emindeniz99", "applepurchasereceiptverifier", "ClasspathGuard.java");
        Path shared = Paths.get("..", "java", "src", "shared", "java").resolve(file);
        assertTrue(Files.isRegularFile(shared), shared.toString());
        for (String artifact : new String[] {"java", "java-wasm"}) {
            Path own = Paths.get("..", artifact, "src", "main", "java").resolve(file);
            assertFalse(Files.exists(own), own + " duplicates " + shared);
        }
    }

    /**
     * Verifier.create runs the guard: this classpath holds only this
     * artifact, so create gets past it to the engine, whose one source fails.
     */
    @Test
    void createRunsTheGuardFirst() {
        IllegalStateException engine = assertThrows(
                IllegalStateException.class,
                () -> Verifier.create(
                        Config.defaults(),
                        Engine.server(ServerSource.executable(java.nio.file.Paths.get("/nonexistent/aprv")))));
        assertTrue(engine.getMessage().startsWith("no aprv-server source worked"), engine.getMessage());
    }
}
