package io.github.emindeniz99.applepurchasereceiptverifier;

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
 * rule against the two real jars is {@code ClasspathGuardJarsIT}.
 */
class ClasspathGuardTest {

    @TempDir
    Path temp;

    /** A classpath root holding {@code resource}, as a jar that ships it would. */
    private URL rootWith(String name, String resource) throws Exception {
        Path root = temp.resolve(name);
        Path file = root.resolve(resource);
        Files.createDirectories(file.getParent());
        Files.write(file, "stand-in\n".getBytes(StandardCharsets.UTF_8));
        return root.toUri().toURL();
    }

    /**
     * The guard would refuse this artifact on its own if it shipped the
     * class it looks for. Its marker stays for the main artifact's releases
     * up to 0.11, whose guard looks for it.
     */
    @Test
    void thisArtifactLacksTheMainArtifactsClassAndShipsItsMarker() {
        ClassLoader loader = Verifier.class.getClassLoader();
        assertTrue(loader.getResource(ClasspathGuard.MAIN_CLASS) == null, ClasspathGuard.MAIN_CLASS);
        String marker = "META-INF/io.github.emindeniz99/" + ClasspathGuard.WASM + ".marker";
        assertTrue(loader.getResource(marker) != null, marker);
    }

    @Test
    void theMainArtifactOnTheClasspathFails() throws Exception {
        URL main = rootWith("main", ClasspathGuard.MAIN_CLASS);
        URL other = rootWith("other", "io/github/emindeniz99/applepurchasereceiptverifier/Engine.class");
        for (URL[] urls : new URL[][] {{main}, {other, main}, {main, other}}) {
            try (URLClassLoader loader = new URLClassLoader(urls, null)) {
                IllegalStateException e = assertThrows(IllegalStateException.class, () -> ClasspathGuard.check(loader));
                assertTrue(e.getMessage().contains("Depend on exactly one"), e.getMessage());
                assertTrue(e.getMessage().contains(main.toString()), e.getMessage());
            }
        }
    }

    @Test
    void aClasspathWithoutTheMainArtifactPasses() throws Exception {
        URL wasm = rootWith("wasm", "io/github/emindeniz99/applepurchasereceiptverifier/Engine.class");
        URL wasmAgain = rootWith("wasm-again", "io/github/emindeniz99/applepurchasereceiptverifier/Engine.class");
        for (URL[] urls : new URL[][] {{wasm}, {wasm, wasmAgain}, {}}) {
            try (URLClassLoader loader = new URLClassLoader(urls, null)) {
                ClasspathGuard.check(loader);
            }
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
