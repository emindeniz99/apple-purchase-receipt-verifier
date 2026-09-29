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
 * The classpath guard: this artifact and {@code apple-purchase-receipt-verifier-wasm}
 * share every public class name, so {@link Verifier#create} refuses a
 * classpath that holds both. The two real jars on one classpath are tested
 * in {@code java-wasm} ({@code ClasspathGuardJarsTest}).
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
        assertTrue(loader.getResource(ClasspathGuard.MAIN_MARKER) != null, ClasspathGuard.MAIN_MARKER);
        assertTrue(loader.getResource(ClasspathGuard.WASM_MARKER) == null, ClasspathGuard.WASM_MARKER);
    }

    @Test
    void bothArtifactsOnOneClasspathFailInEitherOrder() throws Exception {
        URL main = markerDirectory("main", ClasspathGuard.MAIN);
        URL wasm = markerDirectory("wasm", ClasspathGuard.WASM);
        for (URL[] order : new URL[][] {{main, wasm}, {wasm, main}}) {
            try (URLClassLoader loader = new URLClassLoader(order, null)) {
                IllegalStateException e = assertThrows(IllegalStateException.class, () -> ClasspathGuard.check(loader));
                assertTrue(e.getMessage().contains("Depend on exactly one"), e.getMessage());
            }
        }
    }

    @Test
    void oneArtifactPasses() throws Exception {
        URL main = markerDirectory("main", ClasspathGuard.MAIN);
        URL mainAgain = markerDirectory("main-again", ClasspathGuard.MAIN);
        for (URL[] urls : new URL[][] {{main}, {main, mainAgain}, {}}) {
            try (URLClassLoader loader = new URLClassLoader(urls, null)) {
                ClasspathGuard.check(loader);
            }
        }
    }
}
