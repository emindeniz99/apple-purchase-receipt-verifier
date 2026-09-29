package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * The jar carries the licence and NOTICE texts of the code compiled into
 * aprv.wasm (ARCHITECTURE §9): every file of the repository's
 * {@code licenses/wasm/}, byte for byte, under
 * {@code META-INF/licenses/aprv-wasm/}, and nothing else there. Nothing but
 * this test would notice a file dropped from the packaging. A server
 * classifier directory, when the build made one, carries the same set,
 * since its binary embeds the module.
 */
class LicensesTest {

    private static final Path SOURCE = Paths.get("..", "licenses", "wasm");
    private static final String PACKAGED = "META-INF/licenses/aprv-wasm/";

    private static List<String> names(Path directory) throws IOException {
        try (Stream<Path> files = Files.list(directory)) {
            return files.map(p -> p.getFileName().toString()).sorted().collect(Collectors.toList());
        }
    }

    private static byte[] resource(String name) throws IOException {
        try (InputStream in = Verifier.class.getClassLoader().getResourceAsStream(PACKAGED + name)) {
            assertNotNull(in, PACKAGED + name + " is not on the classpath");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) > 0) {
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        }
    }

    @Test
    void theJarCarriesEveryLicenceTextOfTheModuleByteForByte() throws IOException {
        List<String> expected = names(SOURCE);
        assertTrue(expected.size() >= 5, "licenses/wasm holds the texts: " + expected);
        for (String name : expected) {
            assertArrayEquals(Files.readAllBytes(SOURCE.resolve(name)), resource(name), name);
        }
        assertEquals(expected, names(Paths.get("target", "classes", "META-INF", "licenses", "aprv-wasm")));
    }

    @Test
    void aServerClassifierCarriesTheSameTexts() throws IOException {
        int checked = 0;
        for (String classifier : new String[] {"linux-x86_64", "linux-aarch64"}) {
            Path packaged = Paths.get("target", "server-jars", classifier, "META-INF", "licenses", "aprv-wasm");
            if (!Files.isDirectory(Paths.get("target", "server-jars", classifier))) {
                continue; // no binary for this classifier in this build
            }
            checked++;
            List<String> expected = names(SOURCE);
            assertEquals(expected, names(packaged), classifier);
            for (String name : expected) {
                assertArrayEquals(
                        Files.readAllBytes(SOURCE.resolve(name)),
                        Files.readAllBytes(packaged.resolve(name)),
                        classifier + " " + name);
            }
        }
        Assumptions.assumeTrue(checked > 0, "this build made no server classifier directory");
    }
}
