package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AppleRootCertsTest {

    /** Where the roots live inside the jar: this class's package, never the jar root. */
    private static final String RESOURCE_DIR = "io/github/emindeniz99/applepurchasereceiptverifier/certs";

    private static final List<String> ROOT_FILES =
            Arrays.asList("AppleIncRootCertificate.cer", "AppleRootCA-G2.cer", "AppleRootCA-G3.cer");

    /**
     * Apple's published SHA-256 root fingerprints, spelled out here as well as
     * in {@code AppleRootCerts} so that the two have to be changed together: a
     * single copy of a pinned digest is a digest that can be updated to match
     * whatever bytes happen to be in the tree.
     */
    private static final Set<String> ROOT_FINGERPRINTS = new HashSet<String>(Arrays.asList(
            "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
            "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
            "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"));

    // Both sets carry all three published Apple roots (PLAN D15): Apple only
    // commits to "an Apple root certificate", so a single-root anchor would
    // break silently if Apple re-anchored a path.
    @Test
    void bundledJwsRootsAreAllThreePublishedAppleRoots() {
        assertAllThreeRoots(AppleRootCerts.jwsRoots());
    }

    @Test
    void bundledReceiptRootsAreAllThreePublishedAppleRoots() {
        assertAllThreeRoots(AppleRootCerts.receiptRoots());
    }

    /**
     * The anchors this library hands out are exactly the three certificates
     * whose fingerprints it pins. Every other assertion about trust in this
     * suite is made against these bytes, so nothing else in it can notice a
     * substitution.
     */
    @Test
    void bundledRootsMatchTheirPinnedFingerprints() throws Exception {
        Set<String> loaded = new HashSet<String>();
        for (X509Certificate root : AppleRootCerts.jwsRoots()) {
            loaded.add(sha256Hex(root.getEncoded()));
        }
        assertEquals(ROOT_FINGERPRINTS, loaded);
    }

    /**
     * Where the resources sit is the finding, not a detail. A jar-root
     * {@code /certs/} lookup is first-match across the whole classpath, so any
     * earlier jar, or a shaded uber-jar that merged its own {@code certs/}
     * tree, supplies the trust anchors instead, silently.
     */
    @Test
    void rootsAreLoadedFromThisPackageAndNotFromTheJarRoot() {
        for (String name : ROOT_FILES) {
            assertNotNull(
                    AppleRootCerts.class.getResourceAsStream("certs/" + name),
                    name + " is not next to AppleRootCerts, so the package-relative load cannot find it");
            assertNull(
                    AppleRootCerts.class.getResourceAsStream("/certs/" + name),
                    name + " is still at the classpath root, where any earlier jar can shadow it");
        }
    }

    /**
     * The demonstration the finding was raised on, run in reverse: a directory
     * carrying three files with the right names at the right package-relative
     * path, ahead of {@code target/classes} on a class loader. The premise is
     * established first, so that the shadow really is what the loader
     * resolves, and then the library refuses to hand back anchors at all rather than handing
     * back the planted ones.
     */
    @Test
    void classpathShadowingCannotSubstituteTheAnchors(@TempDir Path tmp) throws Exception {
        Path certs = tmp.resolve(RESOURCE_DIR);
        Files.createDirectories(certs);
        // Real X.509 certificates from the generated test PKI, so the planted
        // files parse cleanly and the fingerprint check is the only thing that
        // can refuse them. Bytes that merely failed to parse would prove less.
        Path fixtures = Paths.get("..", "fixtures", "generated");
        Files.copy(fixtures.resolve("receipt-root.der"), certs.resolve("AppleIncRootCertificate.cer"));
        Files.copy(fixtures.resolve("jws-root.der"), certs.resolve("AppleRootCA-G2.cer"));
        Files.copy(fixtures.resolve("receipt-root.der"), certs.resolve("AppleRootCA-G3.cer"));

        URL library = AppleRootCerts.class.getProtectionDomain().getCodeSource().getLocation();
        URLClassLoader shadowed = new URLClassLoader(
                new URL[] {tmp.toUri().toURL(), library},
                ClassLoader.getSystemClassLoader().getParent());
        try {
            // The premise: on this loader the planted directory really does
            // win. Without it the refusal below could be a refusal for any
            // reason at all.
            URL resolved = shadowed.getResource(RESOURCE_DIR + "/AppleIncRootCertificate.cer");
            assertNotNull(resolved, "the planted directory is not on the shadowing loader");
            assertEquals(
                    certs.resolve("AppleIncRootCertificate.cer").toAbsolutePath(),
                    Paths.get(resolved.toURI()).toAbsolutePath(),
                    "the shadowing loader resolved " + resolved + " rather than the planted copy");

            Class<?> shadowedRoots = Class.forName(AppleRootCerts.class.getName(), true, shadowed);
            Method jwsRoots = shadowedRoots.getMethod("jwsRoots");
            InvocationTargetException thrown =
                    assertThrows(InvocationTargetException.class, () -> jwsRoots.invoke(null));
            assertTrue(
                    thrown.getCause() instanceof IllegalStateException,
                    "expected the anchor load to fail closed, got " + thrown.getCause());
            assertTrue(
                    thrown.getCause().getMessage().contains("SHA-256"),
                    "the failure does not name the fingerprint check: "
                            + thrown.getCause().getMessage());
        } finally {
            shadowed.close();
        }
    }

    private static void assertAllThreeRoots(Set<X509Certificate> roots) {
        assertEquals(3, roots.size());
        Set<String> subjects =
                roots.stream().map(c -> c.getSubjectX500Principal().getName()).collect(Collectors.toSet());
        assertTrue(subjects.stream().anyMatch(s -> s.contains("Apple Root CA - G2")), subjects.toString());
        assertTrue(subjects.stream().anyMatch(s -> s.contains("Apple Root CA - G3")), subjects.toString());
        // The file Apple labels "Apple Inc. Root" has subject CN=Apple Root CA.
        assertTrue(subjects.stream().anyMatch(s -> s.contains("CN=Apple Root CA,")), subjects.toString());
    }

    private static String sha256Hex(byte[] bytes) throws Exception {
        StringBuilder hex = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(bytes)) {
            hex.append(String.format("%02x", Byte.valueOf(b)));
        }
        return hex.toString();
    }
}
