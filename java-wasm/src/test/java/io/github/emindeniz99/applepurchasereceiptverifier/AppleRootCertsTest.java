package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * The bundled roots behind {@link Config#defaults()}, as the main artifact
 * pins them: Apple's fingerprints and the repository's {@code certs/}.
 */
class AppleRootCertsTest {

    private static final List<String> ROOT_FILES =
            Arrays.asList("AppleIncRootCertificate.cer", "AppleRootCA-G2.cer", "AppleRootCA-G3.cer");

    /**
     * Apple's published SHA-256 root fingerprints, kept apart from the
     * base64 in {@code AppleRootCerts} so that the two have to be changed
     * together: a digest stored next to the bytes it pins can be updated to
     * match whatever bytes happen to be there.
     */
    private static final Set<String> ROOT_FINGERPRINTS = new HashSet<String>(Arrays.asList(
            "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
            "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
            "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"));

    // One set carries all three published Apple roots (PLAN D15) for JWS and
    // receipts alike: Apple only commits to "an Apple root certificate", so a
    // single-root anchor would break silently if Apple re-anchored a path.
    @Test
    void defaultRootsAreAllThreePublishedAppleRoots() {
        assertAllThreeRoots(Config.defaults().roots());
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
        for (X509Certificate root : Config.defaults().roots()) {
            loaded.add(sha256Hex(root.getEncoded()));
        }
        assertEquals(ROOT_FINGERPRINTS, loaded);
    }

    /**
     * The roots are parsed once and shared, so no caller may change them:
     * emptying the set would otherwise strip every later verifier of its
     * anchors.
     */
    @Test
    void theDefaultRootsAreParsedOnceAndCannotBeChanged() {
        Set<X509Certificate> first = Config.defaults().roots();
        Set<X509Certificate> second = Config.defaults().roots();
        for (X509Certificate root : first) {
            assertTrue(second.stream().anyMatch(c -> c == root), "certificate was parsed again");
        }
        assertThrows(UnsupportedOperationException.class, first::clear);
        assertThrows(UnsupportedOperationException.class, AppleRootCerts.roots()::clear);
        assertAllThreeRoots(Config.defaults().roots());
    }

    /**
     * The compiled-in roots are byte for byte the repository's
     * {@code certs/}, which apple-root-watch diffs against Apple's published
     * files every week. {@code tools/check-cert-copies.mjs} finds only
     * {@code .cer} copies, so this is the link that covers Java's inlined one.
     */
    @Test
    void bundledRootsAreTheRepositorysCertsDirectory() throws Exception {
        Path certs = Cases.FIXTURES.toAbsolutePath().normalize().resolveSibling("certs");
        Set<String> expected = new HashSet<String>();
        for (String name : ROOT_FILES) {
            expected.add(Base64.getEncoder().encodeToString(Files.readAllBytes(certs.resolve(name))));
        }
        Set<String> bundled = new HashSet<String>();
        for (X509Certificate root : AppleRootCerts.roots()) {
            bundled.add(Base64.getEncoder().encodeToString(root.getEncoded()));
        }
        assertEquals(expected, bundled);
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
