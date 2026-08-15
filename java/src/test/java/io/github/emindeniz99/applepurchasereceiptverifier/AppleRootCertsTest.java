package io.github.emindeniz99.applepurchasereceiptverifier;

import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppleRootCertsTest {

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

    private static void assertAllThreeRoots(Set<X509Certificate> roots) {
        assertEquals(3, roots.size());
        Set<String> subjects = roots.stream()
                .map(c -> c.getSubjectX500Principal().getName())
                .collect(Collectors.toSet());
        assertTrue(subjects.stream().anyMatch(s -> s.contains("Apple Root CA - G2")), subjects.toString());
        assertTrue(subjects.stream().anyMatch(s -> s.contains("Apple Root CA - G3")), subjects.toString());
        // The file Apple labels "Apple Inc. Root" has subject CN=Apple Root CA.
        assertTrue(subjects.stream().anyMatch(s -> s.contains("CN=Apple Root CA,")), subjects.toString());
    }
}
