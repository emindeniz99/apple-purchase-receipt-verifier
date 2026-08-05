package io.github.emindeniz99.applepurchase;

import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppleRootCertsTest {

    @Test
    void bundledJwsRootIsAppleRootCaG3() {
        Set<X509Certificate> roots = AppleRootCerts.jwsRoots();
        assertEquals(1, roots.size());
        String subject = roots.iterator().next().getSubjectX500Principal().getName();
        assertTrue(subject.contains("Apple Root CA - G3"), subject);
    }

    @Test
    void bundledReceiptRootIsAppleIncRootCa() {
        Set<X509Certificate> roots = AppleRootCerts.receiptRoots();
        assertEquals(1, roots.size());
        String subject = roots.iterator().next().getSubjectX500Principal().getName();
        assertTrue(subject.contains("Apple Root CA"), subject);
        assertTrue(subject.contains("Apple Inc."), subject);
    }
}
