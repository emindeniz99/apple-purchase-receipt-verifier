package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.bouncycastle.util.encoders.Hex;
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
     * The roots are parsed once, but a caller still owns the set it gets:
     * emptying one must not reach the next caller, or one careless caller
     * would strip every later verifier of its anchors.
     */
    @Test
    void eachCallReturnsItsOwnSetOfTheSameCachedCertificates() {
        Set<X509Certificate> first = AppleRootCerts.jwsRoots();
        Set<X509Certificate> second = AppleRootCerts.receiptRoots();
        assertNotSame(first, second);
        for (X509Certificate root : first) {
            assertTrue(second.stream().anyMatch(c -> c == root), "certificate was parsed again");
        }
        first.clear();
        assertAllThreeRoots(AppleRootCerts.jwsRoots());
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
        Path fixtures = TestFixtures.generated();
        Files.copy(fixtures.resolve("receipt-root.der"), certs.resolve("AppleIncRootCertificate.cer"));
        Files.copy(fixtures.resolve("jws-root.der"), certs.resolve("AppleRootCA-G2.cer"));
        Files.copy(fixtures.resolve("receipt-root.der"), certs.resolve("AppleRootCA-G3.cer"));

        URL library = AppleRootCerts.class.getProtectionDomain().getCodeSource().getLocation();
        // The library's own runtime dependency, which the fingerprint check
        // uses for its hex rendering.
        URL bouncyCastle = Hex.class.getProtectionDomain().getCodeSource().getLocation();
        URLClassLoader shadowed = new URLClassLoader(
                new URL[] {tmp.toUri().toURL(), library, bouncyCastle},
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

    // ---------------------------------------------- Apple's production chain

    /*
     * A real App Store signing chain: the leaf, the WWDR G6 intermediate and
     * Apple Root CA - G3, copied from the REAL_APPLE_* constants in
     * ChainVerifierTest.java of Apple's app-store-server-library-java
     * (https://github.com/apple/app-store-server-library-java, MIT licence,
     * Copyright 2023 Apple Inc.). They are Apple's public certificates, not
     * secrets. EFFECTIVE_DATE is Apple's own validation instant for them.
     */
    private static final String REAL_APPLE_SIGNING_CERTIFICATE =
            "MIIEMTCCA7agAwIBAgIQR8KHzdn554Z/UoradNx9tzAKBggqhkjOPQQDAzB1MUQwQgYDVQQDDDtBcHBs"
                    + "ZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTELMAkG"
                    + "A1UECwwCRzYxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTI1MDkxOTE5NDQ1MVoX"
                    + "DTI3MTAxMzE3NDcyM1owgZIxQDA+BgNVBAMMN1Byb2QgRUNDIE1hYyBBcHAgU3RvcmUgYW5kIGlUdW5l"
                    + "cyBTdG9yZSBSZWNlaXB0IFNpZ25pbmcxLDAqBgNVBAsMI0FwcGxlIFdvcmxkd2lkZSBEZXZlbG9wZXIg"
                    + "UmVsYXRpb25zMRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqG"
                    + "SM49AwEHA0IABNnVvhcv7iT+7Ex5tBMBgrQspHzIsXRi0Yxfek7lv8wEmj/bHiWtNwJqc2BoHzsQiEjP"
                    + "7KFIIKg4Y8y0/nynuAmjggIIMIICBDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFD8vlCNR01DJmig9"
                    + "7bB85c+lkGKZMHAGCCsGAQUFBwEBBGQwYjAtBggrBgEFBQcwAoYhaHR0cDovL2NlcnRzLmFwcGxlLmNv"
                    + "bS93d2RyZzYuZGVyMDEGCCsGAQUFBzABhiVodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLXd3ZHJn"
                    + "NjAyMIIBHgYDVR0gBIIBFTCCAREwggENBgoqhkiG92NkBQYBMIH+MIHDBggrBgEFBQcCAjCBtgyBs1Jl"
                    + "bGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBv"
                    + "ZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwg"
                    + "Y2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDYG"
                    + "CCsGAQUFBwIBFipodHRwOi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eS8wHQYDVR0O"
                    + "BBYEFIFioG4wMMVA1ku9zJmGNPAVn3eqMA4GA1UdDwEB/wQEAwIHgDAQBgoqhkiG92NkBgsBBAIFADAK"
                    + "BggqhkjOPQQDAwNpADBmAjEA+qXnREC7hXIWVLsLxznjRpIzPf7VHz9V/CTm8+LJlrQepnmcPvGLNcX6"
                    + "XPnlcgLAAjEA5IjNZKgg5pQ79knF4IbTXdKv8vutIDMXDmjPVT3dGvFtsGRwXOywR2kZCdSrfeot";

    private static final String REAL_APPLE_INTERMEDIATE =
            "MIIDFjCCApygAwIBAgIUIsGhRwp0c2nvU4YSycafPTjzbNcwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwS"
                    + "QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTET"
                    + "MBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMjEwMzE3MjAzNzEwWhcNMzYwMzE5MDAw"
                    + "MDAwWjB1MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZp"
                    + "Y2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzYxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYT"
                    + "AlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEbsQKC94PrlWmZXnXgtxzdVJL8T0SGYngDRGpngn3N6PT"
                    + "8JMEb7FDi4bBmPhCnZ3/sq6PF/cGcKXWsL5vOteRhyJ45x3ASP7cOB+aao90fcpxSv/EZFbniAbNgZGh"
                    + "IhpIo4H6MIH3MBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUu7DeoVgziJqkipnevr3rr9rL"
                    + "JKswRgYIKwYBBQUHAQEEOjA4MDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAz"
                    + "LWFwcGxlcm9vdGNhZzMwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5hcHBsZS5jb20vYXBwbGVy"
                    + "b290Y2FnMy5jcmwwHQYDVR0OBBYEFD8vlCNR01DJmig97bB85c+lkGKZMA4GA1UdDwEB/wQEAwIBBjAQ"
                    + "BgoqhkiG92NkBgIBBAIFADAKBggqhkjOPQQDAwNoADBlAjBAXhSq5IyKogMCPtw490BaB677CaEGJXuf"
                    + "QB/EqZGd6CSjiCtOnuMTbXVXmxxcxfkCMQDTSPxarZXvNrkxU3TkUMI33yzvFVVRT4wxWJC994OsdcZ4"
                    + "+RGNsYDyR5gmdr0nDGg=";

    private static final String REAL_APPLE_ROOT =
            "MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBD"
                    + "QSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBw"
                    + "bGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYD"
                    + "VQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9y"
                    + "aXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IA"
                    + "BJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA"
                    + "/VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4ia"
                    + "pIqZ3r6966/ayySrMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gA"
                    + "MGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK"
                    + "1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM6BgD56KyKA==";

    /** Apple's EFFECTIVE_DATE for the chain above, 2025-11-01T02:09:35Z. */
    private static final long EFFECTIVE_DATE_MILLIS = 1761962975000L;

    /**
     * The production chain Apple signs with today verifies offline against
     * the bundled anchors, marker OIDs included. No signed payload exists for
     * it, so the JWS carries the real x5c and a zero signature: the verifier
     * checks the marker OIDs and the chain before the signature, so reaching
     * INVALID_SIGNATURE (and not INVALID_CERTIFICATE_PURPOSE or
     * INVALID_CHAIN) is the proof that both passed on the library's real code
     * path. If this fails, the bundled roots or the OID checks no longer
     * accept what Apple actually ships.
     */
    @Test
    void acceptsApplesRealProductionChainAtItsEffectiveDate() throws Exception {
        assertTrue(
                ROOT_FINGERPRINTS.contains(sha256Hex(der(REAL_APPLE_ROOT))),
                "Apple's Root CA - G3 from Apple's test suite is not among the bundled JWS roots");
        VerificationException e = assertThrows(
                VerificationException.class, () -> productionVerifier().verifyRaw(realChainJws(EFFECTIVE_DATE_MILLIS)));
        assertEquals(Reason.INVALID_SIGNATURE, e.reason(), e.getMessage());
    }

    /**
     * The same chain judged at an instant outside the leaf's validity
     * (2025-09-19 to 2027-10-13) fails the chain check: a genuine chain is
     * not a pass at any date.
     */
    @Test
    void rejectsApplesRealProductionChainOutsideItsValidity() throws Exception {
        long beforeLeaf = 1756684800000L; // 2025-09-01T00:00:00Z
        long afterLeaf = 1823472000000L; // 2027-10-14T00:00:00Z
        for (long at : new long[] {beforeLeaf, afterLeaf}) {
            VerificationException e = assertThrows(
                    VerificationException.class, () -> productionVerifier().verifyRaw(realChainJws(at)));
            assertEquals(Reason.INVALID_CHAIN, e.reason(), "signedDate " + at + ": " + e.getMessage());
        }
    }

    private static JwsVerifier productionVerifier() {
        return new JwsVerifier(AppleRootCerts.jwsRoots(), "com.example", EnumSet.of(Environment.PRODUCTION));
    }

    /** A JWS over the real x5c whose signedDate is {@code signedAtMillis}; its signature is 64 zero bytes. */
    private static String realChainJws(long signedAtMillis) {
        String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + REAL_APPLE_SIGNING_CERTIFICATE + "\",\""
                + REAL_APPLE_INTERMEDIATE + "\",\"" + REAL_APPLE_ROOT + "\"]}";
        String payload = "{\"signedDate\":" + signedAtMillis + "}";
        Base64.Encoder url = Base64.getUrlEncoder().withoutPadding();
        return url.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                + url.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "."
                + url.encodeToString(new byte[64]);
    }

    private static byte[] der(String base64) {
        return Base64.getDecoder().decode(base64);
    }
}
