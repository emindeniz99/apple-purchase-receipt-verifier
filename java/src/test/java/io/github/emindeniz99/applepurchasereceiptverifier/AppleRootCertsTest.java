package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
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
        Path certs = TestFixtures.root().toAbsolutePath().normalize().resolveSibling("certs");
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
     * UNTRUSTED_CHAIN) is the proof that both passed on the library's real code
     * path. If this fails, the bundled roots or the OID checks no longer
     * accept what Apple actually ships.
     */
    @Test
    void acceptsApplesRealProductionChainAtItsEffectiveDate() throws Exception {
        assertTrue(
                ROOT_FINGERPRINTS.contains(sha256Hex(der(REAL_APPLE_ROOT))),
                "Apple's Root CA - G3 from Apple's test suite is not among the bundled JWS roots");
        VerificationException e = assertThrows(
                VerificationException.class,
                () -> Checks.signedData(productionVerifier(), realChainJws(EFFECTIVE_DATE_MILLIS)));
        assertEquals(Reason.INVALID_SIGNATURE, e.reason(), e.getMessage());
    }

    /**
     * The same chain judged at an instant outside the leaf's validity
     * (2025-09-19 to 2027-10-13) fails as INVALID_CERTIFICATE: a genuine
     * chain is not a pass at any date.
     */
    @Test
    void rejectsApplesRealProductionChainOutsideItsValidity() throws Exception {
        long beforeLeaf = 1756684800000L; // 2025-09-01T00:00:00Z
        long afterLeaf = 1823472000000L; // 2027-10-14T00:00:00Z
        for (long at : new long[] {beforeLeaf, afterLeaf}) {
            VerificationException e = assertThrows(
                    VerificationException.class, () -> Checks.signedData(productionVerifier(), realChainJws(at)));
            assertEquals(Reason.INVALID_CERTIFICATE, e.reason(), "signedDate " + at + ": " + e.getMessage());
        }
    }

    private static Verifier productionVerifier() {
        return Verifier.create(Config.defaults());
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
