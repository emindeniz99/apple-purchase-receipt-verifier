package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Loads the Apple root certificates bundled with this library (copies of the
 * public roots from <a href="https://www.apple.com/certificateauthority/">Apple PKI</a>).
 * These are the production trust anchors; tests use a generated fake PKI instead.
 *
 * <p>Both sets contain all three published Apple roots. Apple deliberately
 * documents the JWS chain as ending in "an Apple root certificate" (not a
 * specific one) and its guidance is to trust every root on the PKI page, so
 * anchoring on a single root would break silently if Apple re-anchored a
 * path — see PLAN.md D15.
 *
 * <p><strong>The anchors are fingerprint-pinned.</strong> The resources are
 * loaded from this class's own package rather than from the jar root, so a
 * {@code certs/} tree in an earlier jar (or in a shaded uber-jar) cannot sit
 * in front of them, and every loaded certificate is checked against the
 * SHA-256 of the root it must be. A mismatch, a missing resource, or anything
 * other than the three distinct roots is an {@link IllegalStateException}:
 * both accessors fail closed rather than hand back an anchor set that is not
 * Apple's. That is a deployment defect, not a verdict about a payload, which
 * is why it is unchecked and never a {@link VerificationException}.
 */
public final class AppleRootCerts {

    private AppleRootCerts() {}

    /**
     * The three roots, each with the SHA-256 of its DER encoding. The digests
     * are Apple's published root fingerprints and are compile-time constants
     * on purpose: a resource that does not match one of them is not the root
     * this library pins, wherever on the classpath it came from.
     */
    private static final String[][] ROOTS = {
        {"AppleIncRootCertificate.cer", "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"},
        {"AppleRootCA-G2.cer", "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050"},
        {"AppleRootCA-G3.cer", "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"},
    };

    /**
     * Trust anchors for StoreKit 2 / App Store Server JWS chains.
     * Production chains currently end at Apple Root CA - G3.
     *
     * @throws IllegalStateException if the bundled roots are missing, do not
     *                               parse, or do not match their pinned
     *                               fingerprints
     */
    public static Set<X509Certificate> jwsRoots() {
        return allRoots();
    }

    /**
     * Trust anchors for legacy PKCS#7 app-receipt chains.
     * Production chains currently end at the Apple Inc. Root CA.
     *
     * @throws IllegalStateException if the bundled roots are missing, do not
     *                               parse, or do not match their pinned
     *                               fingerprints
     */
    public static Set<X509Certificate> receiptRoots() {
        return allRoots();
    }

    private static Set<X509Certificate> allRoots() {
        Set<X509Certificate> roots = new LinkedHashSet<X509Certificate>();
        for (String[] root : ROOTS) {
            roots.add(load(root[0], root[1]));
        }
        // A set, so three certificates that all matched their fingerprints
        // cannot collapse to fewer: the count is asserted rather than assumed.
        if (roots.size() != ROOTS.length) {
            throw new IllegalStateException("expected " + ROOTS.length + " distinct Apple roots, got " + roots.size());
        }
        return roots;
    }

    private static X509Certificate load(String name, String expectedSha256) {
        // Package-relative on purpose: an absolute "/certs/..." lookup is
        // first-match across the whole classpath, so any jar ahead of this one
        // carrying a certs/ tree would supply the trust anchors instead.
        byte[] der = read(name);
        X509Certificate certificate;
        try {
            certificate = (X509Certificate)
                    CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException e) {
            throw new IllegalStateException("bundled certificate unparseable: " + name, e);
        }
        // The digest is taken over the certificate's own encoding rather than
        // over the file bytes, so what is pinned is the certificate this
        // library will actually hand to the path builder.
        byte[] encoded;
        try {
            encoded = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("bundled certificate cannot be re-encoded: " + name, e);
        }
        String actual = sha256Hex(encoded);
        if (!actual.equals(expectedSha256)) {
            throw new IllegalStateException("bundled certificate " + name + " has SHA-256 " + actual + ", expected "
                    + expectedSha256 + ": the pinned Apple roots have been replaced");
        }
        return certificate;
    }

    private static byte[] read(String name) {
        InputStream in = AppleRootCerts.class.getResourceAsStream("certs/" + name);
        if (in == null) {
            throw new IllegalStateException("bundled certificate missing: " + name);
        }
        try {
            try {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
                return out.toByteArray();
            } finally {
                in.close();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String sha256Hex(byte[] bytes) {
        byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable, so the pinned roots cannot be checked", e);
        }
        StringBuilder hex = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            hex.append(Character.forDigit((b >> 4) & 0xf, 16));
            hex.append(Character.forDigit(b & 0xf, 16));
        }
        return hex.toString();
    }
}
