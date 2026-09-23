package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import org.bouncycastle.util.encoders.Hex;
import org.jspecify.annotations.Nullable;

/**
 * Loads the Apple root certificates bundled with this library (copies of the
 * public roots from <a href="https://www.apple.com/certificateauthority/">Apple PKI</a>).
 * These are the production trust anchors; tests use a generated fake PKI instead.
 *
 * <p>Both sets contain all three published Apple roots. Apple deliberately
 * documents the JWS chain as ending in "an Apple root certificate" (not a
 * specific one) and its guidance is to trust every root on the PKI page, so
 * anchoring on a single root would break silently if Apple re-anchored a
 * path.
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
     * The roots are loaded and checked once; each call returns a new
     * mutable set of the same certificates.
     *
     * @throws IllegalStateException if the bundled roots are missing, do not
     *                               parse, or do not match their pinned
     *                               fingerprints
     */
    public static Set<X509Certificate> jwsRoots() {
        return new LinkedHashSet<X509Certificate>(allRoots());
    }

    /**
     * Trust anchors for legacy PKCS#7 app-receipt chains.
     * Production chains currently end at the Apple Inc. Root CA.
     * The roots are loaded and checked once; each call returns a new
     * mutable set of the same certificates.
     *
     * @throws IllegalStateException if the bundled roots are missing, do not
     *                               parse, or do not match their pinned
     *                               fingerprints
     */
    public static Set<X509Certificate> receiptRoots() {
        return new LinkedHashSet<X509Certificate>(allRoots());
    }

    /**
     * The roots, read, parsed and pinned once per class loader. Each accessor
     * hands out its own mutable copy, so a caller changing its set cannot
     * change what the next caller gets; the certificates themselves are
     * immutable. A failed load is not cached: it is rethrown as the same
     * {@link IllegalStateException} on every call, which a static holder
     * class would instead turn into an {@link ExceptionInInitializerError}
     * and then a {@link NoClassDefFoundError}. Two threads racing the first
     * load both build the same set, and the volatile write publishes one.
     */
    private static volatile @Nullable Set<X509Certificate> cached;

    private static Set<X509Certificate> allRoots() {
        Set<X509Certificate> roots = cached;
        if (roots == null) {
            roots = Collections.unmodifiableSet(loadRoots());
            cached = roots;
        }
        return roots;
    }

    private static Set<X509Certificate> loadRoots() {
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
        X509Certificate certificate;
        // Package-relative on purpose: an absolute "/certs/..." lookup is
        // first-match across the whole classpath, so any jar ahead of this one
        // carrying a certs/ tree would supply the trust anchors instead.
        try (InputStream in = AppleRootCerts.class.getResourceAsStream("certs/" + name)) {
            if (in == null) {
                throw new IllegalStateException("bundled certificate missing: " + name);
            }
            certificate =
                    (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (CertificateException e) {
            throw new IllegalStateException("bundled certificate unparseable: " + name, e);
        } catch (IOException e) {
            throw new IllegalStateException("bundled certificate unreadable: " + name, e);
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

    private static String sha256Hex(byte[] bytes) {
        byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable, so the pinned roots cannot be checked", e);
        }
        return Hex.toHexString(digest);
    }
}
