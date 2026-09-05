package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

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
 */
public final class AppleRootCerts {

    private AppleRootCerts() {}

    /**
     * Trust anchors for StoreKit 2 / App Store Server JWS chains.
     * Production chains currently end at Apple Root CA - G3.
     */
    public static Set<X509Certificate> jwsRoots() {
        return allRoots();
    }

    /**
     * Trust anchors for legacy PKCS#7 app-receipt chains.
     * Production chains currently end at the Apple Inc. Root CA.
     */
    public static Set<X509Certificate> receiptRoots() {
        return allRoots();
    }

    private static Set<X509Certificate> allRoots() {
        return Arrays.stream(new String[] {
                    "/certs/AppleIncRootCertificate.cer", "/certs/AppleRootCA-G2.cer", "/certs/AppleRootCA-G3.cer",
                })
                .map(AppleRootCerts::load)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static X509Certificate load(String resource) {
        try (InputStream in = AppleRootCerts.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("bundled certificate missing: " + resource);
            }
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (CertificateException e) {
            throw new IllegalStateException("bundled certificate unparseable: " + resource, e);
        }
    }
}
