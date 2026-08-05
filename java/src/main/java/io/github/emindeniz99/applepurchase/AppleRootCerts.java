package io.github.emindeniz99.applepurchase;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

/**
 * Loads the Apple root certificates bundled with this library (copies of the
 * public roots from <a href="https://www.apple.com/certificateauthority/">Apple PKI</a>).
 * These are the production trust anchors; tests use a generated fake PKI instead.
 */
public final class AppleRootCerts {

    private AppleRootCerts() {
    }

    /** Apple Root CA - G3 — anchors StoreKit 2 / App Store Server JWS chains. */
    public static Set<X509Certificate> jwsRoots() {
        return Collections.singleton(load("/certs/AppleRootCA-G3.cer"));
    }

    /** Apple Inc. Root CA — anchors legacy PKCS#7 app-receipt chains. */
    public static Set<X509Certificate> receiptRoots() {
        return Collections.singleton(load("/certs/AppleIncRootCertificate.cer"));
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
