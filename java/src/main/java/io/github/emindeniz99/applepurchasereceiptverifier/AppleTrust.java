package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

/**
 * Trust material both verification paths share.
 */
final class AppleTrust {

    /**
     * Apple marker OID stamped on the leaf that signs App Store JWS payloads
     * and legacy receipts alike. The chain check alone is not enough:
     * developer "Apple Distribution" certificates chain through the same WWDR
     * intermediate to the same pinned root, so without this purpose check any
     * developer could sign a forged payload or receipt.
     */
    static final String SIGNING_LEAF_OID = "1.2.840.113635.100.6.11.1";

    /** Apple marker OID: Worldwide Developer Relations intermediate CA. */
    static final String INTERMEDIATE_OID = "1.2.840.113635.100.6.2.1";

    private AppleTrust() {}

    /**
     * One {@link TrustAnchor} per root, with no name constraints.
     *
     * @throws IllegalArgumentException if {@code trustedRoots} is null or empty
     */
    static Set<TrustAnchor> anchors(Set<X509Certificate> trustedRoots) {
        if (trustedRoots == null || trustedRoots.isEmpty()) {
            throw new IllegalArgumentException("trustedRoots must not be empty");
        }
        Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();
        for (X509Certificate root : trustedRoots) {
            anchors.add(new TrustAnchor(root, null));
        }
        return anchors;
    }

    /**
     * Whether a path validator or builder failure, or anything it wraps, says
     * a certificate was outside its validity window at the checked instant.
     * That is a verdict about a certificate (INVALID_CERTIFICATE), not about
     * the chain to a root.
     */
    static boolean outsideValidity(Throwable failure) {
        for (Throwable t = failure; t != null; t = t.getCause() == t ? null : t.getCause()) {
            if (t instanceof CertificateExpiredException || t instanceof CertificateNotYetValidException) {
                return true;
            }
            if (t instanceof CertPathValidatorException) {
                CertPathValidatorException.Reason reason = ((CertPathValidatorException) t).getReason();
                if (reason == CertPathValidatorException.BasicReason.EXPIRED
                        || reason == CertPathValidatorException.BasicReason.NOT_YET_VALID) {
                    return true;
                }
            }
        }
        return false;
    }
}
