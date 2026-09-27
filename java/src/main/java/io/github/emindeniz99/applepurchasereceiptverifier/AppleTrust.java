package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.GeneralSecurityException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Trust material both paths share, and their rule for it: no key a pinned
 * root has not vouched for is ever decoded or used, so certificates are
 * checked top-down from the roots (#161). BouncyCastle validates an RSA key as it decodes it, which
 * costs seconds for a 16384-bit modulus. {@code UnauthenticatedKeyCostTest}
 * pins the rule.
 */
final class AppleTrust {

    /** On the leaf that signs JWS and receipts; developer certificates chain to the same roots. */
    static final String SIGNING_LEAF_OID = "1.2.840.113635.100.6.11.1";

    /** Apple marker OID: Worldwide Developer Relations intermediate CA. */
    static final String INTERMEDIATE_OID = "1.2.840.113635.100.6.2.1";

    private AppleTrust() {}

    /**
     * One {@link TrustAnchor} per root, with no name constraints.
     *
     * @throws IllegalArgumentException if {@code trustedRoots} is empty
     */
    static Set<TrustAnchor> anchors(Set<X509Certificate> trustedRoots) {
        if (trustedRoots.isEmpty()) {
            throw new IllegalArgumentException("trustedRoots must not be empty");
        }
        Set<TrustAnchor> anchors = new HashSet<>();
        for (X509Certificate root : trustedRoots) {
            anchors.add(new TrustAnchor(root, null));
        }
        return anchors;
    }

    /**
     * Whether one of {@code issuers}, each a root or a certificate a root
     * vouched for, signed {@code certificate}. A key is decoded only for an
     * issuer whose subject names it.
     */
    static boolean signedByAny(X509Certificate certificate, Iterable<X509Certificate> issuers) {
        for (X509Certificate issuer : issuers) {
            if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                continue;
            }
            try {
                certificate.verify(issuer.getPublicKey(), BouncyCastle.PROVIDER);
                return true;
            } catch (GeneralSecurityException | RuntimeException e) {
                // Not signed by this issuer; try the next one.
            }
        }
        return false;
    }

    /** The certificates of {@code trustAnchors}. */
    static List<X509Certificate> roots(Set<TrustAnchor> trustAnchors) {
        List<X509Certificate> roots = new ArrayList<>(trustAnchors.size());
        for (TrustAnchor anchor : trustAnchors) {
            roots.add(anchor.getTrustedCert());
        }
        return roots;
    }

    /**
     * INVALID_CERTIFICATE when a certificate was outside its validity window
     * at {@code at}, else UNTRUSTED_CHAIN. The validator's message can quote
     * names out of the certificates, so it stays in the cause.
     */
    static VerificationException chainFailure(
            GeneralSecurityException failure, String certificates, String chain, Date at) {
        if (outsideValidity(failure)) {
            return new VerificationException(
                    Reason.INVALID_CERTIFICATE,
                    certificates + " certificate is outside its validity window at " + at.getTime(),
                    failure);
        }
        return new VerificationException(
                Reason.UNTRUSTED_CHAIN, chain + " does not validate to a pinned Apple root", failure);
    }

    /** Whether a path failure, or anything it wraps, says a certificate was outside its validity window. */
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
