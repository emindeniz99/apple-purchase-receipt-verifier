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
 * Trust material both verification paths share, and the rule they share for
 * using it.
 *
 * <p><strong>No key a pinned root has not vouched for is ever decoded or
 * used.</strong> A certificate's public key is decoded only after its own
 * signature has verified under a pinned root, or under a certificate already
 * accepted that way: top-down, never bottom-up. BouncyCastle validates an RSA
 * key as it decodes it, with a primality test that costs seconds for a
 * 16384-bit modulus, and a path builder verifies signatures with whatever
 * keys it is handed, so the other order would let a few KB of unsigned
 * certificates cost the caller seconds of CPU. The receipt path walks its
 * certificate bag down from the roots ({@code ReceiptCore.authenticatedTopDown})
 * and refuses a signer that walk did not reach before anything else touches
 * it; the JWS path checks its intermediate against the roots and then its
 * leaf against the intermediate ({@code JwsCore.authenticateTopDown}). Both
 * use {@link #signedByAny}. {@code UnauthenticatedKeyCostTest} pins the rule
 * by recording every key used and by timing hostile keys.</p>
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
     * Whether one of {@code issuers} signed {@code certificate}. An issuer's
     * key is decoded only when its subject is the certificate's issuer name,
     * and every issuer handed here is one a pinned root has vouched for (a
     * root itself, or a certificate accepted top-down), so no other key is
     * ever decoded.
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
     * The verdict for a failed PKIX build or validation: INVALID_CERTIFICATE
     * when a certificate was outside its validity window at {@code at}
     * ({@link #outsideValidity}), else UNTRUSTED_CHAIN. {@code certificates}
     * and {@code chain} name the two in the message ("receipt", "signer
     * chain"). The validator's own message can quote names out of the
     * certificates, so it stays in the cause and out of the message.
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
