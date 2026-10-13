package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jcajce.interfaces.BCX509Certificate;
import org.jspecify.annotations.Nullable;

/**
 * Trust material both paths share (the marker OIDs, the anchors and the
 * checker for the critical extensions PKIX leaves unresolved), and their
 * rule for it: no key is ever decoded or used unless a pinned root, or a CA
 * it vouched for, has vouched for its certificate, so certificates are
 * checked top-down from the roots. An end entity vouches for nothing:
 * Apple's roots also vouch for developer certificates, whose keys belong to
 * the developers. BouncyCastle validates an RSA key as it decodes it, which
 * costs seconds for a 16384-bit modulus. PKIX then verifies the
 * same signatures again; that duplicate is the price of never decoding an
 * unvouched key.
 */
final class AppleTrust {

    /** On the leaf that signs JWS and receipts; developer certificates chain to the same roots. */
    static final String SIGNING_LEAF_OID = "1.2.840.113635.100.6.11.1";

    /** Apple marker OID: Worldwide Developer Relations intermediate CA. */
    static final String INTERMEDIATE_OID = "1.2.840.113635.100.6.2.1";

    /** The critical extensions {@link #HANDLED_CRITICAL_EXTENSIONS} marks processed. */
    private static final Set<String> HANDLED = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(Extension.extendedKeyUsage.getId(), Extension.cRLDistributionPoints.getId())));

    /**
     * Marks two critical extensions processed on every certificate of a
     * path, which BouncyCastle's PKIX would otherwise refuse as unknown.
     * Neither is a trust decision here.
     *
     * <ul>
     *   <li>extendedKeyUsage (2.5.29.37): RFC 5280 4.2.1.12 lets it be
     *       critical on any certificate. BouncyCastle processes it on the end
     *       entity only; the JDK's PKIX accepts it on a CA too. Like the JDK,
     *       this asks no purpose of a CA, so no genuine chain is refused for
     *       it.</li>
     *   <li>cRLDistributionPoints (2.5.29.31): it only says where a CRL is.
     *       Apple's intermediates carry it non-critical today. Revocation checking is off, so
     *       a critical one would be acted on by nothing here.</li>
     * </ul>
     *
     * <p>Every other critical extension BouncyCastle does not process is
     * still refused.</p>
     */
    static final PKIXCertPathChecker HANDLED_CRITICAL_EXTENSIONS = new PKIXCertPathChecker() {
        @Override
        public void init(boolean forward) {}

        @Override
        public boolean isForwardCheckingSupported() {
            return true;
        }

        @Override
        public Set<String> getSupportedExtensions() {
            return HANDLED;
        }

        @Override
        public void check(Certificate certificate, Collection<String> unresolvedCriticalExtensions) {
            unresolvedCriticalExtensions.removeAll(HANDLED);
        }
    };

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
     * Whether one of {@code issuers}, each a pinned root or a CA a root
     * vouched for, signed {@code certificate}. It compares names and checks
     * the signature only, so the caller passes no end entity. A key is
     * decoded only for an issuer whose subject names it.
     */
    static boolean signedByAny(X509Certificate certificate, Iterable<X509Certificate> issuers) {
        for (X509Certificate issuer : issuers) {
            if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                continue;
            }
            try {
                if (signedBy(certificate, issuer.getPublicKey())) {
                    return true;
                }
            } catch (RuntimeException e) {
                // The issuer's key is one BouncyCastle cannot build; try the
                // next one.
            }
        }
        return false;
    }

    /**
     * Whether {@code issuerKey}, which a pinned root vouches for, signed
     * {@code certificate}, converted by {@link BouncyCastle#PROVIDER}. The
     * signature algorithm is the certificate's own and unsigned until this
     * returns, so the TBS's signed label must equal the outer one (RFC 5280
     * 4.1.1.2), and an RSASSA-PSS label may not name a saltLength longer
     * than {@code issuerKey} can hold: BouncyCastle allocates an array of
     * saltLength bytes while it builds the verifier, before any signature
     * byte is compared.
     */
    static boolean signedBy(X509Certificate certificate, @Nullable PublicKey issuerKey) {
        try {
            AlgorithmIdentifier signed =
                    ((BCX509Certificate) certificate).getTBSCertificateNative().getSignature();
            ASN1Encodable parameters = signed.getParameters();
            if (!signed.getAlgorithm().getId().equals(certificate.getSigAlgOID())
                    || !Arrays.equals(
                            parameters == null
                                    ? null
                                    : parameters.toASN1Primitive().getEncoded(ASN1Encoding.DER),
                            certificate.getSigAlgParams())
                    || !saltFits(signed, issuerKey)) {
                return false;
            }
            certificate.verify(issuerKey, BouncyCastle.PROVIDER);
            return true;
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            // Not signed by this key, or a key verify cannot use (null for
            // an algorithm BouncyCastle does not know, which verify refuses).
            return false;
        }
    }

    /**
     * Whether an RSASSA-PSS {@code algorithm}, or each part of a composite
     * one, names a saltLength {@code key} can hold: at most emLen - hLen - 2
     * octets (RFC 8017 9.1.2), emLen from the modulus and hLen from the hash
     * the parameters name. Any other algorithm fits, and PSS under a key that
     * is not RSA verifies nothing.
     */
    private static boolean saltFits(AlgorithmIdentifier algorithm, @Nullable PublicKey key)
            throws GeneralSecurityException {
        if (MiscObjectIdentifiers.id_alg_composite.equals(algorithm.getAlgorithm())) {
            for (ASN1Encodable part : ASN1Sequence.getInstance(algorithm.getParameters())) {
                if (!saltFits(AlgorithmIdentifier.getInstance(part), key)) {
                    return false;
                }
            }
            return true;
        }
        if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algorithm.getAlgorithm())) {
            return true;
        }
        if (!(key instanceof RSAPublicKey)) {
            return false;
        }
        RSASSAPSSparams parameters = RSASSAPSSparams.getInstance(algorithm.getParameters());
        int emLen = (((RSAPublicKey) key).getModulus().bitLength() + 6) / 8;
        int hLen = MessageDigest.getInstance(
                        parameters.getHashAlgorithm().getAlgorithm().getId(), BouncyCastle.PROVIDER)
                .getDigestLength();
        return parameters.getSaltLength().compareTo(BigInteger.valueOf(emLen - hLen - 2)) <= 0;
    }

    /** The certificates of {@code trustAnchors}. */
    static List<X509Certificate> roots(Set<TrustAnchor> trustAnchors) {
        List<X509Certificate> roots = new ArrayList<>();
        for (TrustAnchor anchor : trustAnchors) {
            roots.add(anchor.getTrustedCert());
        }
        return roots;
    }

    /**
     * INVALID_CERTIFICATE when a certificate was outside its validity window
     * at {@code at}, else UNTRUSTED_CHAIN. The validator's message can quote
     * names out of the certificates, so it is kept out of the failure's own
     * message and is only the exception's cause. {@code VerificationException.toFailure}
     * then drops that cause for both reasons, so a caller never sees it.
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
    private static boolean outsideValidity(Throwable failure) {
        for (Throwable t = failure; t != null; t = t.getCause()) {
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
