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
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jcajce.interfaces.BCX509Certificate;
import org.jspecify.annotations.Nullable;

/**
 * The trust policy both paths share, and their top-down signature rule.
 *
 * <p>Policy: the pinned roots as PKIX anchors ({@link #anchors},
 * {@link #roots}), the critical extensions PKIX leaves unresolved
 * ({@link #HANDLED_CRITICAL_EXTENSIONS}), Apple's marker OIDs
 * ({@link #requireMarkers}), and the verdict for a path that fails
 * ({@link #chainFailure}).</p>
 *
 * <p>Rule: no key is ever decoded or used unless a pinned root, or a CA it
 * vouched for, has vouched for its certificate, so certificates are checked
 * top-down from the roots ({@link #signedByAny}, {@link #signedBy}). An end
 * entity vouches for nothing: Apple's roots also vouch for developer
 * certificates, whose keys belong to the developers. BouncyCastle validates
 * an RSA key as it decodes it, which costs seconds for a 16384-bit modulus.
 * PKIX then verifies the same signatures again; that duplicate is the price
 * of never decoding an unvouched key. A signature label is the sender's
 * until its signature verifies, so the rule also refuses the labels that
 * cost work before a byte is compared ({@link #GENERIC_COMPOSITE_SIGNATURE},
 * {@link #REFUSED_SIGNATURE_ALGORITHM}, {@link #saltFits}).</p>
 *
 * <p>The shapes screened before any of this runs are in
 * {@link PreTrustScreen}.</p>
 */
final class AppleTrust {

    /** On the leaf that signs JWS and receipts; developer certificates chain to the same roots. */
    static final String SIGNING_LEAF_OID = "1.2.840.113635.100.6.11.1";

    /** Apple marker OID: Worldwide Developer Relations intermediate CA. */
    static final String INTERMEDIATE_OID = "1.2.840.113635.100.6.2.1";

    /**
     * The generic composite signature label (id-alg-composite) of the
     * individual draft draft-ounsworth-pq-composite-sigs, from -01 (January
     * 2020) until -09 (May 2023) removed it, refused wherever BouncyCastle would build a
     * verifier from it: a certificate with it is signed by nobody, and a
     * SignerInfo with it is refused before a verifier is built. Its
     * parameters are a SEQUENCE of algorithm identifiers with no bound on
     * their number, and BouncyCastle makes one JCA Signature per part. On a
     * SignerInfo every part also takes its own pass over the signed
     * content; on a certificate every part also compares the whole list of
     * parts, a cost that grows with the square of a count the sender picks.
     * Neither label nor parameters are signed, and no Apple certificate or
     * receipt uses it. The per-pair composite OIDs of the LAMPS draft (IANA
     * 1.3.6.1.5.5.7.6.37 to .54 since draft -13), which BouncyCastle
     * verifies through their own SPI and not through this generic path,
     * stay accepted.
     */
    static final String GENERIC_COMPOSITE_SIGNATURE = MiscObjectIdentifiers.id_alg_composite.getId();

    /**
     * md2WithRSAEncryption, the one signature label refused for what its
     * digest costs: a SignerInfo labelled with it is refused, and a
     * certificate labelled with it is signed by nobody. The label is the
     * sender's unsigned choice, and BouncyCastle runs MD2, about 16 times
     * slower than SHA-256, over the signed attributes or over the TBS, once
     * per issuer tried, before it compares a signature byte. Apple signs
     * nothing with MD2.
     */
    static final String REFUSED_SIGNATURE_ALGORITHM = PKCSObjectIdentifiers.md2WithRSAEncryption.getId();

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
     * {@code certificate}.
     *
     * <p>The certificate must be one {@link BouncyCastle#PROVIDER} built;
     * another provider's returns false. Its signature algorithm is its own
     * choice and stays unsigned until this returns. So the label inside the
     * TBS, which the signature covers, must equal the outer one (RFC 5280
     * 4.1.1.2), and its saltLength must fit {@code issuerKey}
     * ({@link #saltFits}). A certificate labelled
     * {@link #GENERIC_COMPOSITE_SIGNATURE} or
     * {@link #REFUSED_SIGNATURE_ALGORITHM} is signed by nobody.</p>
     */
    static boolean signedBy(X509Certificate certificate, @Nullable PublicKey issuerKey) {
        try {
            // Another provider's certificate fails this cast and lands in the
            // catch below as "not signed".
            AlgorithmIdentifier signed =
                    ((BCX509Certificate) certificate).getTBSCertificateNative().getSignature();
            ASN1Encodable parameters = signed.getParameters();
            if (GENERIC_COMPOSITE_SIGNATURE.equals(signed.getAlgorithm().getId())
                    || REFUSED_SIGNATURE_ALGORITHM.equals(signed.getAlgorithm().getId())
                    || !signed.getAlgorithm().getId().equals(certificate.getSigAlgOID())
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
     * Whether an RSASSA-PSS {@code algorithm} names a saltLength {@code key}
     * can hold: at most emLen - hLen - 2 octets (RFC 8017 9.1.2), emLen from
     * the modulus and hLen from the hash the parameters name. The salt is a
     * non-negative integer (RFC 8017 9.1.1), so a negative one does not fit.
     * BouncyCastle allocates an array of saltLength bytes (the low 32 bits of
     * it) while it builds a PSS verifier, before it compares any signature
     * byte, so both callers ask this first.
     * Any other algorithm fits, and PSS under a key that is not RSA, or with
     * no parameters, verifies nothing. That includes a composite with a PSS
     * part, which this does not look inside: both callers refuse
     * {@link #GENERIC_COMPOSITE_SIGNATURE} before they ask.
     */
    static boolean saltFits(AlgorithmIdentifier algorithm, @Nullable PublicKey key) throws GeneralSecurityException {
        if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algorithm.getAlgorithm())) {
            return true;
        }
        if (!(key instanceof RSAPublicKey) || algorithm.getParameters() == null) {
            return false;
        }
        RSASSAPSSparams parameters = RSASSAPSSparams.getInstance(algorithm.getParameters());
        int emLen = (((RSAPublicKey) key).getModulus().bitLength() + 6) / 8;
        int hLen = MessageDigest.getInstance(
                        parameters.getHashAlgorithm().getAlgorithm().getId(), BouncyCastle.PROVIDER)
                .getDigestLength();
        BigInteger salt = parameters.getSaltLength();
        return salt.signum() >= 0 && salt.compareTo(BigInteger.valueOf(emLen - hLen - 2)) <= 0;
    }

    /**
     * Apple's marker OIDs, checked once the chain to a pinned root holds:
     * the signing marker on {@code signer} and the WWDR marker on
     * {@code intermediate}, the certificate that issued it, null for a signer
     * a root issued directly. Developer certificates chain to the same roots.
     * {@code what} names the input in the message.
     */
    static void requireMarkers(X509Certificate signer, @Nullable X509Certificate intermediate, String what)
            throws VerificationException {
        if (signer.getExtensionValue(SIGNING_LEAF_OID) == null) {
            throw new VerificationException(
                    Reason.INVALID_CERTIFICATE_PURPOSE,
                    what + " signer certificate lacks Apple receipt-signing marker OID " + SIGNING_LEAF_OID);
        }
        if (intermediate == null) {
            throw new VerificationException(
                    Reason.INVALID_CERTIFICATE_PURPOSE,
                    what + " signer is issued by a root directly, with no WWDR intermediate");
        }
        if (intermediate.getExtensionValue(INTERMEDIATE_OID) == null) {
            throw new VerificationException(
                    Reason.INVALID_CERTIFICATE_PURPOSE,
                    what + " intermediate certificate lacks Apple WWDR marker OID " + INTERMEDIATE_OID);
        }
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
     * UNTRUSTED_CHAIN for an unchecked exception, BouncyCastle's report of
     * malformed certificate content, whatever it wraps; otherwise
     * INVALID_CERTIFICATE when a certificate was outside its validity window
     * at {@code at}, else UNTRUSTED_CHAIN. The validator's message can quote
     * names out of the certificates, so it is kept out of the failure's own
     * message and is only the exception's cause. {@code VerificationException.toFailure}
     * then drops that cause for both reasons, so a caller never sees it.
     */
    static VerificationException chainFailure(Exception failure, String certificates, String chain, Date at) {
        if (failure instanceof RuntimeException) {
            return new VerificationException(
                    Reason.UNTRUSTED_CHAIN,
                    chain + " raised " + failure.getClass().getName(),
                    failure);
        }
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
