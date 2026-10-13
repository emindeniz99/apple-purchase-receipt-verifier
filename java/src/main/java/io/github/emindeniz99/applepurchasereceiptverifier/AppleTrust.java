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
import org.bouncycastle.asn1.ASN1External;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.TBSCertificate;
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

    /**
     * The generic composite signature label of an abandoned 2021 draft
     * (id-alg-composite), refused wherever BouncyCastle would build a
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
    static final String GENERIC_COMPOSITE_SIGNATURE = "1.3.6.1.4.1.18227.2.1";

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
     * 4.1.1.2). An RSASSA-PSS label may not name a saltLength longer than
     * {@code issuerKey} can hold, because BouncyCastle allocates an array of
     * saltLength bytes while it builds the verifier, before it compares any
     * signature byte. A certificate labelled
     * {@link #GENERIC_COMPOSITE_SIGNATURE} is signed by nobody.</p>
     */
    static boolean signedBy(X509Certificate certificate, @Nullable PublicKey issuerKey) {
        try {
            // Another provider's certificate fails this cast and lands in the
            // catch below as "not signed".
            AlgorithmIdentifier signed =
                    ((BCX509Certificate) certificate).getTBSCertificateNative().getSignature();
            ASN1Encodable parameters = signed.getParameters();
            if (GENERIC_COMPOSITE_SIGNATURE.equals(signed.getAlgorithm().getId())
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
     * the modulus and hLen from the hash the parameters name. Any other
     * algorithm fits, and PSS under a key that is not RSA verifies nothing.
     */
    static boolean saltFits(AlgorithmIdentifier algorithm, @Nullable PublicKey key) throws GeneralSecurityException {
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

    /**
     * Whether BouncyCastle can turn {@code certificate} into a JCA object, and
     * verify and compare that object, without sorting a SET the sender
     * nested. Encoding to DER sorts every SET by its members' encodings, at a
     * cost that grows with the nesting, and BouncyCastle's X.509 object
     * DER-encodes the names and the signature parameters as it is built, the
     * TBS as it is verified and the whole certificate as it is compared.
     *
     * <p>The X.509 grammar leaves two places open to any ASN.1, and
     * BouncyCastle parses the rest strictly or keeps it as octets (extension
     * values, the key, the signature): an attribute value in the issuer or
     * subject name, and the parameters of the three AlgorithmIdentifiers
     * (the TBS signature, the outer signatureAlgorithm, the key's). So the
     * certificate is convertible when every name value is a string and no
     * parameters hold a SET. Apple's names hold PrintableString and
     * UTF8String, and no signature or key algorithm defines a SET in its
     * parameters, so a certificate that is not convertible is not one Apple
     * issued. The one SET left, an RDN's SET OF values, BouncyCastle 1.86
     * sorts in N log N.</p>
     */
    static boolean convertible(org.bouncycastle.asn1.x509.Certificate certificate) {
        TBSCertificate tbs = certificate.getTBSCertificate();
        return stringsOnly(tbs.getIssuer())
                && stringsOnly(tbs.getSubject())
                && !holdsSet(tbs.getSignature().getParameters())
                && !holdsSet(certificate.getSignatureAlgorithm().getParameters())
                && !holdsSet(tbs.getSubjectPublicKeyInfo().getAlgorithm().getParameters());
    }

    /** Whether every attribute value in {@code name} is a string. */
    static boolean stringsOnly(X500Name name) {
        for (RDN rdn : name.getRDNs()) {
            for (AttributeTypeAndValue value : rdn.getTypesAndValues()) {
                if (!(value.getValue() instanceof ASN1String)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Whether {@code value} is a SET or holds one inside a SEQUENCE, a
     * tagged object, or an EXTERNAL's content or data value descriptor, the
     * containers BouncyCastle's parser builds besides constructed strings,
     * which hold only strings. BouncyCastle puts any EXTERNAL element that is
     * not an OID, an INTEGER or a tagged object in the descriptor, a SET
     * included. The depth is the parser's own bound.
     */
    static boolean holdsSet(@Nullable ASN1Encodable value) {
        if (value == null) {
            return false;
        }
        ASN1Primitive primitive = value.toASN1Primitive();
        if (primitive instanceof ASN1Set) {
            return true;
        }
        if (primitive instanceof ASN1Sequence) {
            for (ASN1Encodable member : (ASN1Sequence) primitive) {
                if (holdsSet(member)) {
                    return true;
                }
            }
            return false;
        }
        if (primitive instanceof ASN1TaggedObject) {
            return holdsSet(((ASN1TaggedObject) primitive).getBaseObject());
        }
        if (primitive instanceof ASN1External) {
            ASN1External external = (ASN1External) primitive;
            return holdsSet(external.getDataValueDescriptor()) || holdsSet(external.getExternalContent());
        }
        return false;
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
