package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.jspecify.annotations.Nullable;

/**
 * The receipt half of {@link Verifier#verifyReceipt}, offline, against the
 * pinned roots. Stateless; every cryptographic step uses
 * {@link BouncyCastle#PROVIDER}.
 */
final class ReceiptCore {

    /** Genuine receipts carry one; each SignerInfo costs a chain build and a signature check. */
    static final int MAX_SIGNER_INFOS = 4;

    /**
     * The most attributes a SignerInfo may carry, signed and unsigned
     * together, counted before BouncyCastle reads each set into the same
     * OID-keyed table as a certificate's extensions, at the cost
     * {@link PreTrustScreen#MAX_CERTIFICATE_EXTENSIONS} gives. The unsigned
     * attributes are anyone's to add; Apple's receipt SignerInfos carry
     * none. A SignerInfo over it is left out.
     */
    static final int MAX_SIGNER_INFO_ATTRIBUTES = 1000;

    /**
     * The largest receipt accepted: the base64 text's length in UTF-8 bytes,
     * checked before it is decoded. The figure is Apple's limit on a whole
     * verifyReceipt body ({@link Endpoint#MAX_REQUEST_BYTES}).
     */
    static final int MAX_RECEIPT_BYTES = Endpoint.MAX_REQUEST_BYTES;

    /**
     * Digest algorithms a SignerInfo's digestAlgorithm or signatureAlgorithm
     * may not name: GOST R 34.11-94, MD2, Whirlpool, GOST R 34.11-2012
     * (Streebog, 256 and 512) and DSTU 7564 (256, 384, 512), none a hash
     * Apple signs receipts with. Both fields are the sender's unsigned
     * choice, and BouncyCastle 1.86 runs the digest they name over up to the
     * whole receipt before any signature is checked, where these eight cost
     * 2.9 to 25 times SHA-256 and every other digest it resolves at most 2.6
     * times. {@link AppleTrust#REFUSED_SIGNATURE_ALGORITHM} is the one
     * signature label that names one of them.
     */
    static final Set<String> REFUSED_DIGESTS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            CryptoProObjectIdentifiers.gostR3411.getId(), // GOST R 34.11-94
            PKCSObjectIdentifiers.md2.getId(), // MD2
            ISOIECObjectIdentifiers.whirlpool.getId(), // Whirlpool
            RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.getId(), // GOST R 34.11-2012, 256 bits
            RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.getId(), // GOST R 34.11-2012, 512 bits
            UAObjectIdentifiers.dstu7564digest_256.getId(), // DSTU 7564, 256 bits
            UAObjectIdentifiers.dstu7564digest_384.getId(), // DSTU 7564, 384 bits
            UAObjectIdentifiers.dstu7564digest_512.getId()))); // DSTU 7564, 512 bits

    private ReceiptCore() {}

    /** Verifies a base64 receipt and decodes it: the size cap, then base64, then the signature, then the payload. */
    static ReceiptPayload verify(@Nullable String base64, Set<TrustAnchor> trustAnchors, long now)
            throws VerificationException {
        if (base64 == null || base64.isEmpty()) {
            throw new VerificationException(Reason.MALFORMED, "receipt is empty");
        }
        if (Utf8Length.exceeds(base64, MAX_RECEIPT_BYTES)) {
            throw new VerificationException(
                    Reason.TOO_LARGE, "receipt exceeds the maximum accepted size of " + MAX_RECEIPT_BYTES + " bytes");
        }
        return verifyDer(StrictBase64.decode(base64, false, Reason.MALFORMED, "receipt"), trustAnchors, now);
    }

    /** {@link #verify} after the base64 step. */
    static ReceiptPayload verifyDer(byte[] receiptDer, Set<TrustAnchor> trustAnchors, long now)
            throws VerificationException {
        byte[] payload;
        try {
            payload = verifySignature(receiptDer, trustAnchors, now);
        } catch (RuntimeException e) {
            // BouncyCastle reports hostile input with undocumented unchecked
            // exceptions.
            throw VerificationException.unexpected(e);
        }
        return parseSignedPayload(payload);
    }

    /** Apple signed these bytes, so whatever stops the parse is UNREADABLE_PAYLOAD, never MALFORMED. */
    private static ReceiptPayload parseSignedPayload(byte[] payload) throws VerificationException {
        try {
            return ReceiptDecoder.parse(payload);
        } catch (RuntimeException e) {
            throw new VerificationException(
                    Reason.UNREADABLE_PAYLOAD,
                    "signed receipt content could not be read: " + e.getClass().getName(),
                    e);
        }
    }

    /** Every check up to and including a signature; returns the signed payload, not yet decoded. */
    private static byte[] verifySignature(byte[] receiptDer, Set<TrustAnchor> trustAnchors, long now)
            throws VerificationException {
        CMSSignedData cms = parseCms(receiptDer);
        byte[] payload = encapsulatedPayload(cms);
        List<SignerInformation> signers = signerInfos(cms);
        // The one payload read before trust: the sender's own creation date
        // picks the instant the chain must be valid at. That only moves the
        // validity window; the signature and the chain to a pinned root are
        // still required, as in Apple's own rule. A date that does not parse
        // moves the instant to the clock.
        Long creationDate = ReceiptDecoder.readCreationDate(payload);
        Date at = new Date(creationDate != null ? creationDate : now);
        ReceiptCertificates certificates = ReceiptCertificates.decode(cms);
        // Signer-independent, so walked once for every SignerInfo.
        List<X509Certificate> authenticated = authenticatedTopDown(certificates.all(), trustAnchors);
        // Every SignerInfo signs the same content, so one passing is enough;
        // when none does, the first one's failure is the verdict.
        VerificationException first = null;
        for (SignerInformation signer : signers) {
            try {
                verifySigner(signer, certificates.signers(signer), authenticated, at, trustAnchors);
                return payload;
            } catch (VerificationException e) {
                if (first == null) {
                    first = e;
                }
            }
        }
        throw first;
    }

    /** The receipt as CMS, parsed once from its ASN.1 tree; bytes after the DER are refused. */
    private static CMSSignedData parseCms(byte[] receiptDer) throws VerificationException {
        ASN1Primitive parsed;
        try {
            parsed = ASN1Primitive.fromByteArray(receiptDer);
        } catch (IOException e) {
            throw new VerificationException(Reason.MALFORMED, "receipt has trailing or unparseable bytes", e);
        }
        try {
            // IllegalArgumentException is ContentInfo.getInstance's documented
            // refusal of anything but a two-element SEQUENCE.
            return new CMSSignedData(ContentInfo.getInstance(parsed));
        } catch (IllegalArgumentException | CMSException e) {
            throw new VerificationException(Reason.MALFORMED, "not a PKCS#7/CMS blob", e);
        }
    }

    private static byte[] encapsulatedPayload(CMSSignedData cms) throws VerificationException {
        CMSTypedData signedContent = cms.getSignedContent();
        Object content = signedContent != null ? signedContent.getContent() : null;
        if (!(content instanceof byte[])) {
            throw new VerificationException(Reason.MALFORMED, "no encapsulated payload");
        }
        return (byte[]) content;
    }

    private static List<SignerInformation> signerInfos(CMSSignedData cms) throws VerificationException {
        SignedData signedData = SignedData.getInstance(cms.toASN1Structure().getContent());
        ASN1Set raw = signedData.getSignerInfos();
        if (raw.size() > MAX_SIGNER_INFOS) {
            throw new VerificationException(
                    Reason.MALFORMED,
                    "receipt carries " + raw.size() + " SignerInfos, more than the maximum of " + MAX_SIGNER_INFOS);
        }
        List<SignerInformation> signers = new ArrayList<>();
        for (int i = 0; i < raw.size(); i++) {
            ASN1Encodable entry = raw.getObjectAt(i);
            if (appleShaped(SignerInfo.getInstance(entry))) {
                signers.add(oneSigner(signedData, entry));
            }
        }
        if (signers.isEmpty()) {
            throw new VerificationException(Reason.MALFORMED, "signer certificate not embedded");
        }
        return signers;
    }

    /**
     * Whether {@code info} has a shape Apple issues. One that does not names
     * no Apple certificate and is left out before BouncyCastle does
     * super-linear work on it.
     */
    private static boolean appleShaped(SignerInfo info) {
        // Hashing a SignerId, and comparing its issuer with each
        // certificate's, re-encodes every issuer value that is not a
        // string, at a cost that grows with its nesting: up to 10 s for
        // one cap-sized value. Every name Apple issues holds strings, so
        // such an issuer names no Apple certificate, and its SignerInfo
        // is left out before either.
        SignerIdentifier sid = info.getSID();
        if (!sid.isTagged()
                && !PreTrustScreen.stringsOnly(
                        IssuerAndSerialNumber.getInstance(sid.getId()).getName())) {
            return false;
        }
        // BouncyCastle compares these parameters with the
        // CMSAlgorithmProtection attribute's, which sorts a SET on both
        // sides, and no digest or signature algorithm defines one.
        if (PreTrustScreen.holdsSet(info.getDigestAlgorithm().getParameters())
                || PreTrustScreen.holdsSet(info.getDigestEncryptionAlgorithm().getParameters())) {
            return false;
        }
        // Counted before BouncyCastle builds its tables of them.
        return size(info.getAuthenticatedAttributes()) + size(info.getUnauthenticatedAttributes())
                <= MAX_SIGNER_INFO_ATTRIBUTES;
    }

    private static int size(@Nullable ASN1Set attributes) {
        return attributes == null ? 0 : attributes.size();
    }

    /**
     * {@code signerInfo} as the one signer of a copy of {@code signedData}.
     * BouncyCastle's SignerInformationStore keys its signers by SignerId,
     * comparing issuer names in time quadratic in their RDN count; a store
     * of one signer compares nothing.
     */
    private static SignerInformation oneSigner(SignedData signedData, ASN1Encodable signerInfo)
            throws VerificationException {
        SignedData one = new SignedData(
                signedData.getDigestAlgorithms(),
                signedData.getEncapContentInfo(),
                signedData.getCertificates(),
                signedData.getCRLs(),
                new DERSet(signerInfo));
        try {
            return new CMSSignedData(new ContentInfo(CMSObjectIdentifiers.signedData, one))
                    .getSignerInfos()
                    .getSigners()
                    .iterator()
                    .next();
        } catch (CMSException e) {
            throw new VerificationException(Reason.MALFORMED, "not a PKCS#7/CMS blob", e);
        }
    }

    /**
     * The embedded certificates a pinned root vouches for, directly or
     * through a CA already accepted, walking down from the roots. An
     * accepted end entity is returned but vouches for nothing: a developer
     * certificate is one, and its key belongs to the developer. Only these
     * reach the path builder; see {@link AppleTrust}. The walk's work is
     * bounded by {@link ReceiptCertificates#MAX_EMBEDDED_CERTIFICATES}; the
     * path's length is the builder's business (BouncyCastle 1.86 refuses an
     * eighth certificate below the anchor).
     */
    private static List<X509Certificate> authenticatedTopDown(
            List<X509Certificate> embedded, Set<TrustAnchor> trustAnchors) {
        List<X509Certificate> issuers = AppleTrust.roots(trustAnchors);
        List<X509Certificate> vouchers = new ArrayList<>(issuers);
        List<X509Certificate> accepted = new ArrayList<>();
        List<X509Certificate> pending = new ArrayList<>(embedded);
        while (!pending.isEmpty()) {
            List<X509Certificate> acceptedThisRound = new ArrayList<>();
            for (X509Certificate candidate : pending) {
                if (AppleTrust.signedByAny(candidate, issuers)) {
                    acceptedThisRound.add(candidate);
                }
            }
            if (acceptedThisRound.isEmpty()) {
                break;
            }
            pending.removeAll(acceptedThisRound);
            accepted.addAll(acceptedThisRound);
            // Only a CA vouches further (RFC 5280 4.2.1.9): an end entity's
            // key belongs to whoever it was issued to, an Apple developer
            // among them. Reading basicConstraints decodes no key.
            // A copy of a root or of an earlier issuer vouches for nothing
            // new, and each issuer costs every later candidate a check.
            issuers = new ArrayList<>();
            for (X509Certificate certificate : acceptedThisRound) {
                if (certificate.getBasicConstraints() != -1 && !vouchers.contains(certificate)) {
                    issuers.add(certificate);
                    vouchers.add(certificate);
                }
            }
        }
        return accepted;
    }

    /**
     * Tries every certificate {@code signer} names, as the SignerInfos are
     * tried: one passing is enough, and when none does the first one's
     * failure is the verdict. Together the two loops are one loop over
     * (SignerInfo, certificate) pairs in receipt order.
     */
    private static void verifySigner(
            SignerInformation signer,
            List<X509Certificate> matches,
            List<X509Certificate> authenticated,
            Date at,
            Set<TrustAnchor> trustAnchors)
            throws VerificationException {
        VerificationException first = null;
        for (X509Certificate signerCert : matches) {
            try {
                List<? extends Certificate> path = validateChain(signerCert, authenticated, at, trustAnchors);
                // The certificate after the signer on the path; a signer a
                // root issued directly has none.
                AppleTrust.requireMarkers(
                        signerCert, path.size() < 2 ? null : (X509Certificate) path.get(1), "receipt");
                // The chain before the signature: checking the signature
                // first would run the attacker's own key before anything
                // about it is trusted.
                verifyCmsSignature(signer, signerCert);
                return;
            } catch (VerificationException e) {
                if (first == null) {
                    first = e;
                }
            }
        }
        throw first;
    }

    /**
     * PKIX-builds signer, then the authenticated embedded certificates, then a
     * pinned root, at {@code at}; returns the path, leaf first, anchor
     * excluded.
     */
    private static List<? extends Certificate> validateChain(
            X509Certificate signerCert, List<X509Certificate> authenticated, Date at, Set<TrustAnchor> trustAnchors)
            throws VerificationException {
        // Refused before anything decodes its key (see AppleTrust).
        if (!authenticated.contains(signerCert)) {
            throw new VerificationException(
                    Reason.UNTRUSTED_CHAIN, "signer certificate is not issued under a pinned Apple root");
        }
        try {
            // BouncyCastle throws for a key that does not decode and returns
            // null for a key algorithm it does not know; neither can check
            // the signature.
            Objects.requireNonNull(signerCert.getPublicKey(), "unknown public key algorithm");
        } catch (RuntimeException e) {
            throw new VerificationException(
                    Reason.INVALID_CERTIFICATE, "receipt signer certificate does not decode", e);
        }
        try {
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(signerCert);
            PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, target);
            params.addCertStore(CertStore.getInstance(
                    "Collection", new CollectionCertStoreParameters(authenticated), BouncyCastle.PROVIDER));
            params.setRevocationEnabled(false);
            params.setDate(at);
            params.addCertPathChecker(AppleTrust.HANDLED_CRITICAL_EXTENSIONS);
            // Per call: BouncyCastle's builder keeps state for the build it runs.
            CertPathBuilderResult result =
                    CertPathBuilder.getInstance("PKIX", BouncyCastle.PROVIDER).build(params);
            return result.getCertPath().getCertificates();
        } catch (GeneralSecurityException | RuntimeException e) {
            throw AppleTrust.chainFailure(e, "receipt", "signer chain", at);
        }
    }

    private static void verifyCmsSignature(SignerInformation signer, X509Certificate signerCert)
            throws VerificationException {
        // No algorithm allowlist of our own: the signer is pinned to an
        // Apple root and carries Apple's marker, so any algorithm
        // BouncyCastle can verify is accepted but the refused ones. One it
        // has no verifier for is refused below as INVALID_SIGNATURE, so a
        // genuine receipt signed with such an algorithm is rejected unless
        // another SignerInfo verifies.
        String digest = signer.getDigestAlgOID();
        String signature = signer.getEncryptionAlgOID();
        // Both labels are the sender's unsigned choice, and BouncyCastle runs
        // the digest either one names before it compares a signature byte,
        // so both are checked before it digests a byte or builds a verifier,
        // with the verdict of an algorithm it does not implement.
        if (REFUSED_DIGESTS.contains(digest)) {
            throw new VerificationException(
                    Reason.INVALID_SIGNATURE, "CMS verifier refused the signer info: digest " + digest + " is refused");
        }
        if (AppleTrust.REFUSED_SIGNATURE_ALGORITHM.equals(signature)) {
            throw new VerificationException(
                    Reason.INVALID_SIGNATURE,
                    "CMS verifier refused the signer info: signature algorithm " + signature + " is refused");
        }
        try {
            // Wrapped here, not when the SignerInfos are read: the copy reads
            // the attributes, and ones that do not decode fail this SignerInfo
            // alone.
            if (!new SignedAsSent(signer).verify(signerVerifier(signerCert.getPublicKey()))) {
                throw new VerificationException(
                        Reason.INVALID_SIGNATURE, "CMS signature does not match the signer certificate's key");
            }
        } catch (CMSException | OperatorCreationException | RuntimeException e) {
            if (e.getCause() instanceof RefusedBeforeBuilding) {
                throw new VerificationException(
                        Reason.INVALID_SIGNATURE,
                        "CMS verifier refused the signer info: " + e.getCause().getMessage());
            }
            // A digest that does not match, a key with no CMS verifier, an
            // algorithm BouncyCastle does not implement, or a value it reads
            // only while verifying (the CMSAlgorithmProtection attribute):
            // this SignerInfo fails and the next one is tried (RFC 4853:
            // implementations MUST gracefully handle unimplemented signature
            // algorithms).
            throw new VerificationException(Reason.INVALID_SIGNATURE, "CMS verifier refused the signer info", e);
        }
    }

    /**
     * A SignerInfo whose signed attributes are hashed as they were sent.
     * BouncyCastle hashes their DER encoding, and DER sorts every SET in the
     * sender's attribute values before any signature is checked: seconds for
     * a cap-sized value of nested SETs. RFC 5652 5.4 signs the DER encoding
     * of the attributes, and a definite-length encoding of a DER input
     * reproduces it.
     */
    private static final class SignedAsSent extends SignerInformation {
        SignedAsSent(SignerInformation signer) {
            super(signer);
        }

        @Override
        public byte @Nullable [] getEncodedSignedAttributes() throws IOException {
            return signedAttributeSet == null ? null : signedAttributeSet.getEncoded(ASN1Encoding.DL);
        }
    }

    /**
     * The CMS verifier for the signer's key, made per call so no
     * BouncyCastle object is shared between threads. Built from the key,
     * not the certificate: with a certificate BouncyCastle also refuses a
     * signer outside its validity at a signed signingTime, which RFC 5652
     * 11.3 does not ask, and the chain is judged at the creation date
     * already.
     *
     * <p>Assembled as {@code JcaSimpleSignerInfoVerifierBuilder.build(PublicKey)}
     * assembles it, with one check in the middle. BouncyCastle hands its
     * content verifier provider the algorithm it is about to build: the one
     * its CMS name for the SignerInfo's labels resolves to, carrying the
     * signatureAlgorithm's unsigned parameters, whatever that label's OID.
     * So the provider first refuses
     * {@link AppleTrust#GENERIC_COMPOSITE_SIGNATURE} and a saltLength the
     * key cannot hold ({@link AppleTrust#saltFits}).</p>
     */
    private static SignerInformationVerifier signerVerifier(PublicKey signerKey) throws OperatorCreationException {
        ContentVerifierProvider built = new JcaContentVerifierProviderBuilder()
                .setProvider(BouncyCastle.PROVIDER)
                .build(signerKey);
        ContentVerifierProvider bounded = new ContentVerifierProvider() {
            @Override
            public boolean hasAssociatedCertificate() {
                return false;
            }

            @Override
            public @Nullable X509CertificateHolder getAssociatedCertificate() {
                return null;
            }

            @Override
            public ContentVerifier get(AlgorithmIdentifier algorithm) throws OperatorCreationException {
                if (AppleTrust.GENERIC_COMPOSITE_SIGNATURE.equals(
                        algorithm.getAlgorithm().getId())) {
                    throw new RefusedBeforeBuilding("the composite signature label is refused");
                }
                boolean fits;
                try {
                    fits = AppleTrust.saltFits(algorithm, signerKey);
                } catch (GeneralSecurityException e) {
                    throw new OperatorCreationException("unknown digest in the signature parameters", e);
                }
                if (!fits) {
                    throw new RefusedBeforeBuilding("the RSASSA-PSS label does not fit the signer's key");
                }
                return built.get(algorithm);
            }
        };
        return new SignerInformationVerifier(
                new DefaultCMSSignatureAlgorithmNameGenerator(),
                new DefaultSignatureAlgorithmIdentifierFinder(),
                bounded,
                new JcaDigestCalculatorProviderBuilder()
                        .setProvider(BouncyCastle.PROVIDER)
                        .build());
    }

    /**
     * A signature algorithm refused before any verifier is built: its
     * message, which names no input byte, completes the refusal's.
     */
    private static final class RefusedBeforeBuilding extends OperatorCreationException {
        private static final long serialVersionUID = 1L;

        RefusedBeforeBuilding(String message) {
            super(message);
        }
    }
}
