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
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
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
     * times. {@link #REFUSED_SIGNATURE_ALGORITHMS} holds the one signature
     * label that names one of them.
     */
    static final Set<String> REFUSED_DIGESTS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "1.2.643.2.2.9", // GOST R 34.11-94
            "1.2.840.113549.2.2", // MD2
            "1.0.10118.3.0.55", // Whirlpool
            "1.2.643.7.1.1.2.2", // GOST R 34.11-2012, 256 bits
            "1.2.643.7.1.1.2.3", // GOST R 34.11-2012, 512 bits
            "1.2.804.2.1.1.1.1.2.2.1", // DSTU 7564, 256 bits
            "1.2.804.2.1.1.1.1.2.2.2", // DSTU 7564, 384 bits
            "1.2.804.2.1.1.1.1.2.2.3"))); // DSTU 7564, 512 bits

    /**
     * Signature algorithms a SignerInfo may not name, neither one Apple signs
     * receipts with: md2WithRSAEncryption, whose MD2 BouncyCastle runs over
     * the signed attributes before the signature is checked, and RSASSA-PSS,
     * whose unsigned saltLength sizes an array BouncyCastle allocates before
     * the signature is compared.
     */
    static final Set<String> REFUSED_SIGNATURE_ALGORITHMS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "1.2.840.113549.1.1.2", // md2WithRSAEncryption
            "1.2.840.113549.1.1.10"))); // RSASSA-PSS

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
        ContentInfo contentInfo;
        try {
            contentInfo = ContentInfo.getInstance(parsed);
        } catch (IllegalArgumentException e) {
            // Its documented refusal of anything but a two-element SEQUENCE.
            throw new VerificationException(Reason.MALFORMED, "not a PKCS#7/CMS blob", e);
        }
        try {
            return new CMSSignedData(contentInfo);
        } catch (CMSException e) {
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
        if (raw.size() == 0) {
            throw new VerificationException(Reason.MALFORMED, "no signer info");
        }
        if (raw.size() > MAX_SIGNER_INFOS) {
            throw new VerificationException(
                    Reason.MALFORMED,
                    "receipt carries " + raw.size() + " SignerInfos, more than the maximum of " + MAX_SIGNER_INFOS);
        }
        // BouncyCastle's SignerInformationStore keys its signers by SignerId,
        // comparing issuer names in time quadratic in their RDN count; a store
        // of one signer compares nothing.
        List<SignerInformation> signers = new ArrayList<>();
        for (int i = 0; i < raw.size(); i++) {
            // Hashing a SignerId, and comparing its issuer with each
            // certificate's, re-encodes every issuer value that is not a
            // string, at a cost that grows with its nesting: up to 10 s for
            // one cap-sized value. Every name Apple issues holds strings, so
            // such an issuer names no Apple certificate, and its SignerInfo
            // is left out before either.
            SignerIdentifier sid = SignerInfo.getInstance(raw.getObjectAt(i)).getSID();
            if (!sid.isTagged()
                    && !stringsOnly(
                            IssuerAndSerialNumber.getInstance(sid.getId()).getName())) {
                continue;
            }
            SignedData one = new SignedData(
                    signedData.getDigestAlgorithms(),
                    signedData.getEncapContentInfo(),
                    signedData.getCertificates(),
                    signedData.getCRLs(),
                    new DERSet(raw.getObjectAt(i)));
            try {
                signers.add(new CMSSignedData(new ContentInfo(CMSObjectIdentifiers.signedData, one))
                        .getSignerInfos()
                        .getSigners()
                        .iterator()
                        .next());
            } catch (CMSException e) {
                throw new VerificationException(Reason.MALFORMED, "not a PKCS#7/CMS blob", e);
            }
        }
        if (signers.isEmpty()) {
            throw new VerificationException(Reason.MALFORMED, "signer certificate not embedded");
        }
        return signers;
    }

    private static boolean stringsOnly(X500Name name) {
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
                requireMarkers(signerCert, path);
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

    /**
     * Apple's marker OIDs on the signer and on the intermediate after it in
     * the path: developer certificates chain to the same pinned roots.
     */
    private static void requireMarkers(X509Certificate signerCert, List<? extends Certificate> path)
            throws VerificationException {
        if (signerCert.getExtensionValue(AppleTrust.SIGNING_LEAF_OID) == null) {
            throw new VerificationException(
                    Reason.INVALID_CERTIFICATE_PURPOSE,
                    "receipt signer certificate lacks Apple receipt-signing marker OID " + AppleTrust.SIGNING_LEAF_OID);
        }
        if (path.size() < 2) {
            throw new VerificationException(
                    Reason.INVALID_CERTIFICATE_PURPOSE,
                    "receipt signer is issued by a root directly, with no WWDR intermediate");
        }
        if (((X509Certificate) path.get(1)).getExtensionValue(AppleTrust.INTERMEDIATE_OID) == null) {
            throw new VerificationException(
                    Reason.INVALID_CERTIFICATE_PURPOSE,
                    "receipt intermediate certificate lacks Apple WWDR marker OID " + AppleTrust.INTERMEDIATE_OID);
        }
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
        } catch (GeneralSecurityException e) {
            throw AppleTrust.chainFailure(e, "receipt", "signer chain", at);
        } catch (RuntimeException e) {
            // BouncyCastle's unchecked exceptions for malformed certificate content.
            throw new VerificationException(
                    Reason.UNTRUSTED_CHAIN,
                    "path builder raised " + e.getClass().getName(),
                    e);
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
            issuers = new ArrayList<>();
            for (X509Certificate certificate : acceptedThisRound) {
                if (certificate.getBasicConstraints() != -1) {
                    issuers.add(certificate);
                }
            }
        }
        return accepted;
    }

    private static void verifyCmsSignature(SignerInformation signer, X509Certificate signerCert)
            throws VerificationException {
        // No algorithm allowlist of our own: the signer is pinned to an
        // Apple root and carries Apple's marker, so any algorithm
        // BouncyCastle can verify is accepted but the refused ones. One it
        // has no verifier for is refused below as INVALID_SIGNATURE, so a
        // genuine receipt signed with such an algorithm is rejected unless
        // another SignerInfo verifies.
        // An RSA signature binds its hash in the DigestInfo, so the
        // signatureAlgorithm label is not trusted.
        String digest = signer.getDigestAlgOID();
        String signature = signer.getEncryptionAlgOID();
        // Both before BouncyCastle digests a byte or builds a verifier, and
        // the same verdict as an algorithm it does not implement.
        if (REFUSED_DIGESTS.contains(digest)) {
            throw new VerificationException(
                    Reason.INVALID_SIGNATURE, "CMS verifier refused the signer info: digest " + digest + " is refused");
        }
        if (REFUSED_SIGNATURE_ALGORITHMS.contains(signature)) {
            throw new VerificationException(
                    Reason.INVALID_SIGNATURE,
                    "CMS verifier refused the signer info: signature algorithm " + signature + " is refused");
        }
        try {
            if (!signer.verify(signerVerifier(signerCert.getPublicKey()))) {
                throw new VerificationException(
                        Reason.INVALID_SIGNATURE, "CMS signature does not match the signer certificate's key");
            }
        } catch (CMSException | OperatorCreationException | RuntimeException e) {
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
     * The CMS verifier for the signer's key, from a builder made per call so
     * no BouncyCastle object is shared between threads. Built from the key,
     * not the certificate: with a certificate BouncyCastle also refuses a
     * signer outside its validity at a signed signingTime, which RFC 5652
     * 11.3 does not ask, and the chain is judged at the creation date
     * already.
     */
    private static SignerInformationVerifier signerVerifier(PublicKey signerKey) throws OperatorCreationException {
        return new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider(BouncyCastle.PROVIDER)
                .build(signerKey);
    }
}
