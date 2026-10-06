package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
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
     * Certificates below the anchor, leaf included. PKIX's own limit counts
     * intermediates and skips self-issued ones, so the built path is measured
     * again.
     */
    private static final int MAX_PATH_LENGTH = 6;

    /**
     * The largest receipt accepted: the base64 text's length in UTF-8 bytes,
     * checked before it is decoded. The figure is Apple's limit on a whole
     * verifyReceipt body ({@link Endpoint#MAX_REQUEST_BYTES}).
     */
    static final int MAX_RECEIPT_BYTES = 3145728;

    private ReceiptCore() {}

    /** Verifies a base64 receipt and decodes it; the order of checks is docs/design/0.7-api.md's. */
    static ReceiptPayload verify(@Nullable String base64, Set<TrustAnchor> trustAnchors, long now)
            throws VerificationException {
        if (base64 == null || base64.isEmpty()) {
            throw new VerificationException(Reason.MALFORMED, "receipt is empty");
        }
        if (Utf8Length.exceeds(base64, MAX_RECEIPT_BYTES)) {
            throw new VerificationException(
                    Reason.TOO_LARGE, "receipt exceeds the maximum accepted size of " + MAX_RECEIPT_BYTES + " bytes");
        }
        return verifyDer(StrictBase64.decode(base64, Reason.MALFORMED, "receipt"), trustAnchors, now);
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
        ASN1Primitive parsed;
        try {
            // Throws when the input is not used up, so appended bytes cannot ride along.
            parsed = ASN1Primitive.fromByteArray(receiptDer);
        } catch (IOException e) {
            throw new VerificationException(Reason.MALFORMED, "receipt has trailing or unparseable bytes", e);
        }
        CMSSignedData cms;
        try {
            // The tree, not the bytes, so the receipt is parsed once.
            cms = new CMSSignedData(ContentInfo.getInstance(parsed));
        } catch (CMSException e) {
            throw new VerificationException(Reason.MALFORMED, "not a PKCS#7/CMS blob", e);
        }
        CMSTypedData signedContent = cms.getSignedContent();
        Object content = signedContent != null ? signedContent.getContent() : null;
        if (!(content instanceof byte[])) {
            throw new VerificationException(Reason.MALFORMED, "no encapsulated payload");
        }
        byte[] payload = (byte[]) content;

        List<SignerInformation> signers = new ArrayList<>(cms.getSignerInfos().getSigners());
        if (signers.isEmpty()) {
            throw new VerificationException(Reason.MALFORMED, "no signer info");
        }
        if (signers.size() > MAX_SIGNER_INFOS) {
            throw new VerificationException(
                    Reason.MALFORMED,
                    "receipt carries " + signers.size() + " SignerInfos, more than the maximum of " + MAX_SIGNER_INFOS);
        }
        // Every SignerInfo's signedAttrs are read before any is tried: a
        // SignerInfo whose syntax is broken makes the whole SignedData
        // malformed, whatever its position. BouncyCastle reads them lazily
        // and throws from here, which verifyDer reports as MALFORMED.
        for (SignerInformation signer : signers) {
            signer.getSignedAttributes();
        }
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
                X509Certificate signerCert = certificates.signer(signer);
                List<? extends Certificate> path = validateChain(signerCert, authenticated, at, trustAnchors);
                requireMarkers(signerCert, path);
                // The chain before the signature: checking the signature
                // first would run the attacker's own key before anything
                // about it is trusted.
                verifyCmsSignature(signer, signerCert);
                return payload;
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
            signerCert.getPublicKey();
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
            params.setMaxPathLength(MAX_PATH_LENGTH - 1);
            // Per call: BouncyCastle's builder keeps state for the build it runs.
            CertPathBuilderResult result =
                    CertPathBuilder.getInstance("PKIX", BouncyCastle.PROVIDER).build(params);
            List<? extends Certificate> path = result.getCertPath().getCertificates();
            if (path.size() > MAX_PATH_LENGTH) {
                throw new VerificationException(Reason.UNTRUSTED_CHAIN, "chain exceeds maximum length");
            }
            return path;
        } catch (CertPathBuilderException e) {
            throw AppleTrust.chainFailure(e, "receipt", "signer chain", at);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            // Raised for the pinned anchors, the parameters or a missing
            // PKIX/Collection implementation, never for a certificate: the
            // runtime cannot build the validator, which says nothing about
            // the receipt.
            throw new VerificationException(Reason.INTERNAL_ERROR, "chain validator could not be constructed", e);
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
     * through one already accepted, walking down from the roots. Only these
     * reach the path builder; see {@link AppleTrust}.
     */
    private static List<X509Certificate> authenticatedTopDown(
            List<X509Certificate> embedded, Set<TrustAnchor> trustAnchors) {
        List<X509Certificate> issuers = AppleTrust.roots(trustAnchors);
        List<X509Certificate> accepted = new ArrayList<>();
        List<X509Certificate> pending = new ArrayList<>(embedded);
        for (int round = 0; round < MAX_PATH_LENGTH && !pending.isEmpty(); round++) {
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
            issuers = acceptedThisRound;
        }
        return accepted;
    }

    private static void verifyCmsSignature(SignerInformation signer, X509Certificate signerCert)
            throws VerificationException {
        // No algorithm allowlist of our own: the signer is pinned to an
        // Apple root and carries Apple's marker, so any algorithm
        // BouncyCastle can verify is accepted. One it has no verifier for is
        // refused below as INVALID_SIGNATURE, so a genuine receipt signed
        // with such an algorithm is rejected until BouncyCastle supports it.
        // An RSA signature binds its hash in the DigestInfo, so the
        // signatureAlgorithm label is not trusted.
        try {
            boolean valid = signer.verify(signerVerifier(signerCert));
            if (!valid) {
                throw new VerificationException(
                        Reason.INVALID_SIGNATURE, "CMS signature does not match the signer certificate's key");
            }
        } catch (CMSException e) {
            throw new VerificationException(Reason.INVALID_SIGNATURE, "CMS verifier refused the signer info", e);
        } catch (OperatorCreationException e) {
            throw new VerificationException(
                    Reason.INVALID_SIGNATURE, "no CMS verifier for the signer certificate's key", e);
        } catch (IllegalArgumentException e) {
            // An algorithm BouncyCastle does not implement: this SignerInfo
            // fails and the next one is tried (RFC 4853: implementations
            // MUST gracefully handle unimplemented signature algorithms).
            throw new VerificationException(
                    Reason.INVALID_SIGNATURE, "no CMS verifier for the SignerInfo's algorithms", e);
        }
    }

    /**
     * The CMS verifier for {@code signerCert}, from a builder made per call
     * so no BouncyCastle object is shared between threads.
     */
    static SignerInformationVerifier signerVerifier(X509Certificate signerCert) throws OperatorCreationException {
        DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastle.PROVIDER)
                .build();
        return new JcaSignerInfoVerifierBuilder(digests)
                .setProvider(BouncyCastle.PROVIDER)
                .build(signerCert);
    }
}
