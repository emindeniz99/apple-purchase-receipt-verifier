package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
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
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.jspecify.annotations.Nullable;

/**
 * The receipt half of {@link Verifier#verifyReceipt}: a server-side port of
 * Apple's "Validating receipts on the device" procedure, completely offline,
 * against the pinned roots.
 *
 * <p>Stateless: every method is static and keeps its per-call state in
 * locals, and the only shared object, the CMS signer-verifier builder, is
 * only read after class initialization (see {@link #signerVerifier}).</p>
 *
 * <p><strong>Security providers.</strong> Every cryptographic step uses a
 * private BouncyCastle instance that is never registered: certificate
 * decoding, the {@code PKIX} {@code CertPathBuilder} and its
 * {@code Collection} {@code CertStore}, and the CMS signature and its digest.
 * The JVM's provider list and its {@code java.security} policy,
 * {@code jdk.certpath.disabledAlgorithms} included, do not reach any of them,
 * so they cannot change a verdict. The trade-off: an administrator cannot
 * restrict verification through that policy either.</p>
 */
final class ReceiptCore {

    /**
     * Ceiling on the certificates a receipt may embed. Genuine receipts carry
     * one to three, so ten clears any chain Apple ships and still rejects a
     * flood before a single certificate is decoded.
     *
     * <p>A cross-signed mesh (layers of certificates that each name several
     * valid issuers) costs an unbounded backtracking path builder 2^layers.
     * {@link #MAX_PATH_LENGTH} already cuts that off; this count bound does
     * not rely on it.</p>
     */
    static final int MAXIMUM_EMBEDDED_CERTIFICATES = 10;

    /**
     * Ceiling on the SignerInfos a receipt may carry. Genuine receipts carry
     * one; four leaves room for a future dual-signed receipt while bounding
     * the chain builds and signature checks one receipt can ask for, since
     * every SignerInfo gets its own.
     */
    static final int MAXIMUM_SIGNER_INFOS = 4;

    /**
     * The longest path the builder will walk, anchor excluded: at most this
     * many certificates starting at the leaf before a pinned anchor must be
     * reached. Genuine receipt chains
     * are two certificates below the root, so six leaves room for a longer
     * Apple chain while bounding what a hostile embedded set can cost.
     *
     * <p>Two things stand between this constant and the JDK, and both are
     * needed to make the bound mean here what it means there:</p>
     *
     * <ul>
     *   <li>{@link PKIXBuilderParameters#setMaxPathLength} counts <em>the
     *       intermediates</em> rather than the certificates, so it is set one
     *       lower. Stating it also removes the reliance on the JDK's own
     *       default of 5, which happens to land on the same boundary, but is
     *       a default this class does not control.</li>
     *   <li>That parameter exempts self-issued intermediates from its count
     *       (RFC 5280 6.1.4), so a path builder honouring it can still return
     *       a path longer than this constant. The built path is therefore
     *       measured afterwards.</li>
     * </ul>
     */
    private static final int MAX_PATH_LENGTH = 6;

    /**
     * Ceiling on the base64 receipt, in UTF-8 bytes, checked before anything
     * is decoded: 3 MiB, Apple's own limit on a verifyReceipt request body, so
     * no receipt Apple would accept is larger.
     *
     * <p>Base64 decoding allocates about three quarters of the input again,
     * the CMS parse allocates in proportion to the DER, and none of that is
     * behind a signature check, so without the bound an input large enough to
     * exhaust the heap would leave as an {@link OutOfMemoryError} rather than
     * as a result.</p>
     */
    static final int MAX_RECEIPT_BYTES = 3145728;

    // Built once and shared by every thread; see signerVerifier.
    private static final JcaSignerInfoVerifierBuilder SIGNER_VERIFIERS = signerVerifiers();

    /** The digest each hash-and-sign {@code signatureAlgorithm} names; see {@link #digestNamedBy}. */
    private static final Map<String, String> HASH_OF_SIGNATURE_ALGORITHM = hashOfSignatureAlgorithm();

    private ReceiptCore() {}

    /**
     * Verifies a base64 receipt and decodes it.
     *
     * <p>What it checks, in order: the string is non-empty and at most
     * {@link #MAX_RECEIPT_BYTES} UTF-8 bytes; it is strict base64; the DER
     * parses completely with no trailing bytes and is a CMS SignedData with
     * an encapsulated payload, one to {@link #MAXIMUM_SIGNER_INFOS}
     * SignerInfos and at most {@link #MAXIMUM_EMBEDDED_CERTIFICATES}
     * certificates. Then, for each SignerInfo in turn until one passes: its
     * certificate is embedded and decodes, a path from it reaches one of
     * {@code trustAnchors} at the receipt's creation date ({@code clock},
     * read only then, when the receipt states none) with no revocation check, it carries
     * Apple's receipt-signing marker OID and the intermediate that issued it
     * carries Apple's WWDR marker OID, and its CMS signature verifies. Only
     * then is the payload decoded.</p>
     *
     * <p>When no SignerInfo passes, the first SignerInfo's failure is
     * reported, so a single-signer receipt fails exactly as it always
     * has.</p>
     */
    static ReceiptPayload verify(@Nullable String base64, Set<TrustAnchor> trustAnchors, CallClock clock)
            throws VerificationException {
        if (base64 == null || base64.isEmpty()) {
            throw new VerificationException(Reason.MALFORMED, "receipt is empty");
        }
        // Before the decode, which would otherwise allocate the bytes it
        // decodes to.
        if (Utf8Length.exceeds(base64, MAX_RECEIPT_BYTES)) {
            throw tooLarge();
        }
        return verifyDer(ReceiptBase64.decode(base64), trustAnchors, clock);
    }

    /** {@link #verify} after the base64 step. */
    static ReceiptPayload verifyDer(byte[] receiptDer, Set<TrustAnchor> trustAnchors, CallClock clock)
            throws VerificationException {
        // BouncyCastle's ASN.1 and CMS entry points report malformed input with
        // UNCHECKED exceptions, and which ones is neither documented nor stable
        // across releases, so hostile input is contained by category instead of
        // by type: a list of types would miss the next one.
        byte[] payload;
        try {
            payload = verifySignature(receiptDer, trustAnchors, clock);
        } catch (VerificationException e) {
            throw e;
        } catch (RuntimeException e) {
            // MALFORMED, not INTERNAL_ERROR, on purpose. Everything that can
            // throw here runs before a signature has verified, so it is
            // attacker input; answering an unknown error with INTERNAL_ERROR
            // (21009, "alert and reconcile") would let anyone raise that
            // alert at will. Signed content that cannot be read is
            // UNREADABLE_PAYLOAD, and is decided in parseSignedPayload.
            throw new VerificationException(
                    Reason.MALFORMED, "unexpected " + e.getClass().getName(), e);
        }
        return parseSignedPayload(payload);
    }

    private static VerificationException tooLarge() {
        return new VerificationException(
                Reason.TOO_LARGE, "receipt exceeds the maximum accepted size of " + MAX_RECEIPT_BYTES + " bytes");
    }

    /** Every check up to and including a signature; returns the signed payload, not yet decoded. */
    private static byte[] verifySignature(byte[] receiptDer, Set<TrustAnchor> trustAnchors, CallClock clock)
            throws VerificationException {
        if (Asn1Depth.exceeded(receiptDer)) {
            throw new VerificationException(
                    Reason.MALFORMED, "receipt nests ASN.1 deeper than " + Asn1Depth.MAX_DEPTH + " values");
        }
        ASN1Primitive parsed;
        try {
            // Rejects trailing bytes after the CMS blob, so bytes appended to a
            // signed receipt cannot ride along: BC's fromByteArray throws when
            // parsing does not exhaust the input.
            parsed = ASN1Primitive.fromByteArray(receiptDer);
        } catch (IOException e) {
            throw new VerificationException(Reason.MALFORMED, "receipt has trailing or unparseable bytes", e);
        }
        CMSSignedData cms;
        try {
            // The tree parsed above, not the bytes: new CMSSignedData(byte[])
            // would parse the whole receipt a second time. A tree that is not
            // a ContentInfo makes getInstance throw an unchecked exception,
            // which verifyDer reports as MALFORMED.
            cms = new CMSSignedData(ContentInfo.getInstance(parsed));
        } catch (CMSException e) {
            throw new VerificationException(Reason.MALFORMED, "not a PKCS#7/CMS blob", e);
        }
        if (cms.getSignedContent() == null || !(cms.getSignedContent().getContent() instanceof byte[])) {
            throw new VerificationException(Reason.MALFORMED, "no encapsulated payload");
        }
        byte[] payload = (byte[]) cms.getSignedContent().getContent();

        List<SignerInformation> signers =
                new ArrayList<SignerInformation>(cms.getSignerInfos().getSigners());
        if (signers.isEmpty()) {
            throw new VerificationException(Reason.MALFORMED, "no signer info");
        }
        if (signers.size() > MAXIMUM_SIGNER_INFOS) {
            throw new VerificationException(
                    Reason.MALFORMED,
                    "receipt carries " + signers.size() + " SignerInfos, more than the maximum of "
                            + MAXIMUM_SIGNER_INFOS);
        }
        for (SignerInformation signer : signers) {
            requireAttributeSetSyntax(signer);
        }
        // Raw set, not cms.getCertificates(); see decodeEmbedded.
        ASN1Set certificateSet = embeddedCertificateSet(cms);
        int embeddedCount = certificateSet == null ? 0 : certificateSet.size();
        // Bounded here, before a single embedded certificate is decoded or
        // handed to the path builder, all of which an unverified receipt
        // would otherwise get to pay for out of the caller's CPU.
        if (embeddedCount > MAXIMUM_EMBEDDED_CERTIFICATES) {
            throw new VerificationException(
                    Reason.MALFORMED,
                    "receipt embeds " + embeddedCount + " certificates, more than the maximum of "
                            + MAXIMUM_EMBEDDED_CERTIFICATES);
        }

        // Only the creation date is read before trust is established, because
        // chain validity is anchored at signing time; nothing else in the
        // payload is decoded until the chain and a signature have passed. A
        // date that is missing, empty, unreadable or stated twice cannot blame
        // anyone yet, so it only moves the chain instant to the clock and
        // never rejects by itself.
        Long creationDate = ReceiptDecoder.readCreationDate(payload);
        Date at = null;

        EmbeddedCertificates certificates = decodeEmbedded(certificateSet);
        // Signer-independent, so walked once for all SignerInfos, and only
        // once one of them has named an embedded certificate that decodes.
        List<X509Certificate> authenticated = null;
        VerificationException firstFailure = null;
        for (SignerInformation signer : signers) {
            try {
                X509Certificate signerCert = certificates.signer(signer);
                if (at == null) {
                    at = new Date(creationDate != null ? creationDate.longValue() : clock.millis());
                }
                if (authenticated == null) {
                    authenticated = authenticatedTopDown(certificates.all, trustAnchors);
                }
                List<? extends Certificate> path = validateChain(signerCert, authenticated, at, trustAnchors);
                requireMarkers(signerCert, path);
                // The chain is checked BEFORE the signature on purpose:
                // checking the signature first would run the attacker's own
                // key (their choice of RSA size and exponent) before anything
                // about it is trusted.
                verifyCmsSignature(signer, signerCert);
                return payload;
            } catch (VerificationException e) {
                // Every SignerInfo signs the same content, so another one
                // passing proves the same bytes; only when none does is the
                // first one's failure the verdict.
                if (firstFailure == null) {
                    firstFailure = e;
                }
            }
        }
        throw firstFailure;
    }

    /**
     * The full payload parse, run only after the chain and a signature have
     * passed. A trusted signer signed these bytes, so anything that stops the
     * parse (this library's grammar, a bound, an unexpected runtime exception)
     * is the library's failure or a format Apple added, not the client's:
     * UNREADABLE_PAYLOAD, with the parser's exception as its cause, never
     * MALFORMED, which the endpoint answers as 21002 and an app server reads
     * as "deny".
     */
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
     * Apple's marker OIDs: receipt signing on the signer, and WWDR on the
     * intermediate that issued it, the certificate after the signer in the
     * built path. The chain check alone is not enough: developer certificates
     * chain through the same WWDR intermediate to the same pinned root, and
     * the intermediate check brings the receipt path level with the JWS path.
     * A path with no intermediate at all, a signer issued straight by a root,
     * has no WWDR certificate to carry the marker.
     */
    private static void requireMarkers(X509Certificate signerCert, List<? extends Certificate> path)
            throws VerificationException {
        if (signerCert.getExtensionValue(AppleTrust.SIGNING_LEAF_OID) == null) {
            throw new VerificationException(
                    Reason.INVALID_CERTIFICATE_PURPOSE,
                    "receipt signer certificate lacks Apple receipt-signing marker OID " + AppleTrust.SIGNING_LEAF_OID);
        }
        if (path.size() < 2 || ((X509Certificate) path.get(1)).getExtensionValue(AppleTrust.INTERMEDIATE_OID) == null) {
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
        // A signer the top-down walk did not reach has no path to a pinned
        // root, so it is refused here, before the path builder or anything
        // else can decode its key (see AppleTrust).
        if (!authenticated.contains(signerCert)) {
            throw new VerificationException(
                    Reason.UNTRUSTED_CHAIN, "signer certificate is not issued under a pinned Apple root");
        }
        // Issued under a pinned root, so decoding its key is safe now; a key
        // no decoder accepts is a verdict about the certificate.
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
            CertPathBuilderResult result =
                    CertPathBuilder.getInstance("PKIX", BouncyCastle.PROVIDER).build(params);
            // getCertPath() excludes the trust anchor, so this counts the
            // certificates from the leaf up to the anchor.
            List<? extends Certificate> path = result.getCertPath().getCertificates();
            if (path.size() > MAX_PATH_LENGTH) {
                throw new VerificationException(Reason.UNTRUSTED_CHAIN, "chain exceeds maximum length");
            }
            return path;
        } catch (CertPathBuilderException e) {
            throw AppleTrust.chainFailure(e, "receipt", "signer chain", at);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            // Not raised by the pinned BouncyCastle PKIX and Collection
            // implementations for parameters built from the pinned anchors.
            // Should it happen, it is the library's failure, never the receipt's.
            throw new VerificationException(Reason.INTERNAL_ERROR, "chain validation is not available", e);
        } catch (GeneralSecurityException e) {
            throw new VerificationException(Reason.UNTRUSTED_CHAIN, "embedded certificate could not be used", e);
        } catch (RuntimeException e) {
            // As in JwsCore.validateChain: unchecked exceptions BouncyCastle
            // raises from inside the builder for malformed, unverified
            // certificate content are the chain's failure.
            throw new VerificationException(
                    Reason.UNTRUSTED_CHAIN,
                    "path builder raised " + e.getClass().getName(),
                    e);
        }
    }

    /**
     * The embedded certificates whose signature verifies under a pinned root,
     * or under a certificate already accepted this way, walking down from the
     * roots. Only these reach the path builder.
     *
     * <p>A certificate's own public key is decoded only after its signature
     * has verified. BouncyCastle validates an RSA key as it decodes it, with
     * a primality test that costs seconds for a 16384-bit modulus, and the
     * path builder verifies signatures with whatever keys it is given. Walking
     * down from the roots means no key Apple did not sign is ever decoded or
     * used, so a receipt padded with such certificates costs milliseconds,
     * and the certificates are simply left out.</p>
     */
    private static List<X509Certificate> authenticatedTopDown(
            List<X509Certificate> embedded, Set<TrustAnchor> trustAnchors) {
        List<X509Certificate> issuers = AppleTrust.roots(trustAnchors);
        List<X509Certificate> accepted = new ArrayList<X509Certificate>();
        List<X509Certificate> pending = new ArrayList<X509Certificate>(embedded);
        for (int round = 0; round < MAX_PATH_LENGTH && !pending.isEmpty(); round++) {
            List<X509Certificate> acceptedThisRound = new ArrayList<X509Certificate>();
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

    /**
     * The embedded certificate bag, decoded once for every SignerInfo: the
     * entries that decoded, with their holders, and the ones that did not.
     */
    private static final class EmbeddedCertificates {
        final List<X509Certificate> all = new ArrayList<X509Certificate>();
        /** Parallel to {@link #all}. */
        final List<X509CertificateHolder> holders = new ArrayList<X509CertificateHolder>();

        final List<UnreadableEntry> unreadable = new ArrayList<UnreadableEntry>();

        /**
         * The certificate {@code signer} names, or the verdict for the bag.
         * The signer's own entry not decoding is INVALID_CERTIFICATE, as an
         * unreadable x5c entry is on the JWS path; any other entry not
         * decoding is MALFORMED, because the bag is unsigned and bytes that
         * cannot be read there are a defect of the receipt, not of a
         * certificate. A broken signer outranks a broken stranger.
         */
        X509Certificate signer(SignerInformation signer) throws VerificationException {
            SignerId sid = signer.getSID();
            for (UnreadableEntry entry : unreadable) {
                // An entry the holder refused has its identity read from the
                // raw DER; see namesTheSigner.
                boolean isSigner = entry.holder != null
                        ? sid.match(entry.holder)
                        : entry.raw != null && namesTheSigner(entry.raw, sid);
                if (isSigner) {
                    throw new VerificationException(
                            Reason.INVALID_CERTIFICATE, "receipt signer certificate does not decode", entry.error);
                }
            }
            if (!unreadable.isEmpty()) {
                throw new VerificationException(
                        Reason.MALFORMED,
                        "an embedded certificate is not a valid certificate",
                        unreadable.get(0).error);
            }
            for (int i = 0; i < holders.size(); i++) {
                if (sid.match(holders.get(i))) {
                    return all.get(i);
                }
            }
            throw new VerificationException(Reason.MALFORMED, "signer certificate not embedded");
        }
    }

    /** An embedded entry that did not decode, with as much of it as was read. */
    private static final class UnreadableEntry {
        final byte @Nullable [] raw;
        final @Nullable X509CertificateHolder holder;
        final Exception error;

        UnreadableEntry(byte @Nullable [] raw, @Nullable X509CertificateHolder holder, Exception error) {
            this.raw = raw;
            this.holder = holder;
            this.error = error;
        }
    }

    /**
     * Decodes every embedded certificate, except its public key.
     *
     * <p>This is the only place a receipt certificate is decoded, so a
     * defect gets one verdict whichever layer finds it: the X.509 structure,
     * a basicConstraints or keyUsage value (which only the JCA object
     * decodes), or a signature BIT STRING that is not whole octets (which
     * BouncyCastle reads lazily, and would otherwise throw from inside the
     * path builder). Keys are decoded later, and only for certificates a
     * pinned root vouches for; see {@link #authenticatedTopDown}. Which
     * verdict an entry that does not decode gets is decided per SignerInfo,
     * in {@link EmbeddedCertificates#signer}.</p>
     *
     * <p>This walk over the raw set, and {@link #namesTheSigner}, exist so
     * that the two can be told apart for an entry no decoder accepts.
     * {@code cms.getCertificates()} decodes every entry eagerly and throws on
     * the first bad one without saying which, so a broken signer (version
     * 11, an extension carried twice, an unimplemented curve, a corrupt
     * extension) could not be told from a broken stranger. Do not replace
     * this walk with {@code cms.getCertificates()}.</p>
     */
    private static EmbeddedCertificates decodeEmbedded(@Nullable ASN1Set certificateSet) {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BouncyCastle.PROVIDER);
        EmbeddedCertificates certificates = new EmbeddedCertificates();
        int embeddedCount = certificateSet == null ? 0 : certificateSet.size();
        for (int i = 0; i < embeddedCount; i++) {
            byte @Nullable [] raw = null;
            @Nullable X509CertificateHolder holder = null;
            try {
                raw = certificateSet.getObjectAt(i).toASN1Primitive().getEncoded("DER");
                holder = new X509CertificateHolder(raw);
                X509Certificate certificate = converter.getCertificate(holder);
                // Result unused: reading it here is what makes a lazily
                // decoded signature fail in this loop. The key is not read:
                // see authenticatedTopDown.
                certificate.getSignature();
                certificates.all.add(certificate);
                certificates.holders.add(holder);
            } catch (Exception e) {
                certificates.unreadable.add(new UnreadableEntry(raw, holder, e));
            }
        }
        return certificates;
    }

    /**
     * Whether {@code raw} carries the issuer Name and serialNumber
     * {@code sid} names, read as generic ASN.1 because the entries asked
     * about are the ones {@link X509CertificateHolder} refused. Inferring it
     * from the entries that did decode would blame the wrong entry whenever
     * the receipt names a certificate it does not carry.
     *
     * <p>{@code TBSCertificate ::= SEQUENCE { [0] version DEFAULT v1,
     * serialNumber INTEGER, signature AlgorithmIdentifier, issuer Name,
     * ... }} — anything without that shape is not an identity and cannot
     * match.</p>
     */
    private static boolean namesTheSigner(byte[] raw, SignerId sid) {
        try {
            ASN1Sequence certificate = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(raw));
            ASN1Encodable first = certificate.getObjectAt(0);
            if (!(first instanceof ASN1Sequence)) {
                return false;
            }
            ASN1Sequence tbs = (ASN1Sequence) first;
            int index = tbs.getObjectAt(0) instanceof ASN1TaggedObject ? 1 : 0;
            BigInteger serial = ASN1Integer.getInstance(tbs.getObjectAt(index)).getValue();
            X500Name issuer = X500Name.getInstance(tbs.getObjectAt(index + 2));
            return serial.equals(sid.getSerialNumber()) && issuer.equals(sid.getIssuer());
        } catch (RuntimeException | IOException e) {
            return false;
        }
    }

    /**
     * The raw {@code certificates [0] IMPLICIT SET} of the SignedData, or
     * null when the receipt carries none. BouncyCastle's ASN.1
     * {@link SignedData} hands the set back undecoded, so an entry no
     * certificate decoder accepts is still counted and still locatable.
     */
    private static @Nullable ASN1Set embeddedCertificateSet(CMSSignedData cms) {
        return SignedData.getInstance(cms.toASN1Structure().getContent()).getCertificates();
    }

    /**
     * The syntax of one {@code SignerInfo}'s {@code signedAttrs}, judged for
     * every {@code SignerInfo} before any key is used, so a set that is not
     * an RFC 5652 attribute set, {@code SEQUENCE { OID, SET OF value }}
     * with at least one value, is MALFORMED whichever position it holds. A
     * well-formed set lacking {@code contentType} or {@code messageDigest}
     * is left to the signature check, as INVALID_SIGNATURE for that signer.
     */
    private static void requireAttributeSetSyntax(SignerInformation signer) throws VerificationException {
        ASN1Set attributes = signer.toASN1Structure().getAuthenticatedAttributes();
        if (attributes == null) {
            return;
        }
        for (ASN1Encodable element : attributes) {
            if (!(element instanceof ASN1Sequence)) {
                throw malformedSignedAttributes();
            }
            ASN1Sequence attribute = (ASN1Sequence) element;
            if (attribute.size() < 2
                    || !(attribute.getObjectAt(0) instanceof ASN1ObjectIdentifier)
                    || !(attribute.getObjectAt(1) instanceof ASN1Set)
                    || ((ASN1Set) attribute.getObjectAt(1)).size() == 0) {
                throw malformedSignedAttributes();
            }
        }
    }

    private static VerificationException malformedSignedAttributes() {
        return new VerificationException(Reason.MALFORMED, "malformed signedAttrs: not an attribute set");
    }

    /**
     * The digest a {@code signatureAlgorithm} names, when it names one: the
     * hash-and-sign OIDs, and the hash in RSASSA-PSS parameters. Null for
     * {@code rsaEncryption}, {@code id-ecPublicKey} and anything else, which
     * take the {@code SignerInfo}'s {@code digestAlgorithm}.
     */
    private static @Nullable String digestNamedBy(SignerInformation signer) {
        String oid = signer.getEncryptionAlgOID();
        if (PKCSObjectIdentifiers.id_RSASSA_PSS.getId().equals(oid)) {
            try {
                return RSASSAPSSparams.getInstance(signer.getEncryptionAlgParams())
                        .getHashAlgorithm()
                        .getAlgorithm()
                        .getId();
            } catch (RuntimeException e) {
                // Parameters that do not read are the verifier's to refuse.
                return null;
            }
        }
        return HASH_OF_SIGNATURE_ALGORITHM.get(oid);
    }

    private static Map<String, String> hashOfSignatureAlgorithm() {
        String md5 = "1.2.840.113549.2.5";
        String sha1 = "1.3.14.3.2.26";
        String sha224 = "2.16.840.1.101.3.4.2.4";
        String sha256 = "2.16.840.1.101.3.4.2.1";
        String sha384 = "2.16.840.1.101.3.4.2.2";
        String sha512 = "2.16.840.1.101.3.4.2.3";
        Map<String, String> map = new HashMap<String, String>();
        map.put("1.2.840.113549.1.1.4", md5);
        map.put("1.2.840.113549.1.1.5", sha1);
        map.put("1.2.840.113549.1.1.14", sha224);
        map.put("1.2.840.113549.1.1.11", sha256);
        map.put("1.2.840.113549.1.1.12", sha384);
        map.put("1.2.840.113549.1.1.13", sha512);
        map.put("1.2.840.10045.4.1", sha1);
        map.put("1.2.840.10045.4.3.1", sha224);
        map.put("1.2.840.10045.4.3.2", sha256);
        map.put("1.2.840.10045.4.3.3", sha384);
        map.put("1.2.840.10045.4.3.4", sha512);
        return Collections.unmodifiableMap(map);
    }

    private static void verifyCmsSignature(SignerInformation signer, X509Certificate signerCert)
            throws VerificationException {
        // A signatureAlgorithm that names a hash must name the one the
        // SignerInfo digested with: a label that disagrees with what was
        // hashed is not one signature under two names.
        String named = digestNamedBy(signer);
        if (named != null && !named.equals(signer.getDigestAlgOID())) {
            throw new VerificationException(
                    Reason.INVALID_SIGNATURE, "signatureAlgorithm names another hash than digestAlgorithm");
        }
        // No algorithm or key-type allowlist, by design: the signer is
        // already pinned to an Apple root and carries Apple's receipt-signing
        // marker, so whatever algorithm Apple signs with is accepted, and a
        // change on Apple's side cannot reject genuine receipts. A weak hash only helps an attacker holding a signature
        // Apple made over that hash, and an RSA signature binds its hash
        // algorithm in the DigestInfo, so relabelling the field fails.
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
        }
    }

    /**
     * The CMS signature verifier for {@code signerCert}, from one
     * {@link JcaSignerInfoVerifierBuilder} kept for the life of the class.
     * BouncyCastle's builder holds its algorithm-name and algorithm-finder
     * tables (a few hundred entries) and builds only the per-certificate
     * parts in {@code build}, so reusing it avoids rebuilding the tables for
     * every receipt, which {@code JcaSimpleSignerInfoVerifierBuilder} does.
     *
     * <p>Sharing it across threads relies on BouncyCastle internals, checked
     * in BouncyCastle 1.86: {@code build} writes no state, only reads fields
     * set before class initialization finished (not declared final, but
     * safely published by it), and makes a new content-verifier provider per
     * certificate; the name generator, algorithm finder and digest provider
     * it shares are only read. Re-check on every BouncyCastle upgrade.</p>
     */
    static SignerInformationVerifier signerVerifier(X509Certificate signerCert) throws OperatorCreationException {
        return SIGNER_VERIFIERS.build(signerCert);
    }

    private static JcaSignerInfoVerifierBuilder signerVerifiers() {
        try {
            return new JcaSignerInfoVerifierBuilder(new JcaDigestCalculatorProviderBuilder()
                            .setProvider(BouncyCastle.PROVIDER)
                            .build())
                    .setProvider(BouncyCastle.PROVIDER);
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("BouncyCastle digest provider unavailable", e);
        }
    }
}
