package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.internal.AppleTrust;
import io.github.emindeniz99.applepurchasereceiptverifier.internal.SafeText;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.jspecify.annotations.Nullable;

/**
 * Verifies legacy PKCS#7 app receipts (the blob apps used to send to the
 * deprecated {@code verifyReceipt} endpoint) completely offline, against the
 * pinned Apple roots: a server-side port of Apple's "Validating receipts on
 * the device" procedure.
 *
 * <p>Thread-safe once constructed.</p>
 *
 * <p>The receipt argument of every {@code verify} overload is {@code @Nullable}
 * on purpose: a null input is a verdict about the input, so it is reported as
 * {@link Reason#INVALID_RECEIPT_FORMAT} like any other unusable one rather than
 * as a {@link NullPointerException} a caller cannot catch alongside the others.
 * (A literal {@code null} is ambiguous between the {@code String} and
 * {@code byte[]} overloads and needs a cast: {@code verify((String) null)}.)
 * {@code deviceGuid} is {@code @Nullable} because it is the optional
 * device-hash binding: null skips that check, exactly as the shorter overload
 * does.</p>
 *
 * <p><strong>Security providers.</strong> The CMS signature and its digest
 * are checked with a private BouncyCastle instance that is never registered.
 * Everything else resolves through the JVM's provider list: certificate
 * decoding ({@code CertificateFactory}, through
 * {@link JcaX509CertificateConverter}), the {@code PKIX}
 * {@code CertPathBuilder} and its {@code Collection} {@code CertStore}, and
 * the SHA-1 of the device-hash check. A host that inserts BouncyCastle at
 * position 1 therefore gets BouncyCastle's X.509 parser and path builder for
 * those steps instead of the JDK's. This library's tests run against the
 * JDK's providers, so under that host an unusual certificate may get a
 * different verdict.
 * This class reads the provider order and never changes it.</p>
 */
public final class ReceiptVerifier {

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
    private static final int MAXIMUM_EMBEDDED_CERTIFICATES = 10;

    /**
     * The longest path the builder will walk, anchor excluded: at most this
     * many certificates starting at the leaf before a pinned anchor must be
     * reached, the same bound in every port. Genuine receipt chains
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
     *       default of 5 — which happens to land on the same boundary, but is
     *       a default this class does not control.</li>
     *   <li>That parameter exempts self-issued intermediates from its count
     *       (RFC 5280 6.1.4), so a path builder honouring it can still return
     *       a path longer than this constant. The built path is therefore
     *       measured afterwards.</li>
     * </ul>
     */
    private static final int MAX_PATH_LENGTH = 6;

    /**
     * Ceiling on the receipt this class will look at: the transport string at
     * {@link #verify(String, byte[])}, and the DER at every entry point that
     * takes bytes.
     *
     * <p>Checked before anything is decoded. Base64 decoding allocates about
     * three quarters of the input again, the CMS parse allocates in proportion
     * to the DER, and none of that is behind a signature check, so an input
     * large enough to exhaust the heap left {@code verify} as an
     * {@link OutOfMemoryError} rather than as the declared
     * {@link VerificationException}.
     *
     * <p>3 MiB, in bytes: Apple's verifyReceipt refuses a request body over
     * 3,145,728 bytes, so no receipt it would accept is larger. The same
     * fixed constant in every port. The string is measured
     * in characters: any character above U+007F is invalid base64, which the
     * decoder rejects with the same reason, so for every string that could
     * decode, characters and UTF-8 bytes are the same count.
     */
    public static final int MAX_RECEIPT_BYTES = 3145728;

    // Used as an instance, never registered with Security.addProvider, so this
    // library never changes the JVM's global provider list.
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    // Built once and shared by every thread; see signerVerifier.
    private static final JcaSignerInfoVerifierBuilder SIGNER_VERIFIERS = signerVerifiers();

    private final Set<TrustAnchor> trustAnchors;
    private final String bundleId;

    /**
     * Creates a verifier for one app.
     *
     * <p>This class takes no clock, on purpose. Receipt verification has no
     * staleness rule, so a clock could only reach the chain-validity instant
     * of a receipt carrying no creation date, and an injected clock must
     * never be able to accept a chain that is expired in real time. The
     * clock seams live on {@code JwsVerifier} (max signed age) and on
     * {@link VerifyReceiptEndpoint} ({@code request_date}).</p>
     *
     * @param trustedRoots pinned root CAs (production:
     *                     {@code AppleRootCerts.receiptRoots()})
     * @param bundleId     the app's bundle id the receipt must carry
     */
    public ReceiptVerifier(Set<X509Certificate> trustedRoots, String bundleId) {
        if (bundleId == null) {
            throw new IllegalArgumentException("bundleId must not be null");
        }
        this.trustAnchors = AppleTrust.anchors(trustedRoots);
        this.bundleId = bundleId;
    }

    /** Verifies a base64-encoded receipt (the usual client transport form). */
    public AppReceipt verify(@Nullable String base64Receipt) throws VerificationException {
        return verify(base64Receipt, null);
    }

    /**
     * Verifies a base64-encoded receipt and additionally enforces the
     * device-hash binding; see {@link #verify(byte[], byte[])}.
     */
    public AppReceipt verify(@Nullable String base64Receipt, byte @Nullable [] deviceGuid)
            throws VerificationException {
        // Before the decode, which would otherwise allocate a stripped copy of
        // the string and then the bytes it decodes to.
        if (base64Receipt != null && base64Receipt.length() > MAX_RECEIPT_BYTES) {
            throw tooLarge();
        }
        return verify(ReceiptBase64.decode(base64Receipt), deviceGuid);
    }

    /** Verifies a DER-encoded PKCS#7 receipt. */
    public AppReceipt verify(byte @Nullable [] receiptDer) throws VerificationException {
        return verify(receiptDer, null);
    }

    /**
     * Verifies a receipt and additionally enforces the device-hash binding:
     * {@code SHA1(deviceGuid ‖ opaqueValue ‖ bundleIdBytes)} must equal
     * attribute 5. Optional because it requires the client to send its
     * device GUID, which not every client can: the raw bytes of
     * {@code identifierForVendor} on iOS, iPadOS, tvOS and watchOS, including
     * an iOS app running on an Apple silicon Mac, or the primary network
     * interface's MAC address from {@code copy_mac_address} on macOS and Mac
     * Catalyst. Each
     * device's own receipt embeds that device's GUID, so cross-device
     * restore still works: every device presents its own receipt.
     */
    public AppReceipt verify(byte @Nullable [] receiptDer, byte @Nullable [] deviceGuid) throws VerificationException {
        AppReceipt receipt = verifyCore(receiptDer, trustAnchors);
        if (!bundleId.equals(receipt.bundleId())) {
            throw new VerificationException(
                    Reason.WRONG_BUNDLE_ID,
                    "expected " + bundleId + " but receipt has " + SafeText.quote(receipt.bundleId()));
        }
        if (deviceGuid != null) {
            verifyDeviceHash(receipt, deviceGuid);
        }
        return receipt;
    }

    /**
     * Chain + signature verification WITHOUT the bundle-id claim check — the
     * primitive under both {@link #verify} and {@link VerifyReceiptEndpoint}
     * (which, like Apple's endpoint, accepts any bundle).
     *
     * <p>Public, and static rather than an instance method, so that a caller
     * emulating Apple's endpoint gets the primitive itself instead of having
     * to build a {@link ReceiptVerifier} around a bundle id it does not want
     * checked. The other ports expose the same primitive under the same
     * name.</p>
     *
     * <p>The receipt it returns has been proved Apple-signed, but NO claim in
     * it has been checked: the bundle id in particular is whatever the receipt
     * says. A caller unlocking products must compare it itself, or use
     * {@link #verify(byte[])}.</p>
     */
    public static AppReceipt verifyReceiptCore(byte @Nullable [] receiptDer, Set<X509Certificate> trustedRoots)
            throws VerificationException {
        return verifyCore(receiptDer, AppleTrust.anchors(trustedRoots));
    }

    /** {@link #verifyReceiptCore} over anchors already built, for callers that keep them. */
    static AppReceipt verifyCore(byte @Nullable [] receiptDer, Set<TrustAnchor> trustAnchors)
            throws VerificationException {
        if (receiptDer == null) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "receipt is null");
        }
        if (receiptDer.length > MAX_RECEIPT_BYTES) {
            throw tooLarge();
        }
        // BouncyCastle's ASN.1 and CMS entry points report malformed input with
        // UNCHECKED exceptions, and which ones is neither documented nor stable
        // across releases, so hostile input is contained by category instead of
        // by type: a list of types would miss the next one and let it escape
        // the declared VerificationException contract.
        try {
            return verifyCoreUnguarded(receiptDer, trustAnchors);
        } catch (VerificationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "malformed receipt: " + e, e);
        }
    }

    private static VerificationException tooLarge() {
        return new VerificationException(
                Reason.INVALID_RECEIPT_FORMAT,
                "receipt exceeds the maximum accepted size of " + MAX_RECEIPT_BYTES + " bytes");
    }

    private static AppReceipt verifyCoreUnguarded(byte[] receiptDer, Set<TrustAnchor> trustAnchors)
            throws VerificationException {
        ASN1Primitive parsed;
        try {
            // Rejects trailing bytes after the CMS blob, so bytes appended to a
            // signed receipt cannot ride along: BC's fromByteArray throws when
            // parsing does not exhaust the input.
            parsed = ASN1Primitive.fromByteArray(receiptDer);
        } catch (IOException e) {
            throw new VerificationException(
                    Reason.INVALID_RECEIPT_FORMAT, "receipt has trailing or unparseable bytes", e);
        }
        CMSSignedData cms;
        try {
            // The tree parsed above, not the bytes: new CMSSignedData(byte[])
            // would parse the whole receipt a second time. A tree that is not
            // a ContentInfo makes getInstance throw an unchecked exception,
            // which verifyCore reports as INVALID_RECEIPT_FORMAT.
            cms = new CMSSignedData(ContentInfo.getInstance(parsed));
        } catch (CMSException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "not a PKCS#7/CMS blob", e);
        }
        if (cms.getSignedContent() == null || !(cms.getSignedContent().getContent() instanceof byte[])) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "no encapsulated payload");
        }
        byte[] payload = (byte[]) cms.getSignedContent().getContent();

        // Parsed before signature verification only to learn the creation
        // date (chain validity is anchored at signing time); nothing from it
        // is trusted until after the chain + signature checks pass.
        AppReceipt receipt = ReceiptPayload.parse(payload);
        // Without a creation date (attribute 12) the chain is judged at the
        // system clock, never an injected one; see the constructor.
        Date at = receipt.creationDate() != null ? Date.from(receipt.creationDate()) : new Date();

        Iterator<SignerInformation> signers = cms.getSignerInfos().getSigners().iterator();
        if (!signers.hasNext()) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "no signer info");
        }
        SignerInformation signer = signers.next();
        X509Certificate signerCert = validateChain(cms, signer, at, trustAnchors);
        if (signerCert.getExtensionValue(AppleTrust.SIGNING_LEAF_OID) == null) {
            throw new VerificationException(
                    Reason.INVALID_CERTIFICATE_PURPOSE,
                    "receipt signer certificate lacks Apple receipt-signing marker OID " + AppleTrust.SIGNING_LEAF_OID);
        }
        verifyCmsSignature(signer, signerCert);
        return receipt;
    }

    /** PKIX-builds signer → (intermediates from the CMS) → pinned root at {@code at}. */
    private static X509Certificate validateChain(
            CMSSignedData cms, SignerInformation signer, Date at, Set<TrustAnchor> trustAnchors)
            throws VerificationException {
        // Raw set, not cms.getCertificates(); see decodeEmbeddedAndFindSigner.
        ASN1Set certificateSet = embeddedCertificateSet(cms);
        int embeddedCount = certificateSet == null ? 0 : certificateSet.size();
        // Bounded here, before a single embedded certificate is decoded or
        // handed to the path builder — all of which an unverified receipt
        // would otherwise get to pay for out of the caller's CPU.
        if (embeddedCount > MAXIMUM_EMBEDDED_CERTIFICATES) {
            throw new VerificationException(
                    Reason.INVALID_CHAIN,
                    "receipt embeds "
                            + embeddedCount + " certificates, more than the maximum of "
                            + MAXIMUM_EMBEDDED_CERTIFICATES);
        }
        EmbeddedCertificates certificates = decodeEmbeddedAndFindSigner(certificateSet, signer);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        X509Certificate signerCert;
        try {
            // The JCA decodes the whole X.509 template, including every
            // extension VALUE, where BouncyCastle keeps extensions as encoded
            // bytes, so this is where an extnValue that stops decoding is
            // found, and it is a defect of the certificate rather than of the
            // path it sits on.
            signerCert = converter.getCertificate(certificates.signer);
            // Result unused: decoding the key here makes a key on an
            // unimplemented curve fail now, as INVALID_CERTIFICATE, instead
            // of later inside the path builder or the signature check under
            // another verdict.
            signerCert.getPublicKey();
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new VerificationException(
                    Reason.INVALID_CERTIFICATE, "receipt signer certificate is not a valid certificate", e);
        }
        try {
            List<X509Certificate> embedded = new ArrayList<X509Certificate>();
            for (X509CertificateHolder holder : certificates.all) {
                embedded.add(converter.getCertificate(holder));
            }
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(signerCert);
            PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, target);
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(embedded)));
            params.setRevocationEnabled(false);
            params.setDate(at);
            params.setMaxPathLength(MAX_PATH_LENGTH - 1);
            CertPathBuilderResult result = CertPathBuilder.getInstance("PKIX").build(params);
            // getCertPath() excludes the trust anchor, so this counts the
            // certificates from the leaf up to the anchor.
            if (result.getCertPath().getCertificates().size() > MAX_PATH_LENGTH) {
                throw new VerificationException(Reason.INVALID_CHAIN, "chain exceeds maximum length");
            }
            return signerCert;
        } catch (CertPathBuilderException e) {
            throw new VerificationException(
                    Reason.INVALID_CHAIN,
                    "signer chain does not validate to a pinned Apple root: " + e.getMessage(),
                    e);
        } catch (GeneralSecurityException e) {
            throw new VerificationException(Reason.INVALID_CHAIN, "chain validation unavailable", e);
        }
    }

    /** Every embedded certificate, decoded, and the one the SignerInfo names. */
    private static final class EmbeddedCertificates {
        final List<X509CertificateHolder> all;
        final X509CertificateHolder signer;

        EmbeddedCertificates(List<X509CertificateHolder> all, X509CertificateHolder signer) {
            this.all = all;
            this.signer = signer;
        }
    }

    /**
     * Decodes every embedded certificate and finds the one the SignerInfo
     * names, or throws the verdict for the bag.
     *
     * <p>This walk over the raw set, and {@link #namesTheSigner}, exist so
     * that a signer certificate no decoder accepts is reported as
     * INVALID_CERTIFICATE (as an unreadable x5c entry is on the JWS path),
     * while an unreadable certificate the receipt merely carries is
     * INVALID_RECEIPT_FORMAT. {@code cms.getCertificates()} decodes every
     * entry eagerly and throws on the first bad one without saying which, so
     * it cannot tell the two apart. The four broken-signer-certificate
     * conformance cases (version 11, one extension carried twice, an
     * unimplemented curve, a corrupt extension) pin INVALID_CERTIFICATE; do
     * not replace this walk with {@code cms.getCertificates()}.</p>
     */
    private static EmbeddedCertificates decodeEmbeddedAndFindSigner(
            @Nullable ASN1Set certificateSet, SignerInformation signer) throws VerificationException {
        List<X509CertificateHolder> holders = new ArrayList<X509CertificateHolder>();
        int embeddedCount = certificateSet == null ? 0 : certificateSet.size();
        @Nullable Exception unreadable = null;
        boolean unreadableSigner = false;
        for (int i = 0; i < embeddedCount; i++) {
            byte @Nullable [] raw = null;
            try {
                raw = certificateSet.getObjectAt(i).toASN1Primitive().getEncoded("DER");
                holders.add(new X509CertificateHolder(raw));
            } catch (Exception e) {
                if (unreadable == null) {
                    unreadable = e;
                }
                // Read the identity from the entry itself; see namesTheSigner.
                if (raw != null && namesTheSigner(raw, signer.getSID())) {
                    unreadableSigner = true;
                }
            }
        }
        @Nullable X509CertificateHolder signerHolder = null;
        for (X509CertificateHolder holder : holders) {
            if (signer.getSID().match(holder)) {
                signerHolder = holder;
                break;
            }
        }
        if (signerHolder == null) {
            if (unreadableSigner) {
                throw new VerificationException(
                        Reason.INVALID_CERTIFICATE,
                        "receipt signer certificate is not a valid certificate",
                        unreadable);
            }
            if (unreadable != null) {
                throw new VerificationException(
                        Reason.INVALID_RECEIPT_FORMAT,
                        "an embedded certificate is not a valid certificate",
                        unreadable);
            }
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "signer certificate not embedded");
        }
        if (unreadable != null) {
            throw new VerificationException(
                    Reason.INVALID_RECEIPT_FORMAT, "an embedded certificate is not a valid certificate", unreadable);
        }
        return new EmbeddedCertificates(holders, signerHolder);
    }

    /**
     * Whether {@code raw} carries the issuer Name and serialNumber
     * {@code sid} names, read as generic ASN.1 because the entries asked
     * about are the ones {@link X509CertificateHolder} refused. Inferring it
     * from the entries that did decode would blame the wrong entry whenever
     * the receipt names a certificate it does not carry. All ports resolve
     * the signer off the raw DER, so they agree which entry a defect is in.
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

    private static void verifyCmsSignature(SignerInformation signer, X509Certificate signerCert)
            throws VerificationException {
        if (!(signerCert.getPublicKey() instanceof RSAPublicKey)) {
            throw new VerificationException(Reason.INVALID_SIGNATURE, "receipt signer key is not RSA");
        }
        try {
            // Restrict to the digests Apple actually uses for receipts
            // (SHA-1 / SHA-256), the same set in every port.
            String digestOid = signer.getDigestAlgOID();
            if (!OIWObjectIdentifiers.idSHA1.getId().equals(digestOid)
                    && !NISTObjectIdentifiers.id_sha256.getId().equals(digestOid)) {
                throw new VerificationException(
                        Reason.INVALID_RECEIPT_FORMAT,
                        "unsupported receipt digest algorithm " + SafeText.quote(digestOid));
            }
            boolean valid = signer.verify(signerVerifier(signerCert));
            if (!valid) {
                throw new VerificationException(Reason.INVALID_SIGNATURE, "CMS signature check failed");
            }
        } catch (CMSException e) {
            throw new VerificationException(Reason.INVALID_SIGNATURE, "CMS signature check failed", e);
        } catch (OperatorCreationException e) {
            throw new VerificationException(Reason.INVALID_SIGNATURE, "CMS signature check errored", e);
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
                            .setProvider(PROVIDER)
                            .build())
                    .setProvider(PROVIDER);
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("BouncyCastle digest provider unavailable", e);
        }
    }

    private static void verifyDeviceHash(AppReceipt receipt, byte[] deviceGuid) throws VerificationException {
        if (receipt.opaqueValue() == null || receipt.sha1Hash() == null || receipt.bundleIdBytes() == null) {
            throw new VerificationException(
                    Reason.DEVICE_HASH_MISMATCH, "receipt lacks the attributes needed for the device-hash check");
        }
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(deviceGuid);
            sha1.update(receipt.opaqueValue());
            sha1.update(receipt.bundleIdBytes());
            if (!MessageDigest.isEqual(sha1.digest(), receipt.sha1Hash())) {
                throw new VerificationException(
                        Reason.DEVICE_HASH_MISMATCH, "computed device hash does not match attribute 5");
            }
        } catch (GeneralSecurityException e) {
            throw new VerificationException(Reason.DEVICE_HASH_MISMATCH, "SHA-1 unavailable", e);
        }
    }
}
