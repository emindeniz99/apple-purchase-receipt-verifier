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
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
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
 */
public final class ReceiptVerifier {

    // Receipt attribute types from Apple's archived "Receipt Fields" chapter
    // (developer.apple.com/library/archive/releasenotes/General/
    // ValidateAppStoreReceipt/Chapters/ReceiptFields.html, last revised
    // 2017-12-11; the live "Validating receipts on the device" page defers
    // to it), plus two community-established ones (0: receipt type, 18:
    // original purchase date) needed for verifyReceipt response
    // compatibility.
    //
    // Types 1, 15, 16 and 1713 are on none of those pages either. They were
    // established by decoding a genuine production receipt and lining its
    // attributes up against the answer Apple's verifyReceipt endpoint gives
    // for the same receipt:
    //
    //   1     app item id                -> adam_id AND app_item_id
    //   15    download id                -> download_id
    //   16    version external id        -> version_external_identifier
    //   1713  is trial period (in-app)   -> is_trial_period
    //
    // All four are INTEGER attributes. Apple renders the three app-level ids
    // as JSON numbers and 1713 as the string "true"/"false", exactly as it
    // renders 1719.
    private static final int ATTR_RECEIPT_TYPE = 0;
    private static final int ATTR_APP_ITEM_ID = 1;
    private static final int ATTR_ORIGINAL_PURCHASE_DATE = 18;
    private static final int ATTR_BUNDLE_ID = 2;
    private static final int ATTR_APP_VERSION = 3;
    private static final int ATTR_OPAQUE_VALUE = 4;
    private static final int ATTR_SHA1_HASH = 5;
    private static final int ATTR_CREATION_DATE = 12;
    private static final int ATTR_DOWNLOAD_ID = 15;
    private static final int ATTR_VERSION_EXTERNAL_IDENTIFIER = 16;
    private static final int ATTR_IN_APP = 17;
    private static final int ATTR_ORIGINAL_APP_VERSION = 19;
    private static final int ATTR_EXPIRATION_DATE = 21;

    private static final int IAP_QUANTITY = 1701;
    private static final int IAP_PRODUCT_ID = 1702;
    private static final int IAP_TRANSACTION_ID = 1703;
    private static final int IAP_PURCHASE_DATE = 1704;
    private static final int IAP_ORIGINAL_TRANSACTION_ID = 1705;
    private static final int IAP_ORIGINAL_PURCHASE_DATE = 1706;
    private static final int IAP_EXPIRES_DATE = 1708;
    private static final int IAP_WEB_ORDER_LINE_ITEM_ID = 1711;
    private static final int IAP_CANCELLATION_DATE = 1712;
    private static final int IAP_IS_TRIAL_PERIOD = 1713;
    private static final int IAP_IS_IN_INTRO_OFFER_PERIOD = 1719;

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

    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    // Built once and reused; see signerVerifier.
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
     * device GUID, which not every client can: the raw bytes of {@code identifierForVendor}
     * on iOS, iPadOS, tvOS and watchOS, including an iOS app running on an
     * Apple silicon Mac, or the primary network interface's MAC address
     * from {@code copy_mac_address} on macOS and Mac Catalyst. Each
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
        AppReceipt receipt = parsePayload(payload);
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
        // The certificate bag is read from the raw SignedData rather than
        // through cms.getCertificates(), which decodes every entry eagerly
        // and throws on the first one it dislikes — losing WHICH entry it
        // was, and that is what decides the verdict. A stranger the receipt
        // merely carries is a defect of the receipt; the SIGNER being
        // unreadable is a defect of a certificate and gets the verdict an
        // unreadable x5c entry gets on the JWS path (receipt/reject-signer-*).
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
        List<X509CertificateHolder> holders = new ArrayList<X509CertificateHolder>();
        X509CertificateHolder signerHolder =
                decodeEmbeddedAndFindSigner(certificateSet, embeddedCount, signer, holders);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        X509Certificate signerCert;
        try {
            // The JCA decodes the whole X.509 template, including every
            // extension VALUE, where BouncyCastle keeps extensions as encoded
            // bytes, so this is where an extnValue that stops decoding is
            // found, and it is a defect of the certificate rather than of the
            // path it sits on.
            signerCert = converter.getCertificate(signerHolder);
            signerCert.getPublicKey();
        } catch (GeneralSecurityException e) {
            throw new VerificationException(
                    Reason.INVALID_CERTIFICATE, "receipt signer certificate is not a valid certificate", e);
        } catch (RuntimeException e) {
            throw new VerificationException(
                    Reason.INVALID_CERTIFICATE, "receipt signer certificate is not a valid certificate", e);
        }
        try {
            List<X509Certificate> embedded = new ArrayList<X509Certificate>();
            for (X509CertificateHolder holder : holders) {
                // The signer was converted above; converting it again only
                // re-encodes it and gets the same certificate back.
                embedded.add(holder == signerHolder ? signerCert : converter.getCertificate(holder));
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

    /**
     * Decodes every embedded certificate into {@code holders} and returns the
     * one the SignerInfo names, or throws the verdict for the bag.
     *
     * <p>This walk over the raw set, and {@link #namesTheSigner}, exist so
     * that a signer certificate no decoder accepts is reported as
     * INVALID_CERTIFICATE rather than INVALID_RECEIPT_FORMAT. fixtures/cases.json
     * pins that with receipt/reject-signer-certificate-version-11,
     * reject-signer-carrying-one-extension-twice,
     * reject-signer-on-an-unimplemented-curve and
     * reject-signer-with-a-corrupt-extension; do not replace it with
     * {@code cms.getCertificates()}.</p>
     */
    private static X509CertificateHolder decodeEmbeddedAndFindSigner(
            @Nullable ASN1Set certificateSet,
            int embeddedCount,
            SignerInformation signer,
            List<X509CertificateHolder> holders)
            throws VerificationException {
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
                // Whether the SignerInfo means THIS entry has to be read out
                // of the entry itself: an identity is still legible in bytes
                // that are not a certificate all the way down, and matching
                // the SignerInfo against the entries that DID decode answers
                // a different question — wrongly, whenever the receipt names
                // a certificate it does not carry at all.
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
        return signerHolder;
    }

    /**
     * Whether {@code raw} carries the issuer Name and serialNumber
     * {@code sid} names, read as generic ASN.1 rather than as a certificate.
     *
     * <p>That is the whole point: the entries this is asked about are the
     * ones {@link X509CertificateHolder} refused, and an identity is still
     * legible in bytes that are not a certificate all the way down. Node,
     * Swift and Go resolve the signer the same way, off the raw DER, so all
     * of them agree about which embedded entry a defect belongs to.</p>
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
        } catch (RuntimeException e) {
            return false;
        } catch (IOException e) {
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

    // --- ASN.1 payload parsing -------------------------------------------

    private static AppReceipt parsePayload(byte[] payload) throws VerificationException {
        ASN1Set attributes = parseAttributeSet(payload, "receipt payload");
        String receiptType = null;
        String parsedBundleId = null;
        byte[] bundleIdBytes = null;
        String appVersion = null;
        byte[] opaqueValue = null;
        byte[] sha1Hash = null;
        Instant creationDate = null;
        Instant originalPurchaseDate = null;
        String originalAppVersion = null;
        Instant expirationDate = null;
        Long appItemId = null;
        Long downloadId = null;
        Long versionExternalIdentifier = null;
        List<InAppPurchase> purchases = new ArrayList<InAppPurchase>();
        Map<Integer, List<byte[]>> unknown = new LinkedHashMap<Integer, List<byte[]>>();

        for (ASN1Encodable element : attributes) {
            Attribute attr = Attribute.of(element);
            switch (attr.type) {
                case ATTR_RECEIPT_TYPE:
                    receiptType = decodeString(attr.value);
                    break;
                case ATTR_APP_ITEM_ID:
                    appItemId = decodeInteger(attr.value);
                    break;
                case ATTR_ORIGINAL_PURCHASE_DATE:
                    originalPurchaseDate = decodeDate(attr.value);
                    break;
                case ATTR_BUNDLE_ID:
                    parsedBundleId = decodeString(attr.value);
                    bundleIdBytes = attr.value;
                    break;
                case ATTR_APP_VERSION:
                    appVersion = decodeString(attr.value);
                    break;
                case ATTR_OPAQUE_VALUE:
                    opaqueValue = attr.value;
                    break;
                case ATTR_SHA1_HASH:
                    sha1Hash = attr.value;
                    break;
                case ATTR_CREATION_DATE:
                    creationDate = decodeDate(attr.value);
                    break;
                case ATTR_DOWNLOAD_ID:
                    downloadId = decodeInteger(attr.value);
                    break;
                case ATTR_VERSION_EXTERNAL_IDENTIFIER:
                    versionExternalIdentifier = decodeInteger(attr.value);
                    break;
                case ATTR_IN_APP:
                    purchases.add(parseInApp(attr.value));
                    break;
                case ATTR_ORIGINAL_APP_VERSION:
                    originalAppVersion = decodeString(attr.value);
                    break;
                case ATTR_EXPIRATION_DATE:
                    expirationDate = decodeDate(attr.value);
                    break;
                default:
                    // Undocumented attribute types stay accessible, so a
                    // field Apple adds later is not lost.
                    recordUnknown(unknown, attr);
                    break;
            }
        }
        return new AppReceipt(
                receiptType,
                parsedBundleId,
                bundleIdBytes,
                appVersion,
                opaqueValue,
                sha1Hash,
                creationDate,
                originalPurchaseDate,
                originalAppVersion,
                expirationDate,
                appItemId,
                downloadId,
                versionExternalIdentifier,
                purchases,
                unknown);
    }

    private static InAppPurchase parseInApp(byte[] inAppSet) throws VerificationException {
        ASN1Set attributes = parseAttributeSet(inAppSet, "in-app purchase attribute");
        Long quantity = null;
        String productId = null;
        String transactionId = null;
        String originalTransactionId = null;
        Instant purchaseDate = null;
        Instant originalPurchaseDate = null;
        Instant expiresDate = null;
        Instant cancellationDate = null;
        Long webOrderLineItemId = null;
        Long isTrialPeriod = null;
        Long isInIntroOfferPeriod = null;
        Map<Integer, List<byte[]>> unknown = new LinkedHashMap<Integer, List<byte[]>>();

        for (ASN1Encodable element : attributes) {
            Attribute attr = Attribute.of(element);
            switch (attr.type) {
                case IAP_QUANTITY:
                    quantity = decodeInteger(attr.value);
                    break;
                case IAP_PRODUCT_ID:
                    productId = decodeString(attr.value);
                    break;
                case IAP_TRANSACTION_ID:
                    transactionId = decodeString(attr.value);
                    break;
                case IAP_PURCHASE_DATE:
                    purchaseDate = decodeDate(attr.value);
                    break;
                case IAP_ORIGINAL_TRANSACTION_ID:
                    originalTransactionId = decodeString(attr.value);
                    break;
                case IAP_ORIGINAL_PURCHASE_DATE:
                    originalPurchaseDate = decodeDate(attr.value);
                    break;
                case IAP_EXPIRES_DATE:
                    expiresDate = decodeDate(attr.value);
                    break;
                case IAP_WEB_ORDER_LINE_ITEM_ID:
                    webOrderLineItemId = decodeInteger(attr.value);
                    break;
                case IAP_CANCELLATION_DATE:
                    cancellationDate = decodeDate(attr.value);
                    break;
                case IAP_IS_TRIAL_PERIOD:
                    isTrialPeriod = decodeInteger(attr.value);
                    break;
                case IAP_IS_IN_INTRO_OFFER_PERIOD:
                    isInIntroOfferPeriod = decodeInteger(attr.value);
                    break;
                default:
                    recordUnknown(unknown, attr);
                    break;
            }
        }
        return new InAppPurchase(
                quantity,
                productId,
                transactionId,
                originalTransactionId,
                purchaseDate,
                originalPurchaseDate,
                expiresDate,
                cancellationDate,
                webOrderLineItemId,
                isTrialPeriod,
                isInIntroOfferPeriod,
                unknown);
    }

    private static void recordUnknown(Map<Integer, List<byte[]>> unknown, Attribute attr) {
        List<byte[]> values = unknown.get(attr.type);
        if (values == null) {
            values = new ArrayList<byte[]>();
            unknown.put(attr.type, values);
        }
        values.add(attr.value);
    }

    private static ASN1Set parseAttributeSet(byte[] der, String what) throws VerificationException {
        ASN1Primitive parsed;
        try {
            parsed = ASN1Primitive.fromByteArray(der);
        } catch (IOException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, what + " is not valid ASN.1", e);
        }
        if (parsed instanceof ASN1OctetString) {
            // Xcode receipts double-wrap the payload in an extra OCTET
            // STRING (upstream receipt_utility handles the same shape).
            try {
                parsed = ASN1Primitive.fromByteArray(((ASN1OctetString) parsed).getOctets());
            } catch (IOException e) {
                throw new VerificationException(
                        Reason.INVALID_RECEIPT_FORMAT, what + " double-wrap is not valid ASN.1", e);
            }
        }
        if (!(parsed instanceof ASN1Set)) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, what + " is not an ASN.1 SET");
        }
        return (ASN1Set) parsed;
    }

    /** {@code ReceiptAttribute ::= SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING }} */
    private static final class Attribute {
        final int type;
        final byte[] value;

        private Attribute(int type, byte[] value) {
            this.type = type;
            this.value = value;
        }

        static Attribute of(ASN1Encodable element) throws VerificationException {
            try {
                ASN1Sequence seq = ASN1Sequence.getInstance(element);
                if (seq.size() < 3) {
                    throw new VerificationException(
                            Reason.INVALID_RECEIPT_FORMAT,
                            "receipt attribute has " + seq.size() + " fields, expected 3");
                }
                long type =
                        boundedInt(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
                byte[] value = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
                // A type wider than a 32-bit signed integer is rejected rather
                // than renamed: renaming invents an attribute the receipt never
                // carried. All ports fail closed here.
                if (type > Integer.MAX_VALUE) {
                    throw new VerificationException(
                            Reason.INVALID_RECEIPT_FORMAT, "receipt attribute type out of range: " + type);
                }
                return new Attribute((int) type, value);
            } catch (IllegalArgumentException e) {
                throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "malformed receipt attribute", e);
            }
        }
    }

    /** Non-negative, <= 8 bytes — real receipts carry 7-byte integers. */
    private static long boundedInt(BigInteger value) throws VerificationException {
        if (value.signum() < 0 || value.bitLength() > 63) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "receipt integer out of range");
        }
        return value.longValue();
    }

    /**
     * A UTF8String or an IA5String, the two string types Apple's receipts
     * use and the only two any port accepts. Any other
     * {@link ASN1String} (a BIT STRING or UniversalString included) is
     * refused rather than rendered through {@code getString()}.
     */
    private static String decodeString(byte[] der) throws VerificationException {
        try {
            ASN1Primitive parsed = ASN1Primitive.fromByteArray(der);
            if (!(parsed instanceof ASN1UTF8String) && !(parsed instanceof ASN1IA5String)) {
                throw new VerificationException(
                        Reason.INVALID_RECEIPT_FORMAT, "attribute value is not a UTF8String or IA5String");
            }
            return ((ASN1String) parsed).getString();
        } catch (IOException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "attribute value is not valid ASN.1", e);
        }
    }

    private static Long decodeInteger(byte[] der) throws VerificationException {
        try {
            ASN1Primitive parsed = ASN1Primitive.fromByteArray(der);
            if (!(parsed instanceof ASN1Integer)) {
                throw new VerificationException(
                        Reason.INVALID_RECEIPT_FORMAT, "attribute value is not an ASN.1 integer");
            }
            return Long.valueOf(boundedInt(((ASN1Integer) parsed).getValue()));
        } catch (IOException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "attribute value is not valid ASN.1", e);
        }
    }

    /** RFC 3339 date in an IA5String; empty means absent (real receipts do this). */
    private static @Nullable Instant decodeDate(byte[] der) throws VerificationException {
        String text = decodeString(der);
        if (text.isEmpty()) {
            return null;
        }
        Instant instant;
        try {
            instant = Instant.parse(text);
        } catch (DateTimeParseException e) {
            throw new VerificationException(
                    Reason.INVALID_RECEIPT_FORMAT, "unparseable receipt date: " + SafeText.quote(text), e);
        }
        // Instant.parse accepts expanded years (e.g. +1000000000-...) that no
        // longer fit an epoch-milli long; toEpochMilli overflows on those, and
        // that conversion happens (via Date.from) before verification, so a
        // hostile date is rejected here rather than escaping as an
        // ArithmeticException past the declared VerificationException contract.
        try {
            instant.toEpochMilli();
        } catch (ArithmeticException e) {
            throw new VerificationException(
                    Reason.INVALID_RECEIPT_FORMAT,
                    "receipt date out of representable range: " + SafeText.quote(text),
                    e);
        }
        return instant;
    }
}
