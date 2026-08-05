package io.github.emindeniz99.applepurchase.receipt;

import io.github.emindeniz99.applepurchase.VerificationException;
import io.github.emindeniz99.applepurchase.VerificationException.Reason;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Verifies legacy PKCS#7 app receipts (the blob apps used to send to the
 * deprecated {@code verifyReceipt} endpoint) completely offline, against the
 * pinned Apple Inc. Root CA — the server-side port of Apple's "Validating
 * receipts on the device" procedure (PLAN.md §2.2).
 *
 * <p>Thread-safe once constructed.</p>
 */
public final class ReceiptVerifier {

    // Receipt attribute types (Apple, "Validating receipts on the device").
    private static final int ATTR_BUNDLE_ID = 2;
    private static final int ATTR_APP_VERSION = 3;
    private static final int ATTR_OPAQUE_VALUE = 4;
    private static final int ATTR_SHA1_HASH = 5;
    private static final int ATTR_CREATION_DATE = 12;
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
    private static final int IAP_IS_IN_INTRO_OFFER_PERIOD = 1719;

    private final Set<TrustAnchor> trustAnchors;
    private final String bundleId;
    private final BouncyCastleProvider provider = new BouncyCastleProvider();

    /**
     * @param trustedRoots pinned root CAs (production:
     *                     {@code AppleRootCerts.receiptRoots()})
     * @param bundleId     the app's bundle id the receipt must carry
     */
    public ReceiptVerifier(Set<X509Certificate> trustedRoots, String bundleId) {
        if (trustedRoots == null || trustedRoots.isEmpty()) {
            throw new IllegalArgumentException("trustedRoots must not be empty");
        }
        if (bundleId == null) {
            throw new IllegalArgumentException("bundleId must not be null");
        }
        Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();
        for (X509Certificate root : trustedRoots) {
            anchors.add(new TrustAnchor(root, null));
        }
        this.trustAnchors = anchors;
        this.bundleId = bundleId;
    }

    /** Verifies a base64-encoded receipt (the usual client transport form). */
    public AppReceipt verify(String base64Receipt) throws VerificationException {
        if (base64Receipt == null) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "receipt is null");
        }
        byte[] der;
        try {
            der = Base64.getMimeDecoder().decode(base64Receipt);
        } catch (IllegalArgumentException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "receipt is not valid base64", e);
        }
        return verify(der);
    }

    /** Verifies a DER-encoded PKCS#7 receipt. */
    public AppReceipt verify(byte[] receiptDer) throws VerificationException {
        return verify(receiptDer, null);
    }

    /**
     * Verifies a receipt and additionally enforces the device-hash binding:
     * {@code SHA1(deviceGuid ‖ opaqueValue ‖ bundleIdBytes)} must equal
     * attribute 5. Optional because it requires the client to send its
     * {@code identifierForVendor} bytes (PLAN.md D4) — each device's own
     * receipt embeds that device's GUID, so cross-device restore still works:
     * every device presents its own receipt.
     */
    public AppReceipt verify(byte[] receiptDer, byte[] deviceGuid) throws VerificationException {
        if (receiptDer == null) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "receipt is null");
        }
        CMSSignedData cms;
        try {
            cms = new CMSSignedData(receiptDer);
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
        Date at = receipt.creationDate() != null ? Date.from(receipt.creationDate()) : new Date();

        X509Certificate signerCert = validateChain(cms, at);
        verifyCmsSignature(cms, signerCert);

        if (!bundleId.equals(receipt.bundleId())) {
            throw new VerificationException(Reason.WRONG_BUNDLE_ID,
                    "expected " + bundleId + " but receipt has " + receipt.bundleId());
        }
        if (deviceGuid != null) {
            verifyDeviceHash(receipt, deviceGuid);
        }
        return receipt;
    }

    /** PKIX-builds signer → (intermediates from the CMS) → pinned root at {@code at}. */
    private X509Certificate validateChain(CMSSignedData cms, Date at) throws VerificationException {
        Iterator<SignerInformation> signers = cms.getSignerInfos().getSigners().iterator();
        if (!signers.hasNext()) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "no signer info");
        }
        SignerInformation signer = signers.next();
        Collection<X509CertificateHolder> matches = cms.getCertificates().getMatches(signer.getSID());
        if (matches.isEmpty()) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "signer certificate not embedded");
        }
        try {
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            X509Certificate signerCert = converter.getCertificate(matches.iterator().next());
            List<X509Certificate> embedded = new ArrayList<X509Certificate>();
            for (X509CertificateHolder holder : cms.getCertificates().getMatches(null)) {
                embedded.add(converter.getCertificate(holder));
            }
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(signerCert);
            PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, target);
            params.addCertStore(CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(embedded)));
            params.setRevocationEnabled(false);
            params.setDate(at);
            CertPathBuilder.getInstance("PKIX").build(params);
            return signerCert;
        } catch (CertPathBuilderException e) {
            throw new VerificationException(Reason.INVALID_CHAIN,
                    "signer chain does not validate to a pinned Apple root: " + e.getMessage(), e);
        } catch (GeneralSecurityException e) {
            throw new VerificationException(Reason.INVALID_CHAIN, "chain validation unavailable", e);
        }
    }

    private void verifyCmsSignature(CMSSignedData cms, X509Certificate signerCert)
            throws VerificationException {
        try {
            SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
            boolean valid = signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(provider)
                    .build(signerCert));
            if (!valid) {
                throw new VerificationException(Reason.INVALID_SIGNATURE, "CMS signature check failed");
            }
        } catch (CMSException e) {
            throw new VerificationException(Reason.INVALID_SIGNATURE, "CMS signature check failed", e);
        } catch (OperatorCreationException e) {
            throw new VerificationException(Reason.INVALID_SIGNATURE, "CMS signature check errored", e);
        }
    }

    private static void verifyDeviceHash(AppReceipt receipt, byte[] deviceGuid)
            throws VerificationException {
        if (receipt.opaqueValue() == null || receipt.sha1Hash() == null
                || receipt.bundleIdBytes() == null) {
            throw new VerificationException(Reason.DEVICE_HASH_MISMATCH,
                    "receipt lacks the attributes needed for the device-hash check");
        }
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(deviceGuid);
            sha1.update(receipt.opaqueValue());
            sha1.update(receipt.bundleIdBytes());
            if (!MessageDigest.isEqual(sha1.digest(), receipt.sha1Hash())) {
                throw new VerificationException(Reason.DEVICE_HASH_MISMATCH,
                        "computed device hash does not match attribute 5");
            }
        } catch (GeneralSecurityException e) {
            throw new VerificationException(Reason.DEVICE_HASH_MISMATCH, "SHA-1 unavailable", e);
        }
    }

    // --- ASN.1 payload parsing -------------------------------------------

    private static AppReceipt parsePayload(byte[] payload) throws VerificationException {
        ASN1Set attributes = parseAttributeSet(payload, "receipt payload");
        String parsedBundleId = null;
        byte[] bundleIdBytes = null;
        String appVersion = null;
        byte[] opaqueValue = null;
        byte[] sha1Hash = null;
        Instant creationDate = null;
        String originalAppVersion = null;
        Instant expirationDate = null;
        List<InAppPurchase> purchases = new ArrayList<InAppPurchase>();

        for (ASN1Encodable element : attributes) {
            Attribute attr = Attribute.of(element);
            switch (attr.type) {
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
                    // Receipts carry undocumented attribute types; ignore them.
                    break;
            }
        }
        return new AppReceipt(parsedBundleId, bundleIdBytes, appVersion, opaqueValue,
                sha1Hash, creationDate, originalAppVersion, expirationDate, purchases);
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
        Long isInIntroOfferPeriod = null;

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
                case IAP_IS_IN_INTRO_OFFER_PERIOD:
                    isInIntroOfferPeriod = decodeInteger(attr.value);
                    break;
                default:
                    break;
            }
        }
        return new InAppPurchase(quantity, productId, transactionId, originalTransactionId,
                purchaseDate, originalPurchaseDate, expiresDate, cancellationDate,
                webOrderLineItemId, isInIntroOfferPeriod);
    }

    private static ASN1Set parseAttributeSet(byte[] der, String what) throws VerificationException {
        ASN1Primitive parsed;
        try {
            parsed = ASN1Primitive.fromByteArray(der);
        } catch (IOException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, what + " is not valid ASN.1", e);
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
                    throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                            "receipt attribute has " + seq.size() + " fields, expected 3");
                }
                BigInteger type = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
                byte[] value = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
                return new Attribute(type.intValueExact(), value);
            } catch (IllegalArgumentException e) {
                throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                        "malformed receipt attribute", e);
            } catch (ArithmeticException e) {
                throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                        "receipt attribute type out of range", e);
            }
        }
    }

    private static String decodeString(byte[] der) throws VerificationException {
        try {
            ASN1Primitive parsed = ASN1Primitive.fromByteArray(der);
            if (!(parsed instanceof ASN1String)) {
                throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                        "attribute value is not an ASN.1 string");
            }
            return ((ASN1String) parsed).getString();
        } catch (IOException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                    "attribute value is not valid ASN.1", e);
        }
    }

    private static Long decodeInteger(byte[] der) throws VerificationException {
        try {
            ASN1Primitive parsed = ASN1Primitive.fromByteArray(der);
            if (!(parsed instanceof ASN1Integer)) {
                throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                        "attribute value is not an ASN.1 integer");
            }
            return ((ASN1Integer) parsed).getValue().longValueExact();
        } catch (IOException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                    "attribute value is not valid ASN.1", e);
        } catch (ArithmeticException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                    "attribute integer out of range", e);
        }
    }

    /** RFC 3339 date in an IA5String; empty means absent (real receipts do this). */
    private static Instant decodeDate(byte[] der) throws VerificationException {
        String text = decodeString(der);
        if (text.isEmpty()) {
            return null;
        }
        try {
            return Instant.parse(text);
        } catch (DateTimeParseException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                    "unparseable receipt date: " + text, e);
        }
    }
}
