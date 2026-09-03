package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

    // Receipt attribute types (Apple, "Validating receipts on the device"),
    // plus two community-established ones (0: receipt type, 18: original
    // purchase date) needed for verifyReceipt response compatibility.
    private static final int ATTR_RECEIPT_TYPE = 0;
    private static final int ATTR_ORIGINAL_PURCHASE_DATE = 18;
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

    /**
     * Apple marker OID stamped on the receipt-signing leaf certificate. The
     * chain check alone is not enough: developer "Apple Distribution" certs
     * chain through the same WWDR intermediate to the same pinned root, so
     * without this purpose check any developer could sign a forged receipt.
     */
    private static final String RECEIPT_SIGNER_OID = "1.2.840.113635.100.6.11.1";

    /**
     * Ceiling on the certificates a receipt may embed. Genuine receipts carry
     * one to three (fixtures/public-receipts: xcode-with-purchases 1,
     * sandbox-g5 3, sandbox-legacy 3), so ten clears any chain Apple ships and
     * still rejects a flood before a single certificate is decoded. With the
     * bound, what is left of a flood is CMS parsing of the blob, which is
     * proportional to the input a caller can already cap.
     *
     * <p>The exponential case is a cross-signed mesh — layers of certificates
     * that each name several equally valid issuers, which an unbounded
     * backtracking path builder spends 2^layers on. Here it stays flat at
     * 1.0-1.5 ms from fourteen layers to twenty-two (measured in
     * ReceiptVerifierTest#rejectsCrossSignedCertificateMeshWithoutWalkingIt),
     * but only because {@link PKIXBuilderParameters} defaults
     * {@code maxPathLength} to 5 and so abandons every path early: a JDK
     * default this class never states and does not control. Bounding the
     * count does not rely on it, and matches the node, python and swift
     * implementations.</p>
     */
    private static final int MAXIMUM_EMBEDDED_CERTIFICATES = 10;

    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    private final Set<TrustAnchor> trustAnchors;
    private final String bundleId;

    /**
     * <p>There is deliberately no clock option on this class, and there must
     * not be one. Receipt verification has no staleness rule, so the only
     * thing a clock could reach is the "else current time" fallback for the
     * chain-validity instant of a receipt carrying no creation date (PLAN.md
     * §2.2 step 2) — a certificate-validity verdict. A caller injecting a
     * clock (to work around skew, or to pin a test) must not thereby be able
     * to accept a chain that is expired in real time, so that fallback reads
     * the system clock and nothing else. node, python and swift agree; the
     * clock seam lives on {@code JwsVerifier} (max signed age) and on
     * {@link VerifyReceiptEndpoint} (request_date stamping), where what it
     * drives genuinely moves with wall-clock time.</p>
     *
     * @param trustedRoots pinned root CAs (production:
     *                     {@code AppleRootCerts.receiptRoots()})
     * @param bundleId     the app's bundle id the receipt must carry
     */
    public ReceiptVerifier(Set<X509Certificate> trustedRoots, String bundleId) {
        if (bundleId == null) {
            throw new IllegalArgumentException("bundleId must not be null");
        }
        this.trustAnchors = anchors(trustedRoots);
        this.bundleId = bundleId;
    }

    private static Set<TrustAnchor> anchors(Set<X509Certificate> trustedRoots) {
        if (trustedRoots == null || trustedRoots.isEmpty()) {
            throw new IllegalArgumentException("trustedRoots must not be empty");
        }
        Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();
        for (X509Certificate root : trustedRoots) {
            anchors.add(new TrustAnchor(root, null));
        }
        return anchors;
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
        AppReceipt receipt = verifyCore(receiptDer, trustAnchors);
        if (!bundleId.equals(receipt.bundleId())) {
            throw new VerificationException(Reason.WRONG_BUNDLE_ID,
                    "expected " + bundleId + " but receipt has " + receipt.bundleId());
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
     * checked. Same name and same shape as node's {@code verifyReceiptCore}
     * and python's {@code verify_receipt_core}.</p>
     *
     * <p>The receipt it returns has been proved Apple-signed, but NO claim in
     * it has been checked: the bundle id in particular is whatever the receipt
     * says. A caller unlocking products must compare it itself, or use
     * {@link #verify(byte[])}.</p>
     */
    public static AppReceipt verifyReceiptCore(byte[] receiptDer,
                                               Set<X509Certificate> trustedRoots)
            throws VerificationException {
        return verifyCore(receiptDer, anchors(trustedRoots));
    }

    private static AppReceipt verifyCore(byte[] receiptDer, Set<TrustAnchor> trustAnchors)
            throws VerificationException {
        if (receiptDer == null) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "receipt is null");
        }
        // BouncyCastle's ASN.1 and CMS entry points report malformed input with
        // UNCHECKED exceptions, and which ones is neither documented nor stable
        // across releases, so hostile input is contained by category instead of
        // by type — enumerating the types is exactly what let eleven characters
        // of attacker base64 escape the declared VerificationException contract.
        try {
            return verifyCoreUnguarded(receiptDer, trustAnchors);
        } catch (VerificationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "malformed receipt: " + e, e);
        }
    }

    private static AppReceipt verifyCoreUnguarded(byte[] receiptDer,
                                                  Set<TrustAnchor> trustAnchors)
            throws VerificationException {
        try {
            // Rejects trailing bytes after the CMS blob (PLAN 2.3) - BC's
            // fromByteArray throws when parsing does not exhaust the input.
            ASN1Primitive.fromByteArray(receiptDer);
        } catch (IOException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                    "receipt has trailing or unparseable bytes", e);
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
        // Deliberately the system clock, with no seam to override it: this is
        // a certificate-validity instant, and an injected clock must never be
        // able to move a certificate-validity verdict. The fallback only fires
        // for a receipt carrying no creation date (attribute 12), where
        // PLAN.md §2.2 step 2's "else current time" leaves the window anchored
        // to real time. node, python and swift read the system clock here too.
        Date at = receipt.creationDate() != null
                ? Date.from(receipt.creationDate()) : new Date();

        X509Certificate signerCert = validateChain(cms, at, trustAnchors);
        if (signerCert.getExtensionValue(RECEIPT_SIGNER_OID) == null) {
            throw new VerificationException(Reason.INVALID_CERTIFICATE_PURPOSE,
                    "receipt signer certificate lacks Apple receipt-signing marker OID "
                            + RECEIPT_SIGNER_OID);
        }
        verifyCmsSignature(cms, signerCert);
        return receipt;
    }

    /** PKIX-builds signer → (intermediates from the CMS) → pinned root at {@code at}. */
    private static X509Certificate validateChain(CMSSignedData cms, Date at,
                                                 Set<TrustAnchor> trustAnchors)
            throws VerificationException {
        Iterator<SignerInformation> signers = cms.getSignerInfos().getSigners().iterator();
        if (!signers.hasNext()) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "no signer info");
        }
        SignerInformation signer = signers.next();
        // Bounded here, before a single embedded certificate is decoded or
        // handed to the path builder — all of which an unverified receipt
        // would otherwise get to pay for out of the caller's CPU.
        Collection<X509CertificateHolder> holders = cms.getCertificates().getMatches(null);
        if (holders.size() > MAXIMUM_EMBEDDED_CERTIFICATES) {
            throw new VerificationException(Reason.INVALID_CHAIN, "receipt embeds "
                    + holders.size() + " certificates, more than the maximum of "
                    + MAXIMUM_EMBEDDED_CERTIFICATES);
        }
        Collection<X509CertificateHolder> matches = cms.getCertificates().getMatches(signer.getSID());
        if (matches.isEmpty()) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT, "signer certificate not embedded");
        }
        try {
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            X509Certificate signerCert = converter.getCertificate(matches.iterator().next());
            List<X509Certificate> embedded = new ArrayList<X509Certificate>();
            for (X509CertificateHolder holder : holders) {
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

    private static void verifyCmsSignature(CMSSignedData cms, X509Certificate signerCert)
            throws VerificationException {
        if (!(signerCert.getPublicKey() instanceof java.security.interfaces.RSAPublicKey)) {
            throw new VerificationException(Reason.INVALID_SIGNATURE, "receipt signer key is not RSA");
        }
        try {
            SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
            // Restrict to the digests Apple actually uses for receipts
            // (SHA-1 / SHA-256), matching the other three implementations.
            String digestOid = signer.getDigestAlgOID();
            if (!"1.3.14.3.2.26".equals(digestOid)
                    && !"2.16.840.1.101.3.4.2.1".equals(digestOid)) {
                throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                        "unsupported receipt digest algorithm " + digestOid);
            }
            boolean valid = signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(PROVIDER)
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
        List<InAppPurchase> purchases = new ArrayList<InAppPurchase>();
        Map<Integer, List<byte[]>> unknown = new LinkedHashMap<Integer, List<byte[]>>();

        for (ASN1Encodable element : attributes) {
            Attribute attr = Attribute.of(element);
            switch (attr.type) {
                case ATTR_RECEIPT_TYPE:
                    receiptType = decodeString(attr.value);
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
                    // Undocumented attribute types stay accessible for
                    // forward compatibility (PLAN D10).
                    recordUnknown(unknown, attr);
                    break;
            }
        }
        return new AppReceipt(receiptType, parsedBundleId, bundleIdBytes, appVersion,
                opaqueValue, sha1Hash, creationDate, originalPurchaseDate,
                originalAppVersion, expirationDate, purchases, unknown);
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
                case IAP_IS_IN_INTRO_OFFER_PERIOD:
                    isInIntroOfferPeriod = decodeInteger(attr.value);
                    break;
                default:
                    recordUnknown(unknown, attr);
                    break;
            }
        }
        return new InAppPurchase(quantity, productId, transactionId, originalTransactionId,
                purchaseDate, originalPurchaseDate, expiresDate, cancellationDate,
                webOrderLineItemId, isInIntroOfferPeriod, unknown);
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
                throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                        what + " double-wrap is not valid ASN.1", e);
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
                    throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                            "receipt attribute has " + seq.size() + " fields, expected 3");
                }
                long type = boundedInt(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
                byte[] value = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
                // A type wider than a 32-bit signed integer is not a valid
                // attribute type, so the receipt is rejected rather than
                // reinterpreted. Renaming an unrepresentable type (this used to
                // file it under -1) invents an attribute the receipt never
                // carried, and is how two ports start disagreeing about what a
                // receipt says. Fail closed; node, python and swift agree.
                if (type > Integer.MAX_VALUE) {
                    throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                            "receipt attribute type out of range: " + type);
                }
                return new Attribute((int) type, value);
            } catch (IllegalArgumentException e) {
                throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                        "malformed receipt attribute", e);
            } catch (ArithmeticException e) {
                throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                        "receipt attribute type out of range", e);
            }
        }
    }

    /** Non-negative, <= 8 bytes — real receipts carry 7-byte integers. */
    private static long boundedInt(BigInteger value) throws VerificationException {
        if (value.signum() < 0 || value.bitLength() > 63) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                    "receipt integer out of range");
        }
        return value.longValue();
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
            return Long.valueOf(boundedInt(((ASN1Integer) parsed).getValue()));
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
        Instant instant;
        try {
            instant = Instant.parse(text);
        } catch (DateTimeParseException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                    "unparseable receipt date: " + text, e);
        }
        // Instant.parse accepts expanded years (e.g. +1000000000-...) that no
        // longer fit an epoch-milli long; toEpochMilli overflows on those, and
        // that conversion happens (via Date.from) before verification, so a
        // hostile date is rejected here rather than escaping as an
        // ArithmeticException past the declared VerificationException contract.
        try {
            instant.toEpochMilli();
        } catch (ArithmeticException e) {
            throw new VerificationException(Reason.INVALID_RECEIPT_FORMAT,
                    "receipt date out of representable range: " + text, e);
        }
        return instant;
    }
}
