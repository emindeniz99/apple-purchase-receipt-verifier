package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.internal.SafeText;
import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.jspecify.annotations.Nullable;

/**
 * Parses the ASN.1 payload of a legacy receipt, the attribute SET inside the
 * CMS envelope, into an {@link AppReceipt}. It checks no signature: before the
 * envelope around it is verified, {@link ReceiptVerifier} reads only the
 * creation date ({@link #readCreationDate}), and it runs the full
 * {@link #parse} only after the chain and the signature have passed.
 */
final class ReceiptPayload {

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

    private ReceiptPayload() {}

    /**
     * The receipt creation date (attribute 12), read the only way anything in
     * a payload is read before its signer is trusted: the top-level attribute
     * SET is walked shallowly, each entry's type is read, and only the value
     * of type 12 is decoded.
     *
     * <p>{@code null} means "judge the chain at now": no attribute 12, an
     * empty one, one that does not decode, more than one, or a walk that
     * fails anywhere. An entry the walk cannot read fails it as a whole rather
     * than being skipped, since that entry might have been a second attribute
     * 12. Never throws: nothing is trusted yet, so nothing here can blame
     * anyone.</p>
     */
    static @Nullable Instant readCreationDate(byte[] payload) {
        try {
            byte[] date = null;
            int dates = 0;
            for (ASN1Encodable element : parseAttributeSet(payload, "receipt payload")) {
                Attribute attr = Attribute.of(element);
                if (attr.type == ATTR_CREATION_DATE) {
                    dates++;
                    date = attr.value;
                }
            }
            return dates == 1 && date != null ? decodeDate(date) : null;
        } catch (VerificationException | RuntimeException e) {
            return null;
        }
    }

    static AppReceipt parse(byte[] payload) throws VerificationException {
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
                // Fields beyond type, version and value are tolerated on
                // purpose, as in the node and swift ports, so a field Apple
                // appends later does not break parsing.
                if (seq.size() < 3) {
                    throw new VerificationException(
                            Reason.INVALID_RECEIPT_FORMAT,
                            "receipt attribute has " + seq.size() + " fields, expected 3");
                }
                long type = nonNegativeLong(
                        ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
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

    /**
     * The value as a long: non-negative and at most 63 bits, else the receipt
     * is refused. Real receipts carry 7-byte integers.
     */
    private static long nonNegativeLong(BigInteger value) throws VerificationException {
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
            return Long.valueOf(nonNegativeLong(((ASN1Integer) parsed).getValue()));
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
