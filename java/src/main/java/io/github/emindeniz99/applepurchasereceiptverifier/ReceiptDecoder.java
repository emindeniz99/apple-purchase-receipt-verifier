package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.math.BigInteger;
import java.time.LocalDate;
import java.time.Month;
import java.time.Year;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
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
import org.bouncycastle.asn1.ASN1UTF8String;
import org.jspecify.annotations.Nullable;

/**
 * Parses the ASN.1 payload of a legacy receipt, the attribute SET inside the
 * CMS envelope, into a {@link ReceiptPayload}. It checks no signature: before
 * the envelope around it is verified, {@link ReceiptCore} reads only the
 * creation date ({@link #readCreationDate}), and it runs the full
 * {@link #parse} only after the chain and the signature have passed, so every
 * failure {@link #parse} reports is {@link Reason#UNREADABLE_PAYLOAD}.
 *
 * <p>Decode rules, the same in every port: a missing attribute is
 * {@code null}; a date that does not parse is {@code null}; the trial and
 * intro flags are 0 for {@code false} and anything else for {@code true};
 * integers are reported as they are when they fit a signed 64-bit value,
 * negative ones included. A string attribute that is not a UTF8String or
 * IA5String, an integer attribute that is not an INTEGER or does not fit, or
 * an attribute SET that does not parse makes the whole payload
 * unreadable.</p>
 */
final class ReceiptDecoder {

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

    /** The top-level types that fill a typed field. 17 is absent: every copy is a purchase. */
    private static final Set<Integer> TOP_LEVEL = new HashSet<Integer>(Arrays.asList(
            ATTR_RECEIPT_TYPE,
            ATTR_APP_ITEM_ID,
            ATTR_BUNDLE_ID,
            ATTR_APP_VERSION,
            ATTR_OPAQUE_VALUE,
            ATTR_SHA1_HASH,
            ATTR_CREATION_DATE,
            ATTR_DOWNLOAD_ID,
            ATTR_VERSION_EXTERNAL_IDENTIFIER,
            ATTR_ORIGINAL_PURCHASE_DATE,
            ATTR_ORIGINAL_APP_VERSION,
            ATTR_EXPIRATION_DATE));

    /** The in-app types that fill a typed field of {@link InAppPurchase}. */
    private static final Set<Integer> IN_APP = new HashSet<Integer>(Arrays.asList(
            IAP_QUANTITY,
            IAP_PRODUCT_ID,
            IAP_TRANSACTION_ID,
            IAP_PURCHASE_DATE,
            IAP_ORIGINAL_TRANSACTION_ID,
            IAP_ORIGINAL_PURCHASE_DATE,
            IAP_EXPIRES_DATE,
            IAP_WEB_ORDER_LINE_ITEM_ID,
            IAP_CANCELLATION_DATE,
            IAP_IS_TRIAL_PERIOD,
            IAP_IS_IN_INTRO_OFFER_PERIOD));

    private ReceiptDecoder() {}

    /**
     * The receipt creation date (attribute 12), read the only way anything in
     * a payload is read before its signer is trusted: the top-level attribute
     * SET is walked shallowly, each entry's type is read, and only the value
     * of type 12 is decoded.
     *
     * <p>The first attribute 12 decides, as it does for the typed field.
     * {@code null} means "judge the chain at the clock": no attribute 12, a
     * first one that is empty or does not decode, or a walk that fails
     * anywhere. An entry the walk cannot read fails it as a whole rather than
     * being skipped, since that entry might have been the first attribute 12.
     * Never throws: nothing is trusted yet, so nothing here can blame
     * anyone.</p>
     */
    static @Nullable Long readCreationDate(byte[] payload) {
        try {
            byte[] date = null;
            for (ASN1Encodable element : parseAttributeSet(payload, "receipt payload")) {
                Attribute attr = Attribute.of(element);
                if (attr.type == ATTR_CREATION_DATE && date == null) {
                    date = attr.value;
                }
            }
            return date != null ? decodeDate(date) : null;
        } catch (VerificationException | RuntimeException e) {
            return null;
        }
    }

    static ReceiptPayload parse(byte[] payload) throws VerificationException {
        ASN1Set attributes = parseAttributeSet(payload, "receipt payload");
        String receiptType = null;
        String parsedBundleId = null;
        byte[] bundleIdBytes = null;
        String appVersion = null;
        byte[] opaqueValue = null;
        byte[] sha1Hash = null;
        Long creationDate = null;
        Long originalPurchaseDate = null;
        String originalAppVersion = null;
        Long expirationDate = null;
        Long appItemId = null;
        Long downloadId = null;
        Long versionExternalIdentifier = null;
        List<InAppPurchase> purchases = new ArrayList<InAppPurchase>();
        Map<Integer, List<byte[]>> unknown = new LinkedHashMap<Integer, List<byte[]>>();

        Set<Integer> seen = new HashSet<Integer>();
        for (ASN1Encodable element : attributes) {
            Attribute attr = Attribute.of(element);
            if (isLaterCopy(attr.type, TOP_LEVEL, seen)) {
                recordUnknown(unknown, attr);
                continue;
            }
            try {
                switch (attr.type) {
                    case ATTR_RECEIPT_TYPE:
                        receiptType = decodeString(attr.value);
                        break;
                    case ATTR_APP_ITEM_ID:
                        appItemId = decodeInteger(attr.value);
                        break;
                    case ATTR_ORIGINAL_PURCHASE_DATE:
                        originalPurchaseDate = date(attr.value);
                        break;
                    case ATTR_BUNDLE_ID:
                        // The raw octets are a typed field of their own, so they
                        // are kept even when the string does not decode.
                        bundleIdBytes = attr.value;
                        parsedBundleId = decodeBundleId(attr.value);
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
                        creationDate = date(attr.value);
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
                        expirationDate = date(attr.value);
                        break;
                    default:
                        // Undocumented attribute types stay accessible, so a
                        // field Apple adds later is not lost.
                        recordUnknown(unknown, attr);
                        break;
                }
            } catch (VerificationException e) {
                // A known attribute whose value does not decode: its typed
                // field stays null and the value is kept raw, so nothing
                // Apple signed is lost.
                recordUnknown(unknown, attr);
            }
        }
        return new ReceiptPayload(
                receiptType,
                appItemId,
                parsedBundleId,
                bundleIdBytes,
                appVersion,
                opaqueValue,
                sha1Hash,
                creationDate,
                downloadId,
                versionExternalIdentifier,
                purchases,
                originalPurchaseDate,
                originalAppVersion,
                expirationDate,
                RawAttributes.wrap(unknown),
                true);
    }

    private static InAppPurchase parseInApp(byte[] inAppSet) throws VerificationException {
        ASN1Set attributes = parseAttributeSet(inAppSet, "in-app purchase attribute");
        Long quantity = null;
        String productId = null;
        String transactionId = null;
        String originalTransactionId = null;
        Long purchaseDate = null;
        Long originalPurchaseDate = null;
        Long expiresDate = null;
        Long cancellationDate = null;
        Long webOrderLineItemId = null;
        Boolean isTrialPeriod = null;
        Boolean isInIntroOfferPeriod = null;
        Map<Integer, List<byte[]>> unknown = new LinkedHashMap<Integer, List<byte[]>>();

        Set<Integer> seen = new HashSet<Integer>();
        for (ASN1Encodable element : attributes) {
            Attribute attr = Attribute.of(element);
            if (isLaterCopy(attr.type, IN_APP, seen)) {
                recordUnknown(unknown, attr);
                continue;
            }
            try {
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
                        purchaseDate = date(attr.value);
                        break;
                    case IAP_ORIGINAL_TRANSACTION_ID:
                        originalTransactionId = decodeString(attr.value);
                        break;
                    case IAP_ORIGINAL_PURCHASE_DATE:
                        originalPurchaseDate = date(attr.value);
                        break;
                    case IAP_EXPIRES_DATE:
                        expiresDate = date(attr.value);
                        break;
                    case IAP_WEB_ORDER_LINE_ITEM_ID:
                        webOrderLineItemId = decodeInteger(attr.value);
                        break;
                    case IAP_CANCELLATION_DATE:
                        cancellationDate = date(attr.value);
                        break;
                    case IAP_IS_TRIAL_PERIOD:
                        isTrialPeriod = decodeFlag(attr.value);
                        break;
                    case IAP_IS_IN_INTRO_OFFER_PERIOD:
                        isInIntroOfferPeriod = decodeFlag(attr.value);
                        break;
                    default:
                        recordUnknown(unknown, attr);
                        break;
                }
            } catch (VerificationException e) {
                recordUnknown(unknown, attr);
            }
        }
        return new InAppPurchase(
                quantity,
                productId,
                transactionId,
                purchaseDate,
                originalTransactionId,
                originalPurchaseDate,
                expiresDate,
                webOrderLineItemId,
                cancellationDate,
                isTrialPeriod,
                isInIntroOfferPeriod,
                RawAttributes.wrap(unknown),
                true);
    }

    /**
     * Whether {@code type} is a known attribute already seen in this SET. The
     * first copy decides the typed field; a later one is kept raw. Attribute
     * 17 is not covered: every copy of it is one in-app purchase.
     */
    private static boolean isLaterCopy(int type, Set<Integer> known, Set<Integer> seen) {
        return known.contains(type) && !seen.add(type);
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
        requireDepth(der, what);
        ASN1Primitive parsed;
        try {
            parsed = ASN1Primitive.fromByteArray(der);
        } catch (IOException e) {
            throw new VerificationException(Reason.UNREADABLE_PAYLOAD, what + " is not valid ASN.1", e);
        }
        if (parsed instanceof ASN1OctetString) {
            // Xcode receipts double-wrap the payload in an extra OCTET
            // STRING (upstream receipt_utility handles the same shape).
            byte[] inner = ((ASN1OctetString) parsed).getOctets();
            requireDepth(inner, what);
            try {
                parsed = ASN1Primitive.fromByteArray(inner);
            } catch (IOException e) {
                throw new VerificationException(Reason.UNREADABLE_PAYLOAD, what + " double-wrap is not valid ASN.1", e);
            }
        }
        if (!(parsed instanceof ASN1Set)) {
            throw new VerificationException(Reason.UNREADABLE_PAYLOAD, what + " is not an ASN.1 SET");
        }
        return (ASN1Set) parsed;
    }

    private static void requireDepth(byte[] der, String what) throws VerificationException {
        if (Asn1Depth.exceeded(der)) {
            throw new VerificationException(
                    Reason.UNREADABLE_PAYLOAD, what + " nests ASN.1 deeper than " + Asn1Depth.MAX_DEPTH + " values");
        }
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
                // purpose, so a field Apple appends later does not break
                // parsing.
                if (seq.size() < 3) {
                    throw new VerificationException(
                            Reason.UNREADABLE_PAYLOAD, "receipt attribute has " + seq.size() + " fields, expected 3");
                }
                int type = attributeType(
                        ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
                byte[] value = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
                return new Attribute(type, value);
            } catch (IllegalArgumentException e) {
                throw new VerificationException(Reason.UNREADABLE_PAYLOAD, "malformed receipt attribute", e);
            }
        }
    }

    /**
     * An attribute type: non-negative and at most {@link Integer#MAX_VALUE}.
     * A wider type is refused rather than narrowed: narrowing invents an
     * attribute the receipt never carried.
     */
    private static int attributeType(BigInteger value) throws VerificationException {
        if (value.signum() < 0 || value.bitLength() > 31) {
            throw new VerificationException(Reason.UNREADABLE_PAYLOAD, "receipt attribute type out of range");
        }
        return value.intValue();
    }

    /**
     * A UTF8String or an IA5String, the two string types Apple's receipts
     * use. Any other
     * {@link ASN1String} (a BIT STRING or UniversalString included) is
     * refused rather than rendered through {@code getString()}.
     *
     * <p>BouncyCastle reports bytes that are not UTF-8 with an unchecked
     * exception, so it is caught here and becomes the same checked failure
     * as any other undecodable value: the caller then keeps that one
     * attribute raw, top level and in-app alike, instead of failing the
     * whole payload.</p>
     */
    private static String decodeString(byte[] der) throws VerificationException {
        try {
            ASN1Primitive parsed = ASN1Primitive.fromByteArray(der);
            if (parsed instanceof ASN1IA5String) {
                // IA5 is seven-bit: a byte from 0x80 up is no IA5 character,
                // and is not read as Latin-1 either (owner, 2026-09-27, Q23).
                for (byte octet : ((ASN1IA5String) parsed).getOctets()) {
                    if (octet < 0) {
                        throw new VerificationException(
                                Reason.UNREADABLE_PAYLOAD, "IA5String attribute value is not seven-bit");
                    }
                }
            } else if (!(parsed instanceof ASN1UTF8String)) {
                throw new VerificationException(
                        Reason.UNREADABLE_PAYLOAD, "attribute value is not a UTF8String or IA5String");
            }
            return ((ASN1String) parsed).getString();
        } catch (IOException e) {
            throw new VerificationException(Reason.UNREADABLE_PAYLOAD, "attribute value is not valid ASN.1", e);
        } catch (RuntimeException e) {
            throw new VerificationException(Reason.UNREADABLE_PAYLOAD, "attribute value does not decode as a string", e);
        }
    }

    /**
     * An INTEGER that fits a signed 64-bit value, reported as it is, negative
     * values included: the decoder reports what the receipt carries. Real
     * receipts carry up to 7-byte integers.
     */
    private static Long decodeInteger(byte[] der) throws VerificationException {
        try {
            ASN1Primitive parsed = ASN1Primitive.fromByteArray(der);
            if (!(parsed instanceof ASN1Integer)) {
                throw new VerificationException(Reason.UNREADABLE_PAYLOAD, "attribute value is not an ASN.1 integer");
            }
            BigInteger value = ((ASN1Integer) parsed).getValue();
            if (value.bitLength() > 63) {
                throw new VerificationException(Reason.UNREADABLE_PAYLOAD, "receipt integer out of range");
            }
            return Long.valueOf(value.longValue());
        } catch (IOException e) {
            throw new VerificationException(Reason.UNREADABLE_PAYLOAD, "attribute value is not valid ASN.1", e);
        } catch (RuntimeException e) {
            // BouncyCastle refuses a malformed INTEGER (one not minimally
            // encoded, say) with an unchecked exception: that one attribute
            // is kept raw, as for a string that does not decode.
            throw new VerificationException(Reason.UNREADABLE_PAYLOAD, "attribute value is not a valid integer", e);
        }
    }

    /** An INTEGER flag: 0 is {@code false}, any other value {@code true}. */
    private static Boolean decodeFlag(byte[] der) throws VerificationException {
        return Boolean.valueOf(decodeInteger(der).longValue() != 0);
    }

    /**
     * A date in an IA5String or UTF8String, as epoch milliseconds, or
     * {@code null} when empty (Apple writes an unset date that way, so it is
     * not kept raw). Anything else must be exactly
     * {@code YYYY-MM-DDTHH:MM:SSZ} (see {@link #parseDate}); a value that is
     * not throws, and the caller keeps it raw.
     */
    private static @Nullable Long date(byte[] der) throws VerificationException {
        String text = decodeString(der);
        if (text.isEmpty()) {
            return null;
        }
        Long millis = parseDate(text);
        if (millis == null) {
            throw new VerificationException(
                    Reason.UNREADABLE_PAYLOAD, "attribute value is not a YYYY-MM-DDTHH:MM:SSZ date");
        }
        return millis;
    }

    /**
     * Exactly {@code YYYY-MM-DDTHH:MM:SSZ} and nothing else (owner,
     * 2026-09-27, Q20a): a four-digit year from 0000 to 9999, uppercase
     * {@code T} and {@code Z}, a day that exists in its month, hour 00 to
     * 23, minute and second 00 to 59; no fraction, no offset, no leap
     * second. Checked by hand rather than by {@code Instant.parse}, whose
     * grammar is wider and has moved between JDKs, so every port reads one
     * receipt the same way. Null when {@code text} is not in that form.
     */
    static @Nullable Long parseDate(String text) {
        if (text.length() != 20
                || text.charAt(4) != '-'
                || text.charAt(7) != '-'
                || text.charAt(10) != 'T'
                || text.charAt(13) != ':'
                || text.charAt(16) != ':'
                || text.charAt(19) != 'Z') {
            return null;
        }
        int year = digits(text, 0, 4);
        int month = digits(text, 5, 2);
        int day = digits(text, 8, 2);
        int hour = digits(text, 11, 2);
        int minute = digits(text, 14, 2);
        int second = digits(text, 17, 2);
        if (year < 0 || month < 1 || month > 12 || day < 1 || hour < 0 || hour > 23
                || minute < 0 || minute > 59 || second < 0 || second > 59) {
            return null;
        }
        if (day > Month.of(month).length(Year.isLeap(year))) {
            return null;
        }
        long days = LocalDate.of(year, month, day).toEpochDay();
        return Long.valueOf(((days * 24 + hour) * 60 + minute) * 60_000L + second * 1000L);
    }

    /** The decimal value of {@code length} ASCII digits at {@code from}, or -1 if any is not one. */
    private static int digits(String text, int from, int length) {
        int value = 0;
        for (int i = from; i < from + length; i++) {
            char c = text.charAt(i);
            if (c < '0' || c > '9') {
                return -1;
            }
            value = value * 10 + (c - '0');
        }
        return value;
    }

    /** {@link #date}, with {@code null} for anything that does not parse. */
    private static @Nullable Long decodeDate(byte[] der) {
        try {
            return date(der);
        } catch (VerificationException | RuntimeException e) {
            return null;
        }
    }

    /** The bundle id string, or {@code null} when it does not decode; its octets are kept either way. */
    private static @Nullable String decodeBundleId(byte[] der) {
        try {
            return decodeString(der);
        } catch (VerificationException | RuntimeException e) {
            return null;
        }
    }
}
