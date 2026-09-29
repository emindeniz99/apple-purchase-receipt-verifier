package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.math.BigInteger;
import java.time.DateTimeException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.ResolverStyle;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
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
 * The receipt payload, the attribute SET inside the CMS envelope, as a
 * {@link ReceiptPayload}, by the decode rules of docs/design/0.7-api.md.
 * Before the signature only {@link #readCreationDate} runs; every failure of
 * {@link #parse} is {@link Reason#UNREADABLE_PAYLOAD}.
 */
final class ReceiptDecoder {

    // Where each type comes from, 0, 1, 15, 16, 18 and 1713 included, is in RECEIPT-FIELDS.md.
    private static final int ATTR_RECEIPT_TYPE = 0;
    private static final int ATTR_APP_ITEM_ID = 1;
    private static final int ATTR_BUNDLE_ID = 2;
    private static final int ATTR_APP_VERSION = 3;
    private static final int ATTR_OPAQUE_VALUE = 4;
    private static final int ATTR_SHA1_HASH = 5;
    private static final int ATTR_CREATION_DATE = 12;
    private static final int ATTR_DOWNLOAD_ID = 15;
    private static final int ATTR_VERSION_EXTERNAL_IDENTIFIER = 16;
    private static final int ATTR_IN_APP = 17;
    private static final int ATTR_ORIGINAL_PURCHASE_DATE = 18;
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

    /** The top-level types that fill a typed field. */
    private static final Set<Integer> TOP_LEVEL = new HashSet<>(Arrays.asList(
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
    private static final Set<Integer> IN_APP = new HashSet<>(Arrays.asList(
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

    private static final DateTimeFormatter RECEIPT_DATE =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss'Z'").withResolverStyle(ResolverStyle.STRICT);

    private ReceiptDecoder() {}

    /**
     * The first attribute 12, or null ("judge the chain at the clock") when
     * it is missing or does not decode, or when any entry does not read,
     * since that entry might have been the first 12. Never throws.
     */
    static @Nullable Long readCreationDate(byte[] payload) {
        try {
            byte[] date =
                    readAttributes(payload, "receipt payload", TOP_LEVEL).firsts.get(ATTR_CREATION_DATE);
            return date != null ? decodeDate(date) : null;
        } catch (VerificationException | RuntimeException e) {
            return null;
        }
    }

    static ReceiptPayload parse(byte[] payload) throws VerificationException {
        Attributes attributes = readAttributes(payload, "receipt payload", TOP_LEVEL);
        // 17 is not in TOP_LEVEL: every copy is one purchase, and one that
        // does not parse is kept raw.
        List<InAppPurchase> purchases = new ArrayList<>();
        List<byte[]> inApp = attributes.unknown.remove(ATTR_IN_APP);
        if (inApp != null) {
            for (byte[] purchase : inApp) {
                try {
                    purchases.add(parseInApp(purchase));
                } catch (VerificationException e) {
                    attributes
                            .unknown
                            .computeIfAbsent(ATTR_IN_APP, type -> new ArrayList<>())
                            .add(purchase);
                }
            }
        }
        // The raw octets are a typed field of their own, kept even when the
        // string does not decode, so they are not also kept raw.
        byte[] bundleIdBytes = attributes.firsts.get(ATTR_BUNDLE_ID);
        return new ReceiptPayload(
                attributes.string(ATTR_RECEIPT_TYPE),
                attributes.integer(ATTR_APP_ITEM_ID),
                bundleIdBytes != null ? decodeBundleId(bundleIdBytes) : null,
                bundleIdBytes,
                attributes.string(ATTR_APP_VERSION),
                attributes.firsts.get(ATTR_OPAQUE_VALUE),
                attributes.firsts.get(ATTR_SHA1_HASH),
                attributes.date(ATTR_CREATION_DATE),
                attributes.integer(ATTR_DOWNLOAD_ID),
                attributes.integer(ATTR_VERSION_EXTERNAL_IDENTIFIER),
                purchases,
                attributes.date(ATTR_ORIGINAL_PURCHASE_DATE),
                attributes.string(ATTR_ORIGINAL_APP_VERSION),
                attributes.date(ATTR_EXPIRATION_DATE),
                attributes.unknown);
    }

    private static InAppPurchase parseInApp(byte[] inAppSet) throws VerificationException {
        Attributes attributes = readAttributes(inAppSet, "in-app purchase attribute", IN_APP);
        return new InAppPurchase(
                attributes.integer(IAP_QUANTITY),
                attributes.string(IAP_PRODUCT_ID),
                attributes.string(IAP_TRANSACTION_ID),
                attributes.date(IAP_PURCHASE_DATE),
                attributes.string(IAP_ORIGINAL_TRANSACTION_ID),
                attributes.date(IAP_ORIGINAL_PURCHASE_DATE),
                attributes.date(IAP_EXPIRES_DATE),
                attributes.integer(IAP_WEB_ORDER_LINE_ITEM_ID),
                attributes.date(IAP_CANCELLATION_DATE),
                attributes.flag(IAP_IS_TRIAL_PERIOD),
                attributes.flag(IAP_IS_IN_INTRO_OFFER_PERIOD),
                attributes.unknown);
    }

    /**
     * One attribute SET: the first value of each type in {@code known}, and
     * every other value raw, by type in ascending order, each type's values
     * in receipt order. The typed getters move a first value that does not
     * decode to the front of its raw list, where receipt order puts it.
     */
    private static Attributes readAttributes(byte[] der, String what, Set<Integer> known) throws VerificationException {
        Attributes attributes = new Attributes();
        // ReceiptAttribute ::= SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING }
        for (ASN1Encodable element : parseAttributeSet(der, what)) {
            int type;
            byte[] value;
            try {
                ASN1Sequence seq = ASN1Sequence.getInstance(element);
                // More than three fields is tolerated, for a field Apple appends later.
                if (seq.size() < 3) {
                    throw new VerificationException(
                            Reason.UNREADABLE_PAYLOAD,
                            "receipt attribute has " + seq.size() + " fields, expected at least 3");
                }
                BigInteger rawType = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
                // 0 to Integer.MAX_VALUE; a wider type is refused, since narrowing would invent one.
                if (rawType.signum() < 0 || rawType.bitLength() > 31) {
                    throw new VerificationException(Reason.UNREADABLE_PAYLOAD, "receipt attribute type out of range");
                }
                type = rawType.intValue();
                value = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
            } catch (IllegalArgumentException e) {
                throw new VerificationException(Reason.UNREADABLE_PAYLOAD, "malformed receipt attribute", e);
            }
            if (!known.contains(type) || attributes.firsts.containsKey(type)) {
                attributes.unknown.computeIfAbsent(type, t -> new ArrayList<>()).add(value);
            } else {
                attributes.firsts.put(type, value);
            }
        }
        return attributes;
    }

    private static final class Attributes {
        final Map<Integer, byte[]> firsts = new HashMap<>();
        final Map<Integer, List<byte[]>> unknown = new TreeMap<>();

        @Nullable
        String string(int type) {
            return typed(type, ReceiptDecoder::decodeString);
        }

        @Nullable
        Long integer(int type) {
            return typed(type, ReceiptDecoder::decodeInteger);
        }

        @Nullable
        Long date(int type) {
            return typed(type, ReceiptDecoder::decodeDate);
        }

        /** An INTEGER flag: 0 is {@code false}, any other value {@code true}. */
        @Nullable
        Boolean flag(int type) {
            Long value = integer(type);
            return value != null ? value != 0 : null;
        }

        /** The first value decoded, or null when absent; one that does not decode is kept raw. */
        private <T> @Nullable T typed(int type, Decoder<T> decoder) {
            byte[] value = firsts.get(type);
            if (value == null) {
                return null;
            }
            try {
                return decoder.decode(value);
            } catch (VerificationException e) {
                unknown.computeIfAbsent(type, t -> new ArrayList<>()).add(0, value);
                return null;
            }
        }
    }

    private interface Decoder<T> {
        @Nullable
        T decode(byte[] der) throws VerificationException;
    }

    private static ASN1Set parseAttributeSet(byte[] der, String what) throws VerificationException {
        requireDepth(der, what);
        ASN1Primitive parsed;
        try {
            parsed = ASN1Primitive.fromByteArray(ConstructedStrings.joined(der));
        } catch (IOException | RuntimeException e) {
            // BouncyCastle's indefinite-length path refuses some values unchecked.
            throw new VerificationException(Reason.UNREADABLE_PAYLOAD, what + " is not valid ASN.1", e);
        }
        if (parsed instanceof ASN1OctetString) {
            // Xcode receipts wrap the payload in one more OCTET STRING.
            byte[] inner = ((ASN1OctetString) parsed).getOctets();
            requireDepth(inner, what);
            try {
                parsed = ASN1Primitive.fromByteArray(ConstructedStrings.joined(inner));
            } catch (IOException | RuntimeException e) {
                throw new VerificationException(Reason.UNREADABLE_PAYLOAD, what + " double-wrap is not valid ASN.1", e);
            }
        }
        if (!(parsed instanceof ASN1Set)) {
            throw new VerificationException(Reason.UNREADABLE_PAYLOAD, what + " is not an ASN.1 SET");
        }
        return (ASN1Set) parsed;
    }

    /**
     * A value whose length takes more than four octets is not read: DER
     * needs one, 0.7 read at most four, and BouncyCastle reads more.
     * With a multi-octet tag the value is no string or INTEGER anyway.
     */
    private static void requireShortLength(byte[] der) throws VerificationException {
        if (der.length > 1 && (der[0] & 0x1F) != 0x1F && (der[1] & 0xFF) > 0x84) {
            throw new VerificationException(
                    Reason.UNREADABLE_PAYLOAD, "attribute value length takes more than four octets");
        }
    }

    private static void requireDepth(byte[] der, String what) throws VerificationException {
        if (Asn1Depth.exceeded(der)) {
            throw new VerificationException(
                    Reason.UNREADABLE_PAYLOAD, what + " nests ASN.1 deeper than " + Asn1Depth.MAX_DEPTH + " values");
        }
        if (Asn1Depth.stringNestExceeded(der)) {
            throw new VerificationException(
                    Reason.UNREADABLE_PAYLOAD,
                    what + " nests a constructed string deeper than " + Asn1Depth.MAX_STRING_NEST + " levels");
        }
    }

    /**
     * A UTF8String or a seven-bit IA5String, the two types Apple uses; any
     * other {@link ASN1String} is refused rather than rendered.
     */
    private static String decodeString(byte[] der) throws VerificationException {
        // A nested encoding inside an OCTET STRING, which the payload's own depth walk did not enter.
        requireDepth(der, "attribute value");
        requireShortLength(der);
        try {
            ASN1Primitive parsed = ASN1Primitive.fromByteArray(der);
            if (parsed instanceof ASN1IA5String) {
                // BouncyCastle does not check this; it would read the byte as Latin-1.
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
            throw new VerificationException(
                    Reason.UNREADABLE_PAYLOAD, "attribute value does not decode as a string", e);
        }
    }

    /** An INTEGER that fits a long, negative values included. */
    private static Long decodeInteger(byte[] der) throws VerificationException {
        requireDepth(der, "attribute value");
        requireShortLength(der);
        try {
            ASN1Primitive parsed = ASN1Primitive.fromByteArray(der);
            if (!(parsed instanceof ASN1Integer)) {
                throw new VerificationException(Reason.UNREADABLE_PAYLOAD, "attribute value is not an ASN.1 integer");
            }
            BigInteger value = ((ASN1Integer) parsed).getValue();
            if (value.bitLength() > 63) {
                throw new VerificationException(Reason.UNREADABLE_PAYLOAD, "receipt integer out of range");
            }
            return value.longValue();
        } catch (IOException e) {
            throw new VerificationException(Reason.UNREADABLE_PAYLOAD, "attribute value is not valid ASN.1", e);
        } catch (RuntimeException e) {
            // BouncyCastle refuses a non-DER INTEGER with an unchecked exception.
            throw new VerificationException(Reason.UNREADABLE_PAYLOAD, "attribute value is not a valid integer", e);
        }
    }

    /** Epoch milliseconds, or null for an empty string, which is how Apple writes "not set". */
    private static @Nullable Long decodeDate(byte[] der) throws VerificationException {
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
     * Exactly {@code YYYY-MM-DDTHH:MM:SSZ}: a year from 0000 to 9999, a real
     * calendar date, hours 00 to 23, minutes and seconds 00 to 59, uppercase
     * {@code T} and {@code Z}, nothing else. Null when {@code text} is not in
     * that form.
     */
    static @Nullable Long parseDate(String text) {
        // uuuu also reads a signed or five-digit year; the accepted form is 20 characters.
        if (text.length() != 20) {
            return null;
        }
        try {
            return LocalDateTime.parse(text, RECEIPT_DATE).toEpochSecond(ZoneOffset.UTC) * 1000;
        } catch (DateTimeException e) {
            return null;
        }
    }

    /** The bundle id string, or {@code null} when it does not decode; its octets are kept either way. */
    private static @Nullable String decodeBundleId(byte[] der) {
        try {
            return decodeString(der);
        } catch (VerificationException e) {
            return null;
        }
    }
}
