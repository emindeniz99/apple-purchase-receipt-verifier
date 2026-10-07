package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.cert.TrustAnchor;
import java.util.Collections;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.junit.jupiter.api.Test;

/**
 * The decoder on payloads written here, rather than signed: what a value that
 * does not decode costs. One attribute, never the receipt, so an app server
 * still sees every purchase Apple signed.
 */
class ReceiptDecoderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** A UTF8String whose content is not UTF-8: a lead byte, then no continuation. */
    private static final byte[] NOT_UTF8 = {0x0C, 0x02, (byte) 0xC3, 0x28};

    @Test
    void aStringThatIsNotUtf8IsKeptRawTopLevelAndInApp() throws Exception {
        byte[] inApp = set(attribute(1702, NOT_UTF8), attribute(1703, new DERUTF8String("1000").getEncoded()));
        byte[] payload = set(attribute(3, NOT_UTF8), attribute(17, inApp));

        ReceiptPayload receipt = ReceiptDecoder.parse(payload);

        assertNull(receipt.applicationVersion());
        assertArrayEquals(NOT_UTF8, receipt.unknownAttributes().get(3).get(0));
        assertEquals(1, receipt.inApp().size());
        InAppPurchase purchase = receipt.inApp().get(0);
        assertNull(purchase.productId());
        assertArrayEquals(NOT_UTF8, purchase.unknownAttributes().get(1702).get(0));
        // The attribute next to it is untouched.
        assertEquals("1000", purchase.transactionId());
    }

    /** IA5 is seven-bit (owner, 2026-09-27, Q23): a byte from 0x80 up is not read as Latin-1. */
    @Test
    void anIa5StringWithAByteFrom0x80UpIsKeptRaw() throws Exception {
        byte[] notIa5 = {0x16, 0x04, 'c', 'a', 'f', (byte) 0xE9};
        byte[] inApp = set(attribute(1702, notIa5));
        ReceiptPayload receipt = ReceiptDecoder.parse(set(attribute(3, notIa5), attribute(17, inApp)));
        assertNull(receipt.applicationVersion());
        assertArrayEquals(notIa5, receipt.unknownAttributes().get(3).get(0));
        assertNull(receipt.inApp().get(0).productId());
        assertArrayEquals(
                notIa5, receipt.inApp().get(0).unknownAttributes().get(1702).get(0));
        // Seven-bit text, DEL included, still decodes.
        byte[] ascii = {0x16, 0x04, '1', '.', '0', 0x7F};
        assertEquals("1.0\u007f", ReceiptDecoder.parse(set(attribute(3, ascii))).applicationVersion());
    }

    /**
     * BouncyCastle refuses an INTEGER that is not minimally encoded with an
     * unchecked exception; that one attribute is kept raw, as a string that
     * does not decode is, for plain integers and flags alike.
     */
    @Test
    void anIntegerOrFlagThatIsNotMinimallyEncodedIsKeptRaw() throws Exception {
        byte[] padded = {0x02, 0x02, 0x00, 0x01};
        byte[] inApp = set(attribute(1713, padded), attribute(1701, padded));
        ReceiptPayload receipt = ReceiptDecoder.parse(set(attribute(1, padded), attribute(17, inApp)));
        assertNull(receipt.appItemId());
        assertArrayEquals(padded, receipt.unknownAttributes().get(1).get(0));
        InAppPurchase purchase = receipt.inApp().get(0);
        assertNull(purchase.isTrialPeriod());
        assertNull(purchase.quantity());
        assertArrayEquals(padded, purchase.unknownAttributes().get(1713).get(0));
        assertArrayEquals(padded, purchase.unknownAttributes().get(1701).get(0));
    }

    /**
     * An in-app SET that BouncyCastle refuses with an unchecked exception
     * costs that one purchase, kept raw, not the receipt. Here an
     * indefinite-length SET holds a BIT STRING claiming a pad bit with no
     * data byte, which BouncyCastle 1.86 rejects with an
     * IllegalArgumentException that its definite-length path would wrap.
     */
    @Test
    void anInAppSetThatBouncyCastleRefusesUncheckedIsKeptRaw() throws Exception {
        byte[] refused = {0x31, (byte) 0x80, 0x03, 0x01, 0x01, 0x00, 0x00};
        byte[] good = set(attribute(1703, new DERUTF8String("1000").getEncoded()));
        byte[] payload =
                set(attribute(3, new DERUTF8String("1.0").getEncoded()), attribute(17, refused), attribute(17, good));

        ReceiptPayload receipt = ReceiptDecoder.parse(payload);

        assertEquals("1.0", receipt.applicationVersion());
        assertEquals(1, receipt.inApp().size());
        assertEquals("1000", receipt.inApp().get(0).transactionId());
        assertEquals(1, receipt.unknownAttributes().get(17).size());
        assertArrayEquals(refused, receipt.unknownAttributes().get(17).get(0));
    }

    /**
     * A receipt date is an RFC 3339 date-time (owner, Q68, 2026-10-06,
     * widening the 2026-09-27 grammar), at every edge of it; the same
     * vectors as the core's {@code rust/tests/datetime.rs}.
     */
    @Test
    void aReceiptDateIsAnRfc3339DateTime() {
        long noon = 1_722_945_600_000L; // 2024-08-06T12:00:00Z
        Object[][] accepted = {
            {"2024-08-06T12:00:00Z", noon},
            {"0000-01-01T00:00:00Z", -62_167_219_200_000L},
            {"9999-12-31T23:59:59Z", 253_402_300_799_000L},
            {"9999-12-31T23:59:59.999999Z", 253_402_300_799_999L},
            {"2024-08-06t12:00:00z", noon},
            {"2024-08-06T12:00:00.000Z", noon},
            {"2024-08-06T12:00:00.5Z", noon + 500},
            {"2024-08-06T12:00:00.123456789012Z", noon + 123},
            {"2024-08-06T12:00:00.9999Z", noon + 999},
            {"2024-08-06T12:00:00+00:00", noon},
            {"2024-08-06T12:00:00-00:00", noon},
            {"2024-08-06T05:00:00-07:00", noon},
            {"2024-08-06T17:30:00+05:30", noon},
            {"2024-08-07T11:59:00+23:59", noon},
            {"2016-12-31T23:59:60Z", 1_483_228_799_000L},
            {"2016-12-31T15:59:60.5-08:00", 1_483_228_799_500L},
            {"0000-01-01T00:00:00.5Z", -62_167_219_199_500L},
            {"0000-01-01T01:00:00+01:00", -62_167_219_200_000L},
            {"1969-12-31T23:59:59.999Z", -1L},
        };
        for (Object[] vector : accepted) {
            assertEquals(vector[1], ReceiptDecoder.parseDate((String) vector[0]), (String) vector[0]);
        }
        assertNotNull(ReceiptDecoder.parseDate("2024-02-29T00:00:00Z"));
        assertNotNull(ReceiptDecoder.parseDate("2000-02-29T00:00:00Z"));
        assertNotNull(ReceiptDecoder.parseDate("0000-02-29T00:00:00Z"), "0000 is a leap year");
        String[] refused = {
            "2024-08-06T12:00:00",
            "2024-08-06T12:00Z",
            "2024-08-06T12:00:00.Z",
            "2024-08-06T12:00:00,5Z",
            "2024-08-06T12:00:00.5",
            "2024-08-06T12:00:00ZZ",
            "2024-08-06T12:00:00+24:00",
            "2024-08-06T12:00:00+03:60",
            "2024-08-06T12:00:00+0300",
            "2024-08-06T12:00:00+03",
            "2024-08-06T12:00:00+03:00:00",
            "2024-08-06T12:00:00\u221203:00",
            "2024-08-06T12:00:61Z",
            "2024-08-06T12:60:00Z",
            "2024-08-06T24:00:00Z",
            "9999-12-31T23:59:59-00:01",
            "0000-01-01T00:00:00+00:01",
            "2023-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2024-04-31T00:00:00Z",
            "2024-00-06T12:00:00Z",
            "2024-13-06T12:00:00Z",
            "2024-08-00T12:00:00Z",
            "10000-01-01T00:00:00Z",
            "+2024-08-06T12:00:00Z",
            "+12024-08-06T12:00:00Z",
            "-0001-08-06T12:00:00Z",
            "2024-08-06 12:00:00Z",
            " 2024-08-06T12:00:00Z",
            "2024-08-06T12:00:00Z ",
            "2024-8-06T12:00:00Z",
            "2024-08-06T12:00:0\u0661Z",
            "2024-08-06T12:00:00.\u0661Z",
            "",
        };
        for (String text : refused) {
            assertNull(ReceiptDecoder.parseDate(text), text);
        }
    }

    /** A date in any other form is kept raw, and does not set the chain instant either. */
    @Test
    void aDateInAnyOtherFormIsKeptRawAndDoesNotSetTheChainInstant() throws Exception {
        byte[] rfc3339 = new DERIA5String("2024-08-06t15:00:00.123+03:00").getEncoded();
        assertEquals(
                Long.valueOf(1_722_945_600_123L),
                ReceiptDecoder.parse(set(attribute(12, rfc3339))).receiptCreationDateMs());
        assertEquals(Long.valueOf(1_722_945_600_123L), ReceiptDecoder.readCreationDate(set(attribute(12, rfc3339))));
        for (String text : new String[] {"2024-08-06 12:00:00Z", "2024-08-06T12:00:00+0300", "2024-08-06T12:00Z"}) {
            byte[] value = new DERIA5String(text).getEncoded();
            byte[] payload = set(attribute(12, value));
            ReceiptPayload receipt = ReceiptDecoder.parse(payload);
            assertNull(receipt.receiptCreationDateMs(), text);
            assertArrayEquals(value, receipt.unknownAttributes().get(12).get(0));
            assertNull(ReceiptDecoder.readCreationDate(payload), text);
        }
    }

    /**
     * Attribute 32 is the pre-order date: the same grammar and the same
     * failure behaviour as the other receipt-level dates. A date fills the
     * field, an empty string is "not set", anything else and every later
     * copy are kept raw.
     */
    @Test
    void attribute32IsThePreorderDateAndReadsLikeAttributes12And18() throws Exception {
        ReceiptPayload receipt =
                ReceiptDecoder.parse(set(attribute(32, new DERIA5String("2024-07-02T09:45:20Z").getEncoded())));
        assertEquals(Long.valueOf(1_719_913_520_000L), receipt.preorderDateMs());
        assertNull(receipt.unknownAttributes().get(32));
        assertEquals(
                1_719_913_520_000L,
                MAPPER.readTree(receipt.toJson()).get("preorder_date_ms").asLong());

        receipt = ReceiptDecoder.parse(set(attribute(32, new DERIA5String("").getEncoded())));
        assertNull(receipt.preorderDateMs());
        assertNull(receipt.unknownAttributes().get(32));

        byte[] notRfc3339 = new DERIA5String("2024-07-02 09:45:20Z").getEncoded();
        receipt = ReceiptDecoder.parse(set(attribute(32, notRfc3339)));
        assertNull(receipt.preorderDateMs());
        assertArrayEquals(notRfc3339, receipt.unknownAttributes().get(32).get(0));
        assertTrue(MAPPER.readTree(receipt.toJson()).get("preorder_date_ms").isNull());

        byte[] later = new DERIA5String("2024-07-03T09:45:20Z").getEncoded();
        receipt = ReceiptDecoder.parse(
                set(attribute(32, new DERIA5String("2024-07-02T09:45:20Z").getEncoded()), attribute(32, later)));
        assertEquals(Long.valueOf(1_719_913_520_000L), receipt.preorderDateMs());
        assertArrayEquals(later, receipt.unknownAttributes().get(32).get(0));
    }

    /**
     * The nesting bound is BouncyCastle's (64 by default; owner,
     * 2026-10-01). Past it the parser throws an IOException, which the
     * envelope maps to MALFORMED and signed content to UNREADABLE_PAYLOAD,
     * as for any other defect there, never an uncaught error.
     */
    @Test
    void asn1NestedPastBouncyCastlesBoundIsRefusedAsADefect() throws Exception {
        byte[] tooDeep = nestedSets(100);
        assertThrows(java.io.IOException.class, () -> ASN1Primitive.fromByteArray(tooDeep));
        VerificationException envelope = assertThrows(
                VerificationException.class,
                () -> ReceiptCore.verifyDer(tooDeep, Collections.<TrustAnchor>emptySet(), System.currentTimeMillis()));
        assertEquals(Reason.MALFORMED, envelope.reason());
        VerificationException content = assertThrows(VerificationException.class, () -> ReceiptDecoder.parse(tooDeep));
        assertEquals(Reason.UNREADABLE_PAYLOAD, content.reason());
    }

    /**
     * An attribute value is parsed on its own, and the creation date before
     * any signature, so a value is held to the same bound: one nested past
     * it is kept raw, and as a creation date it is no date.
     */
    @Test
    void anAttributeValueNestedPastTheBoundIsKeptRawAndIsNoCreationDate() throws Exception {
        byte[] tooDeep = nestedSets(100);
        ReceiptPayload receipt = ReceiptDecoder.parse(set(attribute(3, tooDeep), attribute(1, tooDeep)));
        assertNull(receipt.applicationVersion());
        assertNull(receipt.appItemId());
        assertArrayEquals(tooDeep, receipt.unknownAttributes().get(3).get(0));
        assertArrayEquals(tooDeep, receipt.unknownAttributes().get(1).get(0));
        assertNull(ReceiptDecoder.readCreationDate(set(attribute(12, tooDeep))));
    }

    /** {@code levels} SETs inside one another, the innermost empty. */
    private static byte[] nestedSets(int levels) throws Exception {
        DERSet inner = new DERSet();
        for (int i = 1; i < levels; i++) {
            inner = new DERSet(inner);
        }
        return inner.getEncoded();
    }

    private static byte[] attribute(int type, byte[] value) throws Exception {
        return new DERSequence(
                        new ASN1Encodable[] {new ASN1Integer(type), new ASN1Integer(1), new DEROctetString(value)})
                .getEncoded();
    }

    private static byte[] set(byte[]... attributes) throws Exception {
        ASN1Encodable[] elements = new ASN1Encodable[attributes.length];
        for (int i = 0; i < attributes.length; i++) {
            elements[i] = DERSequence.getInstance(attributes[i]);
        }
        return new DERSet(elements).getEncoded();
    }
}
