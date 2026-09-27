package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.cert.TrustAnchor;
import java.time.Clock;
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

    /** The receipt date grammar (owner, 2026-09-27, Q20a), at every edge of it. */
    @Test
    void aReceiptDateIsExactlyTheOneForm() {
        assertEquals(Long.valueOf(1_722_945_600_000L), ReceiptDecoder.parseDate("2024-08-06T12:00:00Z"));
        assertEquals(Long.valueOf(-62_167_219_200_000L), ReceiptDecoder.parseDate("0000-01-01T00:00:00Z"));
        assertEquals(Long.valueOf(253_402_300_799_000L), ReceiptDecoder.parseDate("9999-12-31T23:59:59Z"));
        assertNotNull(ReceiptDecoder.parseDate("2024-02-29T00:00:00Z"));
        assertNotNull(ReceiptDecoder.parseDate("2000-02-29T00:00:00Z"));
        assertNotNull(ReceiptDecoder.parseDate("0000-02-29T00:00:00Z"), "0000 is a leap year");
        String[] refused = {
            "2024-08-06t12:00:00Z",
            "2024-08-06T12:00:00z",
            "2024-08-06T12:00:00.000Z",
            "2024-08-06T12:00:00.5Z",
            "2024-08-06T12:00:00+00:00",
            "2024-08-06T12:00:00-07:00",
            "2024-08-06T12:00:00",
            "2024-08-06T12:00:60Z",
            "2024-08-06T12:60:00Z",
            "2024-08-06T24:00:00Z",
            "2023-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2024-04-31T00:00:00Z",
            "2024-00-06T12:00:00Z",
            "2024-13-06T12:00:00Z",
            "2024-08-00T12:00:00Z",
            "10000-01-01T00:00:00Z",
            "+2024-08-06T12:00:00Z",
            "-0001-08-06T12:00:00Z",
            "2024-08-06 12:00:00Z",
            " 2024-08-06T12:00:00Z",
            "2024-08-06T12:00:00Z ",
            "2024-8-06T12:00:00Z",
            "2024-08-06T12:00:0\u0661Z",
            "",
        };
        for (String text : refused) {
            assertNull(ReceiptDecoder.parseDate(text), text);
        }
    }

    /** A date in any other form is kept raw, and does not set the chain instant either. */
    @Test
    void aDateInAnyOtherFormIsKeptRawAndDoesNotSetTheChainInstant() throws Exception {
        byte[] exact = new DERIA5String("2024-08-06T12:00:00Z").getEncoded();
        assertEquals(
                Long.valueOf(1_722_945_600_000L),
                ReceiptDecoder.parse(set(attribute(12, exact))).receiptCreationDateMs());
        for (String text : new String[] {"2024-08-06T12:00:00.000Z", "2024-08-06T12:00:00+00:00"}) {
            byte[] value = new DERIA5String(text).getEncoded();
            byte[] payload = set(attribute(12, value));
            ReceiptPayload receipt = ReceiptDecoder.parse(payload);
            assertNull(receipt.receiptCreationDateMs(), text);
            assertArrayEquals(value, receipt.unknownAttributes().get(12).get(0));
            assertNull(ReceiptDecoder.readCreationDate(payload), text);
        }
    }

    /**
     * ASN.1 nests at most {@link Asn1Depth#MAX_DEPTH} constructed values
     * (owner, 2026-09-27, Q24). Beyond it the envelope is MALFORMED and
     * signed content UNREADABLE_PAYLOAD, as for any other defect there.
     */
    @Test
    void asn1NestsAtMost64ConstructedValues() throws Exception {
        assertEquals(64, Asn1Depth.MAX_DEPTH);
        assertFalse(Asn1Depth.exceeded(nestedSets(64)));
        assertTrue(Asn1Depth.exceeded(nestedSets(65)));
        // A primitive inside the innermost constructed value is not one more.
        assertFalse(Asn1Depth.exceeded(nested(64, new ASN1Integer(1)).getEncoded()));
        assertTrue(Asn1Depth.exceeded(nested(65, new ASN1Integer(1)).getEncoded()));
        // Indefinite lengths are counted the same way.
        byte[] indefinite = new byte[65 * 2 + 65 * 2];
        for (int i = 0; i < 65; i++) {
            indefinite[2 * i] = 0x30;
            indefinite[2 * i + 1] = (byte) 0x80;
        }
        assertTrue(Asn1Depth.exceeded(indefinite));
        assertFalse(Asn1Depth.exceeded(java.util.Arrays.copyOfRange(indefinite, 2, indefinite.length - 2)));
        // Why the bound is this library's: BouncyCastle's own applies to
        // indefinite lengths only, and parses a deeper DER encoding.
        ASN1Primitive.fromByteArray(nestedSets(65));

        byte[] tooDeep = nestedSets(65);
        VerificationException envelope = assertThrows(
                VerificationException.class,
                () -> ReceiptCore.verifyDer(
                        tooDeep, Collections.<TrustAnchor>emptySet(), new CallClock(Clock.systemUTC())));
        assertEquals(Reason.MALFORMED, envelope.reason());
        VerificationException content = assertThrows(VerificationException.class, () -> ReceiptDecoder.parse(tooDeep));
        assertEquals(Reason.UNREADABLE_PAYLOAD, content.reason());
    }

    /** {@code levels} SETs inside one another, the innermost empty. */
    private static byte[] nestedSets(int levels) throws Exception {
        return nested(levels, null).getEncoded();
    }

    /** {@code levels} SETs inside one another, the innermost holding {@code leaf} when there is one. */
    private static DERSet nested(int levels, ASN1Encodable leaf) {
        DERSet inner = leaf == null ? new DERSet() : new DERSet(leaf);
        for (int i = 1; i < levels; i++) {
            inner = new DERSet(inner);
        }
        return inner;
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
